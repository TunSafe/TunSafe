// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "netapi.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "tunsafe_endian.h"
#include "tunsafe_config.h"
#include "util.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

#include <sys/socket.h>
#include <net/route.h>
#include <sys/time.h>

#include <pthread.h>

#if defined(OS_MACOSX)
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <net/if_dl.h>
#elif defined(OS_FREEBSD)
#include <net/if_tun.h>
#include <net/if_dl.h>
#elif defined(OS_LINUX)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/prctl.h>
#endif



static Packet *freelist;

void SetThreadName(const char *name) {
#if defined(OS_LINUX)
  prctl(PR_SET_NAME, name, 0, 0, 0);
#endif  // defined(OS_LINUX)
}

void FreePacket(Packet *packet) {
  free(packet);
//  packet->next = freelist;
//  freelist = packet;
}

Packet *AllocPacket() {
  Packet *p = NULL;// freelist;
  if (p) {
    freelist = p->next;
  } else {
    p = (Packet*)malloc(kPacketAllocSize);  
    if (p == NULL) {
      RERROR("Allocation failure");
      abort();
    }
  }
  p->data = p->data_buf + Packet::HEADROOM_BEFORE;
  p->size = 0;
  return p;
}

void FreePackets() {
  Packet *p;
  while ( (p = freelist ) != NULL) {
    freelist = p->next;
    free(p);
  }
}

#if defined(OS_MACOSX) || defined(OS_FREEBSD)
struct MyRouteMsg {
  struct rt_msghdr hdr;
  uint32 pad;
  struct sockaddr_in target;
  struct sockaddr_in netmask;
};

struct MyRouteReply {
  struct rt_msghdr hdr;
  uint8 buf[512];
};

// Zero gets rounded up
#if defined(OS_MACOSX)
#define RTMSG_ROUNDUP(a) ((a) ? ((((a) - 1) | (sizeof(uint32_t) - 1)) + 1) : sizeof(uint32_t))
#else
#define RTMSG_ROUNDUP(a) ((a) ? ((((a) - 1) | (sizeof(long) - 1)) + 1) : sizeof(long))
#endif


static bool GetDefaultRoute(char *iface, size_t iface_size, uint32 *gw_addr) {
  int fd, pid, len;

  union {
    MyRouteMsg rt;
    MyRouteReply rep;
  };

  fd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
  if (fd < 0)
    return false;

  memset(&rt, 0, sizeof(rt));

  rt.hdr.rtm_type = RTM_GET;
  rt.hdr.rtm_flags = RTF_UP | RTF_GATEWAY;
  rt.hdr.rtm_version = RTM_VERSION;
  rt.hdr.rtm_seq = 0;
  rt.hdr.rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;

  rt.target.sin_family = AF_INET;
  rt.netmask.sin_family = AF_INET;

  rt.target.sin_len = sizeof(struct sockaddr_in);
  rt.netmask.sin_len = sizeof(struct sockaddr_in);

  rt.hdr.rtm_msglen = sizeof(rt);

  if (write(fd, (char*)&rt, sizeof(rt)) != sizeof(rt)) {
    RERROR("PF_ROUTE write failed.");
    close(fd);
    return false;
  }

  pid = getpid();
  do {
    len = read(fd, (char *)&rep, sizeof(rep));
    if (len <= 0) {
      RERROR("PF_ROUTE read failed.");
      close(fd);
      return false;
    }
  } while (rep.hdr.rtm_seq != 0 || rep.hdr.rtm_pid != pid);
  close(fd);

  const struct sockaddr_dl *ifp = NULL;
  const struct sockaddr_in *gw = NULL;

  uint8 *pos = rep.buf;
  for (int i = 1; i && i < rep.hdr.rtm_addrs; i <<= 1) {
    if (rep.hdr.rtm_addrs & i) {
      if (1 > rep.buf + 512 - pos)
        break; // invalid
      size_t len = RTMSG_ROUNDUP(((struct sockaddr*)pos)->sa_len);
      if (len > rep.buf + 512 - pos)
        break; // invalid
               //      RINFO("rtm %d %d", i, ((struct sockaddr*)pos)->sa_len);
      if (i == RTA_IFP && ((struct sockaddr*)pos)->sa_len == sizeof(struct sockaddr_dl)) {
        ifp = (struct sockaddr_dl *)pos;
      } else if (i == RTA_GATEWAY && ((struct sockaddr*)pos)->sa_len == sizeof(struct sockaddr_in)) {
        gw = (struct sockaddr_in *)pos;

      }
      pos += len;
    }
  }

  if (ifp && ifp->sdl_nlen && ifp->sdl_nlen < iface_size) {
    iface[ifp->sdl_nlen] = 0;
    memcpy(iface, ifp->sdl_data, ifp->sdl_nlen);
    if (gw && gw->sin_family == AF_INET) {
      *gw_addr = ReadBE32(&gw->sin_addr);
      return true;
    }

  }
  //  RINFO("Read %d %d %d", len, rep.hdr.rtm_addrs, (int)sizeof(struct rt_msghdr ));
  return false;
}
#endif  // defined(OS_MACOSX) || defined(OS_FREEBSD)

#if defined(OS_LINUX)
static bool GetDefaultRoute(char *iface, size_t iface_size, uint32 *gw_addr) {
  return false;
}
#endif  // defined(OS_LINUX)


#if defined(OS_MACOSX)
static mach_timebase_info_data_t timebase = { 0, 0 };
static uint64_t                  initclock;

void InitOsxGetMilliseconds() {
  if (mach_timebase_info(&timebase) != 0)
    abort();
  initclock = mach_absolute_time();

  timebase.denom *= 1000000;
}

uint64 OsGetMilliseconds()
{
  uint64_t clock = mach_absolute_time() - initclock;
  return clock * (uint64_t)timebase.numer / (uint64_t)timebase.denom;
}

#else  // defined(OS_MACOSX)
uint64 OsGetMilliseconds() {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    //error
    fprintf(stderr, "clock_gettime failed\n");
    exit(1);
  }
  return (uint64)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}
#endif

void OsGetTimestampTAI64N(uint8 dst[12]) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  uint64 secs_since_epoch = tv.tv_sec + 0x400000000000000a;
  uint32 nanos = tv.tv_usec * 1000;
  WriteBE64(dst, secs_since_epoch);
  WriteBE32(dst + 8, nanos);
}

void OsGetRandomBytes(uint8 *data, size_t data_size) {
  int fd = open("/dev/urandom", O_RDONLY);
  int r = read(fd, data, data_size);
  if (r < 0) r = 0;
  close(fd);
  for (; r < data_size; r++)
    data[r] = rand() >> 6;
}

void OsInterruptibleSleep(int millis) {
  usleep((useconds_t)millis * 1000);
}

#if defined(OS_MACOSX)
#define TUN_PREFIX_BYTES 4
int open_tun(char *devname, size_t devname_size) {
  struct sockaddr_ctl sc;
  struct ctl_info ctlinfo = {0};
  int fd;

  memcpy(ctlinfo.ctl_name, UTUN_CONTROL_NAME, sizeof(UTUN_CONTROL_NAME));

  for(int i = 0; i < 256; i++) {
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
      RERROR("socket(SYSPROTO_CONTROL) failed");
      return -1;
    }

    if (ioctl(fd, CTLIOCGINFO, &ctlinfo) == -1) {
      RERROR("ioctl(CTLIOCGINFO) failed: %d", errno);
      close(fd);
      return -1;
    }
    sc.sc_id = ctlinfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = i + 1;
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == 0) {
      socklen_t devname_size2 = devname_size;
      if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, devname, &devname_size2)) {
        RERROR("getsockopt(UTUN_OPT_IFNAME) failed");
        close(fd);
        return -1;
      }


      return fd;
    }
    close(fd);
  }
  return -1;  
}

#elif defined(OS_FREEBSD)
#define TUN_PREFIX_BYTES 4
int open_tun(char *devname, size_t devname_size) {
  char buf[32];
  int tun_fd;
  // First open an existing tun device
  for(int i = 0; i < 256; i++) {
    sprintf(buf, "/dev/tun%d", i);
    tun_fd = open(buf, O_RDWR);
    if (tun_fd >= 0) goto did_open;
  }
  tun_fd = open("/dev/tun", O_RDWR);
  if (tun_fd < 0)
    return tun_fd;
did_open:
  if (!fdevname_r(tun_fd, devname, devname_size)) {
    RERROR("Unable to get name of tun device");
    close(tun_fd);
    return -1;
  }
  int flags = IFF_POINTOPOINT | IFF_MULTICAST;
  if (ioctl(tun_fd, TUNSIFMODE, &flags) < 0) {
    RERROR("ioctl(TUNSIFMODE) failed");
    close(tun_fd);
    return -1;

  }
  flags = 1;
  if (ioctl(tun_fd, TUNSIFHEAD, &flags) < 0) {
    RERROR("ioctl(TUNSIFHEAD) failed");
    close(tun_fd);
    return -1;
  }
  return tun_fd;
}

#elif defined(OS_LINUX)
#define TUN_PREFIX_BYTES 0
int open_tun(char *devname, size_t devname_size) {
  int fd, err;
  struct ifreq ifr;

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0)
    return fd;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    close(fd);
    return err;
  }
  strcpy(devname, ifr.ifr_name);
  return fd;
}
#endif

int open_udp(int listen_on_port) {
  int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd < 0) return udp_fd;
  sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(listen_on_port);
  if (bind(udp_fd, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
    close(udp_fd);
    return -1;
  }
  return udp_fd;
}

class WorkerLoop {
public:
  WorkerLoop();
  ~WorkerLoop();

  bool Initialize(WireguardProcessor *processor);

  void *ThreadMain();
  void StartThread();

  void StopThread();

  void NotifyStop();

  enum {
    TARGET_UDP, TARGET_TUN
  };

  void HandleUdpPacket(Packet *packet) {
    HandlePacket(packet, TARGET_UDP);
  }
  void HandleTunPacket(Packet *packet) {
    HandlePacket(packet, TARGET_TUN);
  }

  void HandleSigAlrm() {
    got_sig_alarm_ = true;
  }

private:
  static void *ThreadMainStatic(void *x);
  void HandlePacket(Packet *packet, int target);

  WireguardProcessor *processor_;
  pthread_t tid_;
  Packet *queue_, **queue_end_;
  bool shutting_down_;
  bool got_sig_alarm_;

  pthread_mutex_t lock_;
  pthread_cond_t cond_;
};

// Handles the threads that read/write to the udp socket.
class UdpLoop {
public:
  UdpLoop();
  ~UdpLoop();

  bool Initialize(int listen_port, WorkerLoop *worker);
  void Start();
  void Stop();

  void WriteUdpPacket(Packet *packet);
private:
  static void *ReaderMainStatic(void *x);
  static void *WriterMainStatic(void *x);
  void *ReaderMain();
  void *WriterMain();
  
  int fd_;
  WorkerLoop *worker_;
  pthread_t read_tid_, write_tid_;

  Packet *queue_, **queue_end_;

  bool shutting_down_;

  pthread_mutex_t lock_;
  pthread_cond_t cond_;
};

// Handles the threads that read/write to the tun socket.
class TunLoop {
public:
  TunLoop();
  ~TunLoop();

  bool Initialize(WorkerLoop *worker);
  void Start();
  void Stop();

  void WriteTunPacket(Packet *packet);

  char *devname() { return devname_; }
private:
  static void *ReaderMainStatic(void *x);
  static void *WriterMainStatic(void *x);
  void *ReaderMain();
  void *WriterMain();

  int fd_;
  bool shutting_down_;
  char devname_[16];

  WorkerLoop *worker_;
  pthread_t read_tid_, write_tid_;
  Packet *queue_, **queue_end_;
  pthread_mutex_t lock_;
  pthread_cond_t cond_;
};

WorkerLoop::WorkerLoop() {
  queue_end_ = &queue_;
  queue_ = NULL;
  tid_ = 0;
  shutting_down_ = false;
  got_sig_alarm_ = false;
  processor_ = NULL;
  pthread_mutex_init(&lock_, NULL);
  pthread_cond_init(&cond_, NULL);
}

WorkerLoop::~WorkerLoop() {
  pthread_mutex_destroy(&lock_);
  pthread_cond_destroy(&cond_);
}

bool WorkerLoop::Initialize(WireguardProcessor *processor) {
  processor_ = processor;
  return true;
}

void WorkerLoop::StartThread() {
  assert(tid_ == 0);
  pthread_create(&tid_, NULL, &ThreadMainStatic, this);
}

void WorkerLoop::StopThread() {
  pthread_mutex_lock(&lock_);
  shutting_down_ = true;
  pthread_mutex_unlock(&lock_);

  if (tid_) {
    void *x;
    pthread_join(tid_, &x);
    tid_ = 0;
  }
}


// This is called from signal handler so cannot block etc.
void WorkerLoop::NotifyStop() {
  shutting_down_ = true;
}

void WorkerLoop::HandlePacket(Packet *packet, int target) {
//  RINFO("WorkerLoop::HandlePacket");
  packet->post_target = target;
  pthread_mutex_lock(&lock_);
  Packet *old_queue = queue_;
  *queue_end_ = packet;
  queue_end_ = &packet->next;
  packet->next = NULL;
  if (old_queue == NULL) {
    pthread_mutex_unlock(&lock_);
    pthread_cond_signal(&cond_);
  } else {
    pthread_mutex_unlock(&lock_);
  }
}

void *WorkerLoop::ThreadMainStatic(void *x) {
  return ((WorkerLoop*)x)->ThreadMain();
}

void *WorkerLoop::ThreadMain() {
  Packet *packet_queue;

  pthread_mutex_lock(&lock_);
  for (;;) {
    // Grab the whole list
    for (;;) {
      while (got_sig_alarm_) {
        got_sig_alarm_ = false;
        pthread_mutex_unlock(&lock_);
        processor_->SecondLoop();
        pthread_mutex_lock(&lock_);
      }
      if (shutting_down_ || queue_ != NULL)
        break;
      pthread_cond_wait(&cond_, &lock_);
    }
    if (shutting_down_)
      break;
    packet_queue = queue_;
    queue_ = NULL;
    queue_end_ = &queue_;
    
    pthread_mutex_unlock(&lock_);
    // And send all items in the list
    while (packet_queue != NULL) {
      Packet *next = packet_queue->next;
      if (packet_queue->post_target == TARGET_TUN) {
        processor_->HandleTunPacket(packet_queue);
      } else {
        processor_->HandleUdpPacket(packet_queue, false);
      }
      packet_queue = next;
    }
    pthread_mutex_lock(&lock_);
  }
  pthread_mutex_unlock(&lock_);
  return NULL;
}



UdpLoop::UdpLoop() {
  fd_ = -1;
  read_tid_ = 0;
  write_tid_ = 0;
  shutting_down_ = false;
  worker_ = NULL;
  queue_ = NULL;
  queue_end_ = &queue_;
  pthread_mutex_init(&lock_, NULL);
  pthread_cond_init(&cond_, NULL);
}

UdpLoop::~UdpLoop() {
  if (fd_ != -1)
    close(fd_);
  pthread_mutex_destroy(&lock_);
  pthread_cond_destroy(&cond_);
}

bool UdpLoop::Initialize(int listen_port, WorkerLoop *worker) {
  int fd = open_udp(listen_port);
  if (fd < 0) { RERROR("Error opening udp"); return false; }
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fd_ = fd;
  worker_ = worker;
  return true;
}

void UdpLoop::Start() {
  pthread_create(&read_tid_, NULL, &ReaderMainStatic, this);
  pthread_create(&write_tid_, NULL, &WriterMainStatic, this);
}

void UdpLoop::Stop() {
  void *x;

  pthread_mutex_lock(&lock_);
  shutting_down_ = true;
  pthread_mutex_unlock(&lock_);
  pthread_cond_signal(&cond_);

  pthread_kill(read_tid_, SIGUSR1);
  pthread_kill(write_tid_, SIGUSR1);
  
  pthread_join(read_tid_, &x);
  pthread_join(write_tid_, &x);

  read_tid_ = 0;
  write_tid_ = 0;
}

void *UdpLoop::ReaderMainStatic(void *x) {
  SetThreadName("tunsafe-ur");
  return ((UdpLoop*)x)->ReaderMain();
}

void *UdpLoop::WriterMainStatic(void *x) {
  SetThreadName("tunsafe-uw");
  return ((UdpLoop*)x)->WriterMain();
}

void *UdpLoop::ReaderMain() {
  Packet *packet;
  socklen_t sin_len;
  int r;

  while (!shutting_down_) {
    packet = AllocPacket();
    sin_len = sizeof(packet->addr.sin);
    r = recvfrom(fd_, packet->data, kPacketCapacity, 0, (sockaddr*)&packet->addr.sin, &sin_len);
    if (r < 0) {
      FreePacket(packet);
      if (shutting_down_)
        break;

      RERROR("ReadMain failed %d", errno);

    } else {
      packet->size = r;
      worker_->HandleUdpPacket(packet);
    }
  }
  return NULL;
}

void *UdpLoop::WriterMain() {
  Packet *queue;

  pthread_mutex_lock(&lock_);
  for (;;) {
    // Grab the whole list
    while (!shutting_down_ && queue_ == NULL)
      pthread_cond_wait(&cond_, &lock_);
    if (shutting_down_)
      break;
    queue = queue_;
    queue_ = NULL;
    queue_end_ = &queue_;
    pthread_mutex_unlock(&lock_);
    // And send all items in the list
    while (queue != NULL) {
      int r = sendto(fd_, queue->data, queue->size, 0,
          (sockaddr*)&queue->addr.sin, sizeof(queue->addr.sin));
      if (r != queue->size) {
        if (errno != ENOBUFS)
          RERROR("WriterMain failed: %d", errno);
      } else {
//        RINFO("WRote udp packet!");
      }
      Packet *to_free = queue;
      queue = queue->next;
      FreePacket(to_free);
    }
    pthread_mutex_lock(&lock_);
  }
  pthread_mutex_unlock(&lock_);
  return NULL;
}

void UdpLoop::WriteUdpPacket(Packet *packet) {
//  RINFO("write udp packet to queue!");
  packet->next = NULL;

  pthread_mutex_lock(&lock_);
  Packet *old_queue = queue_;
  *queue_end_ = packet;
  queue_end_ = &packet->next;
  if (old_queue == NULL) {
    pthread_mutex_unlock(&lock_);
    pthread_cond_signal(&cond_);
  } else {
    pthread_mutex_unlock(&lock_);
  }
}

TunLoop::TunLoop() {
  fd_ = -1;
  shutting_down_ = false;
  worker_ = NULL;
  read_tid_ = 0;
  write_tid_ = 0;
  queue_ = NULL;
  queue_end_ = &queue_;
  pthread_mutex_init(&lock_, NULL);
  pthread_cond_init(&cond_, NULL);
}

TunLoop::~TunLoop() {
  if (fd_ != -1)
    close(fd_);
  pthread_mutex_destroy(&lock_);
  pthread_cond_destroy(&cond_);
}

bool TunLoop::Initialize(WorkerLoop *worker) {
  int fd = open_tun(devname_, sizeof(devname_));
  if (fd < 0) { RERROR("Error opening tun"); return false; }
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fd_ = fd;
  worker_ = worker;
  return true;
}

void TunLoop::Start() {
  pthread_create(&read_tid_, NULL, &ReaderMainStatic, this);
  pthread_create(&write_tid_, NULL, &WriterMainStatic, this);
}

void TunLoop::Stop() {
  void *x;

  pthread_mutex_lock(&lock_);
  shutting_down_ = true;
  pthread_mutex_unlock(&lock_);

  pthread_kill(read_tid_, SIGUSR1);
  pthread_kill(write_tid_, SIGUSR1);
  pthread_join(read_tid_, &x);
  pthread_join(write_tid_, &x);

  read_tid_ = 0;
  write_tid_ = 0;
}

void *TunLoop::ReaderMainStatic(void *x) {
  SetThreadName("tunsafe-tr");
  return ((TunLoop*)x)->ReaderMain();
}

void *TunLoop::WriterMainStatic(void *x) {
  SetThreadName("tunsafe-tw");
  return ((TunLoop*)x)->WriterMain();
}

void *TunLoop::ReaderMain() {
  Packet *packet = AllocPacket();
  while (!shutting_down_) {
    int r = read(fd_, packet->data - TUN_PREFIX_BYTES, kPacketCapacity + TUN_PREFIX_BYTES);
    if (r >= 0) {
      packet->size = r - TUN_PREFIX_BYTES;
      if (r >= TUN_PREFIX_BYTES && (!TUN_PREFIX_BYTES || ReadBE32(packet->data - TUN_PREFIX_BYTES) == AF_INET)) {
        worker_->HandleTunPacket(packet);
        packet = AllocPacket();
      }
    }
  }
  return NULL;
}

void *TunLoop::WriterMain() {
  Packet *queue;

  pthread_mutex_lock(&lock_);
  for (;;) {
    // Grab the whole list
    while (!shutting_down_ && queue_ == NULL) {
      pthread_cond_wait(&cond_, &lock_);
    }
    if (shutting_down_)
      break;
    queue = queue_;
    queue_ = NULL;
    queue_end_ = &queue_;
    pthread_mutex_unlock(&lock_);
    // And send all items in the list
    while (queue != NULL) {
      if (TUN_PREFIX_BYTES)
        WriteBE32(queue->data - TUN_PREFIX_BYTES, AF_INET);
      int r = write(fd_, queue->data - TUN_PREFIX_BYTES, queue->size + TUN_PREFIX_BYTES);
      if (r != queue->size + TUN_PREFIX_BYTES) {
        RERROR("WriterMain failed: %d", errno);
        break;
      }
      Packet *to_free = queue;
      queue = queue->next;
      FreePacket(to_free);
    }
    pthread_mutex_lock(&lock_);
  }
  pthread_mutex_unlock(&lock_);
  return NULL;
}

void TunLoop::WriteTunPacket(Packet *packet) {
  packet->next = NULL;

  pthread_mutex_lock(&lock_);
  Packet *old_queue = queue_;
  *queue_end_ = packet;
  queue_end_ = &packet->next;
  if (old_queue == NULL) {
    pthread_mutex_unlock(&lock_);
    pthread_cond_signal(&cond_);
  } else {
    pthread_mutex_unlock(&lock_);
  }
}

struct RouteInfo {
  uint8 family;
  uint8 cidr;
  uint8 ip[16];
  uint8 gw[16];
};

class TunsafeBackendBsd : public TunInterface, public UdpInterface {
public:
  TunsafeBackendBsd();
  ~TunsafeBackendBsd();

  void RunLoop();
  void CleanupRoutes();

  void SetProcessor(WireguardProcessor *wg) { processor_ = wg; }

  // -- from TunInterface
  virtual bool Initialize(const TunConfig &&config, TunConfigOut *out) override;
  virtual void WriteTunPacket(Packet *packet) override;

  // -- from UdpInterface
  virtual bool Initialize(int listen_port) override;
  virtual void WriteUdpPacket(Packet *packet) override;

  void HandleSigAlrm() { worker_.HandleSigAlrm(); }
  void HandleExit() { worker_.NotifyStop(); }
  
private:
  void AddRoute(uint32 ip, uint32 cidr, uint32 gw);
  void DelRoute(const RouteInfo &cd);
  bool AddRoute(int family, const void *dest, int dest_prefix, const void *gateway);
  bool RunPrePostCommand(const std::vector<std::string> &vec);


  WireguardProcessor *processor_;

  bool got_sig_alarm_;
  bool exit_;

  uint32 added_route_addr_, added_route_gw_;

  WorkerLoop worker_;
  UdpLoop udp_;
  TunLoop tun_;

  std::vector<RouteInfo> cleanup_commands_;

  std::vector<std::string> pre_down_, post_down_;
};

TunsafeBackendBsd::TunsafeBackendBsd() 
    : processor_(NULL),
      got_sig_alarm_(false),
      exit_(false) {
}

TunsafeBackendBsd::~TunsafeBackendBsd() {
}

static uint32 CidrToNetmaskV4(int cidr) {
  return cidr == 32 ? 0xffffffff : 0xffffffff << (32 - cidr);
}

static uint32 ComputeIpv4DefaultRoute(uint32 ip, uint32 netmask) {
  uint32 default_route_v4 = (ip & netmask) | 1;
  if (default_route_v4 == ip)
    default_route_v4++;
  return default_route_v4;
}

static void ComputeIpv6DefaultRoute(const uint8 *ipv6_address, uint8 ipv6_cidr, uint8 *default_route_v6) {
  memcpy(default_route_v6, ipv6_address, 16);
  // clear the last bits of the ipv6 address to match the cidr.
  size_t n = (ipv6_cidr + 7) >> 3;
  memset(&default_route_v6[n], 0, 16 - n);
  if (n == 0)
    return;
  // adjust the final byte
  default_route_v6[n - 1] &= ~(0xff >> (ipv6_cidr & 7));
  // set the very last byte to something
  default_route_v6[15] |= 1;
  // ensure it doesn't collide
  if (memcmp(default_route_v6, ipv6_address, 16) == 0)
    default_route_v6[15] ^= 3;
}

void TunsafeBackendBsd::AddRoute(uint32 ip, uint32 cidr, uint32 gw) {
  uint32 ip_be, gw_be;
  WriteBE32(&ip_be, ip);
  WriteBE32(&gw_be, gw);
  AddRoute(AF_INET, &ip_be, cidr, &gw_be);
}

static void AddOrRemoveRoute(const RouteInfo &cd, bool remove) {
  char buf1[kSizeOfAddress], buf2[kSizeOfAddress];

  print_ip_prefix(buf1, cd.family, cd.ip, cd.cidr);
  print_ip_prefix(buf2, cd.family, cd.gw, -1);

#if defined(OS_LINUX)
  const char *cmd = remove ? "delete" : "add";
  if (cd.family == AF_INET) {
    RunCommand("/sbin/route %s -net %s gw %s", cmd, buf1, buf2);
  } else {
    RunCommand("/sbin/route %s -net inet6 %s gw %s", cmd, buf1, buf2);
  }
#elif defined(OS_MACOSX)
  const char *cmd = remove ? "delete" : "add";
  if (cd.family == AF_INET) {
    RunCommand("/sbin/route -q %s %s %s", cmd, buf1, buf2);
  } else {
    RunCommand("/sbin/route -q %s -inet6 %s %s", cmd, buf1, buf2);
  }
#endif
}

bool TunsafeBackendBsd::AddRoute(int family, const void *dest, int dest_prefix, const void *gateway) {
  RouteInfo c;

  c.family = family;
  size_t len = (family == AF_INET) ? 4 : 16;
  memcpy(c.ip, dest, len);
  memcpy(c.gw, gateway, len);
  c.cidr = dest_prefix;
  cleanup_commands_.push_back(c);
  AddOrRemoveRoute(c, false);
  return true;
}

void TunsafeBackendBsd::DelRoute(const RouteInfo &cd) {
  AddOrRemoveRoute(cd, true);
}

static bool IsIpv6AddressSet(const void *p) {
  return (ReadLE64(p) | ReadLE64((char*)p + 8)) != 0;
}

// Called to initialize tun
bool TunsafeBackendBsd::Initialize(const TunConfig &&config, TunConfigOut *out) override {
  char def_iface[12];

  if (!RunPrePostCommand(config.pre_post_commands.pre_up)) {
    RERROR("Pre command failed!");
    return false;
  }

  out->enable_neighbor_discovery_spoofing = false;

  if (!tun_.Initialize(&worker_))
    return false;
  
  if (config.ipv6_cidr)
    RERROR("IPv6 not supported");

  uint32 netmask = CidrToNetmaskV4(config.cidr);
  uint32 default_route_v4 = ComputeIpv4DefaultRoute(config.ip, netmask);
  
  RunCommand("/sbin/ifconfig %s %A mtu %d %A netmask %A up", tun_.devname(), config.ip, config.mtu, config.ip, netmask);
  AddRoute(config.ip & netmask, config.cidr, config.ip);

  if (config.use_ipv4_default_route) {
    if (config.default_route_endpoint_v4) {
      uint32 gw;
      if (!GetDefaultRoute(def_iface, sizeof(def_iface), &gw)) {
        RERROR("Unable to determine default interface.");
        return false;
      }
      AddRoute(config.default_route_endpoint_v4, 32, gw);

    }
    AddRoute(0x00000000, 1, default_route_v4);
    AddRoute(0x80000000, 1, default_route_v4);
  }

  uint8 default_route_v6[16];

  if (config.ipv6_cidr) {
    static const uint8 matchall_1_route[17] = {0x80, 0, 0, 0};
    char buf[kSizeOfAddress];

    ComputeIpv6DefaultRoute(config.ipv6_address, config.ipv6_cidr, default_route_v6);

    RunCommand("/sbin/ifconfig %s inet6 %s", tun_.devname(), print_ip_prefix(buf, AF_INET6, config.ipv6_address, config.ipv6_cidr));

    if (config.use_ipv6_default_route) {
      if (IsIpv6AddressSet(config.default_route_endpoint_v6)) {
        RERROR("default_route_endpoint_v6 not supported");
      }
      AddRoute(AF_INET6, matchall_1_route + 1, 1, default_route_v6);
      AddRoute(AF_INET6, matchall_1_route + 0, 1, default_route_v6);
    }
  }

  // Add all the extra routes
  for (auto it = config.extra_routes.begin(); it != config.extra_routes.end(); ++it) {
    if (it->size == 32) {
      AddRoute(ReadBE32(it->addr), it->cidr, default_route_v4);
    } else if (it->size == 128 && config.ipv6_cidr) {
      AddRoute(AF_INET6, it->addr, it->cidr, default_route_v6);
    }
  }

  RunPrePostCommand(config.pre_post_commands.post_up);

  pre_down_ = std::move(config.pre_post_commands.pre_down);
  post_down_ = std::move(config.pre_post_commands.post_down);

  return true;
}

void TunsafeBackendBsd::CleanupRoutes() {
  RunPrePostCommand(pre_down_);

  for(auto it = cleanup_commands_.begin(); it != cleanup_commands_.end(); ++it)
    DelRoute(*it);
  cleanup_commands_.clear();

  RunPrePostCommand(post_down_);

  pre_down_.clear();
  post_down_.clear();
}

static bool RunOneCommand(const std::string &cmd) {
  RINFO("Run: %s", cmd.c_str());
  int exit_code = system(cmd.c_str());
  if (exit_code) {
    RERROR("Run Failed (%d) : %s", exit_code, cmd.c_str());
    return false;
  }
  return true;
}

bool TunsafeBackendBsd::RunPrePostCommand(const std::vector<std::string> &vec) {
  bool success = true;
  for (auto it = vec.begin(); it != vec.end(); ++it) {
    success &= RunOneCommand(*it);
  }
  return success;
}


void TunsafeBackendBsd::WriteTunPacket(Packet *packet) override {
  tun_.WriteTunPacket(packet);
}

// Called to initialize udp
bool TunsafeBackendBsd::Initialize(int listen_port) override {
  return udp_.Initialize(listen_port, &worker_);
}

void TunsafeBackendBsd::WriteUdpPacket(Packet *packet) override {
  udp_.WriteUdpPacket(packet);
}

static TunsafeBackendBsd *g_tunsafe_backend_bsd;

static void SigAlrm(int sig) {
  if (g_tunsafe_backend_bsd)
    g_tunsafe_backend_bsd->HandleSigAlrm();
}

static void SigUsr1(int sig) {

}

static bool did_ctrlc;

void SigInt(int sig) {
  if (did_ctrlc)
    exit(1);
  did_ctrlc = true;
  write(1, "Ctrl-C detected. Exiting. Press again to force quit.\n", sizeof("Ctrl-C detected. Exiting. Press again to force quit.\n")-1);
  
  if (g_tunsafe_backend_bsd)
    g_tunsafe_backend_bsd->HandleExit();
}

void TunsafeBackendBsd::RunLoop() {
  int free_packet_interval = 10;

  assert(!g_tunsafe_backend_bsd);
  assert(processor_);

  g_tunsafe_backend_bsd = this;
  // We want an alarm signal every second.
  {
    struct sigaction act = {0};
    act.sa_handler = SigAlrm;
    if (sigaction(SIGALRM, &act, NULL) < 0) {
      RERROR("Unable to install SIGALRM handler.");
      return;
    }
  }

  {
    struct sigaction act = {0};
    act.sa_handler = SigInt;
    if (sigaction(SIGINT, &act, NULL) < 0) {
      RERROR("Unable to install SIGINT handler.");
      return;
    }
  }

  {
    struct sigaction act = {0};
    act.sa_handler = SigUsr1;
    if (sigaction(SIGUSR1, &act, NULL) < 0) {
      RERROR("Unable to install SIGUSR1 handler.");
      return;
    }
  }



#if defined(OS_LINUX) || defined(OS_FREEBSD)
  {
    struct itimerspec tv = {0};
    struct sigevent sev;
    timer_t timer_id;

    tv.it_interval.tv_sec = 1;
    tv.it_value.tv_sec = 1;

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGALRM;
    sev.sigev_value.sival_ptr = NULL;

    if (timer_create(CLOCK_MONOTONIC, &sev, &timer_id) < 0) {
      RERROR("timer_create failed");
      return;
    }    

    if (timer_settime(timer_id, 0, &tv, NULL) < 0) {
      RERROR("timer_settime failed");
      return;
    }
  }
#elif defined(OS_MACOSX)
  ualarm(1000000, 1000000);
#endif
  
  worker_.Initialize(processor_);

  // Start the processing threads
  udp_.Start();
  tun_.Start();

  worker_.ThreadMain();

  tun_.Stop();
  udp_.Stop();

  g_tunsafe_backend_bsd = NULL;
}

void InitCpuFeatures();
void Benchmark();


uint32 g_ui_ip;

const char *print_ip(char buf[kSizeOfAddress], in_addr_t ip) {
  snprintf(buf, kSizeOfAddress, "%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip >> 0) & 0xff);
  return buf;
}


class MyProcessorDelegate : public ProcessorDelegate {
public:
  virtual void OnConnected(in_addr_t my_ip) {
    if (my_ip != g_ui_ip) {
      if (my_ip) {
        char buf[kSizeOfAddress];
        print_ip(buf, my_ip);
        RINFO("Connection established. IP %s", buf);
      }
      g_ui_ip = my_ip;
    }
  }
  virtual void OnDisconnected() {
    MyProcessorDelegate::OnConnected(0);
  }
};




int main(int argc, char **argv) {
  bool exit_flag = false;

  InitCpuFeatures();

  if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) {
    Benchmark();
    return 0;
  }

  fprintf(stderr, "%s\n", TUNSAFE_VERSION_STRING);

  if (argc < 2) {
    fprintf(stderr, "Syntax: tunsafe file.conf\n");
    return 1;
  }
  
#if defined(OS_MACOSX)
  InitOsxGetMilliseconds();
#endif

  SetThreadName("tunsafe-m");


  MyProcessorDelegate my_procdel;
  TunsafeBackendBsd socket_loop;
  WireguardProcessor wg(&socket_loop, &socket_loop, &my_procdel);
  socket_loop.SetProcessor(&wg);

  if (!ParseWireGuardConfigFile(&wg, argv[1], &exit_flag)) return 1;
  if (!wg.Start()) return 1;

  socket_loop.RunLoop();
  socket_loop.CleanupRoutes();

  return 0;
}
