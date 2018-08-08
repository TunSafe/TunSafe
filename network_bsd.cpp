// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "netapi.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "tunsafe_endian.h"
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
#endif

static Packet *freelist;

void FreePacket(Packet *packet) {
  packet->next = freelist;
  freelist = packet;
}

Packet *AllocPacket() {
  Packet *p = freelist;
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

struct RouteInfo {
  uint8 family;
  uint8 cidr;
  uint8 ip[16];
  uint8 gw[16];
};

class TunsafeBackendBsd : public TunInterface, public UdpInterface {
public:
  TunsafeBackendBsd();
  void RunLoop();
  void Cleanup();

  void SetProcessor(WireguardProcessor *wg) { processor_ = wg; }

  // -- from TunInterface
  virtual bool Initialize(const TunConfig &&config, TunConfigOut *out) override;
  virtual void WriteTunPacket(Packet *packet) override;

  // -- from UdpInterface
  virtual bool Initialize(int listen_port) override;
  virtual void WriteUdpPacket(Packet *packet) override;


  void HandleSigAlrm() { got_sig_alarm_ = true; }
  void HandleExit() { exit_ = true; }
  
private:
  bool ReadFromUdp();
  bool ReadFromTun();
  bool WriteToUdp();
  bool WriteToTun();


  void SetUdpFd(int fd);
  void SetTunFd(int fd);

  void AddRoute(uint32 ip, uint32 cidr, uint32 gw);
  void DelRoute(const RouteInfo &cd);
  bool AddRoute(int family, const void *dest, int dest_prefix, const void *gateway);


  inline void RecomputeMaxFd() { max_fd_ = ((tun_fd_>udp_fd_) ? tun_fd_ : udp_fd_) + 1; }

  WireguardProcessor *processor_;

  int tun_fd_, udp_fd_, max_fd_;
  bool got_sig_alarm_;
  bool exit_;

  bool tun_readable_, tun_writable_;
  bool udp_readable_, udp_writable_;

  Packet *tun_queue_, **tun_queue_end_;
  Packet *udp_queue_, **udp_queue_end_;

  Packet *read_packet_;

  std::vector<RouteInfo> cleanup_commands_;

  fd_set readfds_, writefds_;


};

TunsafeBackendBsd::TunsafeBackendBsd() 
    : processor_(NULL),
      tun_fd_(-1),
      udp_fd_(-1),
      tun_readable_(false),
      tun_writable_(false),
      udp_readable_(false),
      udp_writable_(false),
      got_sig_alarm_(false),
      exit_(false),
      tun_queue_(NULL),
      tun_queue_end_(&tun_queue_),
      udp_queue_(NULL),
      udp_queue_end_(&udp_queue_),
      read_packet_(NULL) {
  RecomputeMaxFd();

  FD_ZERO(&readfds_);
  FD_ZERO(&writefds_);
  read_packet_ = AllocPacket();
}

void TunsafeBackendBsd::SetUdpFd(int fd) {
  udp_fd_ = fd;
  RecomputeMaxFd();
  udp_writable_ = true;
}

void TunsafeBackendBsd::SetTunFd(int fd) {
  tun_fd_ = fd;
  RecomputeMaxFd();
  tun_writable_ = true;
}


bool TunsafeBackendBsd::ReadFromUdp() {
  socklen_t sin_len;
  sin_len = sizeof(read_packet_->addr.sin);
  int r = recvfrom(udp_fd_, read_packet_->data, kPacketCapacity, 0,
                   (sockaddr*)&read_packet_->addr.sin, &sin_len);
  if (r >= 0) {
//    printf("Read %d bytes from UDP\n", r);
    read_packet_->sin_size = sin_len;
    read_packet_->size = r;
    if (processor_) {
      processor_->HandleUdpPacket(read_packet_, false);
      read_packet_ = AllocPacket();
    }
    return true;        
  } else {
    if (errno != EAGAIN) {
      fprintf(stderr, "Read from UDP failed\n");
    }
    udp_readable_ = false;
    return false;
  }
}

bool TunsafeBackendBsd::WriteToUdp() {
  assert(udp_writable_);
//  RINFO("Send %d bytes to %s", (int)udp_queue_->size, inet_ntoa(udp_queue_->sin.sin_addr));
  int r = sendto(udp_fd_, udp_queue_->data, udp_queue_->size, 0, 
                 (sockaddr*)&udp_queue_->addr.sin, sizeof(udp_queue_->addr.sin));
  if (r < 0) {
    if (errno == EAGAIN) {
      udp_writable_ = false;
      return false;
    }
    perror("Write to UDP failed");
  } else {
    if (r != udp_queue_->size)
      perror("Write to udp incomplete!");
//    else
//      RINFO("Wrote %d bytes to UDP", r);
  }
  Packet *next = udp_queue_->next;
  FreePacket(udp_queue_);
  if ((udp_queue_ = next) != NULL) return true;
  udp_queue_end_ = &udp_queue_;
  return false;
}

static inline bool IsCompatibleProto(uint32 v) {
  return v == AF_INET || v == AF_INET6;
}

bool TunsafeBackendBsd::ReadFromTun() {
  assert(tun_readable_);
  Packet *packet = read_packet_;
  int r = read(tun_fd_, packet->data - TUN_PREFIX_BYTES, kPacketCapacity + TUN_PREFIX_BYTES);
  if (r >= 0) {
//    printf("Read %d bytes from TUN\n", r);
    packet->size = r - TUN_PREFIX_BYTES;
    if (r >= TUN_PREFIX_BYTES && (!TUN_PREFIX_BYTES || IsCompatibleProto(ReadBE32(packet->data - TUN_PREFIX_BYTES))) && processor_) {
//      printf("%X %X %X %X %X %X %X %X\n",
//        read_packet_->data[0], read_packet_->data[1], read_packet_->data[2], read_packet_->data[3], 
//        read_packet_->data[4], read_packet_->data[5], read_packet_->data[6], read_packet_->data[7]);
      read_packet_ = AllocPacket();
      processor_->HandleTunPacket(packet);
    }
    return true;        
  } else {
    if (errno != EAGAIN) {
      fprintf(stderr, "Read from tun failed\n");
    }
    tun_readable_ = false;
    return false;
  }
}

static uint32 GetProtoFromPacket(const uint8 *data, size_t size) {
  return size < 1 || (data[0] >> 4) != 6 ? AF_INET : AF_INET6;
}

bool TunsafeBackendBsd::WriteToTun() {
  assert(tun_writable_);
  if (TUN_PREFIX_BYTES) {
    WriteBE32(tun_queue_->data - TUN_PREFIX_BYTES, GetProtoFromPacket(tun_queue_->data, tun_queue_->size));
  }
  int r = write(tun_fd_, tun_queue_->data - TUN_PREFIX_BYTES, tun_queue_->size + TUN_PREFIX_BYTES);
  if (r < 0) {
    if (errno == EAGAIN) {
      tun_writable_ = false;
      return false;
    }
    RERROR("Write to tun failed");
  } else {
    r -= TUN_PREFIX_BYTES;
    if (r != tun_queue_->size)
      RERROR("Write to tun incomplete!");
//    else
//      RINFO("Wrote %d bytes to TUN", r);
  }  
  Packet *next = tun_queue_->next;
  FreePacket(tun_queue_);
  if ((tun_queue_ = next) != NULL) return true;
  tun_queue_end_ = &tun_queue_;
  return false;
}

static uint32 CidrToNetmaskV4(int cidr) {
  return cidr == 32 ? 0xffffffff : 0xffffffff << (32 - cidr);
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
  for(int i = 1; i && i < rep.hdr.rtm_addrs; i <<= 1) {
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
  char devname[12];
  char def_iface[12];
  char buf[kSizeOfAddress];

  Cleanup();

  out->enable_neighbor_discovery_spoofing = false;

  int tun_fd = open_tun(devname, sizeof(devname));
  if (tun_fd < 0) { RERROR("Error opening tun device"); return false; }

  fcntl(tun_fd, F_SETFD, FD_CLOEXEC);
  fcntl(tun_fd, F_SETFL, O_NONBLOCK);

  SetTunFd(tun_fd);

  uint32 netmask = CidrToNetmaskV4(config.cidr);
  uint32 default_route_v4 = ComputeIpv4DefaultRoute(config.ip, netmask);
 
  RunCommand("/sbin/ifconfig %s %A mtu %d %A netmask %A up", devname, config.ip, config.mtu, config.ip, netmask);
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

    ComputeIpv6DefaultRoute(config.ipv6_address, config.ipv6_cidr, default_route_v6);

    RunCommand("/sbin/ifconfig %s inet6 %s", devname, print_ip_prefix(buf, AF_INET6, config.ipv6_address, config.ipv6_cidr));

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

  return true;
}

void TunsafeBackendBsd::Cleanup() {
  for(auto it = cleanup_commands_.begin(); it != cleanup_commands_.end(); ++it)
    DelRoute(*it);
  cleanup_commands_.clear();
}

void TunsafeBackendBsd::WriteTunPacket(Packet *packet) override {
  assert(tun_fd_ >= 0);
  Packet *queue_is_used = tun_queue_;
  *tun_queue_end_ = packet;
  tun_queue_end_ = &packet->next;
  packet->next = NULL;
  if (!queue_is_used)
    WriteToTun();
}

// Called to initialize udp
bool TunsafeBackendBsd::Initialize(int listen_port) override {
  int udp_fd = open_udp(listen_port);
  if (udp_fd < 0) { RERROR("Error opening udp"); return false; }
  fcntl(udp_fd, F_SETFD, FD_CLOEXEC);
  fcntl(udp_fd, F_SETFL, O_NONBLOCK);
  SetUdpFd(udp_fd);
  return true;
}

void TunsafeBackendBsd::WriteUdpPacket(Packet *packet) override {
  assert(udp_fd_ >= 0);
  Packet *queue_is_used = udp_queue_;
  *udp_queue_end_ = packet;
  udp_queue_end_ = &packet->next;
  packet->next = NULL;
  if (!queue_is_used)
    WriteToUdp();
}

static TunsafeBackendBsd *g_socket_loop;

static void SigAlrm(int sig) {
  if (g_socket_loop)
    g_socket_loop->HandleSigAlrm();
}

static bool did_ctrlc;

void SigInt(int sig) {
  if (did_ctrlc)
    exit(1);
  did_ctrlc = true;
  write(1, "Ctrl-C detected. Exiting. Press again to force quit.\n", sizeof("Ctrl-C detected. Exiting. Press again to force quit.\n")-1);
  
  if (g_socket_loop)
    g_socket_loop->HandleExit();    
}

void TunsafeBackendBsd::RunLoop() {
  int free_packet_interval = 10;

  assert(!g_socket_loop);
  assert(processor_);

  g_socket_loop = this;
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

  while (!exit_) {
    int n = -1;

//    printf("entering sleep %d,%d,%d %d\n", udp_fd_, tun_fd_, max_fd_, FD_ISSET(tun_fd_, &readfds_));
    // Wait for sockets to become usable
    if (!got_sig_alarm_) {

      if (tun_fd_ >= 0) {
        FD_SET(tun_fd_, &readfds_);
        if (tun_writable_) FD_CLR(tun_fd_, &writefds_); else FD_SET(tun_fd_, &writefds_);
      }

      if (udp_fd_ >= 0) {
        FD_SET(udp_fd_, &readfds_);
        if (udp_writable_) FD_CLR(udp_fd_, &writefds_); else FD_SET(udp_fd_, &writefds_);
      }

      n = select(max_fd_, &readfds_, &writefds_, NULL, NULL);
      if (n == -1) {
        if (errno != EINTR) {
          fprintf(stderr, "select failed\n");
          break;
        }
      }
    }
    // This is not fully signal safe.
    if (got_sig_alarm_) {
      got_sig_alarm_ = false;
      processor_->SecondLoop();
      if (free_packet_interval == 0) {
        FreePackets();
        free_packet_interval = 10;
      }
      free_packet_interval--;
    }
    if (n < 0) continue;

    if (tun_fd_ >= 0) {
      tun_readable_ = (FD_ISSET(tun_fd_, &readfds_) != 0);
      tun_writable_ |= (FD_ISSET(tun_fd_, &writefds_) != 0);
    }
    if (udp_fd_ >= 0) {
      udp_readable_ = (FD_ISSET(udp_fd_, &readfds_) != 0);
      udp_writable_ |= (FD_ISSET(udp_fd_, &writefds_) != 0);
    }

    for(int loop = 0; loop < 256; loop++) {
      bool more_work = false;
      if (tun_queue_ != NULL && tun_writable_) more_work |= WriteToTun();
      if (udp_queue_ != NULL && udp_writable_) more_work |= WriteToUdp();
      if (tun_readable_)                       more_work |= ReadFromTun();
      if (udp_readable_)                       more_work |= ReadFromUdp();
      if (!more_work)
        break;
    }    
  }

  g_socket_loop = NULL;
}

void InitCpuFeatures();
void Benchmark();

int main(int argc, char **argv) {
  bool exit_flag = false;

  InitCpuFeatures();

  if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) {
    Benchmark();
    return 0;
  }

  if (argc < 2) {
    fprintf(stderr, "Syntax: tunsafe file.conf\n");
    return 1;
  }
  
#if defined(OS_MACOSX)
  InitOsxGetMilliseconds();
#endif

  TunsafeBackendBsd socket_loop;
  WireguardProcessor wg(&socket_loop, &socket_loop, NULL);
  socket_loop.SetProcessor(&wg);

  if (!ParseWireGuardConfigFile(&wg, argv[1], &exit_flag)) return 1;
  if (!wg.Start()) return 1;

  socket_loop.RunLoop();
  socket_loop.Cleanup();
  return 0;
}
