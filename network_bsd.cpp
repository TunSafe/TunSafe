// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "network_bsd_common.h"
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
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <poll.h>

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


class TunsafeBackendBsdImpl : public TunsafeBackendBsd {
public:
  TunsafeBackendBsdImpl();
  virtual ~TunsafeBackendBsdImpl();

  virtual void RunLoopInner() override;
  virtual bool InitializeTun(char devname[16]) override;

  // -- from TunInterface
  virtual void WriteTunPacket(Packet *packet) override;

  // -- from UdpInterface
  virtual bool Configure(int listen_port) override;
  virtual void WriteUdpPacket(Packet *packet) override;

  virtual void HandleSigAlrm() override { got_sig_alarm_ = true; }
  virtual void HandleExit() override { exit_ = true; }
  
private:
  bool ReadFromUdp(bool overload);
  bool ReadFromTun();
  bool WriteToUdp();
  bool WriteToTun();
  bool InitializeUnixDomainSocket(const char *devname);

  // Exists for the unix domain sockets
  struct SockInfo {
    bool is_listener;

    std::string inbuf, outbuf;
  };
  bool HandleSpecialPollfd(struct pollfd *pollfd, struct SockInfo *sockinfo);
  void CloseSpecialPollfd(size_t i);
  void SetUdpFd(int fd);
  void SetTunFd(int fd);

  bool got_sig_alarm_;
  bool exit_;

  bool tun_readable_, tun_writable_;
  bool udp_readable_, udp_writable_;

  Packet *tun_queue_, **tun_queue_end_;
  Packet *udp_queue_, **udp_queue_end_;

  Packet *read_packet_;

  enum {
    kMaxPollFd = 5,
    kPollFdTun = 0,
    kPollFdUdp = 1,
    kPollFdUnix = 2,
  };

  unsigned int pollfd_num_;
  struct pollfd pollfd_[kMaxPollFd];

  struct SockInfo sockinfo_[kMaxPollFd - 2];

  struct sockaddr_un un_addr_;

  UnixSocketDeletionWatcher un_deletion_watcher_;
};

TunsafeBackendBsdImpl::TunsafeBackendBsdImpl() 
    : tun_readable_(false),
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
  read_packet_ = AllocPacket();
  for(size_t i = 0; i < kMaxPollFd; i++)
    pollfd_[i].fd = -1;
  pollfd_num_ = 3;
  sockinfo_[0].is_listener = true;
  memset(&un_addr_, 0, sizeof(un_addr_));
}

TunsafeBackendBsdImpl::~TunsafeBackendBsdImpl() {
  if (un_addr_.sun_path[0])
    unlink(un_addr_.sun_path);
  if (read_packet_)
    FreePacket(read_packet_);
  for(size_t i = 0; i < pollfd_num_; i++)
    close(pollfd_[i].fd);
}

void TunsafeBackendBsdImpl::SetUdpFd(int fd) {
  pollfd_[kPollFdUdp].fd = fd;
  pollfd_[kPollFdUdp].events = POLLIN;
  udp_writable_ = true;
}

void TunsafeBackendBsdImpl::SetTunFd(int fd) {
  pollfd_[kPollFdTun].fd = fd;
  pollfd_[kPollFdTun].events = POLLIN;
  tun_writable_ = true;
}

bool TunsafeBackendBsdImpl::ReadFromUdp(bool overload) {
  socklen_t sin_len;
  sin_len = sizeof(read_packet_->addr.sin);
  int r = recvfrom(pollfd_[kPollFdUdp].fd, read_packet_->data, kPacketCapacity, 0,
                   (sockaddr*)&read_packet_->addr.sin, &sin_len);
  if (r >= 0) {
//    printf("Read %d bytes from UDP\n", r);
    read_packet_->sin_size = sin_len;
    read_packet_->size = r;
    if (processor_) {
      processor_->HandleUdpPacket(read_packet_, overload);
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

bool TunsafeBackendBsdImpl::WriteToUdp() {
  assert(udp_writable_);
//  RINFO("Send %d bytes to %s", (int)udp_queue_->size, inet_ntoa(udp_queue_->sin.sin_addr));
  int r = sendto(pollfd_[kPollFdUdp].fd, udp_queue_->data, udp_queue_->size, 0, 
                 (sockaddr*)&udp_queue_->addr.sin, sizeof(udp_queue_->addr.sin));
  if (r < 0) {
    if (errno == EAGAIN) {
      udp_writable_ = false;
      pollfd_[kPollFdUdp].events = POLLIN | POLLOUT;
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

bool TunsafeBackendBsdImpl::ReadFromTun() {
  assert(tun_readable_);
  Packet *packet = read_packet_;
  int r = read(pollfd_[kPollFdTun].fd, packet->data - TUN_PREFIX_BYTES, kPacketCapacity + TUN_PREFIX_BYTES);
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

bool TunsafeBackendBsdImpl::WriteToTun() {
  assert(tun_writable_);
  if (TUN_PREFIX_BYTES) {
    WriteBE32(tun_queue_->data - TUN_PREFIX_BYTES, GetProtoFromPacket(tun_queue_->data, tun_queue_->size));
  }
  int r = write(pollfd_[kPollFdTun].fd, tun_queue_->data - TUN_PREFIX_BYTES, tun_queue_->size + TUN_PREFIX_BYTES);
  if (r < 0) {
    if (errno == EAGAIN) {
      tun_writable_ = false;
      pollfd_[kPollFdTun].events = POLLIN | POLLOUT;
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

bool TunsafeBackendBsdImpl::InitializeTun(char devname[16]) {
  int tun_fd = open_tun(devname, 16);
  if (tun_fd < 0) { RERROR("Error opening tun device"); return false; }
  fcntl(tun_fd, F_SETFD, FD_CLOEXEC);
  fcntl(tun_fd, F_SETFL, O_NONBLOCK);
  SetTunFd(tun_fd);

  InitializeUnixDomainSocket(devname);
  return true;  
}

void TunsafeBackendBsdImpl::WriteTunPacket(Packet *packet) override {
  assert(pollfd_[kPollFdTun].fd >= 0);
  Packet *queue_is_used = tun_queue_;
  *tun_queue_end_ = packet;
  tun_queue_end_ = &packet->next;
  packet->next = NULL;
  if (!queue_is_used)
    WriteToTun();
}

// Called to initialize udp
bool TunsafeBackendBsdImpl::Configure(int listen_port) override {
  int udp_fd = open_udp(listen_port);
  if (udp_fd < 0) { RERROR("Error opening udp"); return false; }
  fcntl(udp_fd, F_SETFD, FD_CLOEXEC);
  fcntl(udp_fd, F_SETFL, O_NONBLOCK);
  SetUdpFd(udp_fd);
  return true;
}

void TunsafeBackendBsdImpl::WriteUdpPacket(Packet *packet) override {
  assert(pollfd_[kPollFdUdp].fd >= 0);
  Packet *queue_is_used = udp_queue_;
  *udp_queue_end_ = packet;
  udp_queue_end_ = &packet->next;
  packet->next = NULL;
  if (!queue_is_used)
    WriteToUdp();
}

bool TunsafeBackendBsdImpl::InitializeUnixDomainSocket(const char *devname) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1) {
    RERROR("Error creating unix domain socket");
    return false;
  }

  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fcntl(fd, F_SETFL, O_NONBLOCK);

  mkdir("/var/run/wireguard", 0755);
  un_addr_.sun_family = AF_UNIX;
  snprintf(un_addr_.sun_path, sizeof(un_addr_.sun_path), "/var/run/wireguard/%s.sock", devname);
  unlink(un_addr_.sun_path);
  if (bind(fd, (struct sockaddr*)&un_addr_, sizeof(un_addr_)) == -1) {
    RERROR("Error binding unix domain socket");
    close(fd);
    return false;
  }
  if (listen(fd, 5) == -1) {
    RERROR("Error listening on unix domain socket");
    close(fd);
    return false;
  }

  pollfd_[kPollFdUnix].fd = fd;
  pollfd_[kPollFdUnix].events = POLLIN;

  return true;
}

static const char *FindMessageEnd(const char *start, size_t size) {
  if (size <= 1)
    return NULL;
  const char *start_end = start + size - 1;
  for(;(start = (const char*)memchr(start, '\n', start_end - start)) != NULL; start++) {
    if (start[1] == '\n')
      return start + 2;
  }
  return NULL;
}

bool TunsafeBackendBsdImpl::HandleSpecialPollfd(struct pollfd *pfd, struct SockInfo *sockinfo) {
  // handle domain socket thing
  if (sockinfo->is_listener) {
    if (pfd->revents & POLLIN) {
      // wait if we can't allocate more pollfd
      if (pollfd_num_ == kMaxPollFd) {
        pfd->events = 0;
        return true;
      }
      int fd = accept(pfd->fd, NULL, NULL);
      if (fd >= 0) {
        size_t slot = pollfd_num_++;
        pollfd_[slot].fd = fd;
        pollfd_[slot].events = POLLIN;
        pollfd_[slot].revents = 0;
        sockinfo_[slot - 2].is_listener = false;
      } else {
        RERROR("Unix domain socket accept failed");
      }
    }
    if (pfd->revents & ~POLLIN) {
      RERROR("Unix domain socket got an error code");
      return false;
    }
    return true;
  }
  if (pfd->revents & POLLIN) {
    char buf[4096];
    // read as much data as we can until we see \n\n
    ssize_t n = recv(pfd->fd, buf, sizeof(buf), 0);
    if (n <= 0)
      return (n == -1 && errno == EAGAIN);  // premature eof or error
    sockinfo->inbuf.append(buf, n);
    const char *message_end = FindMessageEnd(&sockinfo->inbuf[0], sockinfo->inbuf.size());
    if (message_end) {
      if (message_end != &sockinfo->inbuf[sockinfo->inbuf.size()]) 
        return false;  // trailing data?
      WgConfig::HandleConfigurationProtocolMessage(processor_, std::move(sockinfo->inbuf), &sockinfo->outbuf);
      if (!sockinfo->outbuf.size())
        return false;
      pfd->revents = pfd->events = POLLOUT;
    }
  }
  if (pfd->revents & POLLOUT) {
    size_t n = send(pfd->fd, sockinfo->outbuf.data(), sockinfo->outbuf.size(), 0);
    if (n <= 0)
      return (n == -1 && errno == EAGAIN);  // premature eof or error
    sockinfo->outbuf.erase(0, n);
    if (!sockinfo->outbuf.size())
      return false;
  }

  if (pfd->revents & ~(POLLIN | POLLOUT)) {
    RERROR("Unix domain socket got an error code");
    return false;
  }
  return true;
}

void TunsafeBackendBsdImpl::CloseSpecialPollfd(size_t i) {
  close(pollfd_[i].fd);
  pollfd_[i].fd = -1;
  sockinfo_[i - 2].inbuf.clear();
  sockinfo_[i - 2].outbuf.clear();
  pollfd_[i] = pollfd_[(size_t)pollfd_num_ - 1];
  std::swap(sockinfo_[i - 2], sockinfo_[(size_t)pollfd_num_ - 1 - 2]);

  // Can now allow more sockets?
  if (pollfd_num_-- == kMaxPollFd && sockinfo_[kPollFdUnix - 2].is_listener)
    pollfd_[kPollFdUnix].events = POLLIN;
}

void TunsafeBackendBsdImpl::RunLoopInner() {
  int free_packet_interval = 10;
  int overload_ctr = 0;

  if (!un_deletion_watcher_.Start(un_addr_.sun_path, &exit_))
    return;

  while (!exit_) {
    int n = -1;

    if (got_sig_alarm_) {
      got_sig_alarm_ = false;

      if (un_deletion_watcher_.Poll(un_addr_.sun_path)) {
        RINFO("Unix socket %s deleted.", un_addr_.sun_path);
        break;
      }
      processor_->SecondLoop();

      if (free_packet_interval == 0) {
        FreePackets();
        free_packet_interval = 10;
      }
      free_packet_interval--;

      overload_ctr -= (overload_ctr != 0);
    }

#if defined(OS_LINUX) || defined(OS_FREEBSD)
    n = ppoll(pollfd_, pollfd_num_, NULL, &orig_signal_mask_);
#else
    n = poll(pollfd_, pollfd_num_, -1);
#endif
    if (n == -1) {
      if (errno != EINTR) {
        RERROR("poll failed");
        break;
      }
    } else {
      
      if (pollfd_[kPollFdTun].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        if (pollfd_[kPollFdTun].revents & POLLERR) {
          tun_interface_gone_ = true;
          RERROR("Tun interface gone, closing.");
        } else {
          RERROR("Tun interface error %d, closing.", pollfd_[kPollFdTun].revents);
        }
        break;
      }
      tun_readable_ = (pollfd_[kPollFdTun].revents & POLLIN) != 0;
      if (pollfd_[kPollFdTun].revents & POLLOUT) {
        pollfd_[kPollFdTun].events = POLLIN;
        tun_writable_ = true;
      }

      if (pollfd_[kPollFdUdp].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        RERROR("UDP error %d, closing.", pollfd_[kPollFdUdp].revents);
        break;
      }

      udp_readable_ = (pollfd_[kPollFdUdp].revents & POLLIN) != 0;
      if (pollfd_[kPollFdUdp].revents & POLLOUT) {
        pollfd_[kPollFdUdp].events = POLLIN;
        udp_writable_ = true;
      }

      for(size_t i = 2; i < pollfd_num_; i++) {
        if (pollfd_[i].revents && !HandleSpecialPollfd(&pollfd_[i], &sockinfo_[i - 2])) {
          // Close the fd / discard the sockinfo
          CloseSpecialPollfd(i);
          i--;
        }
      }
    }

    bool overload = (overload_ctr != 0);

    for(int loop = 0; ; loop++) {
      // Whenever we don't finish set overload ctr.
      if (loop == 256) {
        overload_ctr = 4;
        break;
      }
      bool more_work = false;
      if (tun_queue_ != NULL && tun_writable_) more_work |= WriteToTun();
      if (udp_queue_ != NULL && udp_writable_) more_work |= WriteToUdp();
      if (tun_readable_)                       more_work |= ReadFromTun();
      if (udp_readable_)                       more_work |= ReadFromUdp(overload);
      if (!more_work)
        break;
    }    

    processor_->RunAllMainThreadScheduled();
  }  

  un_deletion_watcher_.Stop();
}

TunsafeBackendBsd *CreateTunsafeBackendBsd() {
  return new TunsafeBackendBsdImpl;
}
