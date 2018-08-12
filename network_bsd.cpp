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
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

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
  virtual bool Initialize(int listen_port) override;
  virtual void WriteUdpPacket(Packet *packet) override;

  virtual void HandleSigAlrm() override { got_sig_alarm_ = true; }
  virtual void HandleExit() override { exit_ = true; }
  
private:
  bool ReadFromUdp(bool overload);
  bool ReadFromTun();
  bool WriteToUdp();
  bool WriteToTun();

  void SetUdpFd(int fd);
  void SetTunFd(int fd);
  inline void RecomputeMaxFd() { max_fd_ = ((tun_fd_>udp_fd_) ? tun_fd_ : udp_fd_) + 1; }

  int tun_fd_, udp_fd_, max_fd_;
  bool got_sig_alarm_;
  bool exit_;

  bool tun_readable_, tun_writable_;
  bool udp_readable_, udp_writable_;

  Packet *tun_queue_, **tun_queue_end_;
  Packet *udp_queue_, **udp_queue_end_;

  Packet *read_packet_;

  fd_set readfds_, writefds_;
};

TunsafeBackendBsdImpl::TunsafeBackendBsdImpl() 
    : tun_fd_(-1),
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

TunsafeBackendBsdImpl::~TunsafeBackendBsdImpl() {
  if (read_packet_)
    FreePacket(read_packet_);
}

void TunsafeBackendBsdImpl::SetUdpFd(int fd) {
  udp_fd_ = fd;
  RecomputeMaxFd();
  udp_writable_ = true;
}

void TunsafeBackendBsdImpl::SetTunFd(int fd) {
  tun_fd_ = fd;
  RecomputeMaxFd();
  tun_writable_ = true;
}


bool TunsafeBackendBsdImpl::ReadFromUdp(bool overload) {
  socklen_t sin_len;
  sin_len = sizeof(read_packet_->addr.sin);
  int r = recvfrom(udp_fd_, read_packet_->data, kPacketCapacity, 0,
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

bool TunsafeBackendBsdImpl::ReadFromTun() {
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

bool TunsafeBackendBsdImpl::WriteToTun() {
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

bool TunsafeBackendBsdImpl::InitializeTun(char devname[16]) {
  int tun_fd = open_tun(devname, 16);
  if (tun_fd < 0) { RERROR("Error opening tun device"); return false; }
  fcntl(tun_fd, F_SETFD, FD_CLOEXEC);
  fcntl(tun_fd, F_SETFL, O_NONBLOCK);
  SetTunFd(tun_fd);
  return true;  
}

void TunsafeBackendBsdImpl::WriteTunPacket(Packet *packet) override {
  assert(tun_fd_ >= 0);
  Packet *queue_is_used = tun_queue_;
  *tun_queue_end_ = packet;
  tun_queue_end_ = &packet->next;
  packet->next = NULL;
  if (!queue_is_used)
    WriteToTun();
}

// Called to initialize udp
bool TunsafeBackendBsdImpl::Initialize(int listen_port) override {
  int udp_fd = open_udp(listen_port);
  if (udp_fd < 0) { RERROR("Error opening udp"); return false; }
  fcntl(udp_fd, F_SETFD, FD_CLOEXEC);
  fcntl(udp_fd, F_SETFL, O_NONBLOCK);
  SetUdpFd(udp_fd);
  return true;
}

void TunsafeBackendBsdImpl::WriteUdpPacket(Packet *packet) override {
  assert(udp_fd_ >= 0);
  Packet *queue_is_used = udp_queue_;
  *udp_queue_end_ = packet;
  udp_queue_end_ = &packet->next;
  packet->next = NULL;
  if (!queue_is_used)
    WriteToUdp();
}

void TunsafeBackendBsdImpl::RunLoopInner() {
  int free_packet_interval = 10;
  int overload_ctr = 0;

  while (!exit_) {
    int n = -1;

    // This is not fully signal safe.
    if (got_sig_alarm_) {
      got_sig_alarm_ = false;
      processor_->SecondLoop();

      if (free_packet_interval == 0) {
        FreePackets();
        free_packet_interval = 10;
      }
      free_packet_interval--;

      overload_ctr -= (overload_ctr != 0);
    }

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
    } else {
      if (tun_fd_ >= 0) {
        tun_readable_ = (FD_ISSET(tun_fd_, &readfds_) != 0);
        tun_writable_ |= (FD_ISSET(tun_fd_, &writefds_) != 0);
      }
      if (udp_fd_ >= 0) {
        udp_readable_ = (FD_ISSET(udp_fd_, &readfds_) != 0);
        udp_writable_ |= (FD_ISSET(udp_fd_, &writefds_) != 0);
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
}

TunsafeBackendBsd *CreateTunsafeBackendBsd() {
  return new TunsafeBackendBsdImpl;
}
