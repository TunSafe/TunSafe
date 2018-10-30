// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TINYVPN_NETAPI_H_
#define TINYVPN_NETAPI_H_

#include "tunsafe_types.h"
#include "tunsafe_ipaddr.h"
#include <vector>
#include <string>

#if !defined(OS_WIN)
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#pragma warning (disable: 4200)

struct QueuedItem;

struct QueuedItemCallback {
  virtual void OnQueuedItemEvent(QueuedItem *ow, uintptr_t extra) = 0;
  virtual void OnQueuedItemDelete(QueuedItem *ow) = 0;
};

struct QueuedItem {
  union {
#if defined(OS_WIN)
    // NOTE: This must be at offset 0 for SLIST to work
    SLIST_ENTRY list_entry;
    OVERLAPPED overlapped;
#endif
    QueuedItem *queue_next;
  };
  QueuedItemCallback *queue_cb;
};

#define Packet_NEXT(p) (*(Packet**)&(p)->queue_next)

struct Packet : QueuedItem {
  int sin_size;
  unsigned int size;

  byte *data;
  uint8 userdata;
  IpAddr addr;            // Optionally set to target/source of the packet
  
  byte data_pre[4];
  byte data_buf[0];
  enum {
    // there's always this much data before data_ptr
    HEADROOM_BEFORE = 64,
  };
};

enum {
  kPacketAllocSize = 2048 - 16,
  kPacketCapacity = kPacketAllocSize - sizeof(Packet) - Packet::HEADROOM_BEFORE,
};

void FreePacket(Packet *packet);
void FreePackets(Packet *packet, Packet **end, int count);
Packet *AllocPacket();
void FreeAllPackets();

class TunInterface {
public:
  struct PrePostCommands {
    std::vector<std::string> pre_up;
    std::vector<std::string> post_up;
    std::vector<std::string> pre_down;
    std::vector<std::string> post_down;
  };

  struct TunConfig {
    // no, yes(firewall), yes(route), yes(both), 255(default)
    uint8 internet_blocking;

    bool block_dns_on_adapters;

    // Set mtu
    int mtu;

    // The ipv6 and ipv4 addresses
    std::vector<WgCidrAddr> addresses;

    // Set this to configure DNS server
    std::vector<IpAddr> dns;

    // This holds all cidr addresses to add as additional routing entries
    std::vector<WgCidrAddr> included_routes;

    // This holds all the ips to exclude
    std::vector<WgCidrAddr> excluded_routes;

    // This holds the pre/post commands
    PrePostCommands pre_post_commands;
  };

  struct TunConfigOut {
    bool enable_neighbor_discovery_spoofing;
    uint8 neighbor_discovery_spoofing_mac[6];
  };

  virtual bool Configure(const TunConfig &&config, TunConfigOut *out) = 0;
  virtual void WriteTunPacket(Packet *packet) = 0;
};

class UdpInterface {
public:
  virtual bool Configure(int listen_port) = 0;
  virtual void WriteUdpPacket(Packet *packet) = 0;
};

extern bool g_allow_pre_post;

#endif  // TINYVPN_NETAPI_H_
