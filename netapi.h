// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TINYVPN_NETAPI_H_
#define TINYVPN_NETAPI_H_

#include "stdafx.h"
#include "tunsafe_types.h"

#include <vector>
#include <string>

#if !defined(OS_WIN)
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#pragma warning (disable: 4200)

void OsGetRandomBytes(uint8 *dst, size_t dst_size);
uint64 OsGetMilliseconds();
void OsGetTimestampTAI64N(uint8 dst[12]);
void OsInterruptibleSleep(int millis);

union IpAddr {
  sockaddr_in sin;
  sockaddr_in6 sin6;
};

struct WgCidrAddr {
  uint8 addr[16];
  uint8 size;
  uint8 cidr;
};

struct Packet {
  union {
    Packet *next;
#if defined(OS_WIN)
    SLIST_ENTRY list_entry;
#endif
  };
  unsigned int post_target, size;
  byte *data;

#if defined(OS_WIN)
  OVERLAPPED overlapped;      // For Windows overlapped IO
#endif

  IpAddr addr;            // Optionally set to target/source of the packet
  int sin_size;

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
    // IP address and netmask of the tun device
    in_addr_t ip;
    uint8 cidr;

    bool block_dns_on_adapters;

    // no, yes(firewall), yes(route), yes(both), 255(default)
    uint8 internet_blocking;

    // Set this to configure a default route for ipv4
    bool use_ipv4_default_route;

    // Set this to configure a default route for ipv6
    bool use_ipv6_default_route;

    // DHCP settings
    const byte *dhcp_options;
    size_t dhcp_options_size;

    // This holds the address of the vpn endpoint, so those get routed to the old iface.
    uint32 default_route_endpoint_v4;
    
    // Set mtu
    int mtu;

    // Set ipv6 address?
    uint8 ipv6_address[16];
    uint8 ipv6_cidr;

    bool set_ipv6_dns;

    // Set this to configure DNS server.
    uint8 dns_server_v6[16];

    // This holds the address of the vpn endpoint, so those get routed to the old iface.
    uint8 default_route_endpoint_v6[16];

    // This holds all cidr addresses to add as additional routing entries
    std::vector<WgCidrAddr> extra_routes;

    // This holds all the ips to exclude
    std::vector<WgCidrAddr> excluded_ips;

    // This holds the pre/post commands
    PrePostCommands pre_post_commands;
  };

  struct TunConfigOut {
    bool enable_neighbor_discovery_spoofing;
    uint8 neighbor_discovery_spoofing_mac[6];
  };

  virtual bool Initialize(const TunConfig &&config, TunConfigOut *out) = 0;
  virtual void WriteTunPacket(Packet *packet) = 0;
};

class UdpInterface {
public:
  virtual bool Initialize(int listen_port) = 0;
  virtual void WriteUdpPacket(Packet *packet) = 0;
};

extern bool g_allow_pre_post;

#endif  // TINYVPN_NETAPI_H_
