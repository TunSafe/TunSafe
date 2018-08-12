// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#include "tunsafe_types.h"
#include <vector>

// Maps CIDR addresses to a peer, always returning the longest match
// Slow O(n) implementation
class IpToPeerMap {
public:
  IpToPeerMap();
  ~IpToPeerMap();

  // Inserts an IP address of a given CIDR length into the lookup table, pointing to peer.
  bool InsertV4(const void *addr, int cidr, void *peer);
  bool InsertV6(const void *addr, int cidr, void *peer);

  // Lookup the peer matching the IP Address
  void *LookupV4(uint32 ip);
  void *LookupV6(const void *addr);

  void *LookupV4DefaultPeer();
  void *LookupV6DefaultPeer();

  // Remove a peer from the table
  void RemovePeer(void *peer);
private:
  struct Entry4 {
    uint32 ip;
    uint32 mask;
    void *peer;
  };
  struct Entry6 {
    uint8 ip[16];
    uint8 cidr_len;
    void *peer;
  };
  std::vector<Entry4> ipv4_;
  std::vector<Entry6> ipv6_;
};
