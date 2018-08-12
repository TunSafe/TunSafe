// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "ip_to_peer_map.h"
#include "bit_ops.h"
#include <string.h>

IpToPeerMap::IpToPeerMap() {

}

IpToPeerMap::~IpToPeerMap() {
}

bool IpToPeerMap::InsertV4(const void *addr, int cidr, void *peer) {
  uint32 mask = cidr == 32 ? 0xffffffff : ~(0xffffffff >> cidr);
  Entry4 e = {ReadBE32(addr) & mask, mask, peer};
  ipv4_.push_back(e);
  return true;
}

bool IpToPeerMap::InsertV6(const void *addr, int cidr, void *peer) {
  Entry6 e;
  e.cidr_len = cidr;
  e.peer = peer;
  memcpy(e.ip, addr, 16);
  ipv6_.push_back(e);
  return true;
}

void *IpToPeerMap::LookupV4(uint32 ip) {
  uint32 best_mask = 0;
  void *best_peer = NULL;
  for (auto it = ipv4_.begin(); it != ipv4_.end(); ++it) {
    if (it->ip == (ip & it->mask) && it->mask >= best_mask) {
      best_mask = it->mask;
      best_peer = it->peer;
    }
  }
  return best_peer;
}

void *IpToPeerMap::LookupV4DefaultPeer() {
  for (auto it = ipv4_.begin(); it != ipv4_.end(); ++it) {
    if (it->mask == 0)
      return it->peer;
  }
  return NULL;
}

void *IpToPeerMap::LookupV6DefaultPeer() {
  for (auto it = ipv6_.begin(); it != ipv6_.end(); ++it) {
    if (it->cidr_len == 0)
      return it->peer;
  }
  return NULL;
}

static int CalculateIPv6CommonPrefix(const uint8 *a, const uint8 *b) {
  uint64 x = ToBE64(*(uint64*)&a[0] ^ *(uint64*)&b[0]);
  uint64 y = ToBE64(*(uint64*)&a[8] ^ *(uint64*)&b[8]);
  return x ? 64 - FindHighestSetBit64(x) : 128 - FindHighestSetBit64(y);
}

void *IpToPeerMap::LookupV6(const void *addr) {
  int best_len = 0;
  void *best_peer = NULL;
  for (auto it = ipv6_.begin(); it != ipv6_.end(); ++it) {
    int len = CalculateIPv6CommonPrefix((const uint8*)addr, it->ip);
    if (len >= it->cidr_len && len >= best_len) {
      best_len = len;
      best_peer = it->peer;
    }
  }
  return best_peer;
}

void IpToPeerMap::RemovePeer(void *peer) {
  {
    size_t n = ipv4_.size();
    Entry4 *r = &ipv4_[0], *w = r;
    for (size_t i = 0; i != n; i++, r++) {
      if (r->peer != peer)
        *w++ = *r;
    }
    ipv4_.resize(w - &ipv4_[0]);
  }
  {
    size_t n = ipv6_.size();
    Entry6 *r = &ipv6_[0], *w = r;
    for (size_t i = 0; i != n; i++, r++) {
      if (r->peer != peer)
        *w++ = *r;
    }
    ipv6_.resize(w - &ipv6_[0]);
  }
}