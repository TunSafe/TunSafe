// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "wireguard.h"
#include "netapi.h"
#include "wireguard_proto.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/blake2s/blake2s.h"
#include "crypto/siphash/siphash.h"
#include "tunsafe_endian.h"
#include <algorithm>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "ipzip2/ipzip2.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "util.h"

enum {
  IPV4_HEADER_SIZE = 20,
  IPV6_HEADER_SIZE = 40,
};

WireguardProcessor::WireguardProcessor(UdpInterface *udp, TunInterface *tun, ProcessorDelegate *procdel) {
  udp_ = udp;
  tun_ = tun;
  procdel_ = procdel;
  mtu_ = 1420;
  memset(&stats_, 0, sizeof(stats_));
  listen_port_ = 0;
  network_discovery_spoofing_ = false;
  add_routes_mode_ = true;
  dns_blocking_ = true;
  internet_blocking_ = kBlockInternet_Default;
  is_started_ = false;
  stats_last_bytes_in_ = 0;
  stats_last_bytes_out_ = 0;
  stats_last_ts_ = OsGetMilliseconds();
}

WireguardProcessor::~WireguardProcessor() {
}

void WireguardProcessor::SetListenPort(int listen_port) {
  if (listen_port_ != listen_port) {
    listen_port_ = listen_port;
    if (is_started_ && !ConfigureUdp()) {
      RINFO("ConfigureUdp failed");
    }
  }
}

void WireguardProcessor::AddDnsServer(const IpAddr &sin) {
  dns_addr_.push_back(sin);
}

bool WireguardProcessor::SetTunAddress(const WgCidrAddr &addr) {
  addresses_.push_back(addr);
  return true;
}

void WireguardProcessor::ClearTunAddress() {
  addresses_.clear();
}

void WireguardProcessor::AddExcludedIp(const WgCidrAddr &cidr_addr) {
  excluded_ips_.push_back(cidr_addr);
}

void WireguardProcessor::SetMtu(int mtu) {
  if (mtu >= 576 && mtu <= 10000)
    mtu_ = mtu;
}

void WireguardProcessor::SetAddRoutesMode(bool mode) {
  add_routes_mode_ = mode;
}

void WireguardProcessor::SetDnsBlocking(bool dns_blocking) {
  dns_blocking_ = dns_blocking;
}

void WireguardProcessor::SetInternetBlocking(InternetBlockState internet_blocking) {
  internet_blocking_ = internet_blocking;
}

void WireguardProcessor::SetHeaderObfuscation(const char *key) {
  dev_.SetHeaderObfuscation(key);
}

const WgProcessorStats &WireguardProcessor::GetStats() {
  // todo: only supports one peer but i want this in the ui for now.
  stats_.endpoint.sin.sin_family = 0;
  WgPeer *peer = dev_.first_peer();
  if (peer) {
    stats_.endpoint = peer->endpoint_;
    stats_.endpoint_protocol = peer->endpoint_protocol_;
  }
  return stats_;
}

void WireguardProcessor::ResetStats() {
  memset(&stats_, 0, sizeof(stats_));
}

void WireguardProcessor::SetupCompressionHeader(WgPacketCompressionVer01 *c) {
  memset(c, 0, sizeof(WgPacketCompressionVer01));
  // Windows uses a ttl of 128 while other platforms use 64
#if defined(OS_WIN)
  c->ttl = 128;
#else // defined(OS_WIN)
  c->ttl = 64;
#endif  // defined(OS_WIN)
  WriteLE16(&c->version, EXT_PACKET_COMPRESSION_VER);

  for (auto it = addresses_.begin(); it != addresses_.end(); ++it) {
    if (it->size == 32) {
      memcpy(c->ipv4_addr, it->addr, 4);
      c->flags = ((it->cidr >> 3) & 3);
      break;
    }
  }
  for (auto it = addresses_.begin(); it != addresses_.end(); ++it) {
    if (it->size == 128) {
      memcpy(c->ipv6_addr, it->addr, 16);
      break;
    }
  }
}

static WgCidrAddr WgCidrAddrFromIpAddr(const IpAddr &addr) {
  WgCidrAddr r = {0};
  if (addr.sin.sin_family == AF_INET) {
    r.size = r.cidr = 32;
    memcpy(r.addr, &addr.sin.sin_addr, 4);
  } else if (addr.sin.sin_family == AF_INET6) {
    r.size = r.cidr = 128;
    memcpy(r.addr, &addr.sin6.sin6_addr, 16);
  }
  return r;
}

bool WireguardProcessor::Start() {
  return ConfigureUdp() && ConfigureTun();
}

bool WireguardProcessor::ConfigureUdp() {
  assert(dev_.IsMainThread());
  return udp_->Configure(listen_port_);
}

bool WireguardProcessor::ConfigureTun() {
  assert(dev_.IsMainThread());

  TunInterface::TunConfig config = {0};
  uint32 ipv4_broadcast_addr = 0xffffffff;

  for (auto it = addresses_.begin(); it != addresses_.end(); ++it) {
    if (it->size == 32) {
      if (it->cidr >= 31) {
        RINFO("TAP is not compatible CIDR /31 or /32. Changing to /24");
        it->cidr = 24;
      }

      // Packets to this IP will not be sent out.
      if (ipv4_broadcast_addr == 0xffffffff) {
        uint32 netmask = it->cidr == 32 ? 0xffffffff : 0xffffffff << (32 - it->cidr);
        ipv4_broadcast_addr = (netmask == 0xffffffff) ? 0xffffffff : ReadBE32(it->addr) | ~netmask;
      }
    } else if (it->size == 128) {
      if (it->cidr > 126) {
        RERROR("IPv6 /127 or /128 not supported. Changing to 120");
        it->cidr = 120;
      }
    }
    config.addresses.push_back(*it);
  }
  
  config.mtu = mtu_;
  config.pre_post_commands = pre_post_;
  config.excluded_routes = excluded_ips_;

  if (add_routes_mode_) {
    // For each peer, add the extra routes to the extra routes table
    for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {
      for (auto it = peer->allowed_ips_.begin(); it != peer->allowed_ips_.end(); ++it) {
        config.included_routes.push_back(*it);
        // If peer has the ::/0 or 0.0.0.0/0 address, disallow endpoint change.
        if (it->cidr == 0)
          peer->allow_endpoint_change_ = false;
      }
    }
    for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {
      // Add the peer's endpoint to the route exclusion list, but only
      // if the endpoint is covered by one of the included_routes.
      WgCidrAddr endpoint_addr = WgCidrAddrFromIpAddr(peer->endpoint_);
      if (endpoint_addr.size != 0 && IsWgCidrAddrSubsetOfAny(endpoint_addr, config.included_routes))
        config.excluded_routes.push_back(endpoint_addr);
    }
  }

  config.block_dns_on_adapters = dns_blocking_;
  config.internet_blocking = internet_blocking_;
  config.dns = dns_addr_;

  TunInterface::TunConfigOut config_out;
  if (!tun_->Configure(std::move(config), &config_out))
    return false;

  SetupCompressionHeader(dev_.compression_header());

  network_discovery_spoofing_ = config_out.enable_neighbor_discovery_spoofing;
  memcpy(network_discovery_mac_, config_out.neighbor_discovery_spoofing_mac, 6);
  
  for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {
    peer->ipv4_broadcast_addr_ = ipv4_broadcast_addr;
    if (peer->endpoint_.sin.sin_family != 0) {
      RINFO("Sending handshake...");
      SendHandshakeInitiation(peer);
    }
  }

  is_started_ = true;
  return true;
}

static uint8 kIcmpv6NeighborMulticastPrefix[] = {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x01, 0xff};

enum {
  kIpProto_ICMPv6 = 0x3A,
  kICMPv6_NeighborSolicitation = 135,
};

#pragma pack(push, 1)
struct ICMPv6NaPacket {
  uint8 type;
  uint8 code;
  uint16 checksum;
  uint8 rso;
  uint8 reserved[3];
  uint8 target[16];
  uint8 opt_type;
  uint8 opt_length;
  uint8 target_mac[6];
};

struct ICMPv6NaPacketWithoutTarget {
  uint8 type;
  uint8 code;
  uint16 checksum;
  uint8 rso;
  uint8 reserved[3];
  uint8 target[16];
};
#pragma pack (pop)

static uint16 ComputeIcmpv6Checksum(const uint8 *buf, int buf_size, const uint8 src_addr[16], const uint8 dst_addr[16]) {
  uint32 sum = 0;
  for (int i = 0; i < buf_size - 1; i += 2)
    sum += ReadBE16(&buf[i]);
  if (buf_size & 1)
    sum += buf[buf_size - 1];
  for (int i = 0; i < 16; i += 2)
    sum += ReadBE16(&src_addr[i]);
  for (int i = 0; i < 16; i += 2)
    sum += ReadBE16(&dst_addr[i]);
  sum += (uint16)IPPROTO_ICMPV6 + (uint16)buf_size;
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return ((uint16)~sum);
}

bool WireguardProcessor::HandleIcmpv6NeighborSolicitation(const byte *data, size_t data_size) {
  if (data_size < 48 + 16)
    return false;

  // Filter out neighbor solicitation
  if (data[40] != kICMPv6_NeighborSolicitation || data[41] != 0 || !network_discovery_spoofing_)
    return false;

  bool is_broadcast = true;
  if (memcmp(data + 24, kIcmpv6NeighborMulticastPrefix, sizeof(kIcmpv6NeighborMulticastPrefix)) != 0) {
    if (memcmp(data + 24, data + 48, 16) != 0)
      return false;
    is_broadcast = false;
  }

  // Target address must match a peer's range.
  WG_ACQUIRE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
  WgPeer *peer = (WgPeer*)dev_.ip_to_peer_map().LookupV6(data + 48);
  WG_RELEASE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
  if (peer == NULL)
    return false;

  // Build response packet
  Packet *out = AllocPacket();
  if (out == NULL)
    return false;

  byte *odata = out->data;
  size_t packet_size = is_broadcast ? sizeof(ICMPv6NaPacket) : sizeof(ICMPv6NaPacketWithoutTarget);

  memcpy(odata, data, 4);
  WriteBE16(odata + 4, packet_size);
  odata[6] = 58; // next = icmp
  odata[7] = 255; // HopLimit
  memcpy(odata + 8, data + 48, 16); // Source Address
  memcpy(odata + 24, data + 8, 16); // Dest addr

  ((ICMPv6NaPacket*)(odata + 40))->type = 136; // NA
  ((ICMPv6NaPacket*)(odata + 40))->code = 0;
  ((ICMPv6NaPacket*)(odata + 40))->checksum = 0;
  ((ICMPv6NaPacket*)(odata + 40))->rso = 0x60; // solicited
  memset(((ICMPv6NaPacket*)(odata + 40))->reserved, 0, 3);
  memcpy(((ICMPv6NaPacket*)(odata + 40))->target, odata + 8, 16);
  if (is_broadcast) {
    ((ICMPv6NaPacket*)(odata + 40))->opt_type = 2;
    ((ICMPv6NaPacket*)(odata + 40))->opt_length = 1;

    memcpy(((ICMPv6NaPacket*)(odata + 40))->target_mac, network_discovery_mac_, 6);

    // For some reason this is openvpn's 'related mac'
    ((ICMPv6NaPacket*)(odata + 40))->target_mac[2] += 1;
  }
  uint16 checksum = ComputeIcmpv6Checksum(odata + 40, (int)packet_size, odata + 8, odata + 24);
  WriteBE16(&((ICMPv6NaPacket*)(odata + 40))->checksum, checksum);

  out->size = (unsigned)(40 + packet_size);
  tun_->WriteTunPacket(out);
  return true;
}

static inline bool IsIpv6Multicast(const uint8 dst[16]) {
  return dst[0] == 0xff;
}

// On incoming packet to the tun interface.
void WireguardProcessor::HandleTunPacket(Packet *packet) {
  uint8 *data = packet->data;
  size_t data_size = packet->size;
  unsigned ip_version, size_from_header;
  WgPeer *peer;

  // Sanity check that it looks like a valid ipv4 or ipv6 packet,
  // and determine the destination peer from the ip header
  if (data_size < IPV4_HEADER_SIZE)
    goto getout;
  
  ip_version = *data >> 4;
  if (ip_version == 4) {
    uint32 ip = ReadBE32(data + 16);
    WG_ACQUIRE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    peer = (WgPeer*)dev_.ip_to_peer_map().LookupV4(ip);
    WG_RELEASE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    if (peer == NULL)
      goto getout;
    if ((ip >= (224 << 24) || ip == peer->ipv4_broadcast_addr_) && !peer->allow_multicast_through_peer_)
      goto getout;

    size_from_header = ReadBE16(data + 2);
    if (size_from_header < IPV4_HEADER_SIZE)
      goto getout;
  } else if (ip_version == 6) {
    if (data_size < IPV6_HEADER_SIZE)
      goto getout;

    // Check if the packet is a Neighbor solicitation ICMP6 packet, in that case fake
    // a reply.
    if (data[6] == kIpProto_ICMPv6 && HandleIcmpv6NeighborSolicitation(data, data_size))
      goto getout;

    WG_ACQUIRE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_); 
    peer = (WgPeer*)dev_.ip_to_peer_map().LookupV6(data + 24);
    WG_RELEASE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    if (peer == NULL)
      goto getout;
    
    if (IsIpv6Multicast(data + 24) && !peer->allow_multicast_through_peer_)
      goto getout;

    size_from_header = IPV6_HEADER_SIZE + ReadBE16(data + 4);
  } else {
    goto getout;
  }
  if (size_from_header > data_size)
    goto getout;

  // WriteAndEncryptPacketToUdp needs a held lock
  WG_ACQUIRE_LOCK(peer->mutex_);
  WriteAndEncryptPacketToUdp_WillUnlock(peer, packet);
  return;
  
getout:
  // send ICMP?
  FreePacket(packet);
}

// This function must be called with the peer lock held. It will remove the lock
void WireguardProcessor::WriteAndEncryptPacketToUdp_WillUnlock(WgPeer *peer, Packet *packet) {
  assert(peer->IsPeerLocked());
  uint8 *data = packet->data, *ad;
  size_t size = packet->size, ad_len, orig_size = size;
  bool want_handshake;
  WgKeypair *keypair;
  uint64 send_ctr;

  // Ensure packet will fit including the biggest padding
  if (peer->endpoint_.sin.sin_family == 0 ||
      size > kPacketCapacity - 15 - CHACHA20POLY1305_AUTHTAGLEN)
    goto getout_discard;

  if ((keypair = peer->curr_keypair_) == NULL ||
      (send_ctr = keypair->send_ctr) >= REJECT_AFTER_MESSAGES) {
    // If RemovePeer has been called then discard any packets currently being written to it.
    // curr_keypair_ is NULL when RemovePeer has been called so it's safe to do this here.
    if (peer->marked_for_delete_)
      goto getout_discard;

    peer->AddPacketToPeerQueue_Locked(packet);
    WG_RELEASE_LOCK(peer->mutex_);
    peer->ScheduleNewHandshake();
    return;
  }
  assert(!peer->marked_for_delete_);

  stats_.tun_bytes_in += size;
  stats_.tun_packets_in++;

  want_handshake = (send_ctr >= REKEY_AFTER_MESSAGES ||
                    keypair->send_key_state == WgKeypair::KEY_WANT_REFRESH);
  keypair->send_ctr = send_ctr + 1;
  packet->addr = peer->endpoint_;
  packet->protocol = peer->endpoint_protocol_;

  if (size == 0) {
    peer->OnKeepaliveSent();
  } else {
    peer->OnDataSent();

#if WITH_HANDSHAKE_EXT
    // Attempt to compress the packet headers using ipzip.
    if (keypair->enabled_features[WG_FEATURE_ID_IPZIP]) {
      uint32 rv = IpzipCompress(data, (uint32)size, &keypair->ipzip_state_, 0);
      if (rv == (uint32)-1)
        goto getout_discard;
      if (rv == 0)
        goto add_padding;
      stats_.compression_hdr_saved_out += (int32)(size - rv);
      data += (int32)(size - rv);
      size = rv;
    } else {
add_padding:
#else
    {
#endif  // WITH_HANDSHAKE_EXT
      // Pad packet to a multiple of 16 bytes, but no more than the mtu bytes.
      unsigned padding = std::min<unsigned>((0 - size) & 15, (unsigned)mtu_ - (unsigned)size);
      memset(data + size, 0, padding);
      size += padding;
    }
  }

#if WITH_SHORT_HEADERS
  if (keypair->enabled_features[WG_FEATURE_ID_SHORT_HEADER]) {
    size_t header_size;
    byte *write = data;
    uint8 tag = WG_SHORT_HEADER_BIT, inner_tag;
    // For every 16 incoming packets, send out an ack.
    if (keypair->incoming_packet_count >= 16) {
      keypair->incoming_packet_count = 0;
      uint64 next_expected_packet = keypair->replay_detector.expected_seq_nr();
      if (next_expected_packet < 0x10000) {
        WriteLE16(write -= 2, (uint16)next_expected_packet);
        inner_tag = WG_ACK_HEADER_COUNTER_2;
      } else if (next_expected_packet < 0x100000000ull) {
        WriteLE32(write -= 4, (uint32)next_expected_packet);
        inner_tag = WG_ACK_HEADER_COUNTER_4;
      } else {
        WriteLE32(write -= 4, (uint32)next_expected_packet);
        WriteLE16(write -= 2, (uint16)(next_expected_packet>>32));
        inner_tag = WG_ACK_HEADER_COUNTER_6;
      }
      if (keypair->broadcast_short_key != 0) {
        inner_tag += keypair->addr_entry_slot;
        keypair->broadcast_short_key = 2;
      }
      *--write = inner_tag;
      tag += WG_SHORT_HEADER_ACK;
    } else if (keypair->broadcast_short_key == 1) {
      keypair->broadcast_short_key = 2;
      *--write = keypair->addr_entry_slot;
      tag += WG_SHORT_HEADER_ACK;
    }
    byte *write_after_ack_header = write;

    // Determine the distance from the most recently acked packet,
    // be conservative when picking a suitable packet length to send.
    uint64 distance = send_ctr - keypair->send_ctr_acked;
    if (distance < (1 << 6)) {
      *(write -= 1) = (uint8)send_ctr;
      tag += WG_SHORT_HEADER_CTR1;
    } else if (distance < (1 << 14)) {
      WriteLE16(write -= 2, (uint16)send_ctr);
      tag += WG_SHORT_HEADER_CTR2;
    } else if (distance < (1 << 30)) {
      WriteLE32(write -= 4, (uint32)send_ctr);
      tag += WG_SHORT_HEADER_CTR4;
    } else {
      // Too far ahead. Can't use short packets.
      goto need_big_packet;
    }

    tag += keypair->can_use_short_key_for_outgoing;
    if (!keypair->can_use_short_key_for_outgoing)
      WriteLE32(write -= 4, keypair->remote_key_id);
    *--write = tag;

    header_size = data - write;
    packet->size = (int)(size + header_size + keypair->auth_tag_length);
    peer->tx_bytes_ += packet->size;
    stats_.compression_wg_saved_out += (int64)16 - header_size;
    packet->data = data - header_size;

    // Not using any fields from now on
    WG_RELEASE_LOCK(peer->mutex_);

    // todo: figure out what to actually use as ad.
    ad = write_after_ack_header;
    ad_len = data - write_after_ack_header;
  } else {
need_big_packet:
#else
  {
#endif  // #if WITH_SHORT_HEADERS
    packet->size = (int)(size + sizeof(MessageData) + keypair->auth_tag_length);
    peer->tx_bytes_ += packet->size;

    // Not using any fields from now on
    WG_RELEASE_LOCK(peer->mutex_);

    ((MessageData*)data)[-1].type = ToLE32(MESSAGE_DATA);
    ((MessageData*)data)[-1].receiver_id = keypair->remote_key_id;
    ((MessageData*)data)[-1].counter = ToLE64(send_ctr);
    packet->data = data - sizeof(MessageData);
    ad = NULL;
    ad_len = 0;
  }

  WgKeypairEncryptPayload(data, size, ad, ad_len, send_ctr, keypair);

  DoWriteUdpPacket(packet);
  if (want_handshake)
    peer->ScheduleNewHandshake();
  return;

getout_discard:
  WG_RELEASE_LOCK(peer->mutex_);
  FreePacket(packet);
  return;
}

// This scrambles the initial 16 bytes of the packet with the
// next 8 bytes of the packet as a seed.
static void ScrambleUnscramblePacket(Packet *packet, ScramblerSiphashKeys *keys) {
  uint8 *data = packet->data;
  size_t data_size = packet->size;

  if (data_size <= 8)
    return;

  uint64 last_uint64 = ReadLE64(data_size >= 24 ? data + 16 : data + data_size - 8);
  uint64 a = siphash_u64_u32(last_uint64, (uint32)data_size, (siphash_key_t*)&keys->keys[0]);
  uint64 b = siphash_u64_u32(last_uint64, (uint32)data_size, (siphash_key_t*)&keys->keys[2]);
  a = ToLE64(a);
  b = ToLE64(b);
  if (data_size >= 24) {
    ((uint64*)data)[0] ^= a;
    ((uint64*)data)[1] ^= b;
  } else {
    union {
      uint64 d[2];
      uint8 s[16];
    } scrambler = {{a,b}};
    for (size_t i = 0; i < data_size - 8; i++)
      data[i] ^= scrambler.s[i];
  }
}

static NOINLINE void ScrambleUnscrambleAndWrite(Packet *packet, ScramblerSiphashKeys *keys, UdpInterface *udp) {
#if WITH_HEADER_OBFUSCATION
  ScrambleUnscramblePacket(packet, keys);
  udp->WriteUdpPacket(packet);
#endif // WITH_HEADER_OBFUSCATION
}

void WireguardProcessor::DoWriteUdpPacket(Packet *packet) {
  stats_.udp_packets_out++;
  stats_.udp_bytes_out += packet->size;
  if (!dev_.header_obfuscation_)
    udp_->WriteUdpPacket(packet);
  else
    ScrambleUnscrambleAndWrite(packet, &dev_.header_obfuscation_key_, udp_); 
}

void WireguardProcessor::RunAllMainThreadScheduled() {
  WgPeer *peer, *next;
  assert(dev_.IsMainThread());

  if (dev_.main_thread_scheduled_ == NULL)
    return;

  WG_ACQUIRE_LOCK(dev_.main_thread_scheduled_lock_);
  peer = dev_.main_thread_scheduled_;
  dev_.main_thread_scheduled_ = NULL;
  dev_.main_thread_scheduled_last_ = &dev_.main_thread_scheduled_;
  WG_RELEASE_LOCK(dev_.main_thread_scheduled_lock_);

  for (; peer; peer = next) {
    // todo: for the multithreaded use case figure out whether to use atomic_thread_fence here,
    // because we need to read this next value before any other thread sees the 0 we write
    // to peer->main_thread_scheduled_.
    next = peer->main_thread_scheduled_next_;
    if (peer->marked_for_delete_)
      continue;

    uint32 ev = peer->main_thread_scheduled_.exchange(0);
    if (ev & WgPeer::kMainThreadScheduled_ScheduleHandshake) {
      peer->handshake_attempts_ = 0;
      SendHandshakeInitiation(peer);
    }
  }
}

void WireguardProcessor::SendHandshakeInitiation(WgPeer *peer) {
  assert(dev_.IsMainThread());

  if (!peer->CheckHandshakeRateLimit() || peer->endpoint_.sin.sin_family == 0)
    return;
  stats_.handshakes_out++;
  Packet *packet = AllocPacket();
  if (packet) {
    peer->CreateMessageHandshakeInitiation(packet);
    WG_ACQUIRE_LOCK(peer->mutex_);
    int attempts = ++peer->total_handshake_attempts_;
    if (procdel_)
      procdel_->OnConnectionRetry(attempts);
    peer->OnHandshakeInitSent();
    packet->addr = peer->endpoint_;
    packet->protocol = peer->endpoint_protocol_;
    peer->tx_bytes_ += packet->size;

    // If this is an incoming oneway connection (such as tcp), forget the
    // endpoint after a number of attempts.
    if (attempts >= 3 && peer->allow_endpoint_change_ &&
        (peer->endpoint_protocol_ & kPacketProtocolIncomingConnection)) {
      peer->endpoint_protocol_ = 0;
      peer->endpoint_.sin.sin_family = 0;
    }

    WG_RELEASE_LOCK(peer->mutex_);
    DoWriteUdpPacket(packet);
    if (attempts > 1 && attempts <= 20)
      RINFO("Retrying handshake, attempt %d...%s", attempts, (attempts == 20) ? " (last notice)" : "");
  }
}

bool WireguardProcessor::IsMainThreadPacket(Packet *packet) {
  // TODO(ludde): Support header obfuscation
  return packet->size == 0 || (packet->data[0] != MESSAGE_DATA && !(packet->data[0] & WG_SHORT_HEADER_BIT));
}

// Handles an incoming WireGuard packet from the UDP side, decrypt etc.
void WireguardProcessor::HandleUdpPacket(Packet *packet, bool overload) {
  uint32 type;

  // Unscramble incoming packets
#if WITH_HEADER_OBFUSCATION
  if (dev_.header_obfuscation_)
    ScrambleUnscramblePacket(packet, &dev_.header_obfuscation_key_);
#endif  // WITH_HEADER_OBFUSCATION

  stats_.udp_bytes_in += packet->size;
  stats_.udp_packets_in++;

  if (packet->size < sizeof(uint32))
    goto invalid_size;
  type = ReadLE32((uint32*)packet->data);
  if (type == MESSAGE_DATA) {
    if (packet->size < sizeof(MessageData))
      goto invalid_size;
    HandleDataPacket(packet);
#if WITH_SHORT_HEADERS
  } else if (type & WG_SHORT_HEADER_BIT) {
    HandleShortHeaderFormatPacket(type, packet);
#endif  // WITH_SHORT_HEADERS
  } else if (type == MESSAGE_HANDSHAKE_COOKIE) {
    assert(dev_.IsMainThread());
    if (packet->size != sizeof(MessageHandshakeCookie) || !dev_.is_private_key_initialized())
      goto invalid_size;
    HandleHandshakeCookiePacket(packet);
  } else if (type == MESSAGE_HANDSHAKE_INITIATION) {
    assert(dev_.IsMainThread());
    if (WITH_HANDSHAKE_EXT ? (packet->size < sizeof(MessageHandshakeInitiation)) : (packet->size != sizeof(MessageHandshakeInitiation)) || 
        !dev_.is_private_key_initialized())
      goto invalid_size;
    stats_.handshakes_in++;
    if (CheckIncomingHandshakeRateLimit(packet, overload))
      HandleHandshakeInitiationPacket(packet);
  } else if (type == MESSAGE_HANDSHAKE_RESPONSE) {
    assert(dev_.IsMainThread());
    if (WITH_HANDSHAKE_EXT ? (packet->size < sizeof(MessageHandshakeResponse)) : (packet->size != sizeof(MessageHandshakeResponse)) || 
        !dev_.is_private_key_initialized())
      goto invalid_size;
    if (CheckIncomingHandshakeRateLimit(packet, overload))
      HandleHandshakeResponsePacket(packet);
  } else {
    // unknown packet
invalid_size:
    FreePacket(packet);
  }
}

// Returns nonzero if two endpoints are different.
static uint32 CompareIpAddr(const IpAddr *a, const IpAddr *b) {
  uint32 rv = b->sin.sin_family ^ a->sin.sin_family;
  if (b->sin.sin_family != AF_INET6) {
    rv |= b->sin.sin_addr.s_addr ^ a->sin.sin_addr.s_addr;
    rv |= b->sin.sin_port ^ a->sin.sin_port;
  } else {
    uint64 rx = ((uint64*)&b->sin6.sin6_addr)[0] ^ ((uint64*)&a->sin6.sin6_addr)[0];
    rx |= ((uint64*)&b->sin6.sin6_addr)[1] ^ ((uint64*)&a->sin6.sin6_addr)[1];
    rv |= rx | (rx >> 32);
    rv |= b->sin6.sin6_port ^ a->sin6.sin6_port;
  }
  return rv;
}

void WgPeer::CopyEndpointToPeer_Locked(WgKeypair *keypair, const IpAddr *addr) {
  // Remember how to send packets to this peer
  if (keypair->peer->allow_endpoint_change_ &&
      CompareIpAddr(&keypair->peer->endpoint_, addr) && addr->sin.sin_family != 0) {
#if WITH_SHORT_HEADERS
    // When the endpoint changes, forget about using the short key.
    keypair->broadcast_short_key = 0;
    keypair->can_use_short_key_for_outgoing = false;
#endif  // WITH_SHORT_HEADERS
    keypair->peer->endpoint_ = *addr;
  }
}

#if WITH_SHORT_HEADERS
void WireguardProcessor::HandleShortHeaderFormatPacket(uint32 tag, Packet *packet) {
  assert(dev_.IsMainOrDataThread());

  uint8 *data = packet->data + 1;
  size_t bytes_left = packet->size - 1;
  WgKeypair *keypair;
  uint64 counter, acked_counter;
  uint8 ack_tag, *ack_start;

  if ((tag & WG_SHORT_HEADER_KEY_ID_MASK) == 0x00) {
    // The key_id is explicitly included in the packet.
    if (bytes_left < 4) goto getout;
    uint32 key_id = ReadLE32(data);
    data += 4, bytes_left -= 4;
    keypair = dev_.LookupKeypairByKeyId(key_id);
  } else {
    keypair = dev_.LookupKeypairInAddrEntryMap(packet->addr, ((tag & WG_SHORT_HEADER_KEY_ID_MASK) / WG_SHORT_HEADER_KEY_ID) - 1);
  }

  if (!keypair || !keypair->enabled_features[WG_FEATURE_ID_SHORT_HEADER])
    goto getout;

  // Pick the closest possible counter value with the same low bits.
  counter = keypair->replay_detector.expected_seq_nr();
  switch (tag & WG_SHORT_HEADER_TYPE_MASK) {
  case WG_SHORT_HEADER_CTR1:
    if (bytes_left < 1) goto getout;
    counter += (int8)(*data - counter);
    data += 1, bytes_left -= 1;
    break;
  case WG_SHORT_HEADER_CTR2:
    if (bytes_left < 2) goto getout;
    counter += (int16)(ReadLE16(data) - counter);
    data += 2, bytes_left -= 2;
    break;
  case WG_SHORT_HEADER_CTR4:
    if (bytes_left < 4) goto getout;
    counter += (int32)(ReadLE32(data) - counter);
    data += 4, bytes_left -= 4;
    break;
  default:
    goto getout; // invalid packet
  }

  acked_counter = 0;
  ack_tag = 0;

  ack_start = data;
  // If the acknowledge header is present, then parse it so we may
  // get an ack for the highest seen packet.
  if (tag & WG_SHORT_HEADER_ACK) {
    if (bytes_left == 0) goto getout;
    ack_tag = *data;
    if (ack_tag & 0xF0) goto getout; // undefined bits
    data += 1, bytes_left -= 1;

    switch (ack_tag & WG_ACK_HEADER_COUNTER_MASK) {
    case WG_ACK_HEADER_COUNTER_2:
      if (bytes_left < 2) goto getout;
      acked_counter = ReadLE16(data);
      data += 2, bytes_left -= 2;
      break;
    case WG_ACK_HEADER_COUNTER_4:
      if (bytes_left < 4) goto getout;
      acked_counter = ReadLE32(data);
      data += 4, bytes_left -= 4;
      break;
    case WG_ACK_HEADER_COUNTER_6:
      if (bytes_left < 6) goto getout;
      acked_counter = ReadLE32(data) | ((uint64)ReadLE16(data + 4) << 32);
      data += 6, bytes_left -= 6;
      break;
    default:
      goto getout;
    }
  }
  if (counter >= REJECT_AFTER_MESSAGES)
    goto getout;
  // Authenticate the packet before we can apply the state changes.
  if (!WgKeypairDecryptPayload(data, bytes_left, ack_start, data - ack_start, counter, keypair))
    goto getout;

  WG_ACQUIRE_LOCK(keypair->peer->mutex_);

  keypair->peer->rx_bytes_ += packet->size;

  if (keypair->recv_key_state == WgKeypair::KEY_INVALID)
    goto getout_unlock;

  if (!keypair->replay_detector.CheckReplay(counter))
    goto getout_unlock;

  stats_.compression_wg_saved_in += 16 - (data - packet->data);

  keypair->send_ctr_acked = std::max<uint64>(keypair->send_ctr_acked, acked_counter);
  keypair->incoming_packet_count++;

  WgPeer::CopyEndpointToPeer_Locked(keypair, &packet->addr);

  // Periodically broadcast out the short key 
  if ((tag & WG_SHORT_HEADER_KEY_ID_MASK) == 0x00 && !keypair->did_attempt_remember_ip_port) {
    keypair->did_attempt_remember_ip_port = true;
    if (keypair->enabled_features[WG_FEATURE_ID_SKIP_KEYID_IN])
      dev_.UpdateKeypairAddrEntry_Locked(packet->addr, keypair);
  }
  // Ack header may also signal that we can omit the key id in packets from now on.
  if (tag & WG_SHORT_HEADER_ACK)
    keypair->can_use_short_key_for_outgoing = (ack_tag & WG_ACK_HEADER_KEY_MASK) * WG_SHORT_HEADER_KEY_ID;

  HandleAuthenticatedDataPacket_WillUnlock(keypair, packet, data, bytes_left - keypair->auth_tag_length);
  return;
getout_unlock:
  WG_RELEASE_LOCK(keypair->peer->mutex_);
getout:
  FreePacket(packet);
  return;
}
#endif  // WITH_SHORT_HEADERS

void WireguardProcessor::NotifyHandshakeComplete() {
  uint64 now = OsGetMilliseconds();
  
  // todo: should lock something
  stats_.last_complete_handshake_timestamp = now;
  if (stats_.first_complete_handshake_timestamp == 0)
    stats_.first_complete_handshake_timestamp = now;

  if (procdel_)
    procdel_->OnConnected();
}

void WireguardProcessor::HandleAuthenticatedDataPacket_WillUnlock(WgKeypair *keypair, Packet *packet, uint8 *data, size_t data_size) {
  WgPeer *peer = keypair->peer;
  assert(peer->IsPeerLocked());

  // Promote the next key to the current key when we receive a data packet,
  // the handshake is now complete.
  if (peer->CheckSwitchToNextKey_Locked(keypair)) {
    stats_.handshakes_in_success++;
    peer->OnHandshakeFullyComplete();
    NotifyHandshakeComplete();
    SendQueuedPackets_Locked(peer);
  }

  // Refresh when current key gets too old
  WgKeypair *curr_keypair = peer->curr_keypair_;
  if (curr_keypair && curr_keypair->recv_key_state == WgKeypair::KEY_WANT_REFRESH) {
    curr_keypair->recv_key_state = WgKeypair::KEY_DID_REFRESH;
    peer->ScheduleNewHandshake();
  }

  if (data_size == 0) {
    peer->OnKeepaliveReceived();
    WG_RELEASE_LOCK(peer->mutex_);
    goto getout;
  }
  peer->OnDataReceived();
  WG_RELEASE_LOCK(peer->mutex_);

#if WITH_HANDSHAKE_EXT
  // Unpack the packet headers using ipzip
  if (keypair->enabled_features[WG_FEATURE_ID_IPZIP]) {
    uint32 rv = IpzipDecompress(data, (uint32)data_size, &keypair->ipzip_state_, IPZIP_RECV_BY_CLIENT);
    if (rv == (uint32)-1)
      goto getout;
    stats_.compression_hdr_saved_in += (int64)rv - data_size;
    data -= (int64)rv - data_size, data_size = rv;
  }
#endif  // WITH_HANDSHAKE_EXT

  // Verify that the packet is a valid ipv4 or ipv6 packet of proper length,
  // with a source address that belongs to the peer.
  WgPeer *peer_from_header;
  unsigned int ip_version, size_from_header;

  ip_version = *data >> 4;
  if (ip_version == 4) {
    if (data_size < IPV4_HEADER_SIZE)
      goto getout_error_header;
    WG_ACQUIRE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    peer_from_header = (WgPeer*)dev_.ip_to_peer_map().LookupV4(ReadBE32(data + 12));
    WG_RELEASE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    size_from_header = ReadBE16(data + 2);
    if (size_from_header < IPV4_HEADER_SIZE) {
      // too small packet?
      goto getout_error_header;
    }
  } else if (ip_version == 6) {
    if (data_size < IPV6_HEADER_SIZE)
      goto getout_error_header;
    WG_ACQUIRE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    peer_from_header = (WgPeer*)dev_.ip_to_peer_map().LookupV6(data + 8);
    WG_RELEASE_RWLOCK_SHARED(dev_.ip_to_peer_map_lock_);
    size_from_header = IPV6_HEADER_SIZE + ReadBE16(data + 4);
  } else {
    // invalid ip version
    goto getout_error_header;
  }
  if (peer_from_header != peer || size_from_header > data_size)
    goto getout_error_header;

  packet->data = data;
  packet->size = size_from_header;

  stats_.tun_bytes_out += packet->size;
  stats_.tun_packets_out++;

  tun_->WriteTunPacket(packet);
  return;

getout_error_header:
  stats_.error_header++;
getout:
  FreePacket(packet);
}

void WireguardProcessor::HandleDataPacket(Packet *packet) {
  assert(dev_.IsMainOrDataThread());

  uint8 *data = packet->data;
  size_t data_size = packet->size;
  uint32 key_id = ((MessageData*)data)->receiver_id;
  uint64 counter = ToLE64((((MessageData*)data)->counter));
  WgKeypair *keypair = dev_.LookupKeypairByKeyId(key_id);
  if (keypair == NULL || counter >= REJECT_AFTER_MESSAGES) {
    stats_.error_key_id++;
getout:
    FreePacket(packet);
    return;
  }

  if (!WgKeypairDecryptPayload(data + sizeof(MessageData), data_size - sizeof(MessageData),
                               NULL, 0, counter, keypair)) {
    stats_.error_mac++;
    goto getout;
  }

  WG_ACQUIRE_LOCK(keypair->peer->mutex_);
  keypair->peer->rx_bytes_ += data_size;
  if (keypair->recv_key_state == WgKeypair::KEY_INVALID) {
    stats_.error_key_id++;
    WG_RELEASE_LOCK(keypair->peer->mutex_);
    goto getout;
  } else if (!keypair->replay_detector.CheckReplay(counter)) {
    stats_.error_duplicate++;
    WG_RELEASE_LOCK(keypair->peer->mutex_);
    goto getout;
  } else {
    assert(!keypair->peer->marked_for_delete_);

    WgPeer::CopyEndpointToPeer_Locked(keypair, &packet->addr);
    HandleAuthenticatedDataPacket_WillUnlock(keypair, packet, data + sizeof(MessageData), data_size - sizeof(MessageData) - keypair->auth_tag_length);
  } 
}

static uint64 GetIpForRateLimit(Packet *packet) {
  if (packet->addr.sin.sin_family == AF_INET) {
    return ReadLE32(&packet->addr.sin.sin_addr);
  } else {
    return ReadLE64(&packet->addr.sin6.sin6_addr);
  }
}

bool WireguardProcessor::CheckIncomingHandshakeRateLimit(Packet *packet, bool overload) {
  assert(dev_.IsMainThread());
  WgRateLimit::RateLimitResult rr = dev_.rate_limiter()->CheckRateLimit(GetIpForRateLimit(packet));
  if ((overload && rr.is_rate_limited()) || !dev_.CheckCookieMac1(packet)) {
    FreePacket(packet);
    return false;
  }
  dev_.rate_limiter()->CommitResult(rr);
  if (overload && !rr.is_first_ip() && !dev_.CheckCookieMac2(packet)) {
    dev_.CreateCookieMessage((MessageHandshakeCookie*)packet->data, packet, ((MessageHandshakeInitiation*)packet->data)->sender_key_id);
    packet->size = sizeof(MessageHandshakeCookie);
    DoWriteUdpPacket(packet);
    return false;
  }
  return true;
}

// server receives this when client wants to setup a session
void WireguardProcessor::HandleHandshakeInitiationPacket(Packet *packet) {
  assert(dev_.IsMainThread());
  WgPeer *peer = WgPeer::ParseMessageHandshakeInitiation(&dev_, packet);
  if (peer) {
    DoWriteUdpPacket(packet);
  } else {
    FreePacket(packet);
  }
}

// client receives this after session is established
void WireguardProcessor::HandleHandshakeResponsePacket(Packet *packet) {
  assert(dev_.IsMainThread());
  WgPeer *peer = WgPeer::ParseMessageHandshakeResponse(&dev_, packet);
  if (peer) {
    stats_.handshakes_out_success++;
    WG_SCOPED_LOCK(peer->mutex_);
    if (peer->allow_endpoint_change_ && packet->addr.sin.sin_family != 0)
      peer->endpoint_ = packet->addr;
    peer->OnHandshakeAuthComplete();
    peer->OnHandshakeFullyComplete();
    NotifyHandshakeComplete();
    SendKeepalive_Locked(peer);
  }
  FreePacket(packet);
}

void WireguardProcessor::SendKeepalive_Locked(WgPeer *peer) {
  assert(dev_.IsMainThread() && peer->IsPeerLocked());
  // can't send keepalive if no endpoint is configured
  if (peer->endpoint_.sin.sin_family == 0)
    return;
  // If nothing is queued, insert a keepalive packet
  if (peer->first_queued_packet_ == NULL) {
    Packet *packet = AllocPacket();
    if (!packet)
      return;
    packet->size = 0;
    Packet_NEXT(packet) = NULL;
    peer->first_queued_packet_ = packet;
  }
  SendQueuedPackets_Locked(peer);
}

void WireguardProcessor::SendQueuedPackets_Locked(WgPeer *peer) {
  assert(peer->IsPeerLocked());
  // Steal the queue of all packets and send them all.
  Packet *packet = peer->first_queued_packet_;
  peer->first_queued_packet_ = NULL;
  peer->last_queued_packet_ptr_ = &peer->first_queued_packet_;
  peer->num_queued_packets_ = 0;
  while (packet != NULL) {
    Packet *next = Packet_NEXT(packet);
    WriteAndEncryptPacketToUdp_WillUnlock(peer, packet);
    packet = next;
    WG_ACQUIRE_LOCK(peer->mutex_);  // WriteAndEncryptPacketToUdp_WillUnlock releases the lock
  }
}

void WireguardProcessor::HandleHandshakeCookiePacket(Packet *packet) {
  assert(dev_.IsMainThread());
  WgPeer::ParseMessageHandshakeCookie(&dev_, (MessageHandshakeCookie *)packet->data);
}

// Only one thread may run the second loop
void WireguardProcessor::SecondLoop() {
  assert(dev_.IsMainThread());
  uint64 now = OsGetMilliseconds();

  uint64 bytes_in = stats_.tun_bytes_in - stats_last_bytes_in_;
  uint64 bytes_out = stats_.tun_bytes_out - stats_last_bytes_out_;

  stats_last_bytes_in_ = stats_.tun_bytes_in;
  stats_last_bytes_out_ = stats_.tun_bytes_out;

  uint64 millis = now - stats_last_ts_;
  stats_last_ts_ = now;

  double f = 1000.0 / std::max<uint32>((uint32)millis, 500);

  stats_.tun_bytes_in_per_second = (float)(bytes_in * f);
  stats_.tun_bytes_out_per_second = (float)(bytes_out * f);

  for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {
    WgKeypair *keypair = peer->curr_keypair_;

    // Allow ip/port to be remembered again for this keypair
    if (keypair)
      keypair->did_attempt_remember_ip_port = false;

    // Avoid taking the lock if it seems unneccessary
    if (now >= peer->time_of_next_key_event_ || peer->timers_ != 0) {
      uint32 mask;
      {
        WG_SCOPED_LOCK(peer->mutex_);
        mask = peer->CheckTimeouts_Locked(now);
        if (mask == 0)
          continue;
        if (mask & WgPeer::ACTION_SEND_KEEPALIVE)
          SendKeepalive_Locked(peer);
      }
      if (mask & WgPeer::ACTION_SEND_HANDSHAKE)
        SendHandshakeInitiation(peer);
    }
  }

  dev_.SecondLoop(now);
}
