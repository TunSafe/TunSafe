// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "wireguard.h"
#include "netapi.h"
#include "wireguard_proto.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/blake2s.h"
#include "crypto/siphash.h"
#include "tunsafe_endian.h"
#include <algorithm>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "wireguard.h"

uint64 OsGetMilliseconds();

enum {
  IPV4_HEADER_SIZE = 20,
  IPV6_HEADER_SIZE = 40,
};

WireguardProcessor::WireguardProcessor(UdpInterface *udp, TunInterface *tun, ProcessorDelegate *procdel) {
  tun_addr_.size = 0;
  tun6_addr_.size = 0;
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
  dns6_addr_.sin.sin_family = dns_addr_.sin.sin_family = 0;
}

WireguardProcessor::~WireguardProcessor() {
}

bool WireguardProcessor::AddDnsServer(const IpAddr &sin) {
  IpAddr *target = (sin.sin.sin_family == AF_INET6) ? &dns6_addr_ : &dns_addr_;
  if (target->sin.sin_family != 0)
    return false;
  *target = sin;
  return true;
}


bool WireguardProcessor::SetTunAddress(const WgCidrAddr &addr) {
  WgCidrAddr *target = (addr.size == 128) ? &tun6_addr_ : &tun_addr_;
  if (target->size != 0)
    return false;
  *target = addr;
  return true;
}


ProcessorStats WireguardProcessor::GetStats() {
  stats_.last_complete_handskake_timestamp = dev_.last_complete_handskake_timestamp();
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
  memcpy(c->ipv4_addr, &tun_addr_.addr, 4);
  if (tun6_addr_.size == 128)
    memcpy(c->ipv6_addr, &tun6_addr_.addr, 16);
  c->flags = ((tun_addr_.cidr >> 3) & 3);
}

static inline bool CheckFirstNbitsEquals(const byte *a, const byte *b, size_t n) {
  return memcmp(a, b, n >> 3) == 0 && ((n & 7) == 0 || !((a[n >> 3] ^ b[n >> 3]) & (0xff << (8 - (n & 7)))));
}

static bool IsWgCidrAddrSubsetOf(const WgCidrAddr &inner, const WgCidrAddr &outer) {
  return inner.size == outer.size && inner.cidr >= outer.cidr &&
         CheckFirstNbitsEquals(inner.addr, outer.addr, outer.cidr);
}

bool WireguardProcessor::Start() {
  if (!udp_->Initialize(listen_port_))
    return false;

  if (tun_addr_.size != 32) {
    RERROR("No IPv4 address configured");
    return false;
  }

  if (tun_addr_.cidr >= 31) {
    RERROR("The TAP driver is not compatible with Address using CIDR /31 or /32. Changing to /24");
    tun_addr_.cidr = 24;
  }

  TunInterface::TunConfig config = {0};
  config.ip = ReadBE32(tun_addr_.addr);
  config.cidr = tun_addr_.cidr;
  config.mtu = mtu_;
  config.pre_post_commands = pre_post_;
  
  uint32 netmask = tun_addr_.cidr == 32 ? 0xffffffff : 0xffffffff << (32 - tun_addr_.cidr);

  uint32 ipv4_broadcast_addr = (netmask == 0xffffffff) ? 0xffffffff : config.ip | ~netmask;

  if (tun6_addr_.size == 128) {
    if (tun6_addr_.cidr > 126) {
      RERROR("IPv6 /127 or /128 not supported. Changing to 120");
      tun6_addr_.cidr = 120;
    }
    config.ipv6_cidr = tun6_addr_.cidr;
    memcpy(&config.ipv6_address, tun6_addr_.addr, 16);
  }

  if (add_routes_mode_) {
    WgPeer *peer = (WgPeer *)dev_.ip_to_peer_map().LookupV4DefaultPeer();
    if (peer != NULL && peer->endpoint_.sin.sin_family != 0) {
      config.default_route_endpoint_v4 = (peer->endpoint_.sin.sin_family == AF_INET) ? ReadBE32(&peer->endpoint_.sin.sin_addr) : 0;
      // Set the default route to something
      config.use_ipv4_default_route = true;
    }

    // Also configure ipv6 gw?
    if (config.ipv6_cidr != 0) {
      peer = (WgPeer*)dev_.ip_to_peer_map().LookupV6DefaultPeer();
      if (peer != NULL && peer->endpoint_.sin.sin_family != 0) {
        if (peer->endpoint_.sin.sin_family == AF_INET6)
          memcpy(&config.default_route_endpoint_v6, &peer->endpoint_.sin6.sin6_addr, 16);
        config.use_ipv6_default_route = true;
      }
    }

    // For each peer, add the extra routes to the extra routes table
    for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {
      for (auto it = peer->allowed_ips_.begin(); it != peer->allowed_ips_.end(); ++it) {
        // Don't add an entry if it's identical to my address or it's a default route
        if (IsWgCidrAddrSubsetOf(*it, tun_addr_) || IsWgCidrAddrSubsetOf(*it, tun6_addr_) || it->cidr == 0)
          continue;
        // Don't add an entry if we have no ipv6 address configured
        if (config.ipv6_cidr == 0 && it->size != 32)
          continue;
        config.extra_routes.push_back(*it);
      }
    }
  }

  uint8 dhcp_options[6];

  config.block_dns_on_adapters = dns_blocking_;
  config.internet_blocking = internet_blocking_;

  if (dns_addr_.sin.sin_family == AF_INET) {
    dhcp_options[0] = 6;
    dhcp_options[1] = 4;
    memcpy(&dhcp_options[2], &dns_addr_.sin.sin_addr, 4);
    config.dhcp_options = dhcp_options;
    config.dhcp_options_size = sizeof(dhcp_options);
  }

  if (dns6_addr_.sin6.sin6_family == AF_INET6) {
    config.set_ipv6_dns = true;
    memcpy(&config.dns_server_v6, &dns6_addr_.sin6.sin6_addr, 16);
  }

  TunInterface::TunConfigOut config_out;
  if (!tun_->Initialize(std::move(config), &config_out))
    return false;

  SetupCompressionHeader(dev_.compression_header());

  network_discovery_spoofing_ = config_out.enable_neighbor_discovery_spoofing;
  memcpy(network_discovery_mac_, config_out.neighbor_discovery_spoofing_mac, 6);
  
  for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {
    peer->ipv4_broadcast_addr_ = ipv4_broadcast_addr;
    if (peer->endpoint_.sin.sin_family != 0) {
      RINFO("Sending handshake...");
      SendHandshakeInitiationAndResetRetries(peer);
    }
  }

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
  if (data[40] != kICMPv6_NeighborSolicitation || data[41] != 0)
    return false;

  if (!network_discovery_spoofing_)
    return false;

  bool is_broadcast = true;

  if (memcmp(data + 24, kIcmpv6NeighborMulticastPrefix, sizeof(kIcmpv6NeighborMulticastPrefix)) != 0) {
    if (memcmp(data + 24, data + 48, 16) != 0)
      return false;
    is_broadcast = false;
  }
   
  // Target address must match a peer's range.
  WgPeer *peer = (WgPeer*)dev_.ip_to_peer_map().LookupV6(data + 48);
  if (peer == NULL)
    return false;

  // Build response packet
  Packet *out = AllocPacket();
  if (out == NULL)
    return false;

  byte *odata = out->data;

  int packet_size = is_broadcast ? sizeof(ICMPv6NaPacket) : sizeof(ICMPv6NaPacketWithoutTarget);

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
  uint16 checksum = ComputeIcmpv6Checksum(odata + 40, packet_size, odata + 8, odata + 24);
  WriteBE16(&((ICMPv6NaPacket*)(odata + 40))->checksum, checksum);

  out->size = 40 + packet_size;
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

  stats_.tun_bytes_in += data_size;
  stats_.tun_packets_in++;

  // Sanity check that it looks like a valid ipv4 or ipv6 packet,
  // and determine the destination peer from the ip header
  if (data_size < IPV4_HEADER_SIZE)
    goto getout;
  
  ip_version = *data >> 4;
  if (ip_version == 4) {
    uint32 ip = ReadBE32(data + 16);
    peer = (WgPeer*)dev_.ip_to_peer_map().LookupV4(ip);
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

    peer = (WgPeer*)dev_.ip_to_peer_map().LookupV6(data + 24);
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
  if (peer->endpoint_.sin.sin_family == 0)
    goto getout;

  WritePacketToUdp(peer, packet);
  return;
  
getout:
  // send ICMP?
  FreePacket(packet);
}

void WireguardProcessor::WritePacketToUdp(WgPeer *peer, Packet *packet) {
  byte *data = packet->data;
  size_t size = packet->size;
  bool want_handshake;
  uint64 send_ctr;
  WgKeypair *keypair = peer->curr_keypair_;

  if (keypair == NULL ||
      keypair->send_key_state == WgKeypair::KEY_INVALID ||
      keypair->send_ctr >= REJECT_AFTER_MESSAGES)
    goto getout_handshake;

  want_handshake = (keypair->send_ctr >= REKEY_AFTER_MESSAGES ||
                    keypair->send_key_state == WgKeypair::KEY_WANT_REFRESH);

  // Ensure packet will fit including the biggest padding
  if (size > kPacketCapacity - 15 - CHACHA20POLY1305_AUTHTAGLEN)
    goto getout_discard;

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
  send_ctr = keypair->send_ctr++;

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
        WriteLE64(write -= 8, next_expected_packet);
        inner_tag = WG_ACK_HEADER_COUNTER_8;
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

    stats_.compression_wg_saved_out += (int64)16 - header_size;

    packet->data = data - header_size;
    packet->size = (int)(size + header_size + keypair->auth_tag_length);
    WgKeypairEncryptPayload(data, size, write, data - write, send_ctr, keypair);
  } else {
need_big_packet:
#else
  {
#endif  // #if WITH_SHORT_HEADERS
    ((MessageData*)data)[-1].type = ToLE32(MESSAGE_DATA);
    ((MessageData*)data)[-1].receiver_id = keypair->remote_key_id;
    ((MessageData*)data)[-1].counter = ToLE64(send_ctr);
    packet->data = data - sizeof(MessageData);
    packet->size = (int)(size + sizeof(MessageData) + keypair->auth_tag_length);
    WgKeypairEncryptPayload(data, size, NULL, 0, send_ctr, keypair);
  }

  packet->addr = peer->endpoint_;
  DoWriteUdpPacket(packet);
  if (want_handshake)
    SendHandshakeInitiationAndResetRetries(peer);
  return;

getout_discard:
  FreePacket(packet);
  return;

getout_handshake:
  // Keep only the first MAX_QUEUED_PACKETS packets.
  while (peer->num_queued_packets_ >= MAX_QUEUED_PACKETS_PER_PEER) {
    Packet *packet = peer->first_queued_packet_;
    peer->first_queued_packet_ = packet->next;
    peer->num_queued_packets_--;
    FreePacket(packet);
  }
  // Add the packet to the out queue that will get sent once handshake completes
  *peer->last_queued_packet_ptr_ = packet;
  peer->last_queued_packet_ptr_ = &packet->next;
  packet->next = NULL;
  peer->num_queued_packets_++;

  SendHandshakeInitiationAndResetRetries(peer);
}

// This scrambles the initial 16 bytes of the packet with the
// trailing 8 bytes of the packet.
static void ScrambleUnscramblePacket(Packet *packet, ScramblerSiphashKeys *keys) {
  uint8 *data = packet->data;
  size_t data_size = packet->size;

  if (data_size < 8)
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
    struct { uint64 a, b; } scramblers = {a, b};
    uint8 *s = (uint8*)&scramblers;
    for (size_t i = 0; i < data_size - 8; i++)
      data[i] ^= s[i];
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

void WireguardProcessor::SendHandshakeInitiationAndResetRetries(WgPeer *peer) {
  peer->handshake_attempts_ = 0;
  SendHandshakeInitiation(peer);
}

void WireguardProcessor::SendHandshakeInitiation(WgPeer *peer) {
  // Send out a handshake init packet to trigger the handshake procedure
  if (!peer->CheckHandshakeRateLimit())
    return;
  Packet *packet = AllocPacket();
  if (!packet)
    return;
  peer->CreateMessageHandshakeInitiation(packet);

  packet->addr = peer->endpoint_;
  DoWriteUdpPacket(packet);
  peer->OnHandshakeInitSent();
}

// Handles an incoming WireGuard packet from the UDP side, decrypt etc.
void WireguardProcessor::HandleUdpPacket(Packet *packet, bool overload) {
  uint32 type;

  stats_.udp_bytes_in += packet->size;
  stats_.udp_packets_in++;

  // Unscramble incoming packets
#if WITH_HEADER_OBFUSCATION
  if (dev_.header_obfuscation_)
    ScrambleUnscramblePacket(packet, &dev_.header_obfuscation_key_);
#endif  // WITH_HEADER_OBFUSCATION

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
    if (packet->size != sizeof(MessageHandshakeCookie))
      goto invalid_size;
    HandleHandshakeCookiePacket(packet);
  } else if (type == MESSAGE_HANDSHAKE_INITIATION) {
    if (WITH_HANDSHAKE_EXT ? (packet->size < sizeof(MessageHandshakeInitiation)) : (packet->size != sizeof(MessageHandshakeInitiation)))
      goto invalid_size;

    if (!CheckIncomingHandshakeRateLimit(packet, overload))
      return;
    HandleHandshakeInitiationPacket(packet);
  } else if (type == MESSAGE_HANDSHAKE_RESPONSE) {
    if (WITH_HANDSHAKE_EXT ? (packet->size < sizeof(MessageHandshakeResponse)) : (packet->size != sizeof(MessageHandshakeResponse)))
      goto invalid_size;
    if (!CheckIncomingHandshakeRateLimit(packet, overload))
      return;
    HandleHandshakeResponsePacket(packet);
  } else {
    // unknown packet
invalid_size:
    FreePacket(packet);
  }
}

// Returns nonzero if two endpoints are different.
static uint32 CompareEndpoint(const IpAddr *a, const IpAddr *b) {
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

void WgPeer::CopyEndpointToPeer(WgKeypair *keypair, const IpAddr *addr) {
  // Remember how to send packets to this peer
  if (CompareEndpoint(&keypair->peer->endpoint_, addr)) {
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
  uint8 *data = packet->data + 1;
  size_t bytes_left = packet->size - 1;
  WgKeypair *keypair;
  uint64 counter, acked_counter;
  uint8 ack_tag;

  if ((tag & WG_SHORT_HEADER_KEY_ID_MASK) == 0x00) {
    // The key_id is explicitly included in the packet.
    if (bytes_left < 4) goto getout;
    uint32 key_id = ReadLE32(data);
    data += 4, bytes_left -= 4;
    auto it = dev_.key_id_lookup().find(key_id);
    if (it == dev_.key_id_lookup().end()) goto getout;
    keypair = it->second.second;
  } else {
    // Lookup the packet source ip and port in the address mapping
    uint64 addr_id = packet->addr.sin.sin_addr.s_addr | ((uint64)packet->addr.sin.sin_port << 32);
    auto it = dev_.addr_entry_map().find(addr_id);
    if (it == dev_.addr_entry_map().end())
      goto getout;
    WgAddrEntry *addr_entry = it->second;
    keypair = addr_entry->keys[((tag / WG_SHORT_HEADER_KEY_ID) & 3) - 1];
  }

  if (!keypair || keypair->recv_key_state == WgKeypair::KEY_INVALID ||
      !keypair->enabled_features[WG_FEATURE_ID_SHORT_HEADER])
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

  // If the acknowledge header is present, then parse it so we may
  // get an ack for the highest seen packet.
  if (tag & WG_SHORT_HEADER_ACK) {
    if (bytes_left == 0) goto getout;
    ack_tag = *data;
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
    case WG_ACK_HEADER_COUNTER_8:
      if (bytes_left < 8) goto getout;
      acked_counter = ReadLE64(data);
      data += 8, bytes_left -= 8;
      break;
    default:
      break;
    }
  }
  if (counter >= REJECT_AFTER_MESSAGES)
    goto getout;
  // Authenticate the packet before we can apply the state changes.
  if (!WgKeypairDecryptPayload(data, bytes_left, packet->data, data - packet->data, counter, keypair))
    goto getout;

  if (!keypair->replay_detector.CheckReplay(counter))
    goto getout;

  stats_.compression_wg_saved_in += 16 - (data - packet->data);

  keypair->send_ctr_acked = std::max<uint64>(keypair->send_ctr_acked, acked_counter);
  keypair->incoming_packet_count++;

  WgPeer::CopyEndpointToPeer(keypair, &packet->addr);

  // Periodically broadcast out the short key 
  if ((tag & WG_SHORT_HEADER_KEY_ID_MASK) == 0x00 && !keypair->did_attempt_remember_ip_port) {
    keypair->did_attempt_remember_ip_port = true;
    if (keypair->enabled_features[WG_FEATURE_ID_SKIP_KEYID_IN]) {
      uint64 addr_id = packet->addr.sin.sin_addr.s_addr | ((uint64)packet->addr.sin.sin_port << 32);
      dev_.UpdateKeypairAddrEntry(addr_id, keypair);
    }
  }

  // Ack header may also signal that we can omit the key id in packets from now on.
  if (tag & WG_SHORT_HEADER_ACK)
    keypair->can_use_short_key_for_outgoing = (ack_tag & WG_ACK_HEADER_KEY_MASK) * WG_SHORT_HEADER_KEY_ID;

  HandleAuthenticatedDataPacket(keypair, packet, data, bytes_left - keypair->auth_tag_length);
  return;
getout:
  FreePacket(packet);
  return;
}
#endif  // WITH_SHORT_HEADERS

void WireguardProcessor::HandleAuthenticatedDataPacket(WgKeypair *keypair, Packet *packet, uint8 *data, size_t data_size) {
  WgPeer *peer = keypair->peer;

  // Promote the next key to the current key when we receive a data packet,
  // the handshake is now complete.
  if (peer->CheckSwitchToNextKey(keypair)) {
    if (procdel_) {
      procdel_->OnConnected(ReadBE32(tun_addr_.addr));
    }
    peer->OnHandshakeFullyComplete();
    SendQueuedPackets(peer);
  }

  // Refresh when current key gets too old
  if (peer->curr_keypair_ && peer->curr_keypair_->recv_key_state == WgKeypair::KEY_WANT_REFRESH) {
    peer->curr_keypair_->recv_key_state = WgKeypair::KEY_DID_REFRESH;
    SendHandshakeInitiationAndResetRetries(peer);
  }

  if (data_size == 0) {
    peer->OnKeepaliveReceived();
    goto getout;
  }
  peer->OnDataReceived();

#if WITH_HANDSHAKE_EXT
  // Unpack the packet headers using ipzip
  if (keypair->enabled_features[WG_FEATURE_ID_IPZIP]) {
    uint32 rv = IpzipDecompress(data, (uint32)data_size, &keypair->ipzip_state_, IPZIP_RECV_BY_CLIENT);
    if (rv == (uint32)-1)
      goto getout; // ipzip failed decompress
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
    if (data_size < IPV4_HEADER_SIZE) {
      // too small ipv4 header
      goto getout;
    }
    peer_from_header = (WgPeer*)dev_.ip_to_peer_map().LookupV4(ReadBE32(data + 12));
    size_from_header = ReadBE16(data + 2);
    if (size_from_header < IPV4_HEADER_SIZE) {
      // too small packet?
      goto getout;
    }
  } else if (ip_version == 6) {
    if (data_size < IPV6_HEADER_SIZE) {
      // too small ipv6 header
      goto getout;
    }
    peer_from_header = (WgPeer*)dev_.ip_to_peer_map().LookupV6(data + 8);
    size_from_header = IPV6_HEADER_SIZE + ReadBE16(data + 4);
  } else {
    // invalid ip version
    goto getout;
  }
  if (size_from_header > data_size) {
    // oversized packet?
    goto getout;
  }
  if (peer_from_header != peer) {
    // source address mismatch?
    goto getout;
  }
  //RINFO("Outgoing TUN packet of size %d", (int)size_from_header);
  packet->data = data;
  packet->size = size_from_header;

  stats_.tun_bytes_out += packet->size;
  stats_.tun_packets_out++;

  tun_->WriteTunPacket(packet);
  return;

getout:
  FreePacket(packet);
  return;
}

void WireguardProcessor::HandleDataPacket(Packet *packet) {
  uint8 *data = packet->data;
  size_t data_size = packet->size;
  uint32 key_id = ((MessageData*)data)->receiver_id;
  uint64 counter = ToLE64((((MessageData*)data)->counter));
  WgKeypair *keypair;

  auto it = dev_.key_id_lookup().find(key_id);
  if (it == dev_.key_id_lookup().end() ||
      (keypair = it->second.second) == NULL ||
      keypair->recv_key_state == WgKeypair::KEY_INVALID) {
getout:
    FreePacket(packet);
    return;
  }

  if (counter >= REJECT_AFTER_MESSAGES)
    goto getout;

  if (!WgKeypairDecryptPayload(data + sizeof(MessageData), data_size - sizeof(MessageData),
                        NULL, 0, counter, keypair)) {
    goto getout;
  }
  if (!keypair->replay_detector.CheckReplay(counter))
    goto getout;

  WgPeer::CopyEndpointToPeer(keypair, &packet->addr);
  HandleAuthenticatedDataPacket(keypair, packet, data + sizeof(MessageData), data_size - sizeof(MessageData) - keypair->auth_tag_length);
}

static uint64 GetIpForRateLimit(Packet *packet) {
  if (packet->addr.sin.sin_family == AF_INET) {
    return ReadLE32(&packet->addr.sin.sin_addr);
  } else {
    return ReadLE64(&packet->addr.sin6.sin6_addr);
  }
}

bool WireguardProcessor::CheckIncomingHandshakeRateLimit(Packet *packet, bool overload) {
  WgRateLimit::RateLimitResult rr = dev_.rate_limiter()->CheckRateLimit(GetIpForRateLimit(packet));
  if ((overload && rr.is_rate_limited()) || !dev_.CheckCookieMac1(packet)) {
    FreePacket(packet);
    return false;
  }
  if (overload && !rr.is_first_ip() && !dev_.CheckCookieMac2(packet)) {
    dev_.rate_limiter()->CommitResult(rr);
    dev_.CreateCookieMessage((MessageHandshakeCookie*)packet->data, packet, ((MessageHandshakeInitiation*)packet->data)->sender_key_id);
    packet->size = sizeof(MessageHandshakeCookie);
    DoWriteUdpPacket(packet);
    return false;
  }
  dev_.rate_limiter()->CommitResult(rr);
  return true;
}

// server receives this when client wants to setup a session
void WireguardProcessor::HandleHandshakeInitiationPacket(Packet *packet) {
  WgPeer *peer = WgPeer::ParseMessageHandshakeInitiation(&dev_, packet);
  if (!peer) {
    FreePacket(packet);
    return;
  }
  peer->OnHandshakeAuthComplete();
  DoWriteUdpPacket(packet);
}

// client receives this after session is established
void WireguardProcessor::HandleHandshakeResponsePacket(Packet *packet) {
  WgPeer *peer = WgPeer::ParseMessageHandshakeResponse(&dev_, packet);
  if (!peer) {
    FreePacket(packet);
    return;
  }
  peer->endpoint_ = packet->addr;
  FreePacket(packet);
  peer->OnHandshakeAuthComplete();
  peer->OnHandshakeFullyComplete();
  if (procdel_)
    procdel_->OnConnected(ReadBE32(tun_addr_.addr));
  SendKeepalive(peer);
}

void WireguardProcessor::SendKeepalive(WgPeer *peer) {
  // can't send keepalive if no endpoint is configured
  if (peer->endpoint_.sin.sin_family == 0)
    return;

  // If nothing is queued, insert a keepalive packet
  if (peer->first_queued_packet_ == NULL) {
    Packet *packet = AllocPacket();
    if (!packet)
      return;
    packet->size = 0;
    packet->next = NULL;
    peer->first_queued_packet_ = packet;
  }
  SendQueuedPackets(peer);
}

void WireguardProcessor::SendQueuedPackets(WgPeer *peer) {
  // Steal the packets
  Packet *packet = peer->first_queued_packet_;
  peer->first_queued_packet_ = NULL;
  peer->last_queued_packet_ptr_ = &peer->first_queued_packet_;
  peer->num_queued_packets_ = 0;
  while (packet) {
    Packet *next = packet->next;
    WritePacketToUdp(peer, packet);
    packet = next;
  }
}

void WireguardProcessor::HandleHandshakeCookiePacket(Packet *packet) {
  WgPeer::ParseMessageHandshakeCookie(&dev_, (MessageHandshakeCookie *)packet->data);
}

void WireguardProcessor::SecondLoop() {
  uint64 now = OsGetMilliseconds();
  for (WgPeer *peer = dev_.first_peer(); peer; peer = peer->next_peer_) {

    // Allow ip/port to be remembered again for this keypair
    if (peer->curr_keypair_)
      peer->curr_keypair_->did_attempt_remember_ip_port = false;

    uint32 mask = peer->CheckTimeouts(now);
    if (mask == 0)
      continue;
    if (mask & WgPeer::ACTION_SEND_KEEPALIVE)
      SendKeepalive(peer);
    if (mask & WgPeer::ACTION_SEND_HANDSHAKE)
      SendHandshakeInitiation(peer);
  }

  dev_.SecondLoop(now);
}

