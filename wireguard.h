// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#include "tunsafe_types.h"
#include "wireguard_proto.h"

struct ProcessorStats {
  // Number of bytes sent/received over the physical UDP connections
  int64 udp_bytes_in, udp_bytes_out;
  int64 udp_packets_in, udp_packets_out;
  // Number of bytes sent/received over the TUN interface
  int64 tun_bytes_in, tun_bytes_out;
  int64 tun_packets_in, tun_packets_out;
  uint64 last_complete_handskake_timestamp;

  int64 compression_hdr_saved_in, compression_hdr_saved_out;

  int64 compression_wg_saved_in, compression_wg_saved_out;
};

class ProcessorDelegate {
public:
  virtual void OnConnected(in_addr_t my_ip) = 0;
  virtual void OnDisconnected() = 0;
};

enum InternetBlockState {
  kBlockInternet_Off,
  kBlockInternet_Route,
  kBlockInternet_Firewall,
  kBlockInternet_Both,

  // An unspecified value that uses either route or firewall
  kBlockInternet_DefaultOn = 254,

  kBlockInternet_Default = 255,
};

class WireguardProcessor {
public:
  WireguardProcessor(UdpInterface *udp, TunInterface *tun, ProcessorDelegate *procdel);
  ~WireguardProcessor();

  void SetListenPort(int listen_port) {
    listen_port_ = listen_port;
  }

  bool SetTunAddress(const WgCidrAddr &addr);

  bool AddDnsServer(const IpAddr &sin);

  void SetMtu(int mtu) {
    if (mtu >= 576 && mtu <= 10000)
      mtu_ = mtu;
  }

  void SetAddRoutesMode(bool mode) {
    add_routes_mode_ = mode;
  }

  void SetDnsBlocking(bool dns_blocking) {
    dns_blocking_ = dns_blocking;
  }

  void SetInternetBlocking(InternetBlockState internet_blocking) {
    internet_blocking_ = internet_blocking;
  }

  void SetHeaderObfuscation(const char *key) {
    dev_.SetHeaderObfuscation(key);
  }
  
  void HandleTunPacket(Packet *packet);
  void HandleUdpPacket(Packet *packet, bool overload);
  void SecondLoop();

  ProcessorStats GetStats();
  void ResetStats();

  bool Start();

  WgDevice &dev() { return dev_; }

  TunInterface::PrePostCommands &prepost() { return pre_post_; }

private:
  void DoWriteUdpPacket(Packet *packet);
  void WritePacketToUdp(WgPeer *peer, Packet *packet);
  void SendHandshakeInitiation(WgPeer *peer);
  void SendHandshakeInitiationAndResetRetries(WgPeer *peer);
  void SendKeepalive(WgPeer *peer);
  void SendQueuedPackets(WgPeer *peer);

  void HandleHandshakeInitiationPacket(Packet *packet);
  void HandleHandshakeResponsePacket(Packet *packet);
  void HandleHandshakeCookiePacket(Packet *packet);
  void HandleDataPacket(Packet *packet);
  
  void HandleAuthenticatedDataPacket(WgKeypair *keypair, Packet *packet, uint8 *data, size_t data_size);

  void HandleShortHeaderFormatPacket(uint32 tag, Packet *packet);

  bool CheckIncomingHandshakeRateLimit(Packet *packet, bool overload);

  bool HandleIcmpv6NeighborSolicitation(const byte *data, size_t data_size);

  void SetupCompressionHeader(WgPacketCompressionVer01 *c);

  int listen_port_;

  ProcessorDelegate *procdel_;
  TunInterface *tun_;
  UdpInterface *udp_;
  int mtu_;
  ProcessorStats stats_;

  bool dns_blocking_;
  uint8 internet_blocking_;
  bool add_routes_mode_;
  bool network_discovery_spoofing_;
  uint8 network_discovery_mac_[6];

  WgDevice dev_;

  WgCidrAddr tun_addr_;
  WgCidrAddr tun6_addr_;

  IpAddr dns_addr_, dns6_addr_;

  TunInterface::PrePostCommands pre_post_;
};

