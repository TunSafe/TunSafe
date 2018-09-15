// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TINYVPN_TINYVPN_H_
#define TINYVPN_TINYVPN_H_

#include "netapi.h"

class WireguardProcessor;
class DnsBlocker;

class DnsResolver {
public:
  explicit DnsResolver(DnsBlocker *dns_blocker);
  ~DnsResolver();

  bool Resolve(const char *hostname, IpAddr *result);

  void ClearCache();

  void SetAbortFlag(bool v) { abort_flag_ = v; }
private:
  struct Entry {
    std::string name;
    IpAddr ip;
    Entry(const std::string &name, const IpAddr &ip) : name(name), ip(ip) {}
  };
  std::vector<Entry> cache_;
  bool abort_flag_;
  DnsBlocker *dns_blocker_;
};


class WgConfig {
public:
  static bool HandleConfigurationProtocolMessage(WireguardProcessor *proc, const std::string &&message, std::string *result);
private:
  static void HandleConfigurationProtocolGet(WireguardProcessor *proc, std::string *result);
};

bool ParseWireGuardConfigFile(WireguardProcessor *wg, const char *filename, DnsResolver *dns_resolver);

#define kSizeOfAddress 64
const char *print_ip_prefix(char buf[kSizeOfAddress], int family, const void *ip, int prefixlen);
char *PrintIpAddr(const IpAddr &addr, char buf[kSizeOfAddress]);
char *PrintWgCidrAddr(const WgCidrAddr &addr, char buf[kSizeOfAddress]);
bool ParseCidrAddr(char *s, WgCidrAddr *out);

#endif  // TINYVPN_TINYVPN_H_
