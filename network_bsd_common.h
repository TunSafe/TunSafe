// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TUNSAFE_NETWORK_BSD_COMMON_H_
#define TUNSAFE_NETWORK_BSD_COMMON_H_

#include "netapi.h"
#include "wireguard.h"
#include "wireguard_config.h"

struct RouteInfo {
  uint8 family;
  uint8 cidr;
  uint8 ip[16];
  uint8 gw[16];
};

class TunsafeBackendBsd : public TunInterface, public UdpInterface {
public:
  TunsafeBackendBsd();
  virtual ~TunsafeBackendBsd();

  void RunLoop();
  void CleanupRoutes();

  void SetProcessor(WireguardProcessor *wg) { processor_ = wg; }

  // -- from TunInterface
  virtual bool Initialize(const TunConfig &&config, TunConfigOut *out) override;

  virtual void HandleSigAlrm() = 0;
  virtual void HandleExit() = 0;
  
protected:
  virtual bool InitializeTun(char devname[16]) = 0;
  virtual void RunLoopInner() = 0;

  void AddRoute(uint32 ip, uint32 cidr, uint32 gw);
  void DelRoute(const RouteInfo &cd);
  bool AddRoute(int family, const void *dest, int dest_prefix, const void *gateway);
  bool RunPrePostCommand(const std::vector<std::string> &vec);

  WireguardProcessor *processor_;
  std::vector<RouteInfo> cleanup_commands_;
  std::vector<std::string> pre_down_, post_down_;
};

#if defined(OS_MACOSX) || defined(OS_FREEBSD)
#define TUN_PREFIX_BYTES 4
#elif defined(OS_LINUX)
#define TUN_PREFIX_BYTES 0
#endif

int open_tun(char *devname, size_t devname_size);
int open_udp(int listen_on_port);

void SetThreadName(const char *name);
TunsafeBackendBsd *CreateTunsafeBackendBsd();

#endif  // TUNSAFE_NETWORK_BSD_COMMON_H_