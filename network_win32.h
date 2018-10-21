// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#include "stdafx.h"
#include "tunsafe_types.h"
#include "netapi.h"
#include "network_win32_api.h"
#include "network_win32_dnsblock.h"
#include "wireguard_config.h"
#include "tunsafe_threading.h"
#include "tunsafe_dnsresolve.h"
#include <functional>

enum {
  ADAPTER_GUID_SIZE = 40,
};

struct Packet;
class WireguardProcessor;
class TunsafeBackendWin32;

class PacketProcessor {
public:
  explicit PacketProcessor();
  ~PacketProcessor();

  enum {
    TARGET_PROCESSOR_UDP = 0,
    TARGET_PROCESSOR_TUN = 1,
    TARGET_UDP_DEVICE = 2,
    TARGET_TUN_DEVICE = 3,
    TARGET_CONFIG_PROTOCOL = 4,
  };

  void Reset();

  int Run(WireguardProcessor *wg, TunsafeBackendWin32 *backend);
  void Post(Packet *packet, Packet **end, int count);
  void ForcePost(Packet *packet);
  void PostExit(int exit_code);

  const uint32 *posted_exit_code() { return &exit_code_; }

private:
  static void CALLBACK ThreadPoolTimerCallback(PTP_CALLBACK_INSTANCE iTimerInstance, PVOID pContext, PTP_TIMER);
  void HandleConfigurationProtocolPacket(WireguardProcessor *wg, TunsafeBackendWin32 *backend, Packet *packet);
  Packet *first_;
  Packet **last_ptr_;
  uint32 packets_in_queue_;
  uint32 need_notify_;
  Mutex mutex_;
  HANDLE event_;

  uint32 exit_code_;
  bool timer_interrupt_;
};

// Encapsulates a UDP socket, optionally listening for incoming packets
// on a specific port.
class UdpSocketWin32 : public UdpInterface {
public:
  explicit UdpSocketWin32();
  ~UdpSocketWin32();

  void SetPacketHandler(PacketProcessor *packet_handler) { packet_handler_ = packet_handler; }

  void StartThread();
  void StopThread();

  // -- from UdpInterface
  virtual bool Configure(int listen_on_port) override;
  virtual void WriteUdpPacket(Packet *packet) override;

private:
  void ThreadMain();
  static DWORD WINAPI UdpThread(void *x);

  // All packets queued for writing. Locked by |mutex_|
  Packet *wqueue_, **wqueue_end_;

  Mutex mutex_;

  PacketProcessor *packet_handler_;
  SOCKET socket_;
  SOCKET socket_ipv6_;
  HANDLE completion_port_handle_;
  HANDLE thread_;

  bool exit_thread_;
};

class DnsBlocker;

class TunWin32Adapter {
public:
  TunWin32Adapter(DnsBlocker *dns_blocker, const char guid[ADAPTER_GUID_SIZE]);
  ~TunWin32Adapter();

  bool OpenAdapter(TunsafeBackendWin32 *backend, DWORD open_flags);
  bool ConfigureAdapter(const TunInterface::TunConfig &&config, TunInterface::TunConfigOut *out);
  void CloseAdapter(bool is_restart);

  HANDLE handle() { return handle_; }

  void DisassociateDnsBlocker() { dns_blocker_ = NULL; }

private:
  bool RunPrePostCommand(const std::vector<std::string> &vec);

  HANDLE handle_;
  DnsBlocker *dns_blocker_;

  std::vector<MIB_IPFORWARD_ROW2> routes_to_undo_;
  uint8 mac_adress_[6];
  bool has_dns6_setting_;
  int mtu_;
  
  int old_ipv4_metric_, old_ipv6_metric_;

  WgCidrAddr old_ipv6_address_;

  NET_LUID interface_luid_;

  void *backend_;

  std::vector<std::string> pre_down_, post_down_;
  char guid_[ADAPTER_GUID_SIZE];
};

// Implementation of TUN interface handling using IO Completion Ports
class TunWin32Iocp : public TunInterface {
public:
  explicit TunWin32Iocp(DnsBlocker *blocker, TunsafeBackendWin32 *backend);
  ~TunWin32Iocp();

  void SetPacketHandler(PacketProcessor *packet_handler) { packet_handler_ = packet_handler; }

  void StartThread();
  void StopThread();

  // -- from TunInterface
  virtual bool Configure(const TunConfig &&config, TunConfigOut *out) override;
  virtual void WriteTunPacket(Packet *packet) override;

  TunWin32Adapter &adapter() { return adapter_; }

private:
  void CloseTun(bool is_restart);
  void ThreadMain();
  static DWORD WINAPI TunThread(void *x);

  PacketProcessor *packet_handler_;
  HANDLE completion_port_handle_;
  HANDLE thread_;

  Mutex mutex_;

  bool exit_thread_;

  // All packets queued for writing
  Packet *wqueue_, **wqueue_end_;

  TunsafeBackendWin32 *backend_;
  TunWin32Adapter adapter_;
};

// Implementation of TUN interface handling using Overlapped IO
class TunWin32Overlapped : public TunInterface {
public:
  explicit TunWin32Overlapped(DnsBlocker *blocker, TunsafeBackendWin32 *backend);
  ~TunWin32Overlapped();

  void SetPacketHandler(PacketProcessor *packet_handler) { packet_handler_ = packet_handler; }

  void StartThread();
  void StopThread();

  // -- from TunInterface
  virtual bool Configure(const TunConfig &&config, TunConfigOut *out) override;
  virtual void WriteTunPacket(Packet *packet) override;

private:
  void CloseTun();
  void ThreadMain();
  static DWORD WINAPI TunThread(void *x);

  PacketProcessor *packet_handler_;
  HANDLE thread_;

  Mutex mutex_;

  HANDLE read_event_, write_event_, wake_event_;

  bool exit_thread_;

  Packet *wqueue_, **wqueue_end_;

  TunWin32Adapter adapter_;

  TunsafeBackendWin32 *backend_;
};

class TunsafeBackendWin32 : public TunsafeBackend, public ProcessorDelegate {
  friend class PacketProcessor;
  friend class TunWin32Iocp;
  friend class TunWin32Overlapped;
  friend class TunWin32Adapter;
public:
  TunsafeBackendWin32(Delegate *delegate);
  ~TunsafeBackendWin32();

  // -- from TunsafeBackend
  virtual bool Configure() override;
  virtual void Teardown() override;
  virtual bool SetTunAdapterName(const char *name) override;
  virtual void Start(const char *config_file) override;
  virtual void Stop() override;
  virtual void RequestStats(bool enable) override;
  virtual void ResetStats() override;
  virtual InternetBlockState GetInternetBlockState() override;
  virtual void SetInternetBlockState(InternetBlockState s) override;
  virtual void SetServiceStartupFlags(uint32 flags) override;
  virtual LinearizedGraph *GetGraph(int type) override;
  virtual std::string GetConfigFileName() override;
  virtual void SendConfigurationProtocolPacket(uint32 identifier, const std::string &&message) override;

  // -- from ProcessorDelegate
  virtual void OnConnected() override;
  virtual void OnConnectionRetry(uint32 attempts) override;

  void SetPublicKey(const uint8 key[32]);
  void PostExit(int exit_code);
  enum {
    MODE_NONE = 0,
    MODE_EXIT = 1,
    MODE_RESTART = 2,
    MODE_TUN_FAILED = 3,
  };
  uint32 exit_code() { return *packet_processor_.posted_exit_code(); }

  void SetStatus(StatusCode status);
private:

  void StopInner(bool is_restart);
  static DWORD WINAPI WorkerThread(void *x);
  void PushStats();

  HANDLE worker_thread_;
  bool want_periodic_stats_;

  Delegate *delegate_;
  char *config_file_;

  DnsBlocker dns_blocker_;
  DnsResolver dns_resolver_;

  WireguardProcessor *wg_processor_;

  uint32 last_tun_adapter_failed_;
  StatsCollector stats_collector_;

  Mutex stats_mutex_;
  WgProcessorStats stats_;

  PacketProcessor packet_processor_;

  char guid_[ADAPTER_GUID_SIZE];
};

// This class ensures that all callbacks get rescheduled to another thread
class TunsafeBackendDelegateThreaded : public TunsafeBackend::Delegate {
public:
  TunsafeBackendDelegateThreaded(TunsafeBackend::Delegate *delegate, const std::function<void(void)> &callback);
  ~TunsafeBackendDelegateThreaded();

private:
  virtual void OnGetStats(const WgProcessorStats &stats) override;
  virtual void OnGraphAvailable() override;
  virtual void OnStateChanged() override;
  virtual void OnClearLog() override;
  virtual void OnLogLine(const char **s) override;
  virtual void OnStatusCode(TunsafeBackend::StatusCode status) override;
  virtual void OnConfigurationProtocolReply(uint32 ident, const std::string &&reply) override;
  virtual void DoWork() override;

  enum Which {
    Id_OnGetStats,
    Id_OnStateChanged,
    Id_OnClearLog,
    Id_OnLogLine,
    Id_OnUpdateUI,
    Id_OnStatusCode,
    Id_OnGraphAvailable,
    Id_OnConfigurationProtocolReply,
  };

  void AddEntry(Which which, intptr_t lparam = 0, uint32 wparam = 0);

  TunsafeBackend::Delegate *delegate_;
  std::function<void(void)> callback_;

  struct Entry {
    uint8 which;
    uint32 wparam;
    intptr_t lparam;
    Entry(uint8 which, uint32 wparam, intptr_t lparam) : which(which), wparam(wparam), lparam(lparam) {}
  };

  static void FreeEntry(Entry *e);

  Mutex mutex_;
  std::vector<Entry> incoming_entry_;
  std::vector<Entry> processing_entry_;
};

// For each adapter, remembers whether the adapter is in use
class TunAdaptersInUse {
public:
  TunAdaptersInUse();

  // attempt to acquire the adapter, so it can't be acquired by anyone else
  bool Acquire(const char guid[ADAPTER_GUID_SIZE], void *context);

  // mark as free
  void Release(void *context);

  // Lookup a context from a guid
  void *LookupContextFromGuid(const char guid[ADAPTER_GUID_SIZE]);

  // Lookup a guid from a context
  bool LookupGuidFromContext(void *context, char guid[ADAPTER_GUID_SIZE]);

  char *GetAllGuid();

  static TunAdaptersInUse *GetInstance();

private:
  enum {
    kMaxAdaptersInUse = 16,
  };
  struct Entry {
    char guid[ADAPTER_GUID_SIZE];
    void *context;
    int count;
  };
  Mutex mutex_;
  uint8 num_inuse_;
  Entry entry_[kMaxAdaptersInUse];
};
