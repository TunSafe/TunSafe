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
#include <functional>

struct Packet;
class WireguardProcessor;
class TunsafeBackendWin32;

class ThreadedPacketQueue {
public:
  explicit ThreadedPacketQueue(WireguardProcessor *wg, TunsafeBackendWin32 *backend);
  ~ThreadedPacketQueue();

  enum {
    TARGET_PROCESSOR_UDP = 0,
    TARGET_PROCESSOR_TUN = 1,
    TARGET_UDP_DEVICE = 2,
    TARGET_TUN_DEVICE = 3,
  };

  void Start();
  void Stop();

  void Post(Packet *packet, Packet **end, int count);
  void AbortingDriver();

private:
  void PostTimerInterrupt();
  static void CALLBACK TimerRoutine(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue);
  
  DWORD ThreadMain();
  static DWORD WINAPI ThreadedPacketQueueLauncher(VOID *x);
  Packet *first_;
  Packet **last_ptr_;
  uint32 packets_in_queue_;
  uint32 need_notify_;
  Mutex mutex_;
  HANDLE event_;

  HANDLE timer_handle_;
  HANDLE handle_;
  WireguardProcessor *wg_;
  bool exit_flag_;
  bool timer_interrupt_;
  TunsafeBackendWin32 *backend_;
};

// Encapsulates a UDP socket, optionally listening for incoming packets
// on a specific port.
class UdpSocketWin32 : public UdpInterface {
public:
  explicit UdpSocketWin32();
  ~UdpSocketWin32();

  void SetPacketHandler(ThreadedPacketQueue *packet_handler) { packet_handler_ = packet_handler; }

  void StartThread();
  void StopThread();

  // -- from UdpInterface
  virtual bool Initialize(int listen_on_port) override;
  virtual void WriteUdpPacket(Packet *packet) override;

private:

  void ThreadMain();
  static DWORD WINAPI UdpThread(void *x);

  // All packets queued for writing. Locked by |mutex_|
  Packet *wqueue_, **wqueue_end_;

  Mutex mutex_;

  ThreadedPacketQueue *packet_handler_;
  SOCKET socket_;
  SOCKET socket_ipv6_;
  HANDLE completion_port_handle_;
  HANDLE thread_;

  bool exit_thread_;
};

class DnsBlocker;

class TunWin32Adapter {
public:
  TunWin32Adapter(DnsBlocker *dns_blocker);
  ~TunWin32Adapter();

  bool OpenAdapter(unsigned int *exit_thread, DWORD open_flags);
  bool InitAdapter(const TunInterface::TunConfig &&config, TunInterface::TunConfigOut *out);
  void CloseAdapter();

  HANDLE handle() { return handle_; }

  void DisassociateDnsBlocker() { dns_blocker_ = NULL; }

private:
  bool RunPrePostCommand(const std::vector<std::string> &vec);

  HANDLE handle_;
  DnsBlocker *dns_blocker_;

  std::vector<MIB_IPFORWARD_ROW2> routes_to_undo_;
  uint8 mac_adress_[6];
  int mtu_;
  char guid_[64];

  std::vector<std::string> pre_down_, post_down_;
};

// Implementation of TUN interface handling using IO Completion Ports
class TunWin32Iocp : public TunInterface {
public:
  explicit TunWin32Iocp(DnsBlocker *blocker, TunsafeBackendWin32 *backend);
  ~TunWin32Iocp();

  void SetPacketHandler(ThreadedPacketQueue *packet_handler) { packet_handler_ = packet_handler; }

  void StartThread();
  void StopThread();

  // -- from TunInterface
  virtual bool Initialize(const TunConfig &&config, TunConfigOut *out) override;
  virtual void WriteTunPacket(Packet *packet) override;

  TunWin32Adapter &adapter() { return adapter_; }

private:
  void CloseTun();
  void ThreadMain();
  static DWORD WINAPI TunThread(void *x);

  ThreadedPacketQueue *packet_handler_;
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

  void SetPacketHandler(ThreadedPacketQueue *packet_handler) { packet_handler_ = packet_handler; }

  void StartThread();
  void StopThread();

  // -- from TunInterface
  virtual bool Initialize(const TunConfig &&config, TunConfigOut *out) override;
  virtual void WriteTunPacket(Packet *packet) override;

private:
  void CloseTun();
  void ThreadMain();
  static DWORD WINAPI TunThread(void *x);

  ThreadedPacketQueue *packet_handler_;
  HANDLE thread_;

  Mutex mutex_;

  HANDLE read_event_, write_event_, wake_event_;

  bool exit_thread_;

  Packet *wqueue_, **wqueue_end_;

  TunWin32Adapter adapter_;

  TunsafeBackendWin32 *backend_;
};

class TunsafeBackendWin32 : public TunsafeBackend, public ProcessorDelegate {
  friend class ThreadedPacketQueue;
  friend class TunWin32Iocp;
  friend class TunWin32Overlapped;
public:
  TunsafeBackendWin32(Delegate *delegate);
  ~TunsafeBackendWin32();

  // -- from TunsafeBackend
  virtual bool Initialize() override;
  virtual void Teardown() override;
  virtual void Start(const char *config_file) override;
  virtual void Stop() override;
  virtual void RequestStats(bool enable) override;
  virtual void ResetStats() override;
  virtual InternetBlockState GetInternetBlockState(bool *is_activated) override;
  virtual void SetInternetBlockState(InternetBlockState s) override;
  virtual void SetServiceStartupFlags(uint32 flags) override;
  virtual LinearizedGraph *GetGraph(int type) override;
  virtual std::string GetConfigFileName() override;

  // -- from ProcessorDelegate
  virtual void OnConnected() override;
  virtual void OnConnectionRetry(uint32 attempts) override;

  void SetPublicKey(const uint8 key[32]);
  void TunAdapterFailed();
private:

  void StopInner(bool is_restart);
  static DWORD WINAPI WorkerThread(void *x);
  void PushStats();

  HANDLE worker_thread_;

  enum {
    MODE_NONE = 0,
    MODE_EXIT = 1,
    MODE_RESTART = 2,
    MODE_TUN_FAILED = 3,
  };

  bool want_periodic_stats_;
  unsigned int stop_mode_;
  
  Delegate *delegate_;
  char *config_file_;

  DnsBlocker dns_blocker_;
  DnsResolver dns_resolver_;

  WireguardProcessor *wg_processor_;

  uint32 last_tun_adapter_failed_;
  StatsCollector stats_collector_;

  Mutex stats_mutex_;
  WgProcessorStats stats_;
};

// This class ensures that all callbacks get rescheduled to another thread
class TunsafeBackendDelegateThreaded : public TunsafeBackend::Delegate {
public:
  TunsafeBackendDelegateThreaded(TunsafeBackend::Delegate *delegate, const std::function<void(void)> &callback);
  ~TunsafeBackendDelegateThreaded();

private:
  virtual void OnGetStats(const WgProcessorStats &stats);
  virtual void OnGraphAvailable();
  virtual void OnStateChanged();
  virtual void OnClearLog();
  virtual void OnLogLine(const char **s);
  virtual void OnStatusCode(TunsafeBackend::StatusCode status);
  virtual void DoWork();

  enum Which {
    Id_OnGetStats,
    Id_OnStateChanged,
    Id_OnClearLog,
    Id_OnLogLine,
    Id_OnUpdateUI,
    Id_OnStatusCode,
    Id_OnGraphAvailable,
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

