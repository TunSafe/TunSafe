// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#include "stdafx.h"
#include "tunsafe_types.h"
#include "netapi.h"
#include "network_win32_api.h"

struct Packet;
class WireguardProcessor;


class ThreadedPacketQueue {
public:
  explicit ThreadedPacketQueue(WireguardProcessor *wg, NetworkStats *stats);
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
  CRITICAL_SECTION mutex_;
  HANDLE event_;

  HANDLE timer_handle_;
  HANDLE handle_;
  WireguardProcessor *wg_;
  bool exit_flag_;
  bool timer_interrupt_;
  NetworkStats *stats_;
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

  CRITICAL_SECTION mutex_;

  ThreadedPacketQueue *packet_handler_;
  SOCKET socket_;
  SOCKET socket_ipv6_;
  HANDLE completion_port_handle_;
  HANDLE thread_;

  bool exit_thread_;
};

class TunWin32Adapter {
public:
  TunWin32Adapter();
  ~TunWin32Adapter();

  bool OpenAdapter(bool *exit_thread, DWORD open_flags);
  bool InitAdapter(const TunInterface::TunConfig &&config, TunInterface::TunConfigOut *out);
  void CloseAdapter();

  HANDLE handle() { return handle_; }

private:
  bool RunPrePostCommand(const std::vector<std::string> &vec);

  HANDLE handle_;
  HANDLE current_dns_block_;

  std::vector<MIB_IPFORWARD_ROW2> routes_to_undo_;
  uint8 mac_adress_[6];
  int mtu_;
  char guid_[64];

  std::vector<std::string> pre_down_, post_down_;
};

// Implementation of TUN interface handling using IO Completion Ports
class TunWin32Iocp : public TunInterface {
public:
  explicit TunWin32Iocp();
  ~TunWin32Iocp();

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
  HANDLE completion_port_handle_;
  HANDLE thread_;

  CRITICAL_SECTION mutex_;

  bool exit_thread_;

  // All packets queued for writing
  Packet *wqueue_, **wqueue_end_;

  TunWin32Adapter adapter_;
};

// Implementation of TUN interface handling using Overlapped IO
class TunWin32Overlapped : public TunInterface {
public:
  explicit TunWin32Overlapped();
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

  CRITICAL_SECTION mutex_;

  HANDLE read_event_, write_event_, wake_event_;

  bool exit_thread_;

  Packet *wqueue_, **wqueue_end_;

  TunWin32Adapter adapter_;
};
