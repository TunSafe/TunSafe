// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#include "service_win32_api.h"
#include <strsafe.h>
#include "util.h"
#include "network_win32_api.h"
#include "tunsafe_threading.h"
#include <algorithm>
#include <string>
#include <assert.h>

struct ServiceState {
  uint8 is_started : 1;
  uint8 internet_block_state_active : 1;
  uint8 internet_block_state;
  uint8 reserved[26+64];
  uint32 ipv4_ip;
  uint8 public_key[32];
};

STATIC_ASSERT(sizeof(ServiceState) == 128, ServiceState_wrong_size);

class PipeMessageHandler {
public:
  class Delegate {
  public:
    virtual bool HandleMessage(int type, uint8 *data, size_t size) = 0;
    virtual bool HandleNotify() = 0;
    virtual bool HandleNewConnection() = 0;
    virtual void HandleDisconnect() = 0;
  };

  PipeMessageHandler(const char *pipe_name, bool is_server_pipe, Delegate *delegate);
  ~PipeMessageHandler();

  bool StartThread();
  void StopThread();

  bool WritePacket(int type, const uint8 *data, size_t data_size);
  
  HANDLE notify_handle() { return wait_handles_[1]; }
  HANDLE pipe_handle() { return pipe_; }

  bool VerifyThread();

  void FlushWrites(int delay);
  bool is_connected() { return connection_established_; }
private:
  bool InitializeServerPipe();
  bool InitializeClientPipe();
  void ClosePipe();
  DWORD ThreadMain();
  void SendNextQueuedWrite();
  uint8 *ReadNamedPipeAsync(size_t *packet_size);
  bool ConnectNamedPipeAsync();
  bool WaitAndHandleWrites(int delay);
  static DWORD WINAPI StaticThreadMain(void *x);

  Delegate *delegate_;

  HANDLE pipe_;
  HANDLE thread_;
  HANDLE wait_handles_[3];
  OVERLAPPED write_overlapped_;
  bool write_overlapped_active_;
  bool exit_;
  bool is_server_pipe_;
  bool connection_established_;
  char *pipe_name_;

  struct OutgoingPacket {
    OutgoingPacket *next;
    uint32 size;
    uint8 data[0];
  };
  OutgoingPacket *packets_, **packets_end_;

  Mutex packets_mutex_;

  DWORD thread_id_;
};


class TunsafeServiceImpl : public TunsafeBackend::Delegate, public PipeMessageHandler::Delegate {
public:
  TunsafeServiceImpl();
  virtual ~TunsafeServiceImpl();

  // -- from TunsafeBackend::Delegate
  virtual void OnGetStats(const WgProcessorStats &stats);
  virtual void OnClearLog();
  virtual void OnLogLine(const char **s);
  virtual void OnStateChanged();
  virtual void OnStatusCode(TunsafeBackend::StatusCode status);
  virtual void OnGraphAvailable();

  // -- from PipeMessageHandler::Delegate
  virtual bool HandleMessage(int type, uint8 *data, size_t size);
  virtual bool HandleNotify();
  virtual bool HandleNewConnection();
  virtual void HandleDisconnect();

  // virtual methods
  virtual unsigned OnStart(int argc, wchar_t **argv);
  virtual void OnStop();
  virtual void OnShutdown();

  TunsafeBackend::Delegate *delegate() { return thread_delegate_; }

private:
  void SendQueuedLogLines();
  bool AuthenticateUser();

  bool did_send_getstate_;

  bool did_authenticate_user_;
  uint32 want_graph_type_;
  
  HKEY hkey_;

  TunsafeBackend *backend_;
  TunsafeBackend::Delegate *thread_delegate_;

  PipeMessageHandler message_handler_;

  uint32 historical_log_lines_pos_;
  uint32 historical_log_lines_count_;
  uint32 last_line_sent_;
  std::string current_filename_;

  enum {
    LOGLINE_COUNT = 256
  };
  char *historical_log_lines_[LOGLINE_COUNT];
};

class TunsafeServiceClient : public TunsafeBackend, public PipeMessageHandler::Delegate {
public:
  TunsafeServiceClient(TunsafeBackend::Delegate *delegate);
  virtual ~TunsafeServiceClient();
  virtual bool Initialize();
  virtual void Teardown();
  virtual void Start(const char *config_file);
  virtual void Stop();
  virtual void RequestStats(bool enable);
  virtual void ResetStats();
  virtual InternetBlockState GetInternetBlockState(bool *is_activated);
  virtual void SetInternetBlockState(InternetBlockState s);
  virtual std::string GetConfigFileName();
  virtual void SetServiceStartupFlags(uint32 flags);
  virtual LinearizedGraph *GetGraph(int type);

  // -- from PipeMessageHandler::Delegate
  virtual bool HandleMessage(int type, uint8 *data, size_t size);
  virtual bool HandleNotify();
  virtual bool HandleNewConnection();
  virtual void HandleDisconnect();

protected:
  TunsafeBackend::Delegate *delegate_;
  uint8 want_stats_;
  bool got_state_from_control_;
  ServiceState service_state_;
  std::string config_file_;
  PipeMessageHandler message_handler_;
  LinearizedGraph *cached_graph_;
  uint32 last_graph_type_;
  Mutex mutex_;
};
