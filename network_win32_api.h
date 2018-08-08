// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#include "stdafx.h"
#include "tunsafe_types.h"
#include "wireguard.h"

struct NetworkStats {
  bool reset_stats;
  CRITICAL_SECTION  mutex;
  ProcessorStats packet_stats;
};

class TunsafeBackendWin32 {
public:
  TunsafeBackendWin32();
  ~TunsafeBackendWin32();

  void Start(ProcessorDelegate *procdel, const char *config_file);
  void Stop();

  ProcessorStats GetStats();
  void ResetStats() { stats_.reset_stats = true; }

  bool is_started() const { return worker_thread_ != NULL; }

private:
  static DWORD WINAPI WorkerThread(void *x);

  NetworkStats stats_;
  HANDLE worker_thread_;
  bool exit_flag_;

  ProcessorDelegate *procdel_;
  char *config_file_;
};



InternetBlockState GetInternetBlockState(bool *is_activated);

// Returns if reconnect is needed
void SetInternetBlockState(InternetBlockState s);



extern int tpq_last_qsize;
extern int g_tun_reads, g_tun_writes;
