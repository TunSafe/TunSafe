// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "tunsafe_threading.h"
#include <stdlib.h>

MultithreadedDelayedDelete::MultithreadedDelayedDelete() {
  table_ = NULL;
  num_threads_ = 0;
}

MultithreadedDelayedDelete::~MultithreadedDelayedDelete() {
  free(table_);
}

void MultithreadedDelayedDelete::Initialize(uint32 num_threads) {
  num_threads_ = num_threads;
  table_ = (CheckpointData*)calloc(sizeof(CheckpointData), num_threads);
}

void MultithreadedDelayedDelete::Add(DoDeleteFunc *func, void *param) {
  if (num_threads_ == 0) {
    func(param);
    return;
  }
  lock_.Acquire();
  Entry e = {func, param};
  curr_.push_back(e);
  lock_.Release();
}

void MultithreadedDelayedDelete::Checkpoint(uint32 thread_id) {
  table_[thread_id].value.store(1);
}

void MultithreadedDelayedDelete::MainCheckpoint() {
  // Wait for all threads to signal that they reached the checkpoint
  for (size_t i = 0; i < num_threads_; i++) {
    if (table_[i].value.load() == 0)
      return;
  }

  // All threads reached the checkpoint, clear the values
  for (size_t i = 0; i < num_threads_; i++)
    table_[i].value.store(0);

  // Swap curr and next, and delete all nexts.
  lock_.Acquire();
  std::swap(curr_, next_);
  std::swap(curr_, to_delete_);
  lock_.Release();

  for (auto it = to_delete_.begin(); it != to_delete_.end(); ++it) {
    it->func(it->param);
  }
  to_delete_.clear();
}
