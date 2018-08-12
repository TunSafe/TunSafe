// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once
#include "tunsafe_types.h"

uint8 *base64_encode(const uint8 *input, size_t length, size_t *out_length);
bool base64_decode(uint8 *in, size_t inLen, uint8 *out, size_t *outLen);
bool IsOnlyZeros(const uint8 *data, size_t data_size);

int RunCommand(const char *fmt, ...);
typedef void Logger(const char *msg);
extern Logger *g_logger;


void *memdup(const void *p, size_t size);
char *my_strndup(const char *p, size_t size);

size_t my_strlcpy(char *dst, size_t dstsize, const char *src);


template<typename T, typename U> static inline T postinc(T&x, U v) {
  T t = x;
  x += v;
  return t;
}
