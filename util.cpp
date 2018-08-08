// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <string>

#if defined(OS_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "tunsafe_types.h"

static char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint8 *base64_encode(const uint8 *input, size_t length, size_t *out_length) {
  uint32 a;
  size_t size;
  uint8 *result, *r;
  const uint8 *end;

  size = length * 4 / 3 + 4 + 1;
  r = result = (byte*)malloc(size);

  end = input + length - 3;

  // Encode full blocks
  while (input <= end) {
    a = (input[0] << 16) + (input[1] << 8) + input[2];
    input += 3;

    r[0] = base64_alphabet[(a >> 18)/* & 0x3F*/];
    r[1] = base64_alphabet[(a >> 12) & 0x3F];
    r[2] = base64_alphabet[(a >> 6) & 0x3F];
    r[3] = base64_alphabet[(a) & 0x3F];
    r += 4;
  }

  if (input == end + 2) {
    a = input[0] << 4;
    r[0] = base64_alphabet[(a >> 6) /*& 0x3F*/];
    r[1] = base64_alphabet[(a) & 0x3F];
    r[2] = '=';
    r[3] = '=';
    r += 4;
  } else if (input == end + 1) {
    a = (input[0] << 10) + (input[1] << 2);
    r[0] = base64_alphabet[(a >> 12) /*& 0x3F*/];
    r[1] = base64_alphabet[(a >> 6) & 0x3F];
    r[2] = base64_alphabet[(a) & 0x3F];
    r[3] = '=';
    r += 4;
  }
  if (out_length)
    *out_length = r - result;
  *r = 0;
  return result;
}

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
  66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
  54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
  10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
  29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
  66,66,66,66,66,66
};

bool base64_decode(uint8 *in, size_t inLen, uint8 *out, size_t *outLen) {
  uint8 *end = in + inLen;
  uint8 iter = 0;
  uint32_t buf = 0;
  size_t len = 0;

  while (in < end) {
    unsigned char c = d[*in++];

    switch (c) {
    case WHITESPACE: continue;   /* skip whitespace */
    case INVALID:    return false;   /* invalid input, return error */
    case EQUALS:                 /* pad character, end of data */
      in = end;
      continue;
    default:
      buf = buf << 6 | c;
      iter++;
      if (iter == 4) {
        if ((len += 3) > *outLen) return 0; /* buffer overflow */
        *(out++) = (buf >> 16) & 255;
        *(out++) = (buf >> 8) & 255;
        *(out++) = buf & 255;
        buf = 0; iter = 0;

      }
    }
  }
  if (iter == 3) {
    if ((len += 2) > *outLen) return 0; /* buffer overflow */
    *(out++) = (buf >> 10) & 255;
    *(out++) = (buf >> 2) & 255;
  } else if (iter == 2) {
    if (++len > *outLen) return 0; /* buffer overflow */
    *(out++) = (buf >> 4) & 255;
  }
  *outLen = len;
  return true;
}



int RunCommand(const char *fmt, ...) {
  const char *fmt_org = fmt;
  va_list va;
  std::string tmp;
  char buf[32], c;
  char *args[33];
  char *envp[1] = {NULL};
  int nargs = 0;
  va_start(va, fmt);
  for (;;) {
    c = *fmt++;
    if (c == '%') {
      c = *fmt++;
      if (c == 0) goto ZERO;
      if (c == 's') {
        tmp += va_arg(va, char*);
      } else if (c == 'd') {
        snprintf(buf, 32, "%d", va_arg(va, int));
        tmp += buf;
      } else if (c == 'u') {
        snprintf(buf, 32, "%u", va_arg(va, int));
        tmp += buf;
      } else if (c == '%') {
        tmp += '%';
      } else if (c == 'A') {
        struct in_addr in;
        in.s_addr = htonl(va_arg(va, in_addr_t));
        tmp += inet_ntoa(in);
      }
    } else if (c == ' ' || c == 0) {
ZERO:
      args[nargs++] = _strdup(tmp.c_str());
      tmp.clear();
      if (nargs == 32 || c == 0) break;
    } else {
      tmp += c;
    }
  }
  args[nargs] = 0;

  fprintf(stderr, "Run:");
  for (int i = 0; args[i]; i++)
    fprintf(stderr, " %s", args[i]);
  fprintf(stderr, "\n");

  int ret = -1;


#if defined(OS_POSIX)
  pid_t pid = fork();
  if (pid == 0) {
    execve(args[0], args, envp);
    exit(127);
  }
  if (pid < 0) {
    RERROR("Fork failed");
  } else if (waitpid(pid, &ret, 0) != pid) {
    ret = -1;
  }
#endif

  if (ret != 0)
    RERROR("Command %s failed %d!", fmt_org, ret);

  return ret;
}

bool IsOnlyZeros(const uint8 *data, size_t data_size) {
  for (size_t i = 0; i != data_size; i++)
    if (data[i])
      return false;
  return true;
}


#ifdef _MSC_VER
void printhex(const char *name, const void *a, size_t l) {
  char buf[256];
  snprintf(buf, 256, "%s (%d):", name, (int)l); OutputDebugString(buf);
  for (size_t i = 0; i < l; i++) {
    if (i % 4 == 0) printf(" ");
    snprintf(buf, 256, "%.2X", *((uint8*)a + i)); OutputDebugString(buf);
  }
  OutputDebugString("\n");
}

#else
void printhex(const char *name, const void *a, size_t l) {
  printf("%s (%d):", name, (int)l);
  for (size_t i = 0; i < l; i++) {
    if (i % 4 == 0) printf(" ");
    printf("%.2X", *((uint8*)a + i));
  }
  printf("\n");
}
#endif

typedef void Logger(const char *msg);
Logger *g_logger;

#undef RERROR
#undef void 

void RERROR(const char *msg, ...);

void RERROR(const char *msg, ...) {
  va_list va;
  char buf[512];
  va_start(va, msg);
  vsnprintf(buf, sizeof(buf), msg, va);
  va_end(va);
  if (g_logger) {
    g_logger(buf);
  } else {
    fputs(buf, stderr);
    fputs("\n", stderr);
  }
}

void rinfo(const char *msg, ...) {
  printf("muu");
}

void rinfo2(const char *msg) {
  printf("muu2");
}

void RINFO(const char *msg, ...) {
  va_list va;
  char buf[512];
  va_start(va, msg);
  vsnprintf(buf, sizeof(buf), msg, va);
  va_end(va);
  if (g_logger) {
    g_logger(buf);
  } else {
    fputs(buf, stderr);
    fputs("\n", stderr);
  }
}
