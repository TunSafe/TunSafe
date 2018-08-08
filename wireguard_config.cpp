// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "wireguard_config.h"
#include "netapi.h"
#include "tunsafe_endian.h"
#include "wireguard.h"
#include "util.h"
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <vector>

#if defined(OS_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netdb.h>
#endif

const char *print_ip_prefix(char buf[kSizeOfAddress], int family, const void *ip, int prefixlen) {
  if (!inet_ntop(family, ip, buf, kSizeOfAddress - 8)) {
    memcpy(buf, "unknown", 8);
  }
  if (prefixlen >= 0)
    snprintf(buf + strlen(buf), 8, "/%d", prefixlen);
  return buf;
}

struct Addr {
  byte addr[4];
  uint8 cidr;
};

static bool ParseCidrAddr(char *s, WgCidrAddr *out) {
  char *slash = strchr(s, '/');
  if (!slash)
    return false;

  *slash = 0;
  int e = atoi(slash + 1);
  if (e < 0) return false;

  if (inet_pton(AF_INET, s, out->addr) == 1) {
    if (e > 32) return false;
    out->cidr = e;
    out->size = 32;
    return true;
  }
  if (inet_pton(AF_INET6, s, out->addr) == 1) {
    if (e > 128) return false;
    out->cidr = e;
    out->size = 128;
    return true;
  }
  return false;
}

struct hostent *gethostbyname_retry_on_failure(const char * name, bool *exit_flag) {
  int attempt = 0;
  static const uint8 retry_delays[] = {1, 2, 3, 5, 10, 20, 40, 60};

  for (;;) {
    hostent *he = gethostbyname(name);
    if (he || exit_flag == NULL || *exit_flag)
      return he;

    RINFO("Unable to resolve %s. Trying again in %d second(s)", name, retry_delays[attempt]);
    OsInterruptibleSleep(retry_delays[attempt] * 1000);
    if (*exit_flag)
      return NULL;

    if (attempt != ARRAY_SIZE(retry_delays) - 1)
      attempt++;
  }
}


static bool ParseSockaddrInWithPort(char *s, IpAddr *sin, bool *exit_flag) {
  memset(sin, 0, sizeof(IpAddr));
  if (*s == '[') {
    char *end = strchr(s, ']');
    if (end == NULL)
      return false;
    *end = 0;
    if (inet_pton(AF_INET6, s + 1, &sin->sin6.sin6_addr) != 1)
      return false;
    char *x = strchr(end + 1, ':');
    if (!x)
      return false;
    sin->sin.sin_family = AF_INET6;
    sin->sin.sin_port = htons(atoi(x + 1));
    return true;
  }
  char *x = strchr(s, ':');
  if (!x) return false;
  *x = 0;
  hostent *he = gethostbyname_retry_on_failure(s, exit_flag);
  if (!he) {
    RERROR("Unable to resolve %s", s);
    return false;
  }
  sin->sin.sin_family = AF_INET;
  sin->sin.sin_port = htons(atoi(x + 1));
  memcpy(&sin->sin.sin_addr, he->h_addr_list[0], 4);
  return true;
}

static bool ParseSockaddrInWithoutPort(char *s, IpAddr *sin, bool *exit_flag) {
  memset(sin, 0, sizeof(IpAddr));
  if (inet_pton(AF_INET6, s, &sin->sin6.sin6_addr) == 1) {
    sin->sin.sin_family = AF_INET6;
    return true;
  }
  hostent *he = gethostbyname_retry_on_failure(s, exit_flag);
  if (!he) {
    RERROR("Unable to resolve %s", s);
    return false;
  }
  sin->sin.sin_family = AF_INET;
  memcpy(&sin->sin.sin_addr, he->h_addr_list[0], 4);
  return true;
}

static bool ParseBase64Key(const char *s, uint8 key[32]) {
  size_t size = 32;
  return base64_decode((uint8*)s, strlen(s), key, &size) && size == 32;
}

class WgFileParser {
public:
  WgFileParser(WireguardProcessor *wg, bool *exit_flag) : wg_(wg), exit_flag_(exit_flag) {}
  bool ParseFlag(const char *group, const char *key, char *value);
  WireguardProcessor *wg_;

  void FinishGroup();
  struct Peer {
    uint8 pub[32];
    uint8 psk[32];
  };
  Peer pi_;
  WgPeer *peer_ = NULL;
  bool *exit_flag_;
  bool had_interface_ = false;
};

bool is_space(uint8_t c) {
  return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}


void SplitString(char *s, int separator, std::vector<char*> *components) {
  for (;;) {
    while (is_space(*s)) s++;
    char *d = strchr(s, separator);
    if (d == NULL) {
      if (*s)
        components->push_back(s);
      return;
    }
    *d = 0;
    char *e = d;
    while (e > s && is_space(e[-1]))
      *--e = 0;
    components->push_back(s);
    s = d + 1;
  }
}

static bool ParseBoolean(const char *str, bool *value) {
  if (_stricmp(str, "true") == 0 ||
      _stricmp(str, "yes") == 0 ||
      _stricmp(str, "1") == 0 ||
      _stricmp(str, "on") == 0) {
    *value = true;
    return true;
  }
  if (_stricmp(str, "false") == 0 ||
      _stricmp(str, "no") == 0 ||
      _stricmp(str, "0") == 0 ||
      _stricmp(str, "off") == 0) {
    *value = false;
    return true;
  }
  return false;
}

static int ParseFeature(const char *str) {
  size_t len = strlen(str);
  int what = WG_BOOLEAN_FEATURE_WANTS;
  if (len > 0) {
    if (str[len - 1] == '?')
      what = WG_BOOLEAN_FEATURE_SUPPORTS, len--;
    else if (str[len - 1] == '!')
      what = WG_BOOLEAN_FEATURE_ENFORCES, len--;
  }
  if (len == 5 && memcmp(str, "mac64", 5) == 0)
    return what + WG_FEATURE_ID_SHORT_MAC * 16;
  if (len == 12 && memcmp(str, "short_header", 12) == 0)
    return what + WG_FEATURE_ID_SHORT_HEADER * 16;
  if (len == 5 && memcmp(str, "ipzip", 5) == 0)
    return what + WG_FEATURE_ID_IPZIP * 16;
  if (len == 10 && memcmp(str, "skip_keyid", 10) == 0)
    return what + WG_FEATURE_ID_SKIP_KEYID_IN * 16 + 1 * 4;
  if (len == 13 && memcmp(str, "skip_keyid_in", 13) == 0)
    return what + WG_FEATURE_ID_SKIP_KEYID_IN * 16;
  if (len == 14 && memcmp(str, "skip_keyid_out", 14) == 0)
    return what + WG_FEATURE_ID_SKIP_KEYID_OUT * 16;
  return -1;
}

static int ParseCipherSuite(const char *cipher) {
  if (!strcmp(cipher, "chacha20-poly1305"))
    return EXT_CIPHER_SUITE_CHACHA20POLY1305;
  if (!strcmp(cipher, "aes128-gcm"))
    return EXT_CIPHER_SUITE_AES128_GCM;
  if (!strcmp(cipher, "aes256-gcm"))
    return EXT_CIPHER_SUITE_AES256_GCM;
  if (!strcmp(cipher, "none"))
    return EXT_CIPHER_SUITE_NONE_POLY1305;
  return -1;
}

void WgFileParser::FinishGroup() {
  if (peer_) {
    peer_->Initialize(pi_.pub, pi_.psk);
    peer_ = NULL;
  }
}

bool WgFileParser::ParseFlag(const char *group, const char *key, char *value) {
  uint8 binkey[32];
  WgCidrAddr addr;
  IpAddr sin;
  std::vector<char*> ss;
  bool ciphermode = false;

  if (strcmp(group, "[Interface]") == 0) {
    if (key == NULL) return true;
    if (strcmp(key, "PrivateKey") == 0) {
      if (!ParseBase64Key(value, binkey))
        return false;
      had_interface_ = true;
      wg_->dev().Initialize(binkey);
    } else if (strcmp(key, "ListenPort") == 0) {
      wg_->SetListenPort(atoi(value));
    } else if (strcmp(key, "Address") == 0) {
      SplitString(value, ',', &ss);
      for (size_t i = 0; i < ss.size(); i++) {
        if (!ParseCidrAddr(ss[i], &addr))
          return false;
        if (!wg_->SetTunAddress(addr)) {
          RERROR("Multiple Address not allowed");
          return false;
        }
      }
    } else if (strcmp(key, "MTU") == 0) {
      wg_->SetMtu(atoi(value));
    } else if (strcmp(key, "Table") == 0) {
      bool mode;
      if (!strcmp(value, "off")) {
        mode = false;
      } else if (!strcmp(value, "auto")) {
        mode = true;
      } else {
        goto err;
      }
      wg_->SetAddRoutesMode(mode);
    } else if (strcmp(key, "DNS") == 0) {
      SplitString(value, ',', &ss);
      for (size_t i = 0; i < ss.size(); i++) {
        if (!ParseSockaddrInWithoutPort(ss[i], &sin, exit_flag_))
          return false;
        if (!wg_->AddDnsServer(sin)) {
          RERROR("Multiple DNS not allowed.");
          return false;
        }
      }
    } else if (strcmp(key, "BlockDNS") == 0) {
      bool v;
      if (!ParseBoolean(value, &v))
        goto err;
      wg_->SetDnsBlocking(v);
    } else if (strcmp(key, "BlockInternet") == 0) {
      uint8 v = kBlockInternet_Default;
      
      SplitString(value, ',', &ss);
      for (size_t i = 0; i < ss.size(); i++) {
        if (strcmp(ss[i], "route") == 0) {
          if (v & 128) v = 0;
          v |= kBlockInternet_Route;
        } else if (strcmp(ss[i], "firewall") == 0) {
          if (v & 128) v = 0;
          v |= kBlockInternet_Firewall;
        } else if (strcmp(ss[i], "off") == 0)
          v = 0;
        else if (strcmp(ss[i], "on") == 0)
          v = kBlockInternet_DefaultOn;
        else if (strcmp(ss[i], "default") == 0)
          v = kBlockInternet_Default;
        else
          RERROR("Unknown mode in BlockInternet: %s", ss[i]);
      }
      
      wg_->SetInternetBlocking((InternetBlockState)v);
    } else if (strcmp(key, "HeaderObfuscation") == 0) {
      wg_->SetHeaderObfuscation(value);
    } else if (strcmp(key, "PostUp") == 0) {
      wg_->prepost().post_up.emplace_back(value);
    } else if (strcmp(key, "PostDown") == 0) {
      wg_->prepost().post_down.emplace_back(value);
    } else if (strcmp(key, "PreUp") == 0) {
      wg_->prepost().pre_up.emplace_back(value);
    } else if (strcmp(key, "PreDown") == 0) {
      wg_->prepost().pre_down.emplace_back(value);
    } else {
      goto err;
    }
  } else if (strcmp(group, "[Peer]") == 0) {
    if (key == NULL) { 
      if (!had_interface_) {
        RERROR("Missing [Interface].PrivateKey.");
        return false;
      }
      FinishGroup();
      peer_ = wg_->dev().AddPeer();
      memset(&pi_, 0, sizeof(pi_));
      return true;
    }
    if (strcmp(key, "PublicKey") == 0) {
      if (!ParseBase64Key(value, pi_.pub))
        return false;
    } else if (strcmp(key, "PresharedKey") == 0) {
      if (!ParseBase64Key(value, pi_.psk))
        return false;
    } else if (strcmp(key, "AllowedIPs") == 0) {
      SplitString(value, ',', &ss);
      for (size_t i = 0; i < ss.size(); i++) {
        if (!ParseCidrAddr(ss[i], &addr))
          return false;
        if (!peer_->AddIp(addr))
          return false;
      }
    } else if (strcmp(key, "Endpoint") == 0) {
      if (!ParseSockaddrInWithPort(value, &sin, exit_flag_))
        return false;
      peer_->SetEndpoint(sin);
    } else if (strcmp(key, "PersistentKeepalive") == 0) {
      peer_->SetPersistentKeepalive(atoi(value));
    } else if (strcmp(key, "AllowMulticast") == 0) {
      bool b;
      if (!ParseBoolean(value, &b))
        return false;
      peer_->SetAllowMulticast(b);
    } else if (strcmp(key, "Features") == 0) {
      SplitString(value, ',', &ss);
      for (size_t i = 0; i < ss.size(); i++) {
        int v = ParseFeature(ss[i]);
        if (v < 0)
          return false;
        for (;; v += 12) {
          peer_->SetFeature(v >> 4, v & 3);
          if (!(v & 12))
            break;
        }
      }
    } else if (strcmp(key, "Ciphers") == 0 || (ciphermode = true, strcmp(key, "Ciphers!") == 0)) {
      SplitString(value, ',', &ss);
      peer_->SetCipherPrio(ciphermode);
      for (size_t i = 0; i < ss.size(); i++) {
        int v = ParseCipherSuite(ss[i]);
        if (v < 0 || !peer_->AddCipher(v))
          return false;
      }
    } else {
      goto err;
    }
  } else {
err:
    return false;
  }
  return true;
}

bool ParseWireGuardConfigFile(WireguardProcessor *wg, const char *filename, bool *exit_flag) {
  char buf[1024];
  char group[32] = {0};

  WgFileParser file_parser(wg, exit_flag);

  RINFO("Loading file: %s", filename);

  FILE *f = fopen(filename, "r");
  if (!f) {
    RERROR("Unable to open: %s", filename);
    return false;
  }

  while (fgets(buf, sizeof(buf), f)) {
    size_t l = strlen(buf);
    while (l && is_space(buf[l - 1]))
      buf[--l] = 0;
    if (buf[0] == '#' || buf[0] == '\0')
      continue;

    if (buf[0] == '[') {
      size_t len = strlen(buf);
      if (len < sizeof(group)) {
        memcpy(group, buf, len + 1);
        if (!file_parser.ParseFlag(group, NULL, NULL)) {
          RERROR("Error parsing %s", group);
          fclose(f);
          return false;
        }
      }
      continue;
    }
    char *sep = strchr(buf, '=');
    if (!sep) {
      RERROR("Missing = on line: %s", buf);
      continue;
    }
    char *sepe = sep;
    while (sepe > buf && is_space(sepe[-1]))
      sepe--;
    *sepe = 0;

    // trim space after =
    sep++;
    while (is_space(*sep))
      sep++;

    if (!file_parser.ParseFlag(group, buf, sep)) {
      RERROR("Error parsing %s.%s = %s", group, buf, sep);
      fclose(f);
      return false;
    }
  }
  file_parser.FinishGroup();
  fclose(f);
  return true;
}
