// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TINYVPN_TINYVPN_H_
#define TINYVPN_TINYVPN_H_

class WireguardProcessor;

bool ParseWireGuardConfigFile(WireguardProcessor *wg, const char *filename, bool *exit_flag);

#define kSizeOfAddress 64
const char *print_ip_prefix(char buf[kSizeOfAddress], int family, const void *ip, int prefixlen);



#endif  // TINYVPN_TINYVPN_H_
