// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

HANDLE BlockDnsExceptOnAdapter(const NET_LUID &luid, bool also_ipv6 );
void RestoreDnsExceptOnAdapter(HANDLE h);

bool AddPersistentInternetBlocking(const NET_LUID *default_interface, const NET_LUID &luid_to_allow, bool also_ipv6);



enum {
  IBS_UNKOWN,
  IBS_INACTIVE,
  IBS_ACTIVE,
  IBS_PENDING,
};
void SetInternetFwBlockingState(bool want);
uint8 GetInternetFwBlockingState();

