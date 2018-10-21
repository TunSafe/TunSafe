// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#pragma once

#define TUNSAFE_VERSION_STRING "TunSafe 1.5-rc1"
#define TUNSAFE_VERSION_STRING_LONG "TunSafe 1.5-rc1"

#define WITH_HANDSHAKE_EXT 0
#define WITH_SHORT_HEADERS 0
#define WITH_HEADER_OBFUSCATION 0
#define WITH_AVX512_OPTIMIZATIONS 0
#define WITH_BENCHMARK 0

// Use bytell hashmap instead. Only works in 64-bit builds
#define WITH_BYTELL_HASHMAP 0
