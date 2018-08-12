// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#ifndef TINYVPN_ENDIAN_H_
#define TINYVPN_ENDIAN_H_

#include "build_config.h"
#include "tunsafe_types.h"
#if defined(OS_WIN) && defined(COMPILER_MSVC)
#include <intrin.h>
#endif
#include <stdint.h>

#define ByteSwap32Fallback(x) (                             \
    (((uint32)(x) & (uint32)0x000000fful) << 24) |          \
    (((uint32)(x) & (uint32)0x0000ff00ul) <<  8) |          \
    (((uint32)(x) & (uint32)0x00ff0000ul) >>  8) |          \
    (((uint32)(x) & (uint32)0xff000000ul) >> 24))

#define ByteSwap16Fallback(x) ((uint16)(                    \
    (((uint16)(x) & (uint16)0x00ffu) << 8) |                \
    (((uint16)(x) & (uint16)0xff00u) >> 8)))

#define ByteSwap64Fallback(x) ((uint64)ByteSwap32Fallback(x)<<32 | ByteSwap32Fallback(x>>32))

#define ReadBE32AlignedFallback(pt) (((uint32)((pt)[0] & 0xFF) << 24) ^ \
                                    ((uint32)((pt)[1] & 0xFF) << 16) ^    \
                                    ((uint32)((pt)[2] & 0xFF) <<  8) ^    \
                                    ((uint32)((pt)[3] & 0xFF)))
#define WriteBE32AlignedFallback(ct, st) {                       \
    (ct)[0] = (char)((st) >> 24);                                \
    (ct)[1] = (char)((st) >> 16);                                \
    (ct)[2] = (char)((st) >>  8);                                \
    (ct)[3] = (char)(st); }




#if defined(OS_WIN) && defined(COMPILER_MSVC)
#define ByteSwap16(x) _byteswap_ushort((uint16)x)
#define ByteSwap32(x) _byteswap_ulong((uint32)x)
#define ByteSwap64(x) _byteswap_uint64((uint64)x)
#elif defined(COMPILER_GCC)
#define ByteSwap16(x) __builtin_bswap16((uint16)x)
#define ByteSwap32(x) __builtin_bswap32((uint32)x)
#define ByteSwap64(x) __builtin_bswap64((uint64)x)
#else
#define ByteSwap16 ByteSwap16Fallback
#define ByteSwap32 ByteSwap32Fallback
#define ByteSwap64 ByteSwap64Fallback
#endif

#if defined(ARCH_CPU_LITTLE_ENDIAN)
#define ToBE64(x) ByteSwap64(x)
#define ToBE32(x) ByteSwap32(x)
#define ToBE16(x) ByteSwap16(x)
#define ToLE64(x) (x)
#define ToLE32(x) (x)
#define ToLE16(x) (x)
#else
#define ToBE64(x) (x)
#define ToBE32(x) (x)
#define ToBE16(x) (x)
#define ToLE64(x) ByteSwap64(x)
#define ToLE32(x) ByteSwap32(x)
#define ToLE16(x) ByteSwap16(x)
#endif

#define ReadBE16Aligned(pt) ToBE16(*(uint16*)(pt))
#define WriteBE16Aligned(ct, st) (*(uint16*)(ct) = ToBE16(st))
#define ReadBE32Aligned(pt) ToBE32(*(uint32*)(pt))
#define WriteBE32Aligned(ct, st) (*(uint32*)(ct) = ToBE32(st))

// todo: these need to support unaligned pointers
#define ReadBE16(pt) ToBE16(*(uint16*)(pt))
#define WriteBE16(ct, st) (*(uint16*)(ct) = ToBE16(st))
#define ReadBE32(pt) ToBE32(*(uint32*)(pt))
#define WriteBE32(ct, st) (*(uint32*)(ct) = ToBE32(st))
#define ReadBE64(pt) ToBE64(*(uint64*)(pt))
#define WriteBE64(ct, st) (*(uint64*)(ct) = ToBE64(st))

#define ReadLE16(pt) ToLE16(*(uint16*)(pt))
#define WriteLE16(ct, st) (*(uint16*)(ct) = ToLE16(st))
#define ReadLE32(pt) ToLE32(*(uint32*)(pt))
#define WriteLE32(ct, st) (*(uint32*)(ct) = ToLE32(st))
#define ReadLE64(pt) ToLE64(*(uint64*)(pt))
#define WriteLE64(ct, st) (*(uint64*)(ct) = ToLE64(st))

#define Read16(pt) (*(uint16*)(pt))
#define Write16(ct, st) (*(uint16*)(ct) = (st))
#define Read32(pt) (*(uint32*)(pt))
#define Write32(ct, st) (*(uint32*)(ct) = (st))
#define Read64(pt) (*(uint64*)(pt))
#define Write64(ct, st) (*(uint64*)(ct) = (st))


#endif  // TINYVPN_ENDIAN_H_
