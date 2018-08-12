#!/bin/sh

set -e

cpp -D__ARM_ARCH__=7 crypto/chacha20/chacha20-arm.s > crypto/chacha20/chacha20-arm.preprocessed.s
cpp -D__ARM_ARCH__=7 crypto/poly1305/poly1305-arm.s > crypto/poly1305/poly1305-arm.preprocessed.s

g++-6 -mfpu=neon  -I . -g -O2 -DNDEBUG -fno-omit-frame-pointer -march=armv7-a -mthumb -std=c++11 -pthread -lrt -o tunsafe util.cpp wireguard_config.cpp wireguard.cpp ip_to_peer_map.cpp tunsafe_threading.cpp \
wireguard_proto.cpp network_bsd.cpp network_bsd_common.cpp tunsafe_cpu.cpp benchmark.cpp crypto/blake2s.cpp crypto/chacha20poly1305.cpp \
crypto/curve25519-donna.cpp crypto/siphash.cpp crypto/aesgcm/aesgcm.cpp ipzip2/ipzip2.cpp \
crypto/chacha20/chacha20-arm.preprocessed.s crypto/poly1305/poly1305-arm.preprocessed.s
