#!/bin/sh
clang++-6.0 -c -march=skylake-avx512 crypto/poly1305_x64_gas.s crypto/chacha20_x64_gas.s 
clang++-6.0 -I . -O3 -mssse3 -pthread -lrt -o tunsafe util.cpp wireguard_config.cpp wireguard.cpp \
wireguard_proto.cpp network_bsd_mt.cpp tunsafe_cpu.cpp benchmark.cpp crypto/blake2s.cpp crypto/blake2s_sse.cpp crypto/chacha20poly1305.cpp \
crypto/curve25519-donna.cpp crypto/siphash.cpp chacha20_x64_gas.o crypto/aesgcm/aesni_gcm_x64_gas.s \
crypto/aesgcm/aesni_x64_gas.s crypto/aesgcm/aesgcm.cpp poly1305_x64_gas.o ipzip2/ipzip2.cpp \
crypto/aesgcm/ghash_x64_gas.s


