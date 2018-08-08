g++7 -I . -O2 -static -mssse3 -o tunsafe benchmark.cpp tunsafe_cpu.cpp wireguard_config.cpp \
wireguard.cpp wireguard_proto.cpp util.cpp network_bsd.cpp network_bsd_common.cpp \
crypto/blake2s.cpp crypto/blake2s_sse.cpp crypto/chacha20poly1305.cpp crypto/curve25519-donna.cpp \
crypto/siphash.cpp crypto/chacha20_x64_gas.s crypto/poly1305_x64_gas.s ipzip2/ipzip2.cpp -lrt -pthread

