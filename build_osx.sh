set -e


clang++ -c -mavx512f -mavx512vl crypto/poly1305_x64_gas_macosx.s crypto/chacha20_x64_gas_macosx.s 

clang++ -g -O3 -I . -std=c++11 -DNDEBUG=1 -fno-exceptions -fno-rtti -ffunction-sections -o tunsafe \
wireguard_config.cpp ip_to_peer_map.cpp tunsafe_threading.cpp wireguard.cpp wireguard_proto.cpp util.cpp network_bsd.cpp network_bsd_common.cpp benchmark.cpp tunsafe_cpu.cpp \
crypto/blake2s.cpp crypto/blake2s_sse.cpp crypto/chacha20poly1305.cpp crypto/curve25519-donna.cpp \
crypto/siphash.cpp crypto/aesgcm/aesgcm.cpp ipzip2/ipzip2.cpp \
crypto/aesgcm/aesni_gcm_x64_gas_macosx.s crypto/aesgcm/aesni_x64_gas_macosx.s crypto/aesgcm/ghash_x64_gas_macosx.s \
chacha20_x64_gas_macosx.o poly1305_x64_gas_macosx.o

cp tunsafe tunsafe.unstripped
strip tunsafe
rm -f tunsafe_osx.zip
zip tunsafe_osx.zip tunsafe readme_osx.txt

