# TunSafe
Source code of the TunSafe client.

This open sourced TunSafe code is AGPL-1.0 licensed. Do note that the repository contains BSD and OpenSSL licensed files, so if you want to release a version based off of this repository you need to take that into account.

To build on Windows, open TunSafe.sln and build, or run build.py.

To build on Linux, run build_linux.sh

To build on FreeBSD, run build_freebsd.sh

## Docker
To use in docker, Just create you configuration file (for example: my-wg1.conf), then
```sh
docker run \
    -it \
    --rm \
    -v `pwd`/my-wg1.conf:/tmp/my-wg1.conf \
    --device /dev/net/tun \
    --cap-add NET_ADMIN \
    --network host \
    moghaddas/tunsafe start /tmp/my-wg1.conf
```

To Build:
```sh
git clone https://github.com/sinamoghaddas/TunSafe
cd TunSafe

docker build -t tunsafe .
```
