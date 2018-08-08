UNAME := $(shell uname)

.PHONY: tunsafe

ifeq ($(UNAME), Linux)
tunsafe:
	sh ./build_linux.sh
endif

ifeq ($(UNAME), FreeBSD)
tunsafe:
	sh ./build_freebsd.sh
endif

ifeq ($(UNAME), Darwin)
tunsafe:
	sh ./build_osx.sh
endif

install:
	cp tunsafe /usr/bin


