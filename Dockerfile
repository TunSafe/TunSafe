FROM ubuntu:18.04

COPY . /tunsafe/

RUN apt-get update && \
    apt-get install -y clang-6.0 build-essential

RUN cd /tunsafe && \
    make && \
    make install



FROM ubuntu:18.04
COPY --from=0 /usr/bin/tunsafe /usr/bin/

RUN apt-get update && \
    apt-get install -y iproute2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/tunsafe"]
