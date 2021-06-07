FROM ubuntu:18.04 AS builder

# Copy the source
COPY . /tunsafe/

# Install some packages to build
RUN apt-get update && \
    apt-get install -y clang-6.0 build-essential

# Build the package
RUN cd /tunsafe && \
    make && \
    make install






FROM ubuntu:18.04

# Copy binary
COPY --from=builder /usr/bin/tunsafe /usr/bin/

# Binary needs 'ip' command
RUN apt-get update && \
    apt-get install -y iproute2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/tunsafe"]
