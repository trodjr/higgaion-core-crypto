# Stage 1: Build C100K Engine natively
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y build-essential libssl-dev gcc make
WORKDIR /opt/src
COPY . .
RUN gcc -Wall -Wextra -O3 -pthread -DUSE_LMDB -DHIGGAION_VERSION='"1.0.0-enterprise"' -Iinclude -c -o gateway/src/gateway.o gateway/src/gateway.c
RUN gcc -Wall -Wextra -O3 -pthread -o higgaion_gateway gateway/src/gateway.o -lssl -lcrypto -lpthread

# Stage 2: Hardened Runtime Layer
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/higgaion

# Inject the naked C executable independently
COPY --from=builder /opt/src/higgaion_gateway .
RUN chmod +x higgaion_gateway

# Map TLS Edge & Internal Telemetry channels
EXPOSE 8443 8081

# Expose C100K constraints bounds organically to OS
CMD ["./higgaion_gateway"]
