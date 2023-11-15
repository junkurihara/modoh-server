FROM ubuntu:22.04 AS base

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

########################################
FROM base as builder

ENV CFLAGS=-Ofast
ENV BUILD_DEPS curl make ca-certificates build-essential pkg-config libssl-dev

WORKDIR /tmp

COPY . /tmp/

ENV RUSTFLAGS "-C link-arg=-s"

RUN update-ca-certificates 2> /dev/null || true

RUN apt-get update && apt-get install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building DoH Auth Relay from source" && \
    cargo build --release --no-default-features --package doh-auth-relay && \
    strip --strip-all /tmp/target/release/doh-auth-relay

########################################
FROM base AS runner
LABEL maintainer="Jun Kurihara"

ENV RUNTIME_DEPS logrotate ca-certificates gosu

RUN apt-get update && \
    apt-get install -qy --no-install-recommends $RUNTIME_DEPS && \
    apt-get -qy clean && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log &&\
    find / -type d -path /proc -prune -o -type f -perm /u+s -ignore_readdir_race -exec chmod u-s {} \; && \
    find / -type d -path /proc -prune -o -type f -perm /g+s -ignore_readdir_race -exec chmod g-s {} \; && \
    mkdir -p /relay/bin &&\
    mkdir -p /relay/log

COPY --from=builder /tmp/target/release/doh-auth-relay /relay/bin/doh-auth-relay
COPY ./docker/run.sh /relay
COPY ./docker/entrypoint.sh /relay

RUN chmod +x /relay/run.sh && \
    chmod +x /relay/entrypoint.sh

EXPOSE 53/udp 53/tcp

CMD ["/usr/bin/bash", "/relay/entrypoint.sh"]

ENTRYPOINT ["/usr/bin/bash", "/relay/entrypoint.sh"]
