FROM ubuntu:24.04 AS base

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

########################################
FROM base AS builder

ARG CFLAGS=-Ofast
ARG BUILD_DEPS="curl make ca-certificates build-essential pkg-config libssl-dev"

WORKDIR /tmp

COPY . /tmp/

ARG RUSTFLAGS="-C link-arg=-s"

RUN update-ca-certificates 2> /dev/null || true

# TODO: do not enable otel-evil-trace for production
RUN apt-get update && apt-get install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building Mutualized Oblivious DNS relay and target from source" && \
    cargo build --release --no-default-features --features=otel-full,otel-evil-trace,qrlog --package modoh-server && \
    strip --strip-all /tmp/target/release/modoh-server

########################################
FROM base AS runner
LABEL maintainer="Jun Kurihara"

ARG RUNTIME_DEPS="logrotate ca-certificates gosu"

RUN apt-get update && \
    apt-get install -qy --no-install-recommends $RUNTIME_DEPS && \
    apt-get -qy clean && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log &&\
    find / -type d -path /proc -prune -o -type f -perm /u+s -ignore_readdir_race -exec chmod u-s {} \; && \
    find / -type d -path /proc -prune -o -type f -perm /g+s -ignore_readdir_race -exec chmod g-s {} \; && \
    mkdir -p /modoh/bin &&\
    mkdir -p /modoh/log

COPY --from=builder /tmp/target/release/modoh-server /modoh/bin/modoh-server
COPY ./docker/run.sh /modoh
COPY ./docker/entrypoint.sh /modoh

RUN chmod +x /modoh/run.sh && \
    chmod +x /modoh/entrypoint.sh

EXPOSE 8080

CMD ["/usr/bin/bash", "/modoh/entrypoint.sh"]

ENTRYPOINT ["/usr/bin/bash", "/modoh/entrypoint.sh"]
