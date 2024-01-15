# modoh-server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/modoh-server/actions/workflows/test.yml/badge.svg)
![Docker](https://github.com/junkurihara/modoh-server/actions/workflows/release_docker.yml/badge.svg)
![ShiftLeft Scan](https://github.com/junkurihara/modoh-server/actions/workflows/shiftleft-analysis.yml/badge.svg)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jqtype/modoh-server)](https://hub.docker.com/r/jqtype/modoh-server)




Relay and target implementation for Oblivious DoH (ODoH) and ODoH-based Mutualized Oblivious DNS (ODoH-based &mu;ODNS; &mu;ODoH) supporting authenticated connection, written in Rust. Standard DoH target server is also supported.

> **NOTE: This is a re-implementation of [https://github.com/junkurihara/doh-server](https://github.com/junkurihara/doh-server) for ease of maintenance and feature updates for &mu;ODNS.**

> **In &mu;ODoH, the target function is fully compatible with that of ODoH. For the detailed information on &mu;ODNS, please also refer to [https://junkurihara.github.io/dns/](https://junkurihara.github.io/dns/).**

## Introduction

![&mu;ODoH Network Structure](./assets/modoh-structure.jpg)

## Installing/Building an Executable Binary

You can build an executable binary yourself by checking out this Git repository.

```bash:
# Cloning the git repository
% git clone https://github.com/junkurihara/modoh-server
% cd modoh-server

# Build (default: opentelemetry is enabled with `otel-evil-trace`)
% cargo build --release

# If you don't need opentelemetry for server observability:
% cargo build --release --no-default-features
```

Then you have an executive binary `modoh-server/target/release/modoh-server`.

Note that if `otel-evil-trace` feature is enabled, you can track requests traveled among your modoh-server instances by propagating the trace id appended to the HTTP request header.

## Usage

`modoh-server` always refers to a configuration file in TOML format, e.g., `config.toml`. You can find an example of the configuration file, `modoh-server.toml`, in this repository.

You can run `modoh-server` with a configuration file like

```bash:
% ./target/release/modoh-server --config config.toml
```

If you specify `-w` option along with the config file path, `modoh-server` tracks the change of `config.toml` in the real-time manner and apply the change immediately without restarting the process.

The full help messages are given follows.

```bash:
% ./target/release/modoh-server --help
Relay and target for (Mutualized) Oblivious DNS over HTTPS with Authorization

Usage: modoh-server [OPTIONS] --config <FILE>

Options:
  -c, --config <FILE>                 Configuration file path like ./config.toml
  -w, --watch                         Activate dynamic reloading of the config file via continuous monitoring
  -t, --otel-trace                    Enable opentelemetry for trace. Unless explicitly specified with '-e', collector endpoint is 'http://localhost:4317'.
  -m, --otel-metrics                  Enable opentelemetry for metrics. Unless explicitly specified with '-e', collector endpoint is 'http://localhost:4317'.
  -e, --otlp-endpoint <ENDPOINT_URL>  Opentelemetry collector endpoint url connected via gRPC
  -h, --help                          Print help
  -V, --version                       Print version
```

## Basic Configuration
