# modoh-server: Relay and Target Server Implementation for Oblivious DNS over HTTPS (ODoH), ODoH-based Mutualized Oblivious DNS (&mu;ODoH), and Standard DoH.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/modoh-server/actions/workflows/test.yml/badge.svg)
![Docker](https://github.com/junkurihara/modoh-server/actions/workflows/release_docker.yml/badge.svg)
![ShiftLeft Scan](https://github.com/junkurihara/modoh-server/actions/workflows/shiftleft-analysis.yml/badge.svg)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jqtype/modoh-server)](https://hub.docker.com/r/jqtype/modoh-server)

Relay and target implementation for Oblivious DoH (ODoH) and ODoH-based Mutualized Oblivious DNS (ODoH-based &mu;ODNS; &mu;ODoH) supporting authenticated connection, written in Rust. Standard DoH target server is also supported.

> **This is a re-implementation of [https://github.com/junkurihara/doh-server](https://github.com/junkurihara/doh-server) for ease of maintenance and feature updates for &mu;ODNS.**
>
> **In &mu;ODoH, the target function is fully compatible with that of ODoH. For the detailed information on &mu;ODNS, please also refer to [https://junkurihara.github.io/dns/](https://junkurihara.github.io/dns/).**

## Introduction

*DNS over HTTPS* (DoH) is an encrypted DNS protocol in which DNS queries and responses are exchanged with the target full-service resolver via HTTPS, i.e., over an encrypted-secure channel ([RFC8484](https://datatracker.ietf.org/doc/rfc8484)). To enhance the privacy of DoH, *Oblivious DNS over HTTPS* (ODoH) has been developed  ([RFC9230](https://datatracker.ietf.org/doc/rfc9230/)). ODoH leverages an intermediate *relay* (or *proxy*) and an end-to-end encryption ([HPKE](https://datatracker.ietf.org/doc/rfc9180/)) in order to decouple the client's IP address and content of his queries. *Mutualized Oblivious DNS over HTTPS* (&mu;ODoH) is an extension of ODoH, which has been (is still being) developed from the concern of the collusion between the relay and the target resolver and corruption of the client's privacy ([Resource](https://junkurihara.github.io/dns/)). To this end, &mu;ODNS leverages multiple relays towards the target resolver, where relays are selected in a random fashion and employed in a distributed manner.

`modoh-server` is server software that provides the target and relay functions of these three encrypted and privacy-enhanced DNS protocols. Note that as the target function, `modoh-server` works not as the full-service resolver like `bind` and `unbound` but as the DNS forwarder decrypting encrypted queries and sends the plaintext ones to the upstream full-service resolver via UDP/TCP over port 53.

### Network Structure of &mu;ODoH

Here is an example of the network architecture of &mu;ODoH.

![&mu;ODoH Network Structure](./assets/modoh-structure.jpg)

The &mu;ODoH network consists of &mu;ODoH client ([`doh-auth-proxy`](https://github.com/junkurihara/doh-auth-proxy)), &mu;ODoH relay and target servers(`modoh-server`), and supplementary authentication server ([`rust-token-server`](https://github.com/junkurihara/rust-token-server)). Note that when there exist two `modoh-server`, i.e., single relay and single target available, it exactly coincides with ODoH.

`modoh-server` supplementary provides several access control functions for incoming and outgoing HTTP requests: For incoming requests, it provides (1) client authentication by Bearer token and (2) acceptance of pre-authorized previous relays by their source IP addresses; For outgoing requests, it enforces (3) filtering requests by pre-authorized target domains. To enable the (1) client authentication, the `rust-token-server` must be configured and deployed on the Internet in addition to `modoh-server`.

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

### First Step

At least, either one or both of `[relay]` and `[target]` directives must be specified.

#### As a Target (Forwarder of plaintext DNS Queries)

`modoh-server` works as a target, i.e., a forwarder of DNS queries to upstream Do53 full-service resolver, with default parameters just by adding the following directive in `config.toml`.

```toml:config.toml
[target]
```

You can run `modoh-server` as a target and check its logs as follows (only `[target]` is specified in the config file).

```log:
% ./modoh-server -c config.toml
2024-01-17T02:33:54.082519Z  INFO main modoh_server: Start MODoH service
2024-01-17T02:33:54.083804Z  INFO main modoh_server::config::target_config: Listening on 0.0.0.0:8080
2024-01-17T02:33:54.083847Z  INFO main modoh_server::config::target_config: Hostname: localhost
2024-01-17T02:33:54.083880Z  INFO main modoh_server::config::target_config: (M)ODoH target enabled
2024-01-17T02:33:54.083899Z  INFO main modoh_server::config::target_config: Target path: /dns-query
2024-01-17T02:33:54.083904Z  INFO main modoh_server::config::target_config: Target upstream: 8.8.8.8:53
2024-01-17T02:33:54.083909Z  INFO main modoh_server::config::target_config: Target local bind address: 0.0.0.0:0
2024-01-17T02:33:54.083926Z  INFO main modoh_server::config::target_config: Target error ttl: 2
2024-01-17T02:33:54.083942Z  INFO main modoh_server::config::target_config: Target max ttl: 604800
2024-01-17T02:33:54.083947Z  INFO main modoh_server::config::target_config: Target min ttl: 10
2024-01-17T02:33:54.268199Z  INFO main modoh_server_lib::router::router_main: Start (M)ODoH services
2024-01-17T02:33:54.268243Z  INFO modoh-server modoh_server_lib::target::target_main: Start odoh config rotation service
2024-01-17T02:33:54.268310Z  INFO         main modoh_server_lib::router::router_main: Start TCP listener serving with HTTP request for configured host names
```

You can check its target functionality by `dig` sending a DoH request as follows.

```bash:
% dig t.co @localhost -p 8080 +http-plain

; <<>> DiG 9.18.21 <<>> t.co @localhost -p 8080 +http-plain
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27036
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
; PAD: (15 bytes)
;; QUESTION SECTION:
;t.co.                          IN      A

;; ANSWER SECTION:
t.co.                   300     IN      A       104.244.42.133

;; Query time: 30 msec
;; SERVER: 127.0.0.1#8080(localhost) (HTTP)
;; WHEN: Wed Jan 17 11:57:34 JST 2024
;; MSG SIZE  rcvd: 68
```

The full configuration options for the target functionality are given as follows.

```toml:config.toml
## Target configuration
[target]
## Target serving path [default: "/dns-query"]
path = "/dns-query"

## Upstream resolver address with port [default: "8.8.8.8:53"]
upstream = "8.8.8.8:53"

## (Optional) TTL for errors, in seconds
error_ttl = 2

## (Optional) Maximum TTL, in seconds
max_ttl = 604800

## (Optional) Minimum TTL, in seconds
min_ttl = 10
```

#### As a Relay

Much like the previous example, the relay (proxy) functionality can be enabled with default parameters just by adding the following directive in `config.toml`.

```toml:config.toml
[relay]
```

You can run `modoh-server` as a relay and check its logs as follows (only `[relay]` is specified in the config file).

```log:
% ./modoh-server -c config.toml
2024-01-17T02:59:38.424488Z  INFO main modoh_server: Start MODoH service
2024-01-17T02:59:38.425403Z  INFO main modoh_server::config::target_config: Listening on 0.0.0.0:8080
2024-01-17T02:59:38.425588Z  INFO main modoh_server::config::target_config: Hostname: localhost
2024-01-17T02:59:38.425598Z  INFO main modoh_server::config::target_config: (M)ODoH relay enabled
2024-01-17T02:59:38.425608Z  INFO main modoh_server::config::target_config: Relay path: /proxy
2024-01-17T02:59:38.425616Z  INFO main modoh_server::config::target_config: Relay max subsequence nodes: 3
2024-01-17T02:59:38.425626Z  INFO main modoh_server::config::target_config: Relay http user agent: modoh-server/0.1.0
2024-01-17T02:59:38.603780Z  INFO main modoh_server_lib::router::router_main: Start (M)ODoH services
2024-01-17T02:59:38.603896Z  INFO main modoh_server_lib::router::router_main: Start TCP listener serving with HTTP request for configured host names
```

The full configuration options for the relay functionality are given as follows.

```toml: config.toml
## Relay configuration
[relay]
## Relay serving path [default: "/proxy"]
path = "/proxy"

## Maximum number of subsequent nodes (relays and target resolver) [default: 3]
max_subsequent_nodes = 3

## (Optional) User agent string to be sent to the next relay/resolver [default "modoh-server/<VERSION>"]
# forwarder_user_agent = "whatever"
```

### Second Step: Configuration of Listening Socket and Hostname

The default listen address and port are `0.0.0.0` and `8080`. To override these parameters, following top-level parameters needs to be specified.

```toml:config.toml
## Listen address [default: "0.0.0.0"]
listen_address = "0.0.0.0"

## Listen port [default: 8080]
listen_port = 8080
```

Also the default hostname is `localhost`, which is used to check the header fo incoming HTTP request. *This should be adequately changed when deployed according to the configured domain* by setting the following top-level parameter.

```toml:config.toml
## Serving hostname [default: "localhost"]
## This will be used to check host header of incoming requests.
hostname = "modoh.example.com"
```

You can check the full options available in `modoh-server` in our example [`modoh-server.toml`](./modoh-server.toml).

## Advanced Configuration for Access Control Mechanisms

For the secure deployment of `modoh-server`, the access control mechanisms should be configured in addition to the basic configuration explained above.

### Client Authentication using Bearer Token

For the client authentication, we can use the Bearer token in HTTP Authorization header, which is issued by [`rust-token-server`](https://github.com/junkurihara/rust-token-server) in the context of OpenID Connect. The authentication through the token validation is configured in the `[validation]` directive in `config.toml` as follows.

```toml:config.toml
## Validation of source, typically user clients, using Id token
[validation]

## Token validation method, multiple methods can be configured
[[validation.token]]
## Token API endpoint
token_api = "https://example.com/v1.0"

## Token issuer, which will be evaluated as `iss` claim of the token
## If not specified, token_api_endpoint will be used as token issuer
token_issuer = "https://example.com/v1.0"

## Allowed client Ids, which will be evaluated as `aud` claim of the token
client_ids = ["client_id_1", "client_id_2"]
```

`modoh-server` allows multiple `[[validation.token]]` directives to accepts multiple clients authorized under various authorities. `modoh-server` periodically fetches their validation keys (public keys) through the token APIs' `jwks` endpoints, and concurrently verifies a request with the retrieved keys.

Note that *when the bearer token does not exist in the HTTP request header, the request filtering based on the token validation is always bypassed*. This is because requests not from clients but from other relays have no such token in their header [^1]. Thus, *you should employ the source IP filtering mechanism for pre-authorized relays simultaneously with token validation.*

[^1]: It is mandatory to strip any client-specific information at the first-hop relay for privacy.

### Configuration of Pre-authorized Relays for Incoming Requests

(Only) When the token validation is not configured or bypassed for requests without Authorization header, `modoh-server` can filters requests incoming from non-authorized nodes by their source IP addresses. The source IP filtering can be configured in `[access]` directive in `config.toml` as follows.

```toml:config.toml
## Access control of source, typically relays, using source ip address and nexthop destination domain
[access]
## Allowed source ip addrs
## This is evaluated when no authorization header is given in the request or no token validation is configured.
## This happens typically for forwarded requests from a relay, not a client.
allowed_source_ips = [
  "127.0.0.1",
  "192.168.1.1",
  "192.168.1.2",
  "192.168.11.0/24",
]
## Trusted CDNs and proxies ip ranges that will be written in X-Forwarded-For / Forwarded header
trusted_cdn_ips = ["192.168.123.0/24"]
trusted_cdn_ips_file = "./cdn_ips.txt"

# Always trust previous hop ip address, retrieved from remote_addr.
# We set [default = true], since we assume that this application is always located internal network and exposed along with a TLS reverse proxy (the previous hop is always trusted).
# If you set this to false, you should put your proxy address in trusted_cdn_ips or trusted_cdn_ips_file.
trust_previous_hop = true
```

When the `modoh-server` instance uses CDNs, `trusted_cdn_ips` and/or `trusted_cdn_ips_file` must be configured. For [Cloudflare's IPs](https://www.cloudflare.com/th-th/ips/) and [Fastly's IPs](https://developer.fastly.com/reference/api/utils/public-ip-list/) are listed in [./cdn_ips.txt](./cdn_ips.txt). Also, when a TLS-terminated reverse proxy is not collocated with the `modoh-server` instance, you should make `trust_previous_hop` to `false`.

### Configuration of Pre-authorized Domains for Outgoing Requests

In &mu;ODoH, the request path to the target through relays is configured by the client itself. Hence, `modoh-server` can filter relaying requests outgoing to unauthorized domains to disallow &mu;ODoH queries to travel towards unexpected destinations and limit the possibility of DoS attacks to external domains. This can be configured in `[access]` directive as well as the source IP filtering in `config.toml`.

```toml:config.toml
[access]
## Allowed next destination target and relay domains
allowed_destination_domains = ["example.com", "example.net", "*.example.org"]
```

## Deployment using Docker

See the [`./docker`](./docker) directory.

## Using Opentelemetry for Observability

`modoh-server` provides the functionality to monitor traces and metrics for DevOps with [Opentelemetry](https://opentelemetry.io/). Namely, `modoh-server` can send traces and metrics to an [`opentelemetry-collector`](https://github.com/open-telemetry/opentelemetry-collector) endpoint via gRPC.

To enable the observability options, start `modoh-server` with `--otel-trace` for traces and `--otel-metrics` for metrics. By default, the gRPC endpoint of `opentelemetry-collector` is `http://localhost:4317`, which can be overridden with `--otel-endpoint <ENDPOINT_URL>` option.

The [`./docker-otel`](./docker-otel) directory contains an example architecture for observability based on `opentelemetry-collector`, metrics storage, visualizer, and analyzer containers.

## License

`modoh-server` is free, open-source software licensed under MIT License.

You can open issues for bugs you've found or features you think are missing. You can also submit pull requests to this repository.

Contributors are more than welcome!
