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

`modoh-server` supplementary provides several access control functions for incoming and outgoing HTTP requests: For incoming requests, it provides (1) client authentication by Bearer token and (2) acceptance of pre-authorized previous relays by their source IP addresses; For outgoing requests, it enforces (3) filtering requests by pre-authorized target domains. Both for incoming and outgoing requests from/to other relays, (4) it validates the source by the HTTP message signature ([RFC9421](https://datatracker.ietf.org/doc/rfc9421/)) and allows to dispatch only when the HTTP signature-enabled domains. To enable the (1) client authentication, the `rust-token-server` must be configured and deployed on the Internet in addition to `modoh-server`. Also note that statically pre-configured (2) allowed source addresses and (3) allowed destination domains are prioritized over (4) HTTP signature-based operations.

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
  -q, --qrlog <PATH>                  Enable query-response logging. Unless specified, it is disabled.
  -h, --help                          Print help
  -V, --version                       Print version
```

## Basic Configuration

### First Step

At least, either one or both of `[relay]` and `[target]` directives must be specified.

#### As a Target (Forwarder of plaintext DNS Queries)

`modoh-server` works as a target, i.e., a forwarder of DNS queries to upstream Do53 full-service resolver, with default parameters just by adding the following directive in `config.toml`.

```toml
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

```toml
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

```toml
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

```toml
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

```toml
## Listen address [default: "0.0.0.0"]
listen_address = "0.0.0.0"

## Listen port [default: 8080]
listen_port = 8080
```

Also the default hostname is `localhost`, which is used to check the header fo incoming HTTP request. *This should be adequately changed when deployed according to the configured domain* by setting the following top-level parameter.

```toml
## Serving hostname [default: "localhost"]
## This will be used to check host header of incoming requests.
hostname = "modoh.example.com"
```

You can check the full options available in `modoh-server` in our example [`modoh-server.toml`](./modoh-server.toml).

## Advanced Configuration for Access Control Mechanisms

For the secure deployment of `modoh-server`, the access control mechanisms should be configured in addition to the basic configuration explained above.

### Client Authentication using Bearer Token

For the client authentication, we can use the Bearer token in HTTP Authorization header, which is issued by [`rust-token-server`](https://github.com/junkurihara/rust-token-server) in the form of **OpenID Connect ID Token** or **Anonymous Token based on the blind RSA signatures ([RFC9474](https://www.rfc-editor.org/rfc/rfc9474.html))**. The authentication through the token validation is configured in the `[validation]` directive in `config.toml` as follows.

```toml
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

`modoh-server` allows multiple `[[validation.token]]` directives to accepts multiple clients authorized under various authorities. `modoh-server` periodically fetches their validation keys (public keys) through the token APIs' `jwks` (for ID tokens) and `blindjwks` (for anonymous token) endpoints, and concurrently verifies a request with the retrieved keys.

Note that *when the bearer token does not exist in the HTTP request header, the request filtering based on the token validation is always bypassed*. This is because requests not from clients but from other relays have no such token in their header [^1]. Thus, *you should employ the source IP filtering mechanism for pre-authorized relays simultaneously with token validation.*

[^1]: It is mandatory to strip any client-specific information at the first-hop relay for privacy.

### Configuration of Pre-authorized Relays for Incoming Requests

(Only) When the token validation is not configured or bypassed for requests without Authorization header, `modoh-server` can filters requests incoming from non-authorized nodes by their source IP addresses or the HTTP message signatures if available. The source IP filtering can be configured in `[access]` directive in `config.toml` as follows.

```toml
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

```toml
[access]
## Allowed next destination target and relay domains
allowed_destination_domains = ["example.com", "example.net", "*.example.org"]
```

### Configuration of HTTP Message Signature-based Authentication for Incoming and Outgoing Requests

The access control mechanisms based on source IP addresses must be pre-configured in the configuration file in a static manner, which means that all relays and targets must updates their configuration files whenever a new allowed node joins or existing nodes changes their IP addresses. This becomes really inconvenient as the network of &mu;ODoH expands. Thus, in addition to the static list of source IP addresses, the `modoh-server` leverages the brand-new IETF-standardized *HTTP message signature* ([RFC9421](https://datatracker.ietf.org/doc/rfc9421/)) to realize the dynamic updates of source access control configurations independent of the IP addresses.

For the HTTP message signature-based authentication, the `modoh-server` exposes its public key at the endpoint `/.well-known/httpsigconfigs` much like the `/.well-known/odohconfigs` endpoint for ODoH. Thus, to enable the HTTP message signature-based authentication, the reverse proxy in front of the `modoh-server` must be configured to allow the access to the `/.well-known/httpsigconfigs` endpoint. The `httpsigconfigs` is a series of public keys serialized in the same manner as the `odohconfigs`. The exposed keys are periodically rotated and refreshed. Currently, the following key types are supported:

- `ed25519`, `es256` for public-key-based signature
- `hs256-x25519-hkdf-sha256`, `hs256-p256-hkdf-sha256` for Diffie-Hellman key exchange (DHKex)-based signature

Here, public-key-based signature means the simple solution directly using the exposed public key to verify the HTTP message signature. On the other hand, DHKex-based signature means the more complex one that uses the Diffie-Hellman key exchange to generate a shared secret key for HMAC signature. In particular, `hs256-x25519-hkdf-sha256` is a procedure that first generates a shared secret key using the x25519 key exchange by fetching the destination's exposed public key, and expands the shared key using HKDF-SHA256 (hkdf-sha256) to generate the HMAC-SHA256 (hs256) key for the signature. The key types are set in the `[access.httpsig.key_types]` directive in `config.toml`, and the keys.

The `modoh-server` periodically fetches public keys for verification in public key-based signature and those for the HMAC key in signing and verification in DHKex-based signature from the `httpsigconfigs` endpoints of domains specified in `[access.httpsig.enabled_domains]` directive. The `enabled_domains_registry` can specified the endpoint serving the file containing the list of enabled domains.

Note that for the destination domain that does not supports DHKex-based signature, no signature is appended to the outgoing request unless public-key-based signature is available in `key_types` directive.

The full configuration options are given as follows.

```toml
## Configuration for HTTP message signatures, which is used to
## - verify if the incoming request is from one of the httpsig-enabled domains,
## - sign outgoing (relayed) requests when the next node is one of the httpsig-enabled domains.
## Note that Source IP address is prioritized over the signature verification.
## The signed request is dispathed to the next hop when the destination domain is in the `allowed_destination_domains` (with public key-based signature)
## or it supports DHKex-based signature (with DHKex-based signature) since it explicitly specify the destination in the config.
## If you need to sign the request for any destination domains with public key-based signature, you should make the `allowed_destination_domains` to be empty.
## Note that in such a case, no signature is appended to the outgoing request when public-key-based signature is unavailable
## and the destination domain does not support DHKex-based signature.
## If [access.httpsig] is not specified, the signature verification is not performed, and public key is not served at endpoint.
[access.httpsig]
## Key types used for httpsig verification
## - Asymmetric key for public-key-based signature like ed25519, ecdsa-p256-sha256 (es256).
## - Diffie-Hellman key exchange for hmac-sha256 (hs256) signature.
## These are automatically generated and exposed at `/.well-known/httpsigconfigs` endpoint.
##   default = ["hs256-x25519-hkdf-sha256"],
##   supported = "hs256-p256-hkdf-sha256" (h256 via ecdh), "hs256-x25519-hkdf-sha256" (h256 via ecdh), "ed25519", and "es256"
## The DH key type is first used for signing only if available according to the target domain.
## If not available for the domain, the public key type is used for signing if the type exists in the list.
key_types = ["dhp256-hkdf-sha256", "x25519-hkdf-sha256"]

## Public key rotation period in seconds.
## Keys are periodically rotated and exposed to mitigate the risk of key compromise.
## (default = 3600)
key_rotation_period = 3600

## List of HTTP message signatures enabled domains, which expose public keys
## to directly verify public key signatures or to use Diffie-Hellman key exchange for hmac signature.
## Keys are periodically refetched from `/.well-known/httpsigconfigs` endpoints of the domains.
## (default = [])
## Note that the for DHKex, the destination domain filtering is always bypassed for dh_signing_target_domain even if `allowd_destination_domains` does not coincide with `httpsig.enabled_domains`.
enabled_domains = [
  ## In this example, httpsig configs are fetched from `https://httpsig.example.com/.well-known/httpsigconfigs` endpoint.
  ## Then, if the fetched configs contains ones for DH based signature, requests dispatched to `*.example.com` are signed with DH based signature.
  ## For public key based signature, the fetched configs are used only to verify the incoming requests, `dh_signing_target_domain` is not used.
  { configs_endpoint_domain = "httpsig.example.com", dh_signing_target_domain = "*.example.com" },
  ## If only configs_endpoint_domain is specified, it is used for both fetching and DH signing target.
  ## Namely the below is equivalent to `{ configs_endpoint_domain = "modoh.example.net", dh_signing_target_domain = "modoh.example.net" }`.
  { configs_endpoint_domain = "modoh.example.net" },
  { configs_endpoint_domain = "modoh.example.org" },
]

## Registry of httpsig enabled domains with public keys, which are served at the given md_url.
## For the served markdown file, minisign signature is served as a file `<markdown_name>.md.minisig`.
## The httpsig enabled domains listed in the markdown file are periodically fetched and updated (default = 300 secs).
## The fetched list is merged with the enabled_domains list.
enabled_domains_registry = [
  { md_url = "https://example.com/httpsig-endpoints.md", public_key = "minisign public key" },
  # { md_url = "file:///path/to/httpsig-endpoints.md", public_key = "minisign public key" },
]

## Accept signatures generated with previously exposed public keys for DHKex+HKDF+HMAC. (default = true)
## Considering the key rotation period, there exist a gap between the time when a new key is exposed and the time when other nodes fetch the new key.
## The new exposed key is not used at the external node for signing until the time when the new key is fetched.
## This option accepts the signature generated with the previous key for the time gap.
accept_previous_dh_public_keys = true

## Force HTTP Signature verification for all requests unless the ID token is given in the http header (default = false)
## By default (false), the signature verification is performed only when the source ip address is not in the allowed_source_ips list.
force_verification = false

## Always ignore the result of signature verification. (default = false)
## By default (false), if the signature verification is failed for given key id, the request is immediately rejected.
## If set to true, the signature verification is performed, but the request is always processed regardless of the result.
## Usefull for debugging or testing.
ignore_verification_result = false

## By default, the signature verification is not performed for the requests from the allowed source ip addresses.
## But if `force_verification` is set to true, the signature verification is performed for all requests.
## This option is used to ignore the result of signature verification for the requests from the allowed source ip addresses.
## In other words, requests from not-allowed source ip addresses are always rejected if the signature verification is failed.
## Even if this is set to true, `ignore_verification_result` is evaluated independently.
## (default = true, but not evaluated if `force_verification` is false)
ignore_verification_result_for_allowed_source_ips = true
```

#### Dispatching Requests to the Next Hop

Note that the pre-configured allow list of source IP addresses is prioritized over HTTP signature-based operations. Also, **the signed request is dispatched to the next hop if either one of the following conditions is satisfied**:

- The destination domain is in the `allowed_destination_domains`
- It supports DHKex-based signature (since it explicitly specifies the destination in the `enabled_domain` config.)

If you need to sign the request for any destination domains, you should make the `allowed_destination_domains` to be empty or not to be specified.

#### Public Key Rotation for HTTP Message Signatures

Since the key rotation happens periodically, the verification fails if the pre-fetched public key is stale in both public key-based and DHKex-based signature. To mitigate this risk and fill the gap for the propagation of rotated keys, `modoh-server` always keeps the previous key pair (stale one) [^keystore] in addition to the fresh one, and it appends the *two signatures* in the header in outgoing requests:

- Public key-based signature: Two signatures generated with the current and previous private keys. This allows the receiver to verify the signature with the previous key if the current key is not fetched yet.
- DHKex-based signature: Two signatures generated with the DHKex shared secret derived from:

  - The current public key and the stored target key
  - The previous public key and the stored target key.

  Since both the sender and receiver stores two generations of their own key pairs, this allows the receiver to verify the signature even if

  - the sender stores the receiver's previous public key; and/or
  - the receiver stores the sender's previous public key.

[^keystore]: `modoh-server` keeps two generations of its own keys in the inner key store while it stores only the one generation of exposed public keys of other nodes specified in `enabled_domains`.

#### DHKex-based Signature for HTTP Message Signatures

Even if both DHKex and public key-based signatures are available, the DHKex-based signing are prioritized over the public key-based signing when the destination domain supports DHKex-based signature. The DHKex-based signature, i.e., `hs256-x25519-hkdf-sha256` or `hs256-p256-hkdf-sha256`, is generated by the HMAC-SHA256 (hs256) with the pre-computed HMAC key derived as follows.

1. The sender fetches the public key of the destination domain from the `httpsigconfigs` endpoint.
2. The sender generates a shared secret key `dh` using the x25519 key exchange (or ECDH with curve p256) with the fetched public key and its own secret key.
3. The shared secret key `dh` is expanded using HKDF-SHA256 to generate the HMAC-SHA256 key `hmac_key` for the signature in the following manner:

    ```plaintext
    - skS: Sender private key
    - pkS: Sender public key
    - pkR: Receiver public key
    - dh = DH(skS, pkR): Derived shared secret key

    pkSm = SerializePublicKey(pkS)
    pkRm = SerializePublicKey(pkR)

    kem_context = pkSm XOR pkRm

    hmac_key = ExtractAndExpand(dh, kem_context)
    ```

The third step follows *DH-based Key Encapsulation Mechanism in Hybrid Public Key Encryption* ([RFC9180, Section 4.1](https://www.rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem)). However, in the HPKE, the `kem_context` is generated by the concatenation of the serialized public keys of the sender and receiver, i.e., `kem_context = concat(pkSm, pkRm)`. On the other hand, in `modoh-server`, the `kem_context` is generated by the XOR operation of the serialized public keys of the sender and receiver. This is because in &mu;ODoH, the sender could be the receiver and vice versa unlike the server-client model in HPKE. Thus we need a commutative and associative operation for the `kem_context` generation. This change allows us the bidirectional signature generation between the sender and receiver.

Also, in `modoh-server`, the sender and receiver keys are statically stored in their key store for the signature generation and verification, while the sender public and private key are always *ephemeral* in HPKE. This means that in `modoh-server`, the forward secrecy for the sender's private key cannot be guaranteed unlike HPKE [^hpke-forward-secrecy]. Thus, the exposed key rotation must be done periodically to mitigate the risk of key compromise.

[^hpke-forward-secrecy]: In HPKE, the forward secrecy with respect to sender compromise is guaranteed by the ephemeral sender's public and private key pair. However, since the receiver's public key is static for the key exchange, the forward secrecy with respect to receiver compromise is not guaranteed. (See [RFC9180, Section 9.4.7](https://www.rfc-editor.org/rfc/rfc9180.html#name-forward-secrecy))

From the deployment aspect, we prioritize the DHKex-based signature, i.e., HMAC signature, over the public key-based signature, ECDSA or EdDSA, since the signing and verification of the DHKex-based signature is much faster than the public key-based signature [^example-speed]. Since the DNS query and response must be exchanged as fast as possible in order to minimize the latency, we believe that the DHKex-based signature is the best choice for the &mu;ODoH deployment.

[^example-speed]: In [the recent research on the signing and verifying performance in JWT](https://iopscience.iop.org/article/10.1088/1757-899X/550/1/012023/pdf), the HMAC-SHA256 is 4.5 times and 1.9 times faster than ECDSA with P-256 curve in signing and verifying, respectively.

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
