/// Header keys that may contain the client IP address by previous routers like CDNs.
const HEADER_IP_KEYS: &[&str] = &[
  "x-client-ip",
  "x-forwarded-for",
  "x-real-ip",
  // load balancer like pulse secure
  "x-cluster-client-ip",
  // cloudflare v4
  "cf-connecting-ip",
  // cloudflare v6
  "cf-connecting-ipv6",
  // cloudflare enterprise
  "true-client-ip",
  // fastly
  "fastly-client-ip",
];

// FastlyやCloudflareの場合、remote_addrがそれらCDNのアドレス帯に含まれているかチェックする。
// remote_addrはTCP/QUIC handshakeが終わっているとして、xffとかはいくらでも偽装できるので一旦必ずCDNのIPチェックしないとダメ。CDN含め信頼できるIPを全部弾いた上で、一番過去のやつがsourceとみなすしかない。
// 単純に一番過去のやつではない
// https://www.m3tech.blog/entry/x-forwarded-for
// https://christina04.hatenablog.com/entry/2016/10/25/190000
// https://mrk21.hatenablog.com/entry/2020/08/06/214922
// https://developers.cloudflare.com/fundamentals/reference/http-request-headers/
// https://developer.fastly.com/reference/http/http-headers/Fastly-Client-IP/
// Forwarded header
// https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
// https://datatracker.ietf.org/doc/html/rfc7239

// cloudflare: https://developers.cloudflare.com/api/operations/cloudflare-i-ps-cloudflare-ip-details
// fastly: https://developer.fastly.com/reference/api/utils/public-ip-list/
// https://github.com/femueller/cloud-ip-ranges githubのリストを使う手もある
