# Zray Cloudflare Worker endpoint

The CDN-fronted fallback from `PLAN-02` §1 — the "class B" endpoint. It is
slower than a direct REALITY server and rate-limited, and that is the trade:
blocking it means blocking Cloudflare, so it tends to survive events that take
a VPS address off the map.

Use it as a fallback, not as a primary. The planner climbs to it when the
direct class stops working and descends again when the direct class recovers.

## What it cannot do

These are platform limits, not gaps in this script:

| | |
|---|---|
| **No UDP** | Workers cannot open UDP sockets. No QUIC, no DNS-over-QUIC, and no UDP-carrying protocol through this endpoint. Route UDP elsewhere or accept that it fails. |
| **Request quota** | The free plan caps daily requests. A busy client will exhaust it. |
| **No Cloudflare-to-Cloudflare** | A Worker cannot open a socket to another Cloudflare address, so a destination that is itself behind Cloudflare needs a separate relay address. |
| **TCP only** | The script refuses VLESS commands other than TCP rather than failing obscurely later. |

## Deploy

```bash
npm install -g wrangler
wrangler login
cd deploy/cloudflare-worker

# Credentials are secrets, never wrangler.toml — that file is committed.
wrangler secret put UUID     # a UUID you generate; keep it private
wrangler secret put PATH     # e.g. /a-path-nobody-will-guess

wrangler deploy
```

`wrangler deploy` prints the Worker's hostname, for example
`zray-edge.your-account.workers.dev`.

## Client configuration

The two names are different on purpose, and that difference *is* the technique:

* `tlsSettings.serverName` — the **front**: a large, ordinary Cloudflare-hosted
  name. This is the only name a passive observer sees.
* `wsSettings.host` — the **Worker**: the name Cloudflare routes on, carried
  inside the encrypted session.

```json
{
  "protocol": "vless",
  "settings": {"vnext": [{
    "address": "<a reachable Cloudflare edge address>",
    "port": 443,
    "users": [{"id": "<the UUID you set as a secret>", "encryption": "none"}]
  }]},
  "streamSettings": {
    "network": "ws",
    "wsSettings": {"path": "<the PATH you set>", "host": "zray-edge.your-account.workers.dev"},
    "security": "tls",
    "tlsSettings": {"serverName": "<the front name>"}
  }
}
```

Setting `serverName` to the Worker hostname defeats the entire arrangement: the
name you meant to hide is then in the ClientHello in plaintext. Setting `host`
to the front name routes to the wrong place and the tunnel will not work.
`crates/zero-runtime/tests/cdn_fronting.rs` asserts both directly against the
wire.

## Alternate ports

When 443 is throttled, Cloudflare's other HTTPS ports often still work:
`8443`, `2053`, `2083`, `2087`, `2096`. The planner's `CdnAlternatePort` rung
uses exactly this set.

## Clean IP selection

Iran blocks *some* Cloudflare ranges, not all. Rather than asking a user to
paste addresses from an external scanner, generate a bounded candidate set and
let the observatory rank it by measured success:

```bash
zray preset iran "<your share link>" --clean-ip --clean-ip-ports 443,2053,8443 -o config.json
```
