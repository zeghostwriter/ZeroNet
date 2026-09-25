# Crowd relay

Lets ZeroNet users help each other connect. After testing servers, the app
sends what it found — which public servers answered on this network, and
which clean Cloudflare addresses the scanner found — to this relay. Every
twenty minutes the `crowd` GitHub Action exports the reports, ranks them,
and publishes `rankings.json` on the repository's `crowd-data` branch. Before
searching, apps try the servers other people on the same carrier or ISP got
through with.

```
app ──report──▶ relay (this Worker, D1) ──export──▶ GitHub Action ──▶ crowd-data/rankings.json
app ◀──────────── raw.githubusercontent.com / cdn.jsdelivr.net ◀─────────────────────┘
```

GitHub is where the rankings live and where apps read them. The relay only
queues reports, because GitHub cannot take anonymous writes without an
access token built into the app, which anyone could extract. Any number of
relays can run side by side, and the list of relays is published inside
`rankings.json`, so a blocked relay can be replaced without an app update.

## What is shared, and what is not

- **Only public servers.** A report names a server by its link key (a hash).
  The Action ranks a key only if it finds that server in the public feeds
  itself (`deploy/crowd/sources.json`), and publishes the link from the
  feed. The app never reports configs the user added or subscribed to, and
  the Action would drop them if it did.
- **Clean Cloudflare addresses** from the scanner. These are Cloudflare's,
  not anyone's server.
- **No addresses or device ids are stored.** The relay derives a pseudonym
  from the sender's IP address and the date (an HMAC, keyed by
  `SALT_SECRET`, that changes every day) so one person counts once. The IP
  address itself is never written. Rows are deleted after two days.
- **The network** is a mobile carrier's code (MCC+MNC, e.g. `cell:43211`
  for MCI) that the phone reports, or otherwise the ISP's AS number, which
  Cloudflare supplies (e.g. `asn:58224`).
- **Users can turn it off**: Settings → Privacy → Help others connect.

A false report cannot put a new server in front of anyone: only servers
already in the public feeds are ranked, nothing counts until two different
reporters agree, each reporter counts once per server, and every app tests
a server before using it.

## Deploy

```bash
npm install -g wrangler
wrangler login
cd deploy/crowd-relay

wrangler d1 create zeronet-crowd          # paste the database_id into wrangler.toml
wrangler d1 execute zeronet-crowd --remote --file schema.sql

wrangler secret put SALT_SECRET           # e.g. the output of: openssl rand -hex 32
wrangler secret put EXPORT_TOKEN          # e.g. the output of: openssl rand -hex 32

wrangler deploy
```

`*.workers.dev` addresses are filtered in Iran; give the Worker a custom
domain (Workers → your worker → Settings → Domains & Routes).

Then, in the GitHub repository (Settings → Secrets and variables → Actions):

| | Name | Value |
|---|---|---|
| Variable | `CROWD_RELAYS` | `https://crowd.example.com` (comma-separated for several) |
| Secret | `CROWD_EXPORT_TOKEN` | the `EXPORT_TOKEN` above |

Run the `crowd` workflow once by hand (Actions → crowd → Run workflow). It
creates the `crowd-data` branch, and apps pick up the relay address from the
rankings it publishes.

## API

`POST /v1/report`

```json
{
  "v": 1,
  "net": "cell:43211",
  "results": [{ "id": "b46d9a15f4bbebc5", "ok": true, "ms": 210 }],
  "clean": [{ "ip": "104.16.132.229", "ms": 90 }]
}
```

`net` is optional: without it (Wi-Fi, desktop), the ISP's AS number is used.
The answer names the network the results were counted under, which the app
remembers for that Wi-Fi: `{ "net": "asn:58224", "accepted": 2 }`. At most 40
results and 10 addresses per request, 200 results per sender per hour.

`GET /v1/export?since=<unix seconds>` with `Authorization: Bearer <EXPORT_TOKEN>`
returns the stored reports; only the Action calls it.
