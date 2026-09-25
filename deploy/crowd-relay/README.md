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
access token built into the app, which anyone could extract. It runs on
Cloudflare's free `*.workers.dev` address, deployed by a GitHub Action, so
no domain is needed. That address is filtered in Iran, which does not
matter: apps send their reports through their own tunnel once connected.
The relay addresses are published inside `rankings.json`, so a relay can be
moved or added without an app update.

## What is shared, and what is not

- **Only public servers.** A report names a server by its link key (a hash).
  The Action ranks a key only if it finds that server in the public feeds
  itself (`deploy/crowd/sources.json`), and publishes the link from the
  feed. The app never reports configs the user added or subscribed to, and
  the Action would drop them if it did.
- **Clean Cloudflare addresses** from the scanner. These are Cloudflare's,
  not anyone's server.
- **No addresses or device ids are stored.** The relay keeps two daily
  pseudonyms (HMACs keyed by a secret, new every day): one of the sending
  address, for the rate limit and so one address cannot pose as many
  people, and one of the address plus a random value the app picks each
  day, so people sharing one VPN server still count separately. Addresses
  themselves are never written. Rows are deleted after two days.
- **The network** is a mobile carrier's code (MCC+MNC, e.g. `cell:43211`
  for MCI) that the phone reports. On Wi-Fi, a report sent through the
  tunnel says `any` and counts only towards the all-networks list; one that
  reaches the relay straight from the user's network is filed under the
  ISP's AS number (e.g. `asn:58224`).
- **Users can turn it off**: Settings → Privacy → Help others connect.

A false report cannot put a new server in front of anyone: only servers
already in the public feeds are ranked, nothing counts until two different
reporters from two different addresses agree, each reporter counts once per
server, and every app tests a server before using it.

## Set up (everything from the GitHub website)

1. Make a free Cloudflare account at <https://dash.cloudflare.com/sign-up>.
   Open **Workers & Pages** once; it asks you to pick a `workers.dev`
   subdomain (any name).
2. Create an API token: **My Profile → API Tokens → Create Token → Create
   Custom Token**, with the permissions **Account · Workers Scripts · Edit**
   and **Account · D1 · Edit**.
3. Copy your **Account ID** (Workers & Pages page, right-hand side).
4. In the GitHub repository, **Settings → Secrets and variables → Actions →
   New repository secret**, add:

   | Name | Value |
   |---|---|
   | `CLOUDFLARE_API_TOKEN` | the token from step 2 |
   | `CLOUDFLARE_ACCOUNT_ID` | the id from step 3 |
   | `CROWD_EXPORT_TOKEN` | any long random string (a password manager can make one) |

5. **Actions → deploy crowd relay → Run workflow.** It creates the
   database, deploys the Worker and prints its address.
6. **Actions → crowd → Run workflow** once. From then on it runs every
   twenty minutes by itself, and apps learn the relay's address from the
   rankings it publishes.

Changes to `deploy/crowd-relay/` redeploy the Worker automatically. A relay
hosted anywhere else can be added with the repository variable
`CROWD_RELAYS` (comma-separated `https://` addresses, same `EXPORT_TOKEN`).

## API

`POST /v1/report`

```json
{
  "v": 1,
  "net": "cell:43211",
  "nonce": "3f9c1a7e5b2d4c6e8a0b1c2d",
  "results": [{ "id": "b46d9a15f4bbebc5", "ok": true, "ms": 210 }],
  "clean": [{ "ip": "104.16.132.229", "ms": 90 }]
}
```

`net` is a carrier (`cell:` + MCC+MNC), `any`, or absent, in which case the
ISP's AS number is used. The answer names the network the results were
counted under: `{ "net": "asn:58224", "accepted": 2 }`. At most 40 results
and 10 addresses per request.

`GET /v1/export?since=<unix seconds>` with `Authorization: Bearer <EXPORT_TOKEN>`
returns the stored reports; only the crowd workflow calls it.
