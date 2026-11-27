# Edge relay

A Tide relay that runs as a Cloudflare Worker. Apps dial the Worker's
`*.workers.dev` address; the Worker passes Tide's requests on to your server
(the egress) and streams the answers back. The bodies stay sealed between the
app and the egress, so the Worker holds no key and sees no destinations.

```
app ──TLS/h2──▶ your-name.workers.dev (this Worker) ──HTTPS──▶ egress (your Tide server)
                 shows a plain page to anyone else            opens the real connections
```

Why: the address a censor sees the app talk to is Cloudflare's, and the
server that opens connections to the world is never that address.

## Set up

1. On the server, run the Tide server as usual (`zerov1` inbound). It accepts
   HTTP/1.1 as well as HTTP/2, so the Worker's request needs no special proxy.
   Its address must be reachable over HTTPS on port 443 (a Worker can only
   dial a few ports).
2. Edit `wrangler.toml`: `ORIGIN` is the server's `https://name` (no path),
   `PATH_PREFIX` is the server's Tide `path`.
3. `wrangler deploy`.
4. Make a client link as for the server itself, but with the Worker's name
   and `upload=packet`:
   `zerov1://<user>@<name>.workers.dev:443?key=<server key>&path=<path>&security=tls&sni=<name>.workers.dev&upload=packet`

`upload=packet` matters. Cloudflare collects an upload request before passing
it on, so a client that keeps its upload open for a moment to send more (the
default) makes every round trip of a proxied connection wait for that moment.
With it, each upload ends as soon as nothing is waiting and a page loads in
about two seconds instead of seven.

## Check

```
node --test test/                                  # the Worker, against a fake server
cargo test -p zero-transport --lib tide_http1 -- --include-ignored
```

The second runs a whole Tide session (handshake, a download pipe, a chunked
upload, an echoed stream) through this Worker under wrangler's local workerd
and into a real server.

## Not checked

- Cloudflare's limits on long downloads and request counts (every upload and
  download pipe is one request), and whether its terms allow this use.
- Whether the Worker's request to the egress arrives as HTTP/1.1 or HTTP/2:
  the server accepts both.
