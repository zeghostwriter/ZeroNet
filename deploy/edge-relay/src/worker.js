// ZeroNet edge relay: a Tide relay that runs as a Cloudflare Worker.
//
// How this works. The Worker answers every request that is not a Tide
// request with a plain decoy page, and passes every Tide request
//   POST <path>/<session>/open
//   POST <path>/<session>/u/<n>
//   GET  <path>/<session>/d/<n>
// on to ORIGIN, the Tide server (the egress), and streams the answer back.
// The bodies are sealed end to end between the app and the egress: the Worker
// holds no key, reads no user, and cannot see where a stream goes. It is the
// same job as the Rust relay (`zero-transport::tide_relay`), with a Cloudflare
// address in front, so the address an app dials is a Cloudflare one and the
// egress, which opens connections to the world, is never that address.
//
// The rules it keeps:
//  - only requests shaped like Tide's are forwarded, and only to ORIGIN,
//    never to an address taken from a request: this is not an open proxy;
//  - nothing about the app (its address, its headers) is passed on;
//  - it keeps no state, so any number of copies can run side by side;
//  - when ORIGIN cannot be reached (the fetch fails, or Cloudflare itself
//    answers with a 52x/530 page) it answers 502, as a proxy with its
//    backend down does, and never with the 404 that means "session gone".
//
// Settings (wrangler.toml [vars]): ORIGIN, the egress's https address with no
// path, e.g. "https://egress.example.com" (a Worker can only reach ports
// 80/443 and a few others); PATH_PREFIX, the Tide path, e.g. "/assets/v2".

const DECOY = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title></head><body><h1>It works</h1><p>This site is being set up. Please check back later.</p></body></html>\n`;
const MISSING = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n`;
const BAD_GATEWAY = `<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center></body></html>\n`;
const HTML = { "content-type": "text/html; charset=utf-8" };

// What any reverse proxy shows when its backend is down. Tide clients retry on
// it; they give a session up only on the 404 the egress itself gives for a
// session it does not know, so a passing outage must not look like that.
const badGateway = () => new Response(BAD_GATEWAY, { status: 502, headers: HTML });

// Headers worth passing back from the egress; everything else is its own.
const PASSED_BACK = ["date", "content-type", "content-length", "cache-control", "x-accel-buffering"];
const QUERY_MAX = 128;

const decoy = (request, pathname) => {
  const front = (pathname === "/" || pathname === "/index.html") &&
    (request.method === "GET" || request.method === "HEAD");
  const body = request.method === "HEAD" ? null : front ? DECOY : MISSING;
  return new Response(body, { status: front ? 200 : 404, headers: HTML });
};

// Whether a request is one Tide would make. `prefix` has no trailing slash.
export function isTide(method, pathname, prefix) {
  if (!pathname.startsWith(prefix + "/")) return false;
  const rest = pathname.slice(prefix.length + 1);
  const cut = rest.indexOf("/");
  if (cut !== 32) return false;
  const name = rest.slice(0, cut);
  const action = rest.slice(cut + 1);
  if (!/^[0-9a-fA-F]{32}$/.test(name)) return false;
  if (method === "POST") return action === "open" || /^u\/[0-9]+$/.test(action);
  if (method === "GET") return /^d\/[0-9]+$/.test(action);
  return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const prefix = (env.PATH_PREFIX || "").replace(/\/+$/, "");
    if (!prefix || !env.ORIGIN || !isTide(request.method, url.pathname, prefix) ||
        url.search.length > QUERY_MAX) {
      return decoy(request, url.pathname);
    }
    const headers = new Headers();
    if (request.method === "POST") headers.set("content-type", "application/octet-stream");
    headers.set("accept", "*/*");
    let upstream;
    try {
      upstream = await fetch(new URL(url.pathname + url.search, env.ORIGIN), {
        method: request.method,
        headers,
        body: request.method === "POST" ? request.body : undefined,
        duplex: "half",
        redirect: "manual",
      });
    } catch {
      return badGateway();
    }
    // Cloudflare answers for an origin it cannot reach with its own 52x/530
    // pages; the egress itself never sends those. Show an ordinary 502.
    if (upstream.status >= 520 && upstream.status <= 530) {
      return badGateway();
    }
    const back = new Headers();
    for (const name of PASSED_BACK) {
      const value = upstream.headers.get(name);
      if (value !== null) back.set(name, value);
    }
    return new Response(upstream.body, { status: upstream.status, headers: back });
  },
};
