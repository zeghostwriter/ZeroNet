// ZeroNet crowd relay.
//
// Apps post the results of their server tests here; the `crowd` GitHub
// Action exports them, ranks them and publishes rankings.json in the
// repository. This Worker only queues: it ranks nothing, and all it tells
// an app is the name of the network its results were counted under.
//
// What is stored, per result: the time, the network (a mobile carrier's
// MCC+MNC, or the ISP's AS number, which Cloudflare supplies), a daily
// pseudonym of the sender, the server's link key or the Cloudflare address,
// success, and delay. The sender's IP address is only used to derive the
// pseudonym and is never written anywhere. Rows are deleted after two days.

const MAX_BODY = 8 * 1024;
const MAX_RESULTS = 40;
const MAX_CLEAN = 10;
// Results one sender may add per hour: plenty for real use, a ceiling for
// a flood.
const PER_HOUR = 200;
const KEEP_SECONDS = 2 * 24 * 3600;
const EXPORT_LIMIT = 100000;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const isServerId = (s) => typeof s === "string" && /^[0-9a-f]{16}$/.test(s);
const isIpv4 = (s) =>
  typeof s === "string" &&
  /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s) &&
  s.split(".").every((p) => String(Number(p)) === p && Number(p) <= 255);
const delay = (ms) => (Number.isInteger(ms) && ms >= 0 && ms <= 60000 ? ms : null);

// The sender's pseudonym for today: an HMAC of the day and the address, so
// it cannot be reversed, and it changes at midnight UTC.
async function pseudonym(secret, ip, now) {
  const day = Math.floor(now / 86400);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${day}|${ip}`));
  return [...new Uint8Array(mac).slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function report(request, env) {
  if (!env.SALT_SECRET) return json({ error: "relay not configured" }, 503);
  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: "too large" }, 413);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: "not JSON" }, 400);
  }
  if (body?.v !== 1) return json({ error: "unsupported version" }, 400);

  // A carrier the phone named, or else the ISP this request came from.
  let net = null;
  if (typeof body.net === "string" && /^cell:\d{5,6}$/.test(body.net)) {
    net = body.net;
  } else if (request.cf?.asn) {
    net = `asn:${request.cf.asn}`;
  }
  if (!net) return json({ error: "unknown network" }, 400);

  const rows = [];
  for (const r of (Array.isArray(body.results) ? body.results : []).slice(0, MAX_RESULTS)) {
    if (isServerId(r?.id) && typeof r.ok === "boolean") rows.push(["server", r.id, r.ok, r.ok ? delay(r.ms) : null]);
  }
  for (const c of (Array.isArray(body.clean) ? body.clean : []).slice(0, MAX_CLEAN)) {
    if (isIpv4(c?.ip)) rows.push(["ip", c.ip, true, delay(c.ms)]);
  }
  if (rows.length === 0) return json({ net, accepted: 0 });

  const now = Math.floor(Date.now() / 1000);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const reporter = await pseudonym(env.SALT_SECRET, ip, now);

  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE reporter = ? AND ts > ?")
    .bind(reporter, now - 3600)
    .first();
  if ((recent?.n ?? 0) + rows.length > PER_HOUR) return json({ error: "slow down", net }, 429);

  const insert = env.DB.prepare(
    "INSERT INTO reports (ts, net, reporter, kind, item, ok, ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  await env.DB.batch(rows.map(([kind, item, ok, ms]) => insert.bind(now, net, reporter, kind, item, ok ? 1 : 0, ms)));
  return json({ net, accepted: rows.length });
}

async function exportReports(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!env.EXPORT_TOKEN || !timingSafeEqual(auth, `Bearer ${env.EXPORT_TOKEN}`)) {
    return json({ error: "unauthorized" }, 401);
  }
  const url = new URL(request.url);
  const since = Number.parseInt(url.searchParams.get("since") || "0", 10) || 0;
  const { results } = await env.DB.prepare(
    "SELECT ts, net, reporter, kind, item, ok, ms FROM reports WHERE ts >= ? ORDER BY id LIMIT ?",
  )
    .bind(since, EXPORT_LIMIT)
    .all();
  return json(results.map((r) => ({ ...r, ok: r.ok === 1, ms: r.ms ?? null })));
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    try {
      if (pathname === "/v1/report" && request.method === "POST") return await report(request, env);
      if (pathname === "/v1/export" && request.method === "GET") return await exportReports(request, env);
      if (pathname === "/") return new Response("ZeroNet crowd relay\n", { headers: { "content-type": "text/plain" } });
      return json({ error: "not found" }, 404);
    } catch {
      return json({ error: "internal error" }, 500);
    }
  },

  async scheduled(_event, env) {
    const cutoff = Math.floor(Date.now() / 1000) - KEEP_SECONDS;
    await env.DB.prepare("DELETE FROM reports WHERE ts < ?").bind(cutoff).run();
  },
};
