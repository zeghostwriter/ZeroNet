// Runs the Worker under wrangler's local workerd and checks it against a fake
// egress: `node --test test/` (needs wrangler on the PATH).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { after, before, test } from "node:test";
import { isTide } from "../src/worker.js";

const NAME = "0123456789abcdef0123456789abcdef";
const PREFIX = "/assets/v2";
let origin, worker, base;
const seen = [];
let cloudflareSays530 = false;

const listen = (server) =>
  new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server.address().port)));

before(async () => {
  origin = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      if (cloudflareSays530) {
        // What Cloudflare itself says when it cannot reach an origin.
        res.writeHead(530, { "content-type": "text/plain" });
        res.end("error code: 1016");
      } else if (req.url.includes("/d/")) {
        // A download: three parts, a little apart, as a real pipe sends.
        res.writeHead(200, { "content-type": "application/octet-stream", "x-secret": "egress-only" });
        let n = 0;
        const timer = setInterval(() => {
          res.write(Buffer.alloc(1000, ++n));
          if (n === 3) { clearInterval(timer); res.end(); }
        }, 120);
      } else {
        res.writeHead(200, { "content-type": "application/octet-stream", "x-secret": "egress-only" });
        res.end(Buffer.from(`got ${Buffer.concat(chunks).length}`));
      }
    });
  });
  const originPort = await listen(origin);
  const probe = http.createServer();
  const port = await listen(probe);
  await new Promise((ok) => probe.close(ok));
  base = `http://127.0.0.1:${port}`;
  worker = spawn("wrangler", [
    "dev", "--port", String(port), "--ip", "127.0.0.1",
    "--var", `ORIGIN:http://127.0.0.1:${originPort}`, "--var", `PATH_PREFIX:${PREFIX}`,
  ], { cwd: new URL("..", import.meta.url).pathname, stdio: ["ignore", "pipe", "pipe"],
       env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" } });
  await new Promise((ok, fail) => {
    const timer = setTimeout(() => fail(new Error("wrangler dev did not start")), 90000);
    const look = (d) => { if (String(d).includes("Ready on")) { clearTimeout(timer); ok(); } };
    worker.stdout.on("data", look);
    worker.stderr.on("data", look);
  });
});

after(() => { worker?.kill(); origin?.close(); });

test("the routing rule accepts Tide's three requests and nothing else", () => {
  assert.ok(isTide("POST", `${PREFIX}/${NAME}/open`, PREFIX));
  assert.ok(isTide("POST", `${PREFIX}/${NAME}/u/12`, PREFIX));
  assert.ok(isTide("GET", `${PREFIX}/${NAME}/d/3`, PREFIX));
  for (const [m, p] of [
    ["GET", `${PREFIX}/${NAME}/open`], ["POST", `${PREFIX}/${NAME}/d/3`],
    ["POST", `${PREFIX}/${NAME}/u/x`], ["POST", `${PREFIX}/${NAME}/u/`],
    ["POST", `${PREFIX}/short/open`], ["POST", `/elsewhere/${NAME}/open`],
    ["GET", "/"], ["DELETE", `${PREFIX}/${NAME}/open`],
    ["POST", `${PREFIX}/${NAME}/open/../x`],
  ]) assert.ok(!isTide(m, p, PREFIX), `${m} ${p}`);
});

test("a visitor sees the decoy site, never the egress", async () => {
  const home = await fetch(`${base}/`);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /^<!doctype html>/);
  const missing = await fetch(`${base}/nothing`);
  assert.equal(missing.status, 404);
  const before = seen.length;
  const garbage = await fetch(`${base}${PREFIX}/short/open`, { method: "POST", body: "x" });
  assert.equal(garbage.status, 404);
  assert.equal(seen.length, before, "nothing reached the egress");
});

test("an upload is passed on whole, without the app's headers, and the answer comes back", async () => {
  const body = Buffer.alloc(300_000, 7);
  const res = await fetch(`${base}${PREFIX}/${NAME}/u/1?t=abc`, {
    method: "POST", body,
    headers: { cookie: "private=1", "x-forwarded-for": "1.2.3.4", authorization: "Bearer x" },
  });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "got 300000");
  assert.equal(res.headers.get("x-secret"), null, "the egress's own headers stay behind");
  const got = seen.at(-1);
  assert.equal(got.url, `${PREFIX}/${NAME}/u/1?t=abc`);
  for (const name of ["cookie", "authorization", "x-forwarded-for", "cf-connecting-ip"]) {
    assert.equal(got.headers[name], undefined, `${name} was passed on`);
  }
});

test("a download is streamed as it arrives, not collected first", async () => {
  const started = Date.now();
  const res = await fetch(`${base}${PREFIX}/${NAME}/d/1?t=abc`);
  assert.equal(res.status, 200);
  const reader = res.body.getReader();
  const first = await reader.read();
  const firstAt = Date.now() - started;
  let total = first.value.length;
  for (;;) { const { done, value } = await reader.read(); if (done) break; total += value.length; }
  assert.equal(total, 3000);
  assert.ok(firstAt < 330, `first bytes took ${firstAt} ms; the whole answer takes ~360`);
});

test("a Cloudflare origin-error page is replaced by an ordinary 502", async () => {
  cloudflareSays530 = true;
  const res = await fetch(`${base}${PREFIX}/${NAME}/u/1`, { method: "POST", body: "x" });
  cloudflareSays530 = false;
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /502 Bad Gateway/);
  assert.doesNotMatch(text, /1016/);
});

test("an egress that cannot be reached looks like a proxy with its backend down", async () => {
  origin.close();
  origin.closeAllConnections?.();
  const res = await fetch(`${base}${PREFIX}/${NAME}/open`, { method: "POST", body: "hello" });
  assert.equal(res.status, 502);
  assert.match(await res.text(), /502 Bad Gateway/);
});
