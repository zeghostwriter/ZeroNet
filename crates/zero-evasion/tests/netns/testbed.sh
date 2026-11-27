#!/usr/bin/env bash
# A client, four routers and a server in a line, built without privileges.
#
#   client -- r1 -- r2 -- r3 -- r4 -- server
#
# Everything runs inside a new user+network namespace (`unshare -Urnm`), so
# nothing here touches the host's network and nothing needs root. A sniffer
# runs on each router; the server echoes what its kernel gives it.
#
# What it checks, with the client run three ways against the same server:
#   * plain          the control: sniffers see the real name on every hop
#   * md5 decoy      a decoy with a TCP MD5 option: the first routers see the
#                    allowed name, the server never does
#   * ttl decoy      a decoy that expires before the server: the routers it
#                    crosses see it, the last router and the server do not
# and that the ICMP probe measures four hops and the decoy sent with the number it
# learned stops where the probe says it should.
#
# Not checked here: a TTL one too high, where the decoy reaches the server. Over
# a virtual link the packet still points at the page the decoy then overwrites
# with the real hello, so the server may read the real bytes out of the decoy
# segment and the outcome varies from run to run. The sniffers use a packet ring
# for the same reason (see sniff.py).
set -euo pipefail
if [ -z "${ZRAY_TESTBED_INNER:-}" ]; then
  exec env ZRAY_TESTBED_INNER=1 unshare -Urnm "$0" "$@"
fi
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
work=$(mktemp -d)
trap 'kill $(jobs -p) $pids 2>/dev/null || true; rm -rf "$work"' EXIT

test_bin=${1:-$(ls -t "$root"/target/debug/deps/decoy_netns-* 2>/dev/null | grep -v '\.d$' | head -1)}
[ -x "$test_bin" ] || { echo "build the client first: cargo test -p zero-evasion --test decoy_netns --no-run"; exit 2; }

REAL=real.hidden-server.example.net
DECOY=speedtest

pids=""
mk() { unshare -n sleep 3600 >/dev/null 2>&1 & pids="$pids $!"; printf -v "$1" %s "$!"; }
mk C; mk R1; mk R2; mk R3; mk R4; mk S
sleep 0.5
ns() { local p=$1; shift; nsenter -t "$p" -n "$@"; }

link() { # link N PID_A ADDR_A PID_B ADDR_B
  ip link add "v$1a" type veth peer name "v$1b"
  ip link set "v$1a" netns "$2"; ip link set "v$1b" netns "$4"
  ns "$2" ip addr add "$3/24" dev "v$1a"; ns "$2" ip link set "v$1a" up
  ns "$4" ip addr add "$5/24" dev "v$1b"; ns "$4" ip link set "v$1b" up
}
link 1 $C 10.0.1.1 $R1 10.0.1.2
link 2 $R1 10.0.2.1 $R2 10.0.2.2
link 3 $R2 10.0.3.1 $R3 10.0.3.2
link 4 $R3 10.0.4.1 $R4 10.0.4.2
link 5 $R4 10.0.5.1 $S 10.0.5.2
for p in $C $R1 $R2 $R3 $R4 $S; do ns $p ip link set lo up; done
ns $C ip route add default via 10.0.1.2
ns $R1 ip route add default via 10.0.2.2
ns $R2 ip route add default via 10.0.3.2; ns $R2 ip route add 10.0.1.0/24 via 10.0.2.1
ns $R3 ip route add default via 10.0.4.2; ns $R3 ip route add 10.0.1.0/24 via 10.0.3.1
ns $R4 ip route add default via 10.0.5.2; ns $R4 ip route add 10.0.1.0/24 via 10.0.4.1
ns $S ip route add default via 10.0.5.1
for p in $R1 $R2 $R3 $R4; do ns $p sysctl -qw net.ipv4.ip_forward=1; done
ns $C sysctl -qw net.ipv4.ping_group_range="0 0"

n=1
for p in $R1 $R2 $R3 $R4; do
  ns $p python3 "$here/sniff.py" "$work/r$n.log" $REAL,zray.test $DECOY,sp.net & n=$((n+1))
done
ns $S python3 "$here/echo_server.py" "$work/server.log" $REAL $DECOY &
sleep 1
ns $C ping -c1 -W2 10.0.5.2 >/dev/null || { echo "the testbed has no route to the server"; exit 3; }

run() { # run MODE TTL
  # Truncate in place: the sniffers hold these files open.
  for f in r1 r2 r3 r4 server; do : > "$work/$f.log"; done
  ns $C env ZRAY_NETNS_TARGET=10.0.5.2:443 ZRAY_DECOY_FOOLING=$1 ZRAY_DECOY_TTL=$2 \
    "$test_bin" --ignored --nocapture the_server_receives_only 2>&1 | grep -E "echoed|test result|panicked|FAILED" || true
  sleep 1
}
verdict() { python3 - "$work" "$@" <<'P'
import json, sys
work, mode, expect = sys.argv[1], sys.argv[2], sys.argv[3]
def rows(name):
    try: return [json.loads(l) for l in open(f"{work}/{name}.log") if l.strip()]
    except FileNotFoundError: return []
hops = {f"r{i}": rows(f"r{i}") for i in (1, 2, 3, 4)}
server = rows("server")
saw_decoy = {h: any(r["has_decoy"] for r in v) for h, v in hops.items()}
saw_real = {h: any(r["has_real"] for r in v) for h, v in hops.items()}
md5 = {h: any(r["md5"] for r in v if r["has_decoy"]) for h, v in hops.items()}
srv_real = any(r["has_real"] for r in server)
srv_decoy = any(r["has_decoy"] for r in server)
no_server = len(sys.argv) > 4 and sys.argv[4] == "noserver"  # Xray is the server: no echo log
import os
if os.environ.get("ZRAY_TESTBED_DUMP"):
    for h, v in hops.items():
        for r in v: print("   ", h, r)
    for r in server: print("    server", r)
print(f"  {mode}: decoy seen at {saw_decoy}")
print(f"  {mode}: real name seen at {saw_real}; md5 option on the decoy at {md5}")
print(f"  {mode}: server received real={srv_real} decoy={srv_decoy}")
ok = no_server or (srv_real and not srv_decoy)
if expect == "plain":
    ok = ok and not any(saw_decoy.values()) and all(saw_real.values())
elif expect == "raw":
    ok = ok and all(saw_decoy[h] for h in ("r1", "r2", "r3", "r4"))
elif expect == "md5":
    ok = ok and all(saw_decoy[h] for h in ("r1", "r2", "r3", "r4")) and all(md5[h] for h in ("r1", "r4"))
elif expect == "ttl":
    ok = ok and saw_decoy["r1"] and saw_decoy["r2"] and saw_decoy["r3"] and not saw_decoy["r4"]
print(f"  {mode}: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
P
}

status=0
echo "== plain (control)";  run none 0;  verdict plain plain || status=1
echo "== md5 decoy";        run md5 0;   verdict md5 md5 || status=1
echo "== ttl decoy (ttl 3, four routers)"; run ttl 3; verdict ttl ttl || status=1
echo "== ttl decoy learned by the ICMP probe (no number given)"; run ttl auto; verdict auto ttl || status=1

# ---- the shipped runtime, end to end -------------------------------------
# The same path with the real client: `zray` dials an Xray server over TLS with
# `sniSpoof` set, and the sniffers watch the hello go out. Skipped when the
# pieces are not installed.
zray=${ZRAY_BIN:-$root/target/debug/zray}
if command -v xray >/dev/null && command -v curl >/dev/null && [ -x "$zray" ]; then
  fixtures=$root/crates/zero-runtime/tests/fixtures
  uuid=b831381d-6324-4d53-ad4f-8cda48b30811
  cat > "$work/xray.json" <<J
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"10.0.5.2","port":444,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$fixtures/loopback-cert.pem","keyFile":"$fixtures/loopback-key.pem"}]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}
J
  echo runtime-ok > "$work/index.html"
  ns $S python3 -m http.server 8080 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 &
  ns $S xray run -c "$work/xray.json" >/dev/null 2>&1 &
  sleep 2
  # The real name here is the short `zray.test`, so a decoy built on a long base
  # name could not fit it; `sp.net` leaves room for a label in front, and
  # `sp.net` is what the sniffers look for.
  runtime() { # runtime NAME SNISPOOF_JSON EXPECT [noraw]
    # `noraw` drops CAP_NET_RAW from the client, as on a phone that is not
    # rooted: the runtime then cannot inject a raw fake hello and falls back to
    # the decoy sent from the socket itself.
    local drop=""; [ "${4:-}" = noraw ] && drop="setpriv --bounding-set=-net_raw"
    for f in r1 r2 r3 r4 server; do : > "$work/$f.log"; done
    python3 - "$fixtures" "$2" "$uuid" > "$work/zray.json" <<'J'
import json, sys
ca = open(sys.argv[1] + "/loopback-ca.pem").read()
print(json.dumps({
  "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 21090, "protocol": "socks"}],
  "outbounds": [{
    "tag": "proxy", "protocol": "vless",
    "settings": {"vnext": [{"address": "10.0.5.2", "port": 444, "users": [{"id": sys.argv[3], "encryption": "none"}]}]},
    "streamSettings": {"network": "tcp", "security": "tls",
      "tlsSettings": {"serverName": "zray.test", "certificates": [{"usage": "verify", "certificate": [ca]}]}},
    "evasion": {"sniSpoof": json.loads(sys.argv[2])}}]}))
J
    ns $C $drop env ZRAY_LOG=debug "$zray" run "$work/zray.json" >"$work/zray.log" 2>&1 &
    local z=$!
    sleep 2
    local ok=1
    for i in 1 2 3; do
      body=$(ns $C curl -sS -m 15 --socks5-hostname 127.0.0.1:21090 http://127.0.0.1:8080/index.html 2>&1) || true
      [ "$body" = runtime-ok ] || { ok=0; echo "  $1: request $i answered: $body"; }
    done
    kill $z 2>/dev/null || true; wait $z 2>/dev/null || true
    sleep 1
    if [ -n "${ZRAY_TESTBED_DUMP:-}" ]; then grep -iE "decoy|spoof|urgent|evasion|warn|error" "$work/zray.log" | head -12 | cut -c1-240 || true; fi
    verdict "$1" "$3" noserver || status=1
    echo "  $1: three requests through the tunnel: $([ $ok = 1 ] && echo OK || echo FAILED)"
    [ $ok = 1 ] || status=1
  }
  echo "== runtime, raw socket available: zray injects a fake hello, through xray over TLS"
  runtime raw '{"fakeSni":"sp.net","method":"decoy","fooling":"md5"}' raw
  echo "== runtime, no raw socket: zray with an md5 decoy from the socket itself"
  runtime md5 '{"fakeSni":"sp.net","method":"decoy","fooling":"md5"}' md5 noraw
  echo "== runtime, no raw socket: zray with a ttl decoy (ttl 3)"
  runtime ttl '{"fakeSni":"sp.net","method":"decoy","fooling":"ttl","ttl":3}' ttl noraw
else
  echo "== runtime: skipped (needs xray, curl and a built zray)"
fi

echo "== autottl"
ns $C env ZRAY_NETNS_TARGET=10.0.5.2:443 "$test_bin" --ignored --nocapture autottl_measures 2>&1 | grep -E "LEARNED|test result|panicked" || status=1
exit $status
