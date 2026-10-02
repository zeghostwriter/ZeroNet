"""Generating an equivalent configuration for every core, in its own dialect.

The comparison is only fair if each core is asked to do the same job. Two ways
to get that wrong, and this module exists to avoid both:

* **One JSON for everyone.** Xray-core and xray-rust read the same dialect, so
  they get byte-identical files. sing-box does not, and pretending otherwise
  would mean measuring a config parser instead of a data path.
* **Silently dropping the parts a core cannot express.** A core that cannot
  carry a scenario is recorded as unsupported, with the diagnostic its own
  config checker produced. It is never quietly given a weaker config and
  reported as equal.

The generated server is the same for every client, which is what makes "only
the client core changed" true. The server core is a single global choice for a
run; a scenario the server cannot serve is skipped rather than quietly measured
against a different server.
"""

from __future__ import annotations

import base64
import json
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

class UnsupportedShape(Exception):
    """A combination this config dialect has no spelling for.

    A dedicated exception rather than `SystemExit`: refusing to invent a config
    is an error the runner has to handle and report, not a request to end the
    process.
    """


# A fixed SNI and path. They have to be stable across every core, because the
# certificate, the reality handshake and the WebSocket upgrade all key off them.
SNI = "bench.local"
WS_PATH = "/bench"
GRPC_SERVICE = "bench"
XHTTP_PATH = "/bench"

# A fixed UUID so a diff of two result files shows a number changing rather than
# a whole config. It is a loopback-only fixture, not a credential.
UUID = "00000000-0000-4000-8000-000000000001"
PASSWORD = "bench-password-0001"


# ---------------------------------------------------------------------------
# The link being measured
# ---------------------------------------------------------------------------


#: What a core is given unless a scenario asks for another. The most common
#: ClientHello there is, so the baseline row is the one a reader expects.
DEFAULT_FINGERPRINT = "chrome"


@dataclass(frozen=True)
class Link:
    """One protocol / transport / security combination.

    The three axes are independent on purpose. Vision is not a security layer
    but a flow inside VLESS, and mux is not a transport either; both are
    attributes of a link, which is why they live here rather than being encoded
    into the transport name.
    """

    protocol: str
    transport: str = "raw"
    security: str = "none"
    vision: bool = False
    mux: bool = False
    mldsa: bool = False
    """REALITY with an ML-DSA-65 post-quantum signature check."""
    fingerprint: str = DEFAULT_FINGERPRINT
    """uTLS ClientHello fingerprint, for the layers that synthesise one.

    Measured per fingerprint because it is a per-fingerprint code path: a
    synthetic ClientHello is not a fixed cost, and the expensive ones are the
    reason a TLS stack is fingerprinted at all.
    """

    @property
    def xhttp_mode(self) -> str | None:
        return {
            "xhttp-h1": "stream-one",
            "xhttp-h2": "stream-up",
            "xhttp-h3": "packet-up",
        }.get(self.transport)

    @property
    def xhttp_version(self) -> str | None:
        return {"xhttp-h1": "1.1", "xhttp-h2": "2", "xhttp-h3": "3"}.get(self.transport)

    @property
    def flow(self) -> str:
        return "xtls-rprx-vision" if self.vision else ""

    @property
    def quic_based(self) -> bool:
        """Hysteria 2 and TUIC carry their own QUIC and TLS, so they have no
        Xray `streamSettings` at all. Treating them as `raw`/`none` would put
        them in a transport comparison they are not part of."""
        return self.protocol in ("hysteria2", "tuic")

    def name(self) -> str:
        parts = [self.protocol]
        if self.transport != "raw":
            parts.append(self.transport)
        if self.security != "none":
            parts.append(self.security)
        if self.vision:
            parts.append("vision")
        if self.mux:
            parts.append("mux")
        if self.mldsa:
            parts.append("mldsa65")
        if self.fingerprint != DEFAULT_FINGERPRINT:
            parts.append(self.fingerprint)
        return "-".join(parts)

    def describe(self) -> str:
        bits = [self.protocol, self.transport, self.security]
        if self.vision:
            bits.append("Vision")
        if self.mux:
            bits.append("mux")
        if self.mldsa:
            bits.append("ML-DSA-65")
        if self.fingerprint != DEFAULT_FINGERPRINT:
            bits.append(f"uTLS {self.fingerprint}")
        return " / ".join(bits)


# ---------------------------------------------------------------------------
# Credentials and certificates
# ---------------------------------------------------------------------------


def _openssl(*args: str, stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["openssl", *args], input=stdin, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"openssl {' '.join(args)} failed:\n{proc.stderr.decode(errors='replace')}"
        )
    return proc.stdout


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _der_tlvs(buf: bytes, out: list | None = None, depth: int = 0) -> list:
    """Minimal DER walker. Enough to pull one value out of a PKCS#8 blob."""
    out = [] if out is None else out
    i = 0
    while i < len(buf):
        tag = buf[i]
        i += 1
        n = buf[i]
        i += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[i : i + k], "big")
            i += k
        body = buf[i : i + n]
        i += n
        if tag & 0x20:
            _der_tlvs(body, out, depth + 1)
        else:
            out.append((depth, tag, body))
    return out


# RFC 7748 X25519, in full. Written out rather than pulled from a dependency so
# the fixture key generation is auditable and needs nothing installed; the
# numbers it produces are checked against the rest of the config by the fact
# that a REALITY handshake either completes or does not.
_P25519 = 2**255 - 19


def _x25519(scalar: bytes, u: int) -> int:
    x1 = u
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (scalar[t // 8] >> (t % 8)) & 1
        if swap ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P25519
        aa = a * a % _P25519
        b = (x2 - z2) % _P25519
        bb = b * b % _P25519
        e = (aa - bb) % _P25519
        c = (x3 + z3) % _P25519
        d = (x3 - z3) % _P25519
        da = d * a % _P25519
        cb = c * b % _P25519
        x3 = (da + cb) % _P25519
        x3 = x3 * x3 % _P25519
        z3 = (da - cb) % _P25519
        z3 = x1 * z3 % _P25519 * z3 % _P25519
        x2 = aa * bb % _P25519
        z2 = e * ((aa + 121665 * e) % _P25519) % _P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2 * pow(z2, _P25519 - 2, _P25519) % _P25519


def reality_keypair() -> tuple[str, str]:
    """(private, public) as unpadded base64url, the spelling every core uses."""
    private = secrets.token_bytes(32)
    private = bytearray(private)
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    private = bytes(private)
    public = _x25519(private, 9).to_bytes(32, "little")
    return _b64url(private), _b64url(public)


def mldsa65_keys() -> tuple[str, str] | None:
    """(seed, verify) as base64url: Xray's `mldsa65Seed` and `mldsa65Verify`.

    OpenSSL 3.5 is the only thing here that can produce an ML-DSA-65 key, so its
    absence downgrades the scenario rather than failing the run: a benchmark that
    cannot run is worse than one that says why it did not.
    """
    try:
        pem = _openssl("genpkey", "-algorithm", "ML-DSA-65")
        der = _openssl("pkey", "-inform", "PEM", "-outform", "DER", stdin=pem)
        spki = _openssl("pkey", "-inform", "PEM", "-pubout", "-outform", "DER", stdin=pem)
    except (RuntimeError, FileNotFoundError):
        return None
    private = [body for _, tag, body in _der_tlvs(der) if tag == 0x04]
    if not private:
        return None
    seed = None
    for _, tag, body in _der_tlvs(private[0]):
        if tag == 0x04 and len(body) == 32:
            seed = body
            break
    # The public key is the BIT STRING at the end of the SPKI: 1952 bytes for
    # ML-DSA-65.
    bits = [body for _, tag, body in _der_tlvs(spki) if tag == 0x03]
    if seed is None or not bits:
        return None
    verify = bits[0][1:]  # strip the unused-bits octet
    if len(verify) != 1952:
        return None
    return _b64url(seed), _b64url(verify)


@dataclass
class Identity:
    """Everything both ends of a fixture need to agree on."""

    directory: Path
    reality_private: str
    reality_public: str
    reality_short_id: str
    ca_pem: str
    cert_pem: str
    key_pem: str
    mldsa_seed: str | None = None
    mldsa_verify: str | None = None
    ss_passwords: dict[str, str] = field(default_factory=dict)

    def path(self, name: str) -> Path:
        return self.directory / name

    def summary(self) -> dict:
        """A redacted description, safe to commit next to the results.

        The private key and the server key are fixture material, but a results
        file is a document people read and copy, so nothing that looks like a
        secret is copied into it.
        """
        return {
            "sni": SNI,
            "cert_sha256": _b64url(_sha256(self.cert_pem.encode())),
            "reality_short_id_len": len(self.reality_short_id),
            "reality_public_key_sha256": _b64url(_sha256(self.reality_public.encode())),
            "mldsa65": bool(self.mldsa_seed),
        }


def _sha256(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()


SS_METHODS = {
    "shadowsocks": "aes-128-gcm",
    "shadowsocks2022": "2022-blake3-aes-128-gcm",
}

# Shadowsocks 2022 keys are the method's key length in bytes, base64 encoded.
_SS2022_KEY_LEN = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}


def generate_identity(directory: Path, *, with_mldsa: bool = False) -> Identity:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_pem, key_pem, cert_pem = _make_certificate_chain(directory)
    priv, pub = reality_keypair()
    # Standard base64 *with* padding, not the URL-safe unpadded form the REALITY
    # keys use. A Shadowsocks 2022 PSK is decoded with Go's standard encoding,
    # which rejects an unpadded string with `illegal base64 data`.
    ss_passwords = {
        "shadowsocks": base64.b64encode(secrets.token_bytes(16)).decode(),
        "shadowsocks2022": base64.b64encode(
            secrets.token_bytes(_SS2022_KEY_LEN[SS_METHODS["shadowsocks2022"]])
        ).decode(),
    }
    identity = Identity(
        directory=directory,
        reality_private=priv,
        reality_public=pub,
        # An even-length hex short id. REALITY pads a short one on the left with
        # zeroes, so an empty or odd-length value is a silent mismatch.
        reality_short_id=secrets.token_hex(4),
        ca_pem=ca_pem,
        cert_pem=cert_pem,
        key_pem=key_pem,
        ss_passwords=ss_passwords,
    )
    if with_mldsa:
        keys = mldsa65_keys()
        if keys is not None:
            identity.mldsa_seed, identity.mldsa_verify = keys
    return identity


def _make_certificate_chain(directory: Path) -> tuple[str, str, str, str]:
    """A private CA and a loopback server certificate.

    Generated through the openssl CLI rather than a Python TLS library because
    every runner that can build the cores can run openssl, and because a
    certificate nobody had to trust system-wide is the only kind that can be
    published next to a benchmark.
    """
    ca_key = directory / "ca.key"
    ca_crt = directory / "ca.pem"
    # The server key is `key.pem` because that is the name every config in this
    # harness refers to, and a mismatch here surfaces as an opaque
    # "failed to parse key" from whichever core was tried first.
    srv_key = directory / "key.pem"
    srv_csr = directory / "server.csr"
    srv_crt = directory / "cert.pem"
    ext = directory / "server.ext"

    for path in (ca_key, ca_crt, srv_key, srv_csr, srv_crt, ext):
        path.unlink(missing_ok=True)

    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
    _openssl(
        "req", "-x509", "-new", "-nodes",
        "-key", str(ca_key), "-sha256", "-days", "2",
        "-subj", "/CN=zray-bench-ca",
        "-out", str(ca_crt),
    )
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(srv_key))
    _openssl(
        "req", "-new", "-key", str(srv_key),
        "-subj", f"/CN={SNI}", "-out", str(srv_csr),
    )
    ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{SNI},DNS:localhost,IP:127.0.0.1\n"
    )
    _openssl(
        "x509", "-req", "-in", str(srv_csr),
        "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(srv_crt), "-days", "2", "-sha256", "-extfile", str(ext),
    )
    for produced in (ca_crt, srv_key, srv_crt):
        if not produced.exists():
            raise RuntimeError(f"openssl did not produce {produced}")
    return ca_key.read_text(), ca_crt.read_text(), srv_key.read_text(), srv_crt.read_text()


# ---------------------------------------------------------------------------
# Xray dialect
# ---------------------------------------------------------------------------


def _xray_transport(
    link: Link, *, inbound: bool, identity: Identity, handshake_port: int = 443
) -> dict:
    """`streamSettings` for the Xray dialect, which Zray and xray-rust also read."""
    if link.quic_based:
        # Hysteria 2 and TUIC carry their own QUIC and TLS; there is nothing to
        # put here and inventing an entry would make the config unreadable.
        return {}
    settings: dict = {
        "network": xray_network(link.transport),
        "security": link.security,
    }
    if link.transport == "ws":
        settings["wsSettings"] = {"path": WS_PATH, "host": SNI}
    elif link.transport == "httpupgrade":
        settings["httpupgradeSettings"] = {"path": WS_PATH, "host": SNI}
    elif link.transport == "grpc":
        settings["grpcSettings"] = {
            "serviceName": GRPC_SERVICE,
            "authority": SNI,
            "multiMode": False,
        }
    elif link.transport.startswith("xhttp"):
        settings["xhttpSettings"] = {
            "host": SNI,
            "path": XHTTP_PATH,
            "mode": link.xhttp_mode,
            "httpVersion": link.xhttp_version,
        }
    if link.security == "tls":
        tls: dict = {
            "serverName": SNI, "alpn": _alpn(link), "fingerprint": link.fingerprint,
        }
        if inbound:
            tls["certificates"] = [
                {
                    "certificateFile": str(identity.path("cert.pem")),
                    "keyFile": str(identity.path("key.pem")),
                }
            ]
        else:
            # A private CA, verified. Zray rejects `allowInsecure: true` outright,
            # and a benchmark that silently disables verification would be
            # measuring a different handshake than the one a user gets.
            tls["certificates"] = [
                {"usage": "verify", "certificateFile": str(identity.path("ca.pem"))}
            ]
        settings["tlsSettings"] = tls
    elif link.security == "reality":
        reality: dict = {
            "serverName": SNI, "fingerprint": link.fingerprint, "spiderX": "/",
        }
        if inbound:
            reality.update(
                {
                    "show": False,
                    "privateKey": identity.reality_private,
                    "serverNames": [SNI],
                    "shortIds": [identity.reality_short_id],
                    # A REALITY server forwards a client that fails the key check
                    # to this address. No valid client ever reaches it, so it
                    # points at the local sink: a fixture that reaches the
                    # internet is a fixture whose result depends on a network it
                    # does not control.
                    "dest": f"127.0.0.1:{handshake_port}",
                    "target": f"127.0.0.1:{handshake_port}",
                    # Xray-core's REALITY server rejects a client whose reported
                    # version is outside this range, and its default lower bound
                    # is the current Xray version. That default is a product
                    # decision about which clients to serve, not a property of
                    # REALITY, and leaving it in place would turn a capability
                    # measurement into a version-number measurement. Both bounds
                    # are widened here, and the fact is recorded in the report.
                    # Each component must fit in a byte: Xray parses these
                    # bounds component by component and refuses a wider one.
                    "minClientVer": "0.0.0",
                    "maxClientVer": "255.255.255",
                    "maxTimeDiff": 0,
                    "xver": 0,
                }
            )
        else:
            reality["publicKey"] = identity.reality_public
            reality["shortId"] = identity.reality_short_id
            if link.mldsa:
                # A row named `...-mldsa65-...` must not carry a plain REALITY
                # handshake, so it is refused rather than generated without it.
                if not identity.mldsa_verify:
                    raise UnsupportedShape(
                        "this scenario is ML-DSA-65 REALITY and the fixture has no "
                        "ML-DSA-65 key, so generating it would produce a plain "
                        "REALITY row under an ML-DSA name"
                    )
                reality["mldsa65Verify"] = identity.mldsa_verify
        settings["realitySettings"] = reality
    return settings


def ss_method(protocol: str) -> str:
    """The Shadowsocks cipher for a scenario protocol.

    Both rows are `protocol: "shadowsocks"`; the ciphers are what differ, and
    2022's are the SIP022 blake3 variants with a key-length-checked password.
    """
    return SS_METHODS[protocol]


def xray_protocol(protocol: str) -> str:
    """The `protocol` spelling for a scenario protocol.

    Shadowsocks 2022 is a Shadowsocks *method*, not a separate protocol: the
    configuration says `protocol: "shadowsocks"` with
    `method: "2022-blake3-..."`. Naming it as its own protocol produces
    `unknown config id: shadowsocks2022`, which reads as a missing feature.
    """
    if protocol == "shadowsocks2022":
        return "shadowsocks"
    return protocol


def xray_network(transport: str) -> str:
    """The `streamSettings.network` spelling for a scenario transport.

    A scenario names the *wire engine* -- `xhttp-h1`, `xhttp-h2`, `xhttp-h3` --
    because that is the thing being varied. Xray's `network` names the
    *protocol*, and selects the engine with `xhttpSettings.httpVersion`. Writing
    the scenario's name straight into `network` produces
    `unknown transport protocol: xhttp-h1`, which is a refusal that looks like a
    missing feature.
    """
    if transport.startswith("xhttp"):
        return "xhttp"
    if transport == "raw":
        return "raw"
    return transport


def _alpn(link: Link) -> list[str]:
    """The ALPN a real CDN front would offer for this transport.

    Picking the same ALPN on both ends is what makes the TLS rows comparable;
    a core that offered `h2` against a raw transport would be measured on a
    different handshake than its neighbour.
    """
    if link.quic_based:
        # Hysteria 2 and TUIC are QUIC end to end; `h3` is the only ALPN that
        # can ever appear, and offering anything else is a configuration error
        # rather than a choice.
        return ["h3"]
    if link.transport.startswith("xhttp"):
        return {"xhttp-h1": ["http/1.1"], "xhttp-h2": ["h2"], "xhttp-h3": ["h3"]}[
            link.transport
        ]
    if link.transport in ("ws", "httpupgrade"):
        return ["http/1.1"]
    if link.transport == "grpc":
        return ["h2"]
    return ["h2", "http/1.1"]


def _xray_credentials(link: Link, identity: Identity, *, inbound: bool) -> dict:
    """`settings` for the Xray dialect."""
    if inbound:
        if link.protocol == "vless":
            clients = [{"id": UUID}]
            if link.vision:
                clients[0]["flow"] = link.flow
            return {"clients": clients, "decryption": "none"}
        if link.protocol == "vmess":
            return {"clients": [{"id": UUID}]}
        if link.protocol == "trojan":
            return {"clients": [{"password": PASSWORD}]}
        if link.protocol in ("shadowsocks", "shadowsocks2022"):
            return {
                "method": ss_method(link.protocol),
                "password": identity.ss_passwords[link.protocol],
            }
        if link.protocol == "anytls":
            return {"password": PASSWORD}
        if link.protocol == "hysteria2":
            return {"password": PASSWORD}
        if link.protocol == "tuic":
            return {"uuid": UUID, "password": PASSWORD}
    else:
        if link.protocol == "vless":
            user = {"id": UUID, "encryption": "none"}
            if link.vision:
                user["flow"] = link.flow
            return {"vnext": [{"address": "127.0.0.1", "port": 0, "users": [user]}]}
        if link.protocol == "vmess":
            return {"vnext": [{"address": "127.0.0.1", "port": 0, "users": [{"id": UUID, "security": "auto"}]}]}
        if link.protocol == "trojan":
            return {"servers": [{"address": "127.0.0.1", "port": 0, "password": PASSWORD}]}
        if link.protocol in ("shadowsocks", "shadowsocks2022"):
            return {
                "servers": [
                    {
                        "address": "127.0.0.1",
                        "port": 0,
                        "method": ss_method(link.protocol),
                        "password": identity.ss_passwords[link.protocol],
                    }
                ]
            }
        if link.protocol == "anytls":
            return {"servers": [{"address": "127.0.0.1", "port": 0, "password": PASSWORD}]}
        if link.protocol == "hysteria2":
            return {"servers": [{"address": "127.0.0.1", "port": 0, "password": PASSWORD}]}
        if link.protocol == "tuic":
            return {
                "servers": [
                    {"address": "127.0.0.1", "port": 0, "uuid": UUID, "password": PASSWORD}
                ]
            }
    raise UnsupportedShape(f"no Xray-dialect credentials for {link.protocol}")


def _xray_fill_ports(settings: dict, port: int) -> None:
    """Fill the reserved port into every place it appears.

    The credential builders do not know which port the server will get -- it is
    allocated per run -- so they leave a zero behind and this walks the finished
    structure. A single `settings.servers[0].port` for one dialect and
    `outbounds[0].server_port` for another is exactly the kind of detail that is
    easy to get wrong and invisible until a run fails on someone else's runner.
    """
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "port" and value == 0:
                    node[key] = port
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(settings)


def xray_server(link: Link, identity: Identity, port: int, handshake_port: int = 443) -> dict:
    inbound = {
        "tag": "in",
        "listen": "127.0.0.1",
        "port": port,
        "protocol": xray_protocol(link.protocol),
        "settings": _xray_credentials(link, identity, inbound=True),
    }
    stream = _xray_transport(
        link, inbound=True, identity=identity, handshake_port=handshake_port
    )
    if stream:
        inbound["streamSettings"] = stream
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["in"], "outboundTag": "direct"}]},
    }


def xray_client(link: Link, identity: Identity, proxy_port: int, server_port: int) -> dict:
    settings = _xray_credentials(link, identity, inbound=False)
    _xray_fill_ports(settings, server_port)
    outbound = {
        "tag": "proxy",
        "protocol": xray_protocol(link.protocol),
        "settings": settings,
    }
    stream = _xray_transport(link, inbound=False, identity=identity)
    if stream:
        outbound["streamSettings"] = stream
    if link.mux and link.protocol == "vless":
        outbound["mux"] = {"enabled": True, "concurrency": 8}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": proxy_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
        "routing": {
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]
        },
    }


# ---------------------------------------------------------------------------
# sing-box dialect
# ---------------------------------------------------------------------------


def _singbox_transport(link: Link) -> dict | None:
    """sing-box expresses raw TCP as the absence of a transport block, so this
    returns None rather than `{"type": "raw"}`, which it would reject."""
    if link.quic_based or link.transport == "raw":
        return None
    if link.transport == "ws":
        return {"type": "ws", "path": WS_PATH, "headers": {"Host": SNI}}
    if link.transport == "httpupgrade":
        return {"type": "httpupgrade", "path": WS_PATH, "host": SNI}
    if link.transport == "grpc":
        return {"type": "grpc", "service_name": GRPC_SERVICE}
    # XHTTP has no sing-box equivalent. The capability probe discovers that;
    # there is deliberately no approximation here.
    raise UnsupportedShape(f"sing-box has no {link.transport} transport")


def _singbox_tls(
    link: Link, identity: Identity, *, inbound: bool, handshake_port: int
) -> dict:
    if link.security in ("tls", "reality") and not singbox_tls_capable(link.protocol):
        raise UnsupportedShape(
            f"sing-box has no TLS block on a {link.protocol} inbound or outbound"
        )
    # Hysteria 2 and TUIC are TLS protocols with no `streamSettings` equivalent;
    # "no TLS" is not a state they can be in, so the security axis of the
    # scenario is upgraded rather than emitted as a config that cannot load.
    security = "tls" if link.quic_based else link.security
    if security == "none":
        return {"enabled": False}
    if inbound:
        tls: dict = {"enabled": True, "server_name": SNI, "alpn": _alpn(link)}
        if security == "tls":
            tls["certificate_path"] = str(identity.path("cert.pem"))
            tls["key_path"] = str(identity.path("key.pem"))
        else:
            if link.mldsa:
                raise UnsupportedShape(
                    "sing-box's REALITY options have no ML-DSA-65 field, so this "
                    "scenario cannot be generated as named for it"
                )
            reality: dict = {
                "enabled": True,
                "private_key": identity.reality_private,
                "short_id": [identity.reality_short_id],
                # The fallback target is never reached by a valid client, and
                # pointing it at loopback keeps the fixture from needing the
                # internet.
                "handshake": {"server": SNI, "server_port": handshake_port},
            }
            tls["reality"] = reality
        return tls
    tls = {"enabled": True, "server_name": SNI, "alpn": _alpn(link)}
    tls["utls"] = {"enabled": True, "fingerprint": link.fingerprint}
    # `security`, not `link.security`: a QUIC protocol rewrites the first to
    # "tls" above, and testing the original sent a Hysteria 2 outbound down the
    # REALITY branch -- a REALITY block and a uTLS fingerprint on a protocol that
    # uses neither, and no `insecure`, which is the flag it actually needs.
    if security == "tls":
        # sing-box has no way to hand a client a private CA, so the fixture
        # certificate is trusted explicitly. The report says so, because it makes
        # the TLS rows a comparison of everything except chain validation.
        tls["insecure"] = True
    else:
        if link.mldsa:
            raise UnsupportedShape(
                "sing-box's REALITY options have no ML-DSA-65 field, so this "
                "scenario cannot be generated as named for it"
            )
        tls["reality"] = {
            "enabled": True,
            "public_key": identity.reality_public,
            "short_id": identity.reality_short_id,
        }
    return tls


def _singbox_credentials(link: Link, identity: Identity, *, inbound: bool) -> dict:
    if inbound:
        if link.protocol in ("vless", "vmess"):
            user = {"uuid": UUID}
            if link.protocol == "vless" and link.vision:
                user["flow"] = link.flow
            return {"users": [user]}
        if link.protocol == "trojan":
            return {"users": [{"password": PASSWORD}]}
        if link.protocol in ("shadowsocks", "shadowsocks2022"):
            return {
                "method": ss_method(link.protocol),
                "password": identity.ss_passwords[link.protocol],
            }
        if link.protocol == "anytls":
            return {"password": PASSWORD}
        if link.protocol == "hysteria2":
            return {"password": PASSWORD}
        if link.protocol == "tuic":
            return {"users": [{"uuid": UUID, "password": PASSWORD}]}
    else:
        base = {"server": "127.0.0.1"}
        if link.protocol in ("vless", "vmess"):
            user = {"uuid": UUID}
            if link.protocol == "vless" and link.vision:
                user["flow"] = link.flow
            return {**base, **user}
        if link.protocol == "trojan":
            return {**base, "password": PASSWORD}
        if link.protocol in ("shadowsocks", "shadowsocks2022"):
            return {
                **base,
                "method": ss_method(link.protocol),
                "password": identity.ss_passwords[link.protocol],
            }
        if link.protocol == "anytls":
            return {**base, "password": PASSWORD}
        if link.protocol == "hysteria2":
            return {**base, "password": PASSWORD}
        if link.protocol == "tuic":
            return {**base, "uuid": UUID, "password": PASSWORD}
    raise UnsupportedShape(f"no sing-box credentials for {link.protocol}")


#: sing-box protocol types that accept a `tls` block. Shadowsocks is not one of
#: them: its outbound has no `tls` field, and there is no generic TLS outbound to
#: chain it through. "Shadowsocks over TLS" is therefore not a configuration
#: sing-box can express, and the cell is recorded as unsupported rather than
#: emitted as a config the core will refuse.
SINGBOX_TLS_CAPABLE = frozenset(
    {"vless", "vmess", "trojan", "anytls", "hysteria2", "tuic"}
)


def singbox_tls_capable(protocol: str) -> bool:
    return protocol in SINGBOX_TLS_CAPABLE


SINGBOX_INBOUND_TYPE = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "shadowsocks": "shadowsocks",
    "shadowsocks2022": "shadowsocks",
    "anytls": "anytls",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
}


def singbox_server(link: Link, identity: Identity, port: int, handshake_port: int) -> dict:
    inbound: dict = {
        "type": SINGBOX_INBOUND_TYPE[link.protocol],
        "tag": "in",
        "listen": "127.0.0.1",
        "listen_port": port,
    }
    inbound.update(_singbox_credentials(link, identity, inbound=True))
    tls = _singbox_tls(link, identity, inbound=True, handshake_port=handshake_port)
    if tls.get("enabled"):
        inbound["tls"] = tls
    elif not link.quic_based:
        # Hysteria 2 and TUIC are QUIC and always TLS; everything else states
        # its TLS explicitly so "no TLS" is a decision on the record.
        inbound["tls"] = {"enabled": False}
    transport = _singbox_transport(link)
    if transport:
        inbound["transport"] = transport
    return {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct", "rules": []},
    }


def singbox_client(
    link: Link, identity: Identity, proxy_port: int, server_port: int, handshake_port: int
) -> dict:
    outbound: dict = {
        "type": SINGBOX_INBOUND_TYPE[link.protocol],
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": server_port,
    }
    outbound.update(_singbox_credentials(link, identity, inbound=False))
    tls = _singbox_tls(link, identity, inbound=False, handshake_port=handshake_port)
    if tls.get("enabled"):
        outbound["tls"] = tls
    transport = _singbox_transport(link)
    if transport:
        outbound["transport"] = transport
    if link.mux and link.protocol == "vless":
        outbound["multiplex"] = {"enabled": True, "max_connections": 8}
    return {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": proxy_port,
            }
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {
            "final": "proxy",
            "rules": [{"inbound": ["socks-in"], "outbound": "proxy"}],
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def server_config(
    dialect: str, link: Link, identity: Identity, port: int, handshake_port: int = 443
) -> dict:
    if dialect == "xray":
        return xray_server(link, identity, port, handshake_port)
    if dialect == "singbox":
        return singbox_server(link, identity, port, handshake_port)
    raise UnsupportedShape(f"unknown config dialect {dialect!r}")


def client_config(
    dialect: str,
    link: Link,
    identity: Identity,
    proxy_port: int,
    server_port: int,
    handshake_port: int = 443,
) -> dict:
    if dialect == "xray":
        return xray_client(link, identity, proxy_port, server_port)
    if dialect == "singbox":
        return singbox_client(link, identity, proxy_port, server_port, handshake_port)
    raise UnsupportedShape(f"unknown config dialect {dialect!r}")


def write_config(path: Path, config: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Absolute paths for the certificate files: cores resolve relative paths
    # against their own working directory, which is the harness's directory, not
    # the run directory.
    path.write_text(json.dumps(config, indent=2) + "\n")
    return path
