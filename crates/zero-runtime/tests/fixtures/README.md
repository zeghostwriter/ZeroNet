# Loopback test PKI

A two-level test PKI used by the loopback interoperability tests:

| file | role |
|---|---|
| `loopback-ca.pem`   | test CA certificate; the client trusts this |
| `loopback-cert.pem` | server leaf for `zray.test` / `localhost` / `127.0.0.1` |
| `loopback-key.pem`  | the leaf's private key |

A leaf signed by a separate CA, rather than one self-signed certificate,
because a CA certificate presented as an end-entity is rejected outright
(`CaUsedAsEndEntity`) — correctly, and the tests must exercise the real
verification path rather than route around it.

These are **test fixtures only**. The private keys are committed deliberately
and are therefore public: nothing that matters may ever be protected by them.
The tests reach the server by pinning `loopback-ca.pem` as an additional trust
anchor, so the fixture is never trusted outside the test process. Note that
`allowInsecure` is refused by the config validator and is not an option here.

Regenerate with:

    openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out loopback-ca.pem \
      -days 36500 -nodes -subj "/CN=Zray Loopback Test CA" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
    openssl req -newkey rsa:2048 -keyout loopback-key.pem -out leaf.csr -nodes \
      -subj "/CN=zray.test"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:zray.test,DNS:localhost,IP:127.0.0.1\n' > leaf.ext
    openssl x509 -req -in leaf.csr -CA loopback-ca.pem -CAkey ca-key.pem \
      -CAcreateserial -out loopback-cert.pem -days 36500 -extfile leaf.ext
