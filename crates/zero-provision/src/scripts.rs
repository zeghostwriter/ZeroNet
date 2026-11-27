//! The shell the installer runs on the server.
//!
//! Each piece does one job and is run on its own by `Connection::script`, which
//! sends it on standard input to `sh -s` with `set -eu` already on. Values come
//! in as environment variables that were checked against a tiny alphabet, so
//! nothing here is ever built by pasting user text into a command. A piece that
//! cannot go on exits with a number the installer turns into a sentence.

/// Make sure the downloader and the certificate store exist. Exit 40 when they
/// are missing and nothing can install them.
pub const TOOLS: &str = r#"
need=""
command -v curl >/dev/null 2>&1 || need="$need curl"
command -v tar >/dev/null 2>&1 || need="$need tar"
[ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || need="$need ca-certificates"
[ -n "$need" ] || exit 0
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >&2
  apt-get install -y -qq $need >&2
elif command -v dnf >/dev/null 2>&1; then dnf install -y -q $need >&2
elif command -v yum >/dev/null 2>&1; then yum install -y -q $need >&2
else echo "no package manager to install:$need" >&2; exit 40; fi
"#;

/// Find the release to install and fetch its signed checksum list. `TAG` is a
/// tag or `latest`. Prints `tag=`, `sums=` (base64) and `sig=`. Exit 20-22:
/// no release, no list, no signature.
pub const MANIFEST: &str = r#"
tag="$TAG"
if [ "$tag" = "latest" ]; then
  tag=$(curl -fsSL --max-time 25 "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
fi
[ -n "$tag" ] || { echo "no release found" >&2; exit 20; }
base="https://github.com/$REPO/releases/download/$tag"
install -d -m 700 "$WORK"
curl -fsSL --max-time 40 -o "$WORK/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || { echo "the release has no checksum list" >&2; exit 21; }
curl -fsSL --max-time 40 -o "$WORK/SHA256SUMS.txt.sig" "$base/SHA256SUMS.txt.sig" || { echo "the release has no signature" >&2; exit 22; }
echo "tag=$tag"
echo "sums=$(base64 -w0 "$WORK/SHA256SUMS.txt")"
echo "sig=$(tr -d '\n' < "$WORK/SHA256SUMS.txt.sig")"
"#;

/// Download one release file and keep it only if its hash is `SHA`. Exit 30 on
/// a mismatch, after deleting the file.
pub const FETCH: &str = r#"
install -d -m 700 "$WORK"
curl -fL --max-time 900 -o "$WORK/program" "https://github.com/$REPO/releases/download/$TAG/$ASSET"
got=$(sha256sum "$WORK/program" | cut -d' ' -f1)
if [ "$got" != "$SHA" ]; then rm -f "$WORK/program"; echo "checksum mismatch" >&2; exit 30; fi
chmod 755 "$WORK/program"
"#;

/// Create the account and directories the server uses.
pub const USER_AND_DIRS: &str = r#"
getent group "$SVC_USER" >/dev/null 2>&1 || groupadd --system "$SVC_USER"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --gid "$SVC_USER" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 755 "$PROGRAM_DIR"
install -d -m 750 -o root -g "$SVC_USER" "$ETC_DIR"
"#;

/// Put the downloaded or uploaded program in place, replacing any older one
/// atomically (a running server keeps its old copy open until restarted).
pub const PLACE_PROGRAM: &str = r#"
install -m 755 -o root -g root "$WORK/program" "$PROGRAM.new"
mv -f "$PROGRAM.new" "$PROGRAM"
"#;

/// Reload systemd, start the service and wait until it stays up.
pub const START: &str = r#"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
i=0
while [ $i -lt 12 ]; do
  if systemctl is-active --quiet "$SERVICE"; then break; fi
  i=$((i+1)); sleep 1
done
if ! systemctl is-active --quiet "$SERVICE"; then
  journalctl -u "$SERVICE" -n 25 --no-pager >&2 || true
  exit 50
fi
sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
  journalctl -u "$SERVICE" -n 25 --no-pager >&2 || true
  exit 51
fi
"#;

/// Wait for a TCP port to be listening; `PORT` and `PROTO` (`tcp` or `udp`).
/// Exit 52 if it never does.
pub const WAIT_PORT: &str = r#"
i=0
flag=ltn; [ "$PROTO" = udp ] && flag=lun
while [ $i -lt 15 ]; do
  if ss -H -$flag "sport = :$PORT" 2>/dev/null | grep -q .; then exit 0; fi
  i=$((i+1)); sleep 1
done
echo "nothing is listening on $PROTO/$PORT" >&2
exit 52
"#;

/// Open ports in the firewall the server already has, if it has one that is
/// switched on; never turns a firewall on. `TCP` and `UDP` are comma lists
/// (possibly `none`). Prints which firewall it changed, or `none`.
pub const FIREWALL: &str = r#"
tcp=$(echo "$TCP" | tr ',' ' '); udp=$(echo "$UDP" | tr ',' ' ')
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  for p in $tcp; do [ "$p" = none ] || ufw allow "$p/tcp" >/dev/null; done
  for p in $udp; do [ "$p" = none ] || ufw allow "$p/udp" >/dev/null; done
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  for p in $tcp; do [ "$p" = none ] || firewall-cmd --permanent --add-port="$p/tcp" >/dev/null; done
  for p in $udp; do [ "$p" = none ] || firewall-cmd --permanent --add-port="$p/udp" >/dev/null; done
  firewall-cmd --reload >/dev/null
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
"#;

/// Let the app's key log in as `LOGIN_USER`. The public key line is in
/// `$WORK/app.pub`. Idempotent.
pub const ADD_KEY: &str = r#"
home=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
[ -n "$home" ] || exit 60
install -d -m 700 -o "$LOGIN_USER" "$home/.ssh"
touch "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
chown "$LOGIN_USER" "$home/.ssh/authorized_keys"
if ! grep -qxF -f "$WORK/app.pub" "$home/.ssh/authorized_keys"; then
  cat "$WORK/app.pub" >> "$home/.ssh/authorized_keys"
fi
"#;

/// Delete the scratch directory.
pub const CLEAN: &str = r#"rm -rf "$WORK""#;

/// Read the live usage figures from the server's own management API.
pub const USAGE: &str = r#"
curl -fsS --max-time 8 -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "http://127.0.0.1:$MANAGEMENT_PORT/usage"
"#;

/// Download a pinned archive and keep it only if its hash is `SHA`; unpack it
/// and leave the server program at `$WORK/program`. Exit 30 on a mismatch, 31
/// when the archive holds no program.
pub const FETCH_PINNED_ARCHIVE: &str = r#"
install -d -m 700 "$WORK"
curl -fL --max-time 900 -o "$WORK/archive.tar.gz" "https://github.com/$REPO/releases/download/$TAG/$ASSET"
got=$(sha256sum "$WORK/archive.tar.gz" | cut -d' ' -f1)
if [ "$got" != "$SHA" ]; then rm -f "$WORK/archive.tar.gz"; echo "checksum mismatch" >&2; exit 30; fi
rm -rf "$WORK/unpack"; install -d -m 700 "$WORK/unpack"
tar -xzf "$WORK/archive.tar.gz" -C "$WORK/unpack"
bin=$(find "$WORK/unpack" -maxdepth 1 -type f ! -name '*.toml' | head -n 1)
[ -n "$bin" ] || { echo "the archive holds no program" >&2; exit 31; }
mv -f "$bin" "$WORK/program"
chmod 755 "$WORK/program"
rm -rf "$WORK/unpack" "$WORK/archive.tar.gz"
"#;

/// The session lines of the MasterDNS server's own log since it last started.
/// They hold no address (the server logs none at its default level), only a
/// session number or a count, which is all the usage figure is built from.
pub const MASTERDNS_LOG: &str = r#"
since=$(systemctl show "$SERVICE" -p ActiveEnterTimestamp --value 2>/dev/null || true)
[ -n "$since" ] || exit 0
journalctl -u "$SERVICE" --since "$since" -o short-unix --no-pager 2>/dev/null | grep -E "Session Created|Session Closed|Expired Sessions Cleaned" || true
"#;
