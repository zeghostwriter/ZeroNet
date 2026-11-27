//! The SSH side of the installer: connect, pin the host key, run commands.
//!
//! How a first contact goes, and why it is two steps:
//!
//! 1. [`fetch_host_key`] opens a connection, lets the key exchange finish, and
//!    reads the server's host key, then refuses it and hangs up. No password
//!    or key has been sent at that point, so nothing secret reaches a server
//!    that has not been vouched for yet.
//! 2. The caller shows the fingerprint to the person, who compares it with
//!    what their hosting panel or console shows. Only after they agree does
//!    [`connect`] run, passing that fingerprint; it then accepts exactly that
//!    key and nothing else. A later connection that meets a different key
//!    fails with [`Error::HostKeyChanged`] instead of continuing.
//!
//! Connections leave through [`zero_core::connect_protected`], so on Android
//! they bypass the app's own VPN: setting a server up must not depend on a
//! tunnel that is not yet working.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handler};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};

/// Longest a connection attempt (TCP plus key exchange) may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The most output kept from one command; the rest is dropped, so a runaway
/// command cannot fill memory on a phone.
const MAX_OUTPUT: usize = 2 * 1024 * 1024;

/// What can go wrong. The wording is for a person: it says what happened and,
/// where there is something to do about it, what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The server could not be reached at all.
    Unreachable(String),
    /// The address answered but nothing accepts connections on that port
    /// (the `address:port` that was tried).
    Refused(String),
    /// It was reached but did not answer in time.
    Timeout(String),
    /// The server's key is not the one the person confirmed.
    HostKeyChanged { expected: String, got: String },
    /// The password or key was refused.
    AuthFailed,
    /// The server accepts no password login at all, only keys.
    PasswordsOff,
    /// The key text could not be used (wrong format, or a passphrase is
    /// needed or wrong). Says what is wrong, never the key.
    BadKey(String),
    /// The server did not accept this key for this user.
    KeyRefused,
    /// Something else went wrong with the connection.
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreachable(why) => write!(
                f,
                "Could not reach the server ({why}). Check the address and the SSH port, and that \
                 the server is running."
            ),
            Error::Refused(at) => write!(
                f,
                "{at} refused the connection: nothing is listening there. Check the SSH port (many \
                 hosts use one other than 22; look in the host's panel), the address, and that the \
                 server is running."
            ),
            Error::Timeout(what) => write!(
                f,
                "The server did not answer in time ({what}). Check the address and the SSH port; \
                 some networks block SSH, so try another network."
            ),
            Error::HostKeyChanged { expected, got } => write!(
                f,
                "The server's identity changed: it was {expected} and is now {got}. This happens \
                 after a reinstall, but it can also mean someone is in the middle. Do not continue \
                 unless you reinstalled the server yourself."
            ),
            Error::AuthFailed => f.write_str(
                "The server refused the login. Check the user name and the password. If you log in \
                 as root: many servers refuse root with a password and only allow it with a key; \
                 set PermitRootLogin yes in /etc/ssh/sshd_config and restart ssh, or use another \
                 user that has sudo.",
            ),
            Error::PasswordsOff => f.write_str(
                "This server does not accept password logins, only SSH keys. Log in with your \
                 SSH private key instead, or turn passwords on in the host's console \
                 (PasswordAuthentication yes in /etc/ssh/sshd_config, then restart ssh).",
            ),
            Error::BadKey(why) => write!(f, "The SSH key could not be used: {why}"),
            Error::KeyRefused => f.write_str(
                "The server did not accept this key. Check the user name, and that this key's \
                 public half is in that user's ~/.ssh/authorized_keys on the server.",
            ),
            Error::Protocol(why) => write!(f, "The SSH connection failed: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<russh::Error> for Error {
    fn from(error: russh::Error) -> Self {
        Error::Protocol(error.to_string())
    }
}

/// How to log in. The password or key is kept only as long as this value is.
#[derive(Clone)]
pub enum Auth {
    Password(String),
    /// The app's own OpenSSH private key in text form (no passphrase).
    Key(String),
    /// A private key the person supplied: OpenSSH, PEM/PKCS#8 or PuTTY text,
    /// with its passphrase when it has one.
    UserKey {
        pem: String,
        passphrase: Option<String>,
    },
}

impl std::fmt::Debug for Auth {
    // Never print the secret, so a stray `{:?}` in a log cannot leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Password(_) => f.write_str("Auth::Password(..)"),
            Auth::Key(_) => f.write_str("Auth::Key(..)"),
            Auth::UserKey { .. } => f.write_str("Auth::UserKey(..)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Login {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
}

/// A server's host key, as the fingerprint people compare.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostKey {
    /// `SHA256:` and unpadded base64, the form `ssh-keygen -l` prints.
    pub fingerprint: String,
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, ...
    pub algorithm: String,
}

/// What the handler saw during key exchange.
type Seen = Arc<Mutex<Option<HostKey>>>;

struct Pinned {
    expected: Option<String>,
    seen: Seen,
}

impl Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let public = key.public_key();
        let host_key = HostKey {
            fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
            algorithm: public.algorithm().to_string(),
        };
        let accept = self
            .expected
            .as_deref()
            .is_some_and(|expected| expected == host_key.fingerprint);
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(host_key);
        Ok(accept)
    }
}

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 4,
        ..Default::default()
    })
}

async fn open(login_host: &str, port: u16) -> Result<tokio::net::TcpStream, Error> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((login_host, port))
        .await
        .map_err(|e| Error::Unreachable(e.to_string()))?
        .collect();
    let mut last = None;
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, zero_core::connect_protected(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                last = Some(Error::Refused(addr.to_string()))
            }
            Ok(Err(e)) => last = Some(Error::Unreachable(e.to_string())),
            Err(_) => last = Some(Error::Timeout("connecting".into())),
        }
    }
    Err(last.unwrap_or_else(|| Error::Unreachable("the name has no address".into())))
}

/// Read the server's host key without sending any credential.
pub async fn fetch_host_key(host: &str, port: u16) -> Result<HostKey, Error> {
    let stream = open(host, port).await?;
    let seen: Seen = Arc::default();
    let handler = Pinned {
        expected: None,
        seen: Arc::clone(&seen),
    };
    // The handler refuses the key, so this is expected to fail; the key is in
    // `seen` by then.
    let attempt = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect_stream(config(), stream, handler),
    )
    .await;
    let found = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    match (found, attempt) {
        (Some(key), _) => Ok(key),
        (None, Err(_)) => Err(Error::Timeout("key exchange".into())),
        (None, Ok(Err(e))) => Err(e.into()),
        (None, Ok(Ok(_))) => Err(Error::Protocol("the server sent no host key".into())),
    }
}

/// What one remote command produced.
#[derive(Debug, Clone, Default)]
pub struct Output {
    pub status: u32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// An authenticated connection to a server whose host key was pinned.
pub struct Connection {
    handle: client::Handle<Pinned>,
    /// Commands are wrapped in `sudo -n` when the login is not root.
    sudo: bool,
}

/// Log in to a server, accepting only the host key `trusted` (a fingerprint
/// from [`fetch_host_key`] or from an earlier session).
pub async fn connect(login: &Login, trusted: &str) -> Result<Connection, Error> {
    let stream = open(&login.host, login.port).await?;
    let seen: Seen = Arc::default();
    let handler = Pinned {
        expected: Some(trusted.to_string()),
        seen: Arc::clone(&seen),
    };
    let attempt = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect_stream(config(), stream, handler),
    )
    .await;
    let mut handle = match attempt {
        Err(_) => return Err(Error::Timeout("key exchange".into())),
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => {
            // A refused key is the one failure with a story of its own.
            if let Some(got) = seen.lock().unwrap_or_else(|p| p.into_inner()).clone() {
                if got.fingerprint != trusted {
                    return Err(Error::HostKeyChanged {
                        expected: trusted.to_string(),
                        got: got.fingerprint,
                    });
                }
            }
            return Err(e.into());
        }
    };
    match &login.auth {
        Auth::Password(password) => {
            log_in_with_password(&mut handle, &login.user, password).await?
        }
        Auth::Key(pem) => log_in_with_key(&mut handle, &login.user, pem, None).await?,
        Auth::UserKey { pem, passphrase } => {
            log_in_with_key(&mut handle, &login.user, pem, passphrase.as_deref()).await?
        }
    }
    Ok(Connection {
        handle,
        sudo: login.user != "root",
    })
}

/// Read a private key in any common text form (OpenSSH, PEM, PKCS#8, PuTTY),
/// decrypting it with `passphrase` when it has one. The error says what is
/// wrong without echoing the key.
pub fn parse_private_key(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, Error> {
    let text = text.trim();
    if !text.contains("PRIVATE KEY") && !text.contains("PuTTY-User-Key-File") {
        return Err(Error::BadKey(
            "this is not a private key (it should start with -----BEGIN ... PRIVATE KEY-----). \
             Did you pick the .pub file?"
                .into(),
        ));
    }
    let passphrase = passphrase.filter(|p| !p.is_empty());
    russh::keys::decode_secret_key(text, passphrase).map_err(|e| {
        let why = e.to_string();
        let lowered = why.to_ascii_lowercase();
        Error::BadKey(
            if passphrase.is_none()
                && (lowered.contains("encrypt")
                    || lowered.contains("passphrase")
                    || lowered.contains("password"))
            {
                "the key is protected by a passphrase; type it in".into()
            } else if passphrase.is_some()
                && (lowered.contains("decrypt")
                    || lowered.contains("passphrase")
                    || lowered.contains("password")
                    || lowered.contains("mac")
                    || lowered.contains("crypto"))
            {
                "the passphrase is wrong".into()
            } else {
                format!("unsupported or damaged key ({why})")
            },
        )
    })
}

/// Log in with a private key. A key the server does not accept gives
/// [`Error::KeyRefused`].
async fn log_in_with_key(
    handle: &mut client::Handle<Pinned>,
    user: &str,
    pem: &str,
    passphrase: Option<&str>,
) -> Result<(), Error> {
    let key = parse_private_key(pem, passphrase)?;
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    let result = handle
        .authenticate_publickey(
            user.to_string(),
            PrivateKeyWithHashAlg::new(Arc::new(key), hash),
        )
        .await?;
    if result.success() {
        Ok(())
    } else {
        Err(Error::KeyRefused)
    }
}

/// Log in with a password. The server is asked first which methods it offers
/// (a `none` attempt, as OpenSSH clients do); then plain `password` is tried
/// when listed, and `keyboard-interactive` when listed, because many servers
/// (PAM setups, some hosting images) only offer the password that way. A
/// server that lists neither gets [`Error::PasswordsOff`] instead of a
/// misleading "wrong password".
async fn log_in_with_password(
    handle: &mut client::Handle<Pinned>,
    user: &str,
    password: &str,
) -> Result<(), Error> {
    use russh::client::{AuthResult, KeyboardInteractiveAuthResponse as Reply};
    use russh::MethodKind;
    let offered = match handle.authenticate_none(user.to_string()).await? {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    let (plain, prompted) = (
        offered.contains(&MethodKind::Password),
        offered.contains(&MethodKind::KeyboardInteractive),
    );
    if !plain && !prompted {
        return Err(Error::PasswordsOff);
    }
    if plain
        && handle
            .authenticate_password(user.to_string(), password.to_string())
            .await?
            .success()
    {
        return Ok(());
    }
    if !prompted {
        return Err(Error::AuthFailed);
    }
    let mut reply = handle
        .authenticate_keyboard_interactive_start(user.to_string(), None)
        .await?;
    // A PAM stack asks for the password once; a few rounds leave room for a
    // banner-only step first. Every prompt is answered with the password.
    for _ in 0..4 {
        match reply {
            Reply::Success => return Ok(()),
            Reply::Failure { .. } => break,
            Reply::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| password.to_string()).collect();
                reply = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Err(Error::AuthFailed)
}

impl Connection {
    /// Run `command` (a shell command line), feeding it `stdin`.
    pub async fn exec(
        &self,
        command: &str,
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<Output, Error> {
        tokio::time::timeout(timeout, self.exec_inner(command, stdin))
            .await
            .map_err(|_| Error::Timeout(format!("running a command (over {timeout:?})")))?
    }

    async fn exec_inner(&self, command: &str, stdin: &[u8]) -> Result<Output, Error> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        if !stdin.is_empty() {
            channel.data(stdin).await?;
        }
        channel.eof().await?;
        let mut out = Output::default();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => append(&mut stdout, &data),
                ChannelMsg::ExtendedData { data, .. } => append(&mut stderr, &data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        out.status = status.unwrap_or(255);
        out.stdout = String::from_utf8_lossy(&stdout).into_owned();
        out.stderr = String::from_utf8_lossy(&stderr).into_owned();
        Ok(out)
    }

    /// Run a shell script on the server: it is sent on standard input to
    /// `sh -s`, so it needs no quoting and leaves nothing on disk. `env` are
    /// variables set before the script; each value must pass [`shell_safe`].
    pub async fn script(
        &self,
        env: &[(&str, &str)],
        script: &str,
        timeout: Duration,
    ) -> Result<Output, Error> {
        let mut text = String::from("set -eu\n");
        for (name, value) in env {
            if !shell_safe(value) {
                return Err(Error::Protocol(format!(
                    "refusing an unsafe value for {name}"
                )));
            }
            text.push_str(&format!("{name}='{value}'\nexport {name}\n"));
        }
        text.push_str(script);
        text.push_str("\nexit 0\n");
        let runner = if self.sudo { "sudo -n sh -s" } else { "sh -s" };
        self.exec(runner, text.as_bytes(), timeout).await
    }

    /// `command` with `sudo -n` in front when the login is not root.
    pub fn privileged(&self, command: &str) -> String {
        if self.sudo {
            format!("sudo -n {command}")
        } else {
            command.to_string()
        }
    }

    /// Write `bytes` to `path` on the server, atomically (a temporary file next
    /// to it, then a rename), with the given `mode` (`640`) and `owner`
    /// (`root:zray`). A reader of `path` never sees half a file.
    pub async fn put_file(
        &self,
        path: &str,
        mode: &str,
        owner: &str,
        bytes: &[u8],
    ) -> Result<(), Error> {
        for value in [path, mode, owner] {
            if !shell_safe(value) {
                return Err(Error::Protocol("refusing an unsafe file name".into()));
            }
        }
        let command = format!(
            "{}sh -c 'set -eu; t=\"$1.part\"; cat > \"$t\"; chmod \"$2\" \"$t\"; \
             chown \"$3\" \"$t\"; mv -f \"$t\" \"$1\"' sh '{path}' '{mode}' '{owner}'",
            if self.sudo { "sudo -n " } else { "" }
        );
        let out = self.exec(&command, bytes, Duration::from_secs(300)).await?;
        if out.ok() {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "could not write {path}: {}",
                out.stderr.trim()
            )))
        }
    }

    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }
}

fn append(buffer: &mut Vec<u8>, data: &[u8]) {
    let room = MAX_OUTPUT.saturating_sub(buffer.len());
    buffer.extend_from_slice(&data[..data.len().min(room)]);
}

/// Whether `value` can be put inside single quotes in a script without any
/// chance of closing them: ordinary path, host and name characters only.
pub fn shell_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/:@+=,".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_characters_are_allowed_in_a_script_value() {
        assert!(shell_safe("ZrayCore-Linux-x64"));
        assert!(shell_safe(
            "https://github.com/o/r/releases/download/v1.2.3/f"
        ));
        assert!(!shell_safe("a'b"));
        assert!(!shell_safe("a b"));
        assert!(!shell_safe("$(id)"));
        assert!(!shell_safe("a;b"));
        assert!(!shell_safe("a\nb"));
        assert!(!shell_safe(""));
    }

    #[test]
    fn a_secret_never_prints() {
        let text = format!("{:?}", Auth::Password("hunter2".into()));
        assert!(!text.contains("hunter2"));
        let text = format!(
            "{:?}",
            Auth::Key("-----BEGIN OPENSSH PRIVATE KEY-----".into())
        );
        assert!(!text.contains("BEGIN"));
    }

    struct Bare;
    struct BareHandler;
    impl russh::server::Handler for BareHandler {
        type Error = russh::Error;
    }
    impl russh::server::Server for Bare {
        type Handler = BareHandler;
        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> BareHandler {
            BareHandler
        }
    }

    /// A server that offers only an RSA host key (older images, hardened
    /// `HostKey` lines) must still be identified: with RSA left out of the
    /// SSH library the key exchange ended in "wrong server signature". The
    /// key is made with `ssh-keygen`; where it is missing the test says so
    /// and passes, since the check needs a real key file.
    #[tokio::test]
    async fn a_server_with_only_an_rsa_host_key_can_be_identified() {
        let dir = std::env::temp_dir().join(format!("zray-rsa-hostkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("key");
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
            .arg(&file)
            .status();
        if !made.is_ok_and(|status| status.success()) {
            eprintln!("ssh-keygen is not available; skipping the RSA host key check");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let key =
            russh::keys::PrivateKey::from_openssh(std::fs::read_to_string(&file).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use russh::server::Server;
            let _ = Bare.run_on_socket(config, &listener).await;
        });
        let host_key = fetch_host_key("127.0.0.1", port).await.unwrap();
        assert!(host_key.algorithm.contains("rsa"), "{host_key:?}");
        assert!(host_key.fingerprint.starts_with("SHA256:"));
    }

    /// What a test server does with a login attempt.
    #[derive(Clone, Copy)]
    enum Policy {
        /// Accepts the password `pw` as plain `password` auth.
        Password,
        /// Offers only `keyboard-interactive`, with one "Password:" prompt.
        Prompt,
        /// Offers only public keys.
        KeysOnly,
    }

    /// The policy, and the fingerprint of the one user key it accepts.
    struct Gate(Policy, Option<String>);
    struct GateHandler(Policy, Option<String>);

    impl russh::server::Handler for GateHandler {
        type Error = russh::Error;
        async fn auth_publickey(
            &mut self,
            _user: &str,
            public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            let seen = public_key.fingerprint(HashAlg::Sha256).to_string();
            Ok(match (&self.1, self.0) {
                (Some(accepted), Policy::KeysOnly) if *accepted == seen => {
                    russh::server::Auth::Accept
                }
                _ => russh::server::Auth::reject(),
            })
        }
        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(match (self.0, password) {
                (Policy::Password, "pw") => russh::server::Auth::Accept,
                _ => russh::server::Auth::reject(),
            })
        }
        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            _user: &str,
            _submethods: &str,
            response: Option<russh::server::Response<'a>>,
        ) -> Result<russh::server::Auth, Self::Error> {
            if !matches!(self.0, Policy::Prompt) {
                return Ok(russh::server::Auth::reject());
            }
            Ok(match response {
                None => russh::server::Auth::Partial {
                    name: "".into(),
                    instructions: "".into(),
                    prompts: vec![("Password: ".into(), false)].into(),
                },
                Some(mut answers) => {
                    if answers.next().as_deref() == Some(&b"pw"[..]) {
                        russh::server::Auth::Accept
                    } else {
                        russh::server::Auth::reject()
                    }
                }
            })
        }
    }

    impl russh::server::Server for Gate {
        type Handler = GateHandler;
        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> GateHandler {
            GateHandler(self.0, self.1.clone())
        }
    }

    /// A host key made with `ssh-keygen`, or `None` where the tool is missing.
    fn host_key(kind: &str) -> Option<russh::keys::PrivateKey> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zray-hostkey-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let file = dir.join("key");
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", kind, "-N", "", "-f"])
            .arg(&file)
            .status();
        let key = made
            .ok()
            .filter(|status| status.success())
            .and_then(|_| std::fs::read_to_string(&file).ok())
            .and_then(|pem| russh::keys::PrivateKey::from_openssh(pem).ok());
        let _ = std::fs::remove_dir_all(&dir);
        key
    }

    /// Start a server with `policy`; returns its port and host key
    /// fingerprint, or `None` where `ssh-keygen` is missing.
    async fn serve(policy: Policy, accepted: Option<String>) -> Option<(u16, String)> {
        use russh::MethodKind;
        let key = host_key("ed25519")?;
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let methods: &[MethodKind] = match policy {
            Policy::Password => &[MethodKind::Password],
            Policy::Prompt => &[MethodKind::KeyboardInteractive],
            Policy::KeysOnly => &[MethodKind::PublicKey],
        };
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            methods: methods.into(),
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use russh::server::Server;
            let _ = Gate(policy, accepted)
                .run_on_socket(config, &listener)
                .await;
        });
        Some((port, fingerprint))
    }

    async fn log_in(policy: Policy, password: &str) -> Option<Result<(), Error>> {
        let (port, fingerprint) = serve(policy, None).await?;
        let login = Login {
            host: "127.0.0.1".into(),
            port,
            user: "root".into(),
            auth: Auth::Password(password.into()),
        };
        Some(connect(&login, &fingerprint).await.map(|_| ()))
    }

    #[tokio::test]
    async fn a_plain_password_login_works() {
        let Some(result) = log_in(Policy::Password, "pw").await else {
            return;
        };
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn a_wrong_password_says_the_login_was_refused() {
        let Some(result) = log_in(Policy::Password, "nope").await else {
            return;
        };
        assert_eq!(result, Err(Error::AuthFailed));
    }

    /// Servers that only offer `keyboard-interactive` (PAM) still take the password.
    #[tokio::test]
    async fn a_keyboard_interactive_only_server_takes_the_password() {
        let Some(result) = log_in(Policy::Prompt, "pw").await else {
            return;
        };
        assert_eq!(result, Ok(()));
        let Some(result) = log_in(Policy::Prompt, "nope").await else {
            return;
        };
        assert_eq!(result, Err(Error::AuthFailed));
    }

    #[tokio::test]
    async fn a_keys_only_server_is_told_apart_from_a_wrong_password() {
        let Some(result) = log_in(Policy::KeysOnly, "pw").await else {
            return;
        };
        assert_eq!(result, Err(Error::PasswordsOff));
    }

    /// A user key made with `ssh-keygen` (extra arguments choose the format
    /// and passphrase), as its text and public fingerprint. `None` where the
    /// tool is missing.
    fn user_key(extra: &[&str]) -> Option<(String, String)> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zray-userkey-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let file = dir.join("key");
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519"])
            .args(extra)
            .arg("-f")
            .arg(&file)
            .status();
        let result = made.ok().filter(|status| status.success()).and_then(|_| {
            let private = std::fs::read_to_string(&file).ok()?;
            let public = std::fs::read_to_string(dir.join("key.pub")).ok()?;
            let fingerprint = russh::keys::PublicKey::from_openssh(public.trim())
                .ok()?
                .fingerprint(HashAlg::Sha256)
                .to_string();
            Some((private, fingerprint))
        });
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    async fn log_in_with_user_key(
        accepted: &str,
        key: &str,
        passphrase: Option<&str>,
    ) -> Result<(), Error> {
        let (port, fingerprint) = serve(Policy::KeysOnly, Some(accepted.to_string()))
            .await
            .expect("ssh-keygen was there a moment ago");
        let login = Login {
            host: "127.0.0.1".into(),
            port,
            user: "root".into(),
            auth: Auth::UserKey {
                pem: key.to_string(),
                passphrase: passphrase.map(str::to_string),
            },
        };
        connect(&login, &fingerprint).await.map(|_| ())
    }

    #[tokio::test]
    async fn a_user_key_logs_in_and_a_stranger_does_not() {
        let Some((key, fingerprint)) = user_key(&["-N", ""]) else {
            return;
        };
        assert_eq!(log_in_with_user_key(&fingerprint, &key, None).await, Ok(()));
        let Some((other, _)) = user_key(&["-N", ""]) else {
            return;
        };
        assert_eq!(
            log_in_with_user_key(&fingerprint, &other, None).await,
            Err(Error::KeyRefused)
        );
    }

    #[tokio::test]
    async fn a_passphrase_protected_key_needs_its_passphrase() {
        let Some((key, fingerprint)) = user_key(&["-N", "correct horse"]) else {
            return;
        };
        assert_eq!(
            log_in_with_user_key(&fingerprint, &key, Some("correct horse")).await,
            Ok(())
        );
        let missing = log_in_with_user_key(&fingerprint, &key, None).await;
        assert!(
            matches!(&missing, Err(Error::BadKey(why)) if why.contains("passphrase")),
            "{missing:?}"
        );
        let wrong = log_in_with_user_key(&fingerprint, &key, Some("nope")).await;
        assert!(
            matches!(&wrong, Err(Error::BadKey(why)) if why.contains("wrong")),
            "{wrong:?}"
        );
    }

    #[tokio::test]
    async fn the_common_key_text_formats_all_work() {
        for format in ["OpenSSH", "PEM", "PKCS8"] {
            let Some((key, fingerprint)) = user_key(&["-N", "", "-m", format]) else {
                return;
            };
            assert_eq!(
                log_in_with_user_key(&fingerprint, &key, None).await,
                Ok(()),
                "{format}"
            );
        }
    }

    #[test]
    fn a_public_key_or_text_that_is_not_a_key_is_explained() {
        for text in ["ssh-ed25519 AAAAC3Nza user@host", "hello", ""] {
            let error = parse_private_key(text, None).unwrap_err();
            assert!(
                matches!(&error, Error::BadKey(why) if why.contains("not a private key")),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_key_never_prints() {
        let text = format!(
            "{:?}",
            Auth::UserKey {
                pem: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
                passphrase: Some("hunter2".into()),
            }
        );
        assert!(!text.contains("BEGIN") && !text.contains("hunter2"));
    }
}
