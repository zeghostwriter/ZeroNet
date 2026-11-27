//! Routing parity against the Xray oracle (PLAN-01 §5).
//!
//! The matcher unit tests are necessary, but they cannot prove that a parsed
//! Xray JSON rule reaches the same runtime outcome as an Xray rule.  This
//! harness generates a deterministic corpus, installs it in both processes,
//! and drives every case through their public SOCKS listeners.  A complete
//! framed exchange with a loopback echo service means the session was routed
//! directly; a SOCKS rejection, close, timeout, or altered exchange means it
//! was blocked.
//!
//! It is deliberately opt-in because it needs an `xray` executable.  Set
//! `ZRAY_XRAY_BINARY` to a binary path, or put `xray` on `PATH`, then run:
//!
//! ```bash
//! cargo test -p zero-runtime --test routing_oracle -- --ignored --test-threads=1
//! ```
//!
//! The generated corpus covers exact, suffix (including label-boundary
//! negatives), keyword, and regular-expression domains; IPv4 CIDRs; ports;
//! combined selectors; source/inbound selectors; TCP-vs-UDP selection; and
//! first-match precedence.  It intentionally measures externally observable
//! routing behavior rather than calling either matcher's internal API.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const GROUPS: usize = 12;
const PROBE_TIMEOUT: Duration = Duration::from_millis(750);

/// Locate Xray before the test starts a Zray listener.  Failing loudly here
/// prevents an opt-in oracle run from looking successful when it did no
/// comparison at all.
fn oracle_binary() -> Result<String, String> {
    if let Some(path) = std::env::var_os("ZRAY_XRAY_BINARY") {
        let path = path.to_string_lossy().into_owned();
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
        return Err(format!(
            "ZRAY_XRAY_BINARY points at {path}, which does not exist"
        ));
    }

    match Command::new("xray").arg("version").output() {
        Ok(output) if output.status.success() => Ok("xray".into()),
        _ => Err("no `xray` on PATH and ZRAY_XRAY_BINARY is unset".into()),
    }
}

/// Process and temporary config owned by one oracle test invocation.
struct Oracle {
    child: Child,
    directory: std::path::PathBuf,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn spawn_oracle(binary: &str, config: &Value) -> Oracle {
    let directory = std::env::temp_dir().join(format!(
        "zray-routing-oracle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&directory).expect("create oracle config directory");
    let config_path = directory.join("config.json");
    let mut file = std::fs::File::create(&config_path).expect("create oracle config");
    file.write_all(
        serde_json::to_string_pretty(config)
            .expect("serialize oracle config")
            .as_bytes(),
    )
    .expect("write oracle config");
    file.sync_all().expect("sync oracle config");

    // `ZRAY_ORACLE_LOG=1` makes a rejected Xray config diagnosable without
    // changing this test, while routine CI output stays quiet.
    let show_logs = std::env::var_os("ZRAY_ORACLE_LOG").is_some();
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(if show_logs {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(if show_logs {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
        .unwrap_or_else(|error| panic!("could not start Xray oracle: {error}"));

    Oracle { child, directory }
}

/// Do not hand two parallel integration tests the same released ephemeral
/// port.  The OS allocator cannot provide that guarantee after `bind(:0)` is
/// dropped, so retain a process-local reservation record.
fn free_port() -> u16 {
    use std::collections::HashSet;

    static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    for _ in 0..500 {
        let port = StdListener::bind("127.0.0.1:0")
            .expect("bind ephemeral port")
            .local_addr()
            .expect("read ephemeral port")
            .port();
        let mut taken = TAKEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if taken.get_or_insert_with(HashSet::new).insert(port) {
            return port;
        }
    }
    panic!("could not allocate an unused test port");
}

fn spawn_zray(config: &Value) -> Arc<zero_runtime::Server> {
    let (generation, _) = zero_config::compile_config(config, zero_core::GenerationId(1))
        .unwrap_or_else(|error| panic!("Zray rejected parity config: {error}\n{config:#}"));
    let server = Arc::new(zero_runtime::Server::new(zero_runtime::ServerConfig {
        config: Arc::clone(&generation.config),
        generation: generation.id,
    }));
    let running = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = running.run().await;
    });
    server
}

async fn wait_for_listener(address: SocketAddr, name: &str) {
    for _ in 0..200 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{name} did not listen on {address}");
}

/// Bind to all IPv4 loopback aliases so the CIDR cases can target distinct
/// addresses while still reaching this process.  The service makes framing
/// explicit, ruling out a coincidental partial read as a successful route.
async fn echo_service() -> SocketAddr {
    let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind echo");
    let address = listener.local_addr().expect("read echo address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut header = [0_u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let length = u32::from_be_bytes(header) as usize;
                    if length == 0 || length > 64 * 1024 {
                        return;
                    }
                    let mut body = vec![0_u8; length];
                    if stream.read_exact(&mut body).await.is_err()
                        || stream.write_all(&header).await.is_err()
                        || stream.write_all(&body).await.is_err()
                        || stream.flush().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    address
}

#[derive(Clone, Debug)]
enum TargetHost {
    Domain(String),
    Ipv4(Ipv4Addr),
}

impl TargetHost {
    fn label(&self) -> String {
        match self {
            TargetHost::Domain(domain) => domain.clone(),
            TargetHost::Ipv4(address) => address.to_string(),
        }
    }

    fn write_socks_address(&self, request: &mut Vec<u8>) {
        match self {
            TargetHost::Domain(domain) => {
                request.push(0x03);
                request.push(u8::try_from(domain.len()).expect("test domain fits SOCKS length"));
                request.extend_from_slice(domain.as_bytes());
            }
            TargetHost::Ipv4(address) => {
                request.push(0x01);
                request.extend_from_slice(&address.octets());
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Case {
    name: String,
    host: TargetHost,
    port: u16,
    direct: bool,
}

impl Case {
    fn domain(name: impl Into<String>, domain: impl Into<String>, port: u16, direct: bool) -> Self {
        Self {
            name: name.into(),
            host: TargetHost::Domain(domain.into()),
            port,
            direct,
        }
    }

    fn ip(name: impl Into<String>, address: Ipv4Addr, port: u16, direct: bool) -> Self {
        Self {
            name: name.into(),
            host: TargetHost::Ipv4(address),
            port,
            direct,
        }
    }
}

/// Build rules and their positive/negative witnesses together, preventing a
/// corpus edit from accidentally asserting a branch it does not exercise.
fn corpus(primary_port: u16, alternate_port: u16, port_gate_port: u16) -> (Vec<Value>, Vec<Case>) {
    let mut rules = Vec::new();
    let mut cases = Vec::new();

    for index in 0..GROUPS {
        let exact = format!("full-{index}.parity.test");
        rules.push(json!({
            "domain": [format!("full:{exact}")],
            "outboundTag": "blocked",
        }));
        cases.push(Case::domain(
            format!("full/{index}/exact"),
            exact.clone(),
            primary_port,
            false,
        ));
        cases.push(Case::domain(
            format!("full/{index}/subdomain-miss"),
            format!("child.{exact}"),
            primary_port,
            true,
        ));

        let suffix = format!("suffix-{index}.parity.test");
        rules.push(json!({
            "domain": [format!("domain:{suffix}")],
            "outboundTag": "blocked",
        }));
        cases.push(Case::domain(
            format!("suffix/{index}/exact"),
            suffix.clone(),
            primary_port,
            false,
        ));
        cases.push(Case::domain(
            format!("suffix/{index}/subdomain"),
            format!("child.{suffix}"),
            primary_port,
            false,
        ));
        cases.push(Case::domain(
            format!("suffix/{index}/not-label-boundary"),
            format!("not-{suffix}"),
            primary_port,
            true,
        ));

        let keyword = format!("needle-{index}");
        rules.push(json!({
            "domain": [format!("keyword:{keyword}")],
            "outboundTag": "blocked",
        }));
        cases.push(Case::domain(
            format!("keyword/{index}/contains"),
            format!("left-{keyword}-right.parity.test"),
            primary_port,
            false,
        ));
        cases.push(Case::domain(
            format!("keyword/{index}/miss"),
            format!("clear-{index}.parity.test"),
            primary_port,
            true,
        ));

        let expression = format!(r"^regex-{index}\.[a-z]+\.parity\.test$");
        rules.push(json!({
            "domain": [format!("regexp:{expression}")],
            "outboundTag": "blocked",
        }));
        cases.push(Case::domain(
            format!("regexp/{index}/match"),
            format!("regex-{index}.hit.parity.test"),
            primary_port,
            false,
        ));
        cases.push(Case::domain(
            format!("regexp/{index}/miss"),
            format!("prefix-regex-{index}.hit.parity.test"),
            primary_port,
            true,
        ));
    }

    rules.push(json!({"ip": ["127.0.0.0/30"], "outboundTag": "blocked"}));
    cases.push(Case::ip(
        "ip/cidr-match",
        Ipv4Addr::new(127, 0, 0, 2),
        primary_port,
        false,
    ));
    cases.push(Case::ip(
        "ip/cidr-miss",
        Ipv4Addr::new(127, 0, 0, 4),
        primary_port,
        true,
    ));

    // Keep this selector on a dedicated listener.  Reusing `primary_port`
    // would turn every otherwise-direct domain witness into a port-rule hit.
    rules.push(json!({"port": port_gate_port, "outboundTag": "blocked"}));
    cases.push(Case::ip(
        "port/exact",
        Ipv4Addr::LOCALHOST,
        port_gate_port,
        false,
    ));
    cases.push(Case::ip(
        "port/miss",
        // 127.0.0.1 is intentionally covered by the preceding /30 rule;
        // use a different loopback alias to isolate this port-only miss.
        Ipv4Addr::new(127, 0, 0, 4),
        alternate_port,
        true,
    ));

    let combined = "combined.parity.test";
    rules.push(json!({
        "domain": [format!("full:{combined}")],
        "port": primary_port,
        "outboundTag": "blocked",
    }));
    cases.push(Case::domain(
        "combined/all-selectors-match",
        combined,
        primary_port,
        false,
    ));
    cases.push(Case::domain(
        "combined/port-miss",
        combined,
        alternate_port,
        true,
    ));

    let priority = "first.priority-zone.parity.test";
    rules.push(json!({
        "domain": [format!("full:{priority}")],
        "outboundTag": "direct",
    }));
    rules.push(json!({
        "domain": ["domain:priority-zone.parity.test"],
        "outboundTag": "blocked",
    }));
    cases.push(Case::domain(
        "order/first-direct-wins",
        priority,
        primary_port,
        true,
    ));
    cases.push(Case::domain(
        "order/fall-through-blocked",
        "other.priority-zone.parity.test",
        primary_port,
        false,
    ));

    let udp_only = "udp-only.parity.test";
    rules.push(json!({
        "domain": [format!("full:{udp_only}")],
        "network": "udp",
        "outboundTag": "blocked",
    }));
    cases.push(Case::domain(
        "network/udp-rule-does-not-match-tcp",
        udp_only,
        primary_port,
        true,
    ));

    let inbound = "inbound-gate.parity.test";
    rules.push(json!({
        "domain": [format!("full:{inbound}")],
        "inboundTag": ["socks-in"],
        "outboundTag": "blocked",
    }));
    cases.push(Case::domain(
        "inbound/tag-match",
        inbound,
        primary_port,
        false,
    ));

    let source = "source-gate.parity.test";
    rules.push(json!({
        "domain": [format!("full:{source}")],
        "source": ["127.0.0.1"],
        "outboundTag": "blocked",
    }));
    cases.push(Case::domain(
        "source/loopback-match",
        source,
        primary_port,
        false,
    ));

    (rules, cases)
}

fn config(socks_port: u16, rules: &[Value], hosts: Map<String, Value>) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth"},
        }],
        "outbounds": [
            // Xray's Freedom defaults to system resolution (`AsIs`), which
            // would make our synthetic direct-domain witnesses depend on the
            // host resolver instead of the shared pinned hosts table.  Zray
            // accepts the same Xray setting and already resolves Freedom
            // domain targets through its configured resolver.
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "dns": {"hosts": hosts},
        "routing": {"rules": rules},
    })
}

/// A public SOCKS flow is considered direct only after it returns our precise
/// framing-aware echo.  This handles the implementations' different
/// blackhole behavior: Zray rejects at SOCKS time, while Xray may accept the
/// CONNECT then close it after receiving a payload.
async fn reaches_echo(socks: SocketAddr, case: &Case) -> bool {
    let exchange = async {
        let mut stream = TcpStream::connect(socks).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [0x05, 0x00] {
            return Ok::<bool, std::io::Error>(false);
        }

        let mut request = vec![0x05, 0x01, 0x00];
        case.host.write_socks_address(&mut request);
        request.extend_from_slice(&case.port.to_be_bytes());
        stream.write_all(&request).await?;

        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 0x05 || reply[1] != 0x00 {
            return Ok(false);
        }
        let tail = match reply[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).await?;
                usize::from(length[0])
            }
            _ => return Ok(false),
        };
        let mut ignored = vec![0_u8; tail + 2];
        stream.read_exact(&mut ignored).await?;

        let body = format!("routing-oracle:{}", case.name).into_bytes();
        stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;

        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await?;
        if u32::from_be_bytes(header) as usize != body.len() {
            return Ok(false);
        }
        let mut echoed = vec![0_u8; body.len()];
        stream.read_exact(&mut echoed).await?;
        Ok(echoed == body)
    };

    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, exchange).await,
        Ok(Ok(true))
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an Xray binary; see this file's module documentation"]
async fn generated_routing_corpus_matches_xray() {
    let binary =
        oracle_binary().unwrap_or_else(|error| panic!("routing oracle unavailable: {error}"));
    let primary = echo_service().await;
    let alternate = echo_service().await;
    let port_gate = echo_service().await;
    let (rules, cases) = corpus(primary.port(), alternate.port(), port_gate.port());
    assert!(cases.len() >= 100, "the generated corpus lost its breadth");

    let mut hosts = Map::new();
    for case in &cases {
        if let TargetHost::Domain(domain) = &case.host {
            hosts.insert(domain.clone(), json!(["127.0.0.1"]));
        }
    }

    let zray_port = free_port();
    let xray_port = free_port();
    let zray_address = SocketAddr::from(([127, 0, 0, 1], zray_port));
    let xray_address = SocketAddr::from(([127, 0, 0, 1], xray_port));
    let zray_config = config(zray_port, &rules, hosts.clone());
    let xray_config = config(xray_port, &rules, hosts);

    let _zray = spawn_zray(&zray_config);
    let _xray = spawn_oracle(&binary, &xray_config);
    wait_for_listener(zray_address, "Zray").await;
    wait_for_listener(xray_address, "Xray").await;

    let mut direct_cases = 0;
    let mut blocked_cases = 0;
    for case in &cases {
        let xray = reaches_echo(xray_address, case).await;
        assert_eq!(
            xray,
            case.direct,
            "Xray oracle disagreed with the generated witness for {} ({}:{})",
            case.name,
            case.host.label(),
            case.port,
        );
        let zray = reaches_echo(zray_address, case).await;
        assert_eq!(
            zray,
            xray,
            "routing parity mismatch for {} ({}:{})",
            case.name,
            case.host.label(),
            case.port,
        );
        if case.direct {
            direct_cases += 1;
        } else {
            blocked_cases += 1;
        }
    }

    assert!(direct_cases > 0, "corpus did not include direct witnesses");
    assert!(
        blocked_cases > 0,
        "corpus did not include blocked witnesses"
    );
    eprintln!(
        "routing oracle parity passed: {} cases ({} direct, {} blocked)",
        cases.len(),
        direct_cases,
        blocked_cases,
    );
}
