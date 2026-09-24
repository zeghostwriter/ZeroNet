use super::parser::ProxyConfig;
use super::validator::ProxyValidationResult;
use crate::probe::trace::extract_colo;
use serde_json::json;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

/// Asks the OS for a currently free loopback port. The old wrapping u16
/// counter handed out ports that were already in use (or privileged, after
/// wrapping to 0).
fn free_local_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// Writes `data` to a new file readable only by the current user. The config
/// contains the proxy UUID/password and lives in the shared temp directory:
/// it must not be world-readable, and an existing file or symlink planted at
/// the path must not be followed.
fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn find_xray_binary() -> Option<PathBuf> {
    for candidate in &["/usr/bin/xray", "/usr/local/bin/xray", "xray"] {
        if let Ok(path) = which::which(candidate) {
            return Some(path);
        }
    }
    None
}

pub struct XrayRunner {
    binary_path: PathBuf,
}

impl XrayRunner {
    pub fn new(binary_path: PathBuf) -> Self {
        Self { binary_path }
    }

    pub fn auto() -> Option<Self> {
        find_xray_binary().map(Self::new)
    }

    pub async fn validate_endpoint(
        &self,
        ip: IpAddr,
        cfg: &ProxyConfig,
        timeout: Duration,
    ) -> ProxyValidationResult {
        let mut result = ProxyValidationResult {
            success: false,
            ttfb_ms: 0.0,
            throughput_mbps: 0.0,
            colo: None,
            error: None,
        };

        let socks_port = match free_local_port() {
            Ok(p) => p,
            Err(e) => {
                result.error = Some(format!("No free local port: {}", e));
                return result;
            }
        };
        let config_json = build_xray_json(cfg, &ip.to_string(), cfg.port, socks_port);

        let config_path = std::env::temp_dir().join(format!(
            "xray-test-{}-{}.json",
            std::process::id(),
            socks_port
        ));

        if let Err(e) = write_private_file(&config_path, config_json.as_bytes()) {
            result.error = Some(format!("Write config error: {}", e));
            return result;
        }
        // Removes the config (it holds the proxy credentials) however this
        // function exits, including when its future is dropped.
        let _config_guard = RemoveOnDrop(config_path.clone());

        let mut child = match Command::new(&self.binary_path)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // A cancelled validation must not leave an xray process behind.
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                result.error = Some(format!("Spawn xray error: {}", e));
                return result;
            }
        };

        // Wait until xray is actually listening instead of guessing with a
        // fixed sleep (too short on a loaded machine, wasted time otherwise).
        let ready_deadline = Instant::now() + timeout.min(Duration::from_secs(3));
        let mut first_stream = loop {
            match TcpStream::connect(("127.0.0.1", socks_port)).await {
                Ok(s) => break Some(s),
                Err(_) if Instant::now() < ready_deadline => {
                    if let Ok(Some(_)) = child.try_wait() {
                        break None;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(_) => break None,
            }
        };
        if first_stream.is_none() {
            result.error = Some("Xray did not start listening".to_string());
            let _ = child.kill().await;
            return result;
        }

        let start = Instant::now();
        let target_host = "cp.cloudflare.com";
        let target_port = 80u16;

        let probe_fut = async {
            let mut stream = match first_stream.take() {
                Some(s) => s,
                None => TcpStream::connect(("127.0.0.1", socks_port)).await?,
            };

            // SOCKS5 greeting
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp != [0x05, 0x00] {
                return Err(std::io::Error::other("SOCKS5 auth failed"));
            }

            // SOCKS5 connect to domain
            let mut conn_req = Vec::with_capacity(32);
            conn_req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, target_host.len() as u8]);
            conn_req.extend_from_slice(target_host.as_bytes());
            conn_req.extend_from_slice(&target_port.to_be_bytes());
            stream.write_all(&conn_req).await?;

            let mut reply_header = [0u8; 4];
            stream.read_exact(&mut reply_header).await?;
            if reply_header[1] != 0x00 {
                return Err(std::io::Error::other("SOCKS5 connection rejected by Xray"));
            }

            // Skip bind address in SOCKS5 reply
            match reply_header[3] {
                0x01 => {
                    let mut dummy = [0u8; 4 + 2];
                    stream.read_exact(&mut dummy).await?;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await?;
                    let mut dummy = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut dummy).await?;
                }
                0x04 => {
                    let mut dummy = [0u8; 16 + 2];
                    stream.read_exact(&mut dummy).await?;
                }
                _ => {}
            }

            // Send HTTP GET /cdn-cgi/trace
            let req = format!(
                "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target_host
            );
            stream.write_all(req.as_bytes()).await?;

            let mut buf = vec![0u8; 4096];
            let mut total_read = 0;
            let mut ttfb = None;

            loop {
                let n = stream.read(&mut buf[total_read..]).await?;
                if n == 0 {
                    break;
                }
                if ttfb.is_none() {
                    ttfb = Some(start.elapsed());
                }
                total_read += n;
                if total_read >= buf.len() - 64
                    || buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n")
                {
                    break;
                }
            }

            Ok::<(Vec<u8>, Duration), std::io::Error>((
                buf[..total_read].to_vec(),
                ttfb.unwrap_or_else(|| start.elapsed()),
            ))
        };

        match tokio::time::timeout(timeout, probe_fut).await {
            Ok(Ok((data, ttfb))) => {
                if data.windows(4).any(|w| w == b"HTTP") || data.windows(5).any(|w| w == b"colo=") {
                    result.success = true;
                    result.ttfb_ms = ttfb.as_secs_f64() * 1000.0;

                    result.colo = extract_colo(&data);
                } else {
                    result.error = Some("Xray returned non-HTTP response".to_string());
                }
            }
            Ok(Err(e)) => result.error = Some(format!("SOCKS test error: {}", e)),
            Err(_) => result.error = Some("Xray test timed out".to_string()),
        }

        let _ = child.kill().await;

        result
    }
}

pub fn build_xray_json(
    cfg: &ProxyConfig,
    endpoint_ip: &str,
    endpoint_port: u16,
    socks_port: u16,
) -> String {
    let mut outbound = json!({
        "tag": "proxy",
        "protocol": cfg.protocol,
        "settings": {},
        "streamSettings": {
            "network": cfg.transport,
            "security": cfg.security,
        }
    });

    if cfg.protocol == "vless" {
        outbound["settings"] = json!({
            "vnext": [{
                "address": endpoint_ip,
                "port": endpoint_port,
                "users": [{
                    "id": cfg.id_or_password,
                    "encryption": "none",
                }]
            }]
        });
    } else if cfg.protocol == "trojan" {
        outbound["settings"] = json!({
            "servers": [{
                "address": endpoint_ip,
                "port": endpoint_port,
                "password": cfg.id_or_password,
            }]
        });
    }

    if cfg.security == "tls" {
        outbound["streamSettings"]["tlsSettings"] = json!({
            "serverName": cfg.sni,
            "allowInsecure": false,
        });
    }

    if cfg.transport == "ws" {
        outbound["streamSettings"]["wsSettings"] = json!({
            "path": cfg.path,
            "headers": {
                "Host": cfg.host,
            }
        });
    }

    let config = json!({
        "log": {
            "loglevel": "none",
            "access": "",
            "error": ""
        },
        "dns": {
            "servers": ["localhost", "1.1.1.1", "8.8.8.8"]
        },
        "inbounds": [{
            "tag": "socks-in",
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "sniffing": {
                "enabled": false
            },
            "settings": {
                "udp": true
            }
        }],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            }
        ]
    });

    serde_json::to_string_pretty(&config).unwrap_or_default()
}

mod which {
    use std::path::PathBuf;

    pub fn which(name: &str) -> Result<PathBuf, ()> {
        if let Ok(paths) = std::env::var("PATH") {
            for dir in paths.split(':') {
                let p = PathBuf::from(dir).join(name);
                if p.is_file() {
                    return Ok(p);
                }
            }
        }
        Err(())
    }
}
