use std::fs;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct IpFileInfo {
    pub path: PathBuf,
    pub name: String,
    pub size_bytes: u64,
    pub valid_count: usize,
    pub sample_ips: Vec<String>,
}

impl IpFileInfo {
    pub fn inspect(path: &Path) -> Option<Self> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }

        let name = path.file_name()?.to_string_lossy().to_string();
        let size_bytes = meta.len();

        // Only the first lines are inspected, so only read those: the
        // search directories (home, cwd) can hold multi-gigabyte .txt/.csv
        // files that must not be slurped into memory just to list them.
        let reader = BufReader::new(fs::File::open(path).ok()?);
        let mut valid_count = 0usize;
        let mut sample_ips = Vec::new();

        for line in reader.lines().take(2000) {
            let Ok(line) = line else { break };
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let field = trimmed.split(',').next().unwrap_or("").trim();
            let host = field.split(':').next().unwrap_or("").trim();

            let is_ip = Ipv4Addr::from_str(host).is_ok();
            let is_cidr = field.contains('/')
                && field
                    .split('/')
                    .next()
                    .is_some_and(|ip_str| Ipv4Addr::from_str(ip_str).is_ok());

            if is_ip || is_cidr {
                valid_count += 1;
                if sample_ips.len() < 4 {
                    sample_ips.push(field.to_string());
                }
            }
        }

        if valid_count > 0 {
            Some(Self {
                path: path.to_path_buf(),
                name,
                size_bytes,
                valid_count,
                sample_ips,
            })
        } else {
            None
        }
    }
}

pub fn scan_for_ip_files(search_dirs: &[PathBuf]) -> Vec<IpFileInfo> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for dir in search_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if matches!(ext, "txt" | "csv" | "ips" | "tsv" | "list")
                        && seen.insert(path.clone())
                    {
                        if let Some(info) = IpFileInfo::inspect(&path) {
                            files.push(info);
                        }
                    }
                }
            }
        }
    }

    files.sort_by_key(|f| std::cmp::Reverse(f.valid_count));
    files
}
