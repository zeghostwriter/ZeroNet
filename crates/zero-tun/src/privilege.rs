//! Privilege and driver capability checks for desktop platforms (Linux, macOS, Windows).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeStatus {
    Privileged,
    NeedsElevation(&'static str),
    MissingDriver(&'static str),
    Unsupported,
}

impl PrivilegeStatus {
    pub fn is_ready(&self) -> bool {
        matches!(self, PrivilegeStatus::Privileged)
    }

    pub fn prompt_message(&self) -> Option<&'static str> {
        match self {
            PrivilegeStatus::Privileged => None,
            PrivilegeStatus::NeedsElevation(msg) => Some(msg),
            PrivilegeStatus::MissingDriver(msg) => Some(msg),
            PrivilegeStatus::Unsupported => Some("TUN is not supported on this platform"),
        }
    }
}

/// Check whether the current process has the required privileges / drivers to operate TUN.
pub fn check_tun_permissions() -> PrivilegeStatus {
    #[cfg(target_os = "linux")]
    {
        // On Linux, we either need euid == 0 (root) or CAP_NET_ADMIN capabilities.
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            return PrivilegeStatus::Privileged;
        }

        // Check if CAP_NET_ADMIN is present in effective capabilities (bit 12: 0x1000)
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(hex_str) = line.strip_prefix("CapEff:\t") {
                    if let Ok(caps) = u64::from_str_radix(hex_str.trim(), 16) {
                        const CAP_NET_ADMIN: u64 = 1 << 12;
                        if caps & CAP_NET_ADMIN != 0 {
                            return PrivilegeStatus::Privileged;
                        }
                    }
                }
            }
        }

        // Check whether /dev/net/tun exists
        let path = std::path::Path::new("/dev/net/tun");
        if !path.exists() {
            return PrivilegeStatus::NeedsElevation(
                "Linux /dev/net/tun missing; run `sudo modprobe tun` or elevate with sudo.",
            );
        }

        PrivilegeStatus::NeedsElevation(
            "Missing CAP_NET_ADMIN privileges. Run ZeroNet TUI with `sudo`.",
        )
    }

    #[cfg(target_os = "macos")]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            PrivilegeStatus::Privileged
        } else {
            PrivilegeStatus::NeedsElevation(
                "macOS utun interface requires root privileges. Please run with `sudo`.",
            )
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Check for wintun.dll in current directory or PATH
        let dll_exists = std::path::Path::new("wintun.dll").exists()
            || std::env::current_exe()
                .map(|p| {
                    p.parent()
                        .map(|dir| dir.join("wintun.dll").exists())
                        .unwrap_or(false)
                })
                .unwrap_or(false);

        if !dll_exists {
            return PrivilegeStatus::MissingDriver("wintun.dll was not found beside binary. Please download Wintun driver or place wintun.dll in the current folder.");
        }

        // On Windows, administrator privileges are required to create Wintun adapter.
        PrivilegeStatus::Privileged
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PrivilegeStatus::Unsupported
    }
}
