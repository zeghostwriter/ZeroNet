//! Terminal capability detection.
//!
//! Two things vary enough between terminals to be worth probing once at
//! startup and then carrying around as plain data:
//!
//! * **Colour depth.** Truecolor lets the theme use exact RGB; otherwise every
//!   colour is quantised into the xterm-256 cube (or the 16 ANSI slots on
//!   genuinely ancient terminals) so the palette still reads correctly.
//! * **Animation budget.** Per-frame colour interpolation over an SSH link
//!   costs a full redraw of every animated cell. On a remote or low-colour
//!   terminal the animations are turned off and the UI falls back to static
//!   colours, which is both cheaper and less noisy.

/// How many colours the attached terminal can actually display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColorDepth {
    /// 16 ANSI colours only — `TERM=linux`, `TERM=xterm`, serial consoles.
    Ansi16,
    /// The 256-colour xterm palette.
    Ansi256,
    /// 24-bit RGB.
    TrueColor,
}

#[derive(Debug, Clone, Copy)]
pub struct TerminalCaps {
    pub depth: ColorDepth,
    /// Whether per-frame animation should run at all.
    pub animations: bool,
    /// Whether the session is attached over SSH.
    pub remote: bool,
}

impl Default for TerminalCaps {
    fn default() -> Self {
        Self {
            depth: ColorDepth::TrueColor,
            animations: true,
            remote: false,
        }
    }
}

impl TerminalCaps {
    /// Probe the environment once. Callers should do this before entering raw
    /// mode and then pass the result down; nothing here re-reads the
    /// environment later.
    pub fn detect() -> Self {
        let depth = detect_depth();
        let remote = is_remote_session();

        // Animations are the first thing to go on a constrained terminal: a
        // remote session pays wire cost for every animated cell, and below
        // 256 colours the interpolated gradients collapse into a flicker
        // between two indistinguishable colours anyway.
        let mut animations = !remote && depth >= ColorDepth::Ansi256;

        // Explicit env overrides win in both directions, so a user on a fast
        // SSH link can opt back in and a user on a local but busy machine can
        // opt out.
        match std::env::var("ZERONET_ANIMATIONS").as_deref() {
            Ok("0") | Ok("off") | Ok("false") | Ok("no") => animations = false,
            Ok("1") | Ok("on") | Ok("true") | Ok("yes") => animations = true,
            _ => {}
        }
        if std::env::var_os("NO_ANIMATIONS").is_some() {
            animations = false;
        }

        Self {
            depth,
            animations,
            remote,
        }
    }

    pub fn truecolor(&self) -> bool {
        self.depth == ColorDepth::TrueColor
    }

    /// A one-line summary for the settings screen.
    pub fn describe(&self) -> String {
        let depth = match self.depth {
            ColorDepth::TrueColor => "truecolor",
            ColorDepth::Ansi256 => "256-color",
            ColorDepth::Ansi16 => "16-color",
        };
        let anim = if self.animations { "on" } else { "off" };
        if self.remote {
            format!("{depth} · ssh · animations {anim}")
        } else {
            format!("{depth} · animations {anim}")
        }
    }
}

fn detect_depth() -> ColorDepth {
    if let Ok(forced) = std::env::var("ZERONET_COLOR_DEPTH") {
        match forced.as_str() {
            "truecolor" | "24" | "24bit" => return ColorDepth::TrueColor,
            "256" | "8bit" => return ColorDepth::Ansi256,
            "16" | "ansi" => return ColorDepth::Ansi16,
            _ => {}
        }
    }

    // `COLORTERM` is the only widely honoured truecolor advertisement.
    if let Ok(ct) = std::env::var("COLORTERM") {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("truecolor") || ct.contains("24bit") {
            return ColorDepth::TrueColor;
        }
    }

    // Terminals that are known-truecolor but do not always export COLORTERM.
    if std::env::var_os("WT_SESSION").is_some() || std::env::var_os("KITTY_WINDOW_ID").is_some() {
        return ColorDepth::TrueColor;
    }
    if let Ok(prog) = std::env::var("TERM_PROGRAM") {
        let prog = prog.to_ascii_lowercase();
        if matches!(
            prog.as_str(),
            "iterm.app" | "wezterm" | "ghostty" | "vscode" | "rio"
        ) {
            return ColorDepth::TrueColor;
        }
    }

    let term = std::env::var("TERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if term.contains("direct") || term.contains("truecolor") {
        ColorDepth::TrueColor
    } else if term.contains("256") {
        ColorDepth::Ansi256
    } else if term.is_empty() || term == "dumb" {
        ColorDepth::Ansi16
    } else {
        // `screen`, `tmux`, `xterm`, `linux`: safe to assume 256, which every
        // one of them has supported for well over a decade.
        ColorDepth::Ansi256
    }
}

fn is_remote_session() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some()
        || std::env::var_os("SSH_TTY").is_some()
        || std::env::var_os("SSH_CLIENT").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_ordering_allows_threshold_checks() {
        assert!(ColorDepth::TrueColor > ColorDepth::Ansi256);
        assert!(ColorDepth::Ansi256 > ColorDepth::Ansi16);
    }

    #[test]
    fn describe_mentions_animation_state() {
        let caps = TerminalCaps {
            depth: ColorDepth::Ansi256,
            animations: false,
            remote: true,
        };
        let text = caps.describe();
        assert!(text.contains("ssh"));
        assert!(text.contains("animations off"));
    }
}
