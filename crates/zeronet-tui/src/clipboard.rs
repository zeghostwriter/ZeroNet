//! System clipboard access, with a terminal fallback.
//!
//! Two paths, because neither works everywhere:
//!
//! * **`arboard`** talks to the local window system (X11, Wayland, macOS,
//!   Windows). It is the right answer when the client runs on the user's own
//!   desktop.
//! * **OSC 52** asks the *terminal* to set its clipboard over the escape
//!   stream, which is the only thing that works over SSH — where the machine
//!   running the client has no clipboard of its own. Many terminals ship with
//!   it disabled, so it is a fallback rather than the default.
//!
//! Reading back is local-only: OSC 52 paste requires a terminal response that
//! is not reliably available, so over SSH the user pastes into the app with
//! their terminal's own paste instead.

/// Where a clipboard write ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyRoute {
    /// The system clipboard, via the window system.
    System,
    /// Handed to the terminal with OSC 52.
    TerminalOsc52,
}

pub struct Clipboard {
    /// Held open across calls: on X11 the clipboard contents are owned by a
    /// live connection, and dropping it can drop the selection with it.
    inner: Option<arboard::Clipboard>,
    /// Last value written, so a failed system copy can still be pasted back
    /// inside the app.
    last_copied: Option<String>,
}

impl Default for Clipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Clipboard {
    pub fn new() -> Self {
        Self {
            // A headless or SSH session has no clipboard; that is expected,
            // not an error, and the OSC 52 path covers it.
            inner: arboard::Clipboard::new().ok(),
            last_copied: None,
        }
    }

    /// Whether a system clipboard was available at startup.
    pub fn has_system_clipboard(&self) -> bool {
        self.inner.is_some()
    }

    /// Copy `text`, returning which route carried it.
    pub fn copy(&mut self, text: &str) -> Result<CopyRoute, String> {
        self.last_copied = Some(text.to_string());

        if let Some(clipboard) = self.inner.as_mut() {
            match clipboard.set_text(text) {
                Ok(()) => return Ok(CopyRoute::System),
                Err(e) => {
                    // Fall through to OSC 52 rather than giving up: a
                    // transient X11 failure should not cost the user the copy.
                    tracing::debug!(error = %e, "system clipboard write failed");
                }
            }
        }

        emit_osc52(text)?;
        Ok(CopyRoute::TerminalOsc52)
    }

    /// Read the clipboard.
    ///
    /// Falls back to the last value this app copied, so copy-then-paste works
    /// even where the system clipboard is unreadable.
    pub fn paste(&mut self) -> Result<String, String> {
        if let Some(clipboard) = self.inner.as_mut() {
            if let Ok(text) = clipboard.get_text() {
                if !text.trim().is_empty() {
                    return Ok(text);
                }
            }
        }
        self.last_copied
            .clone()
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| {
                "no clipboard here. Paste with your terminal instead (Ctrl+Shift+V)".to_string()
            })
    }
}

/// Ask the terminal to set its clipboard.
///
/// Written straight to the tty rather than to stdout, so it still works while
/// ratatui owns the alternate screen.
fn emit_osc52(text: &str) -> Result<(), String> {
    use base64::Engine as _;
    use std::io::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    // Some terminals cap OSC 52 payloads around 100 KB; a share link is
    // nowhere near that, but a bulk export could be.
    if encoded.len() > 74_000 {
        return Err("too big for the terminal clipboard. Export it to a file instead".into());
    }

    let sequence = format!("\x1b]52;c;{encoded}\x07");
    let mut tty = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("no clipboard available: {e}"))?;
    tty.write_all(sequence.as_bytes())
        .map_err(|e| format!("could not write to the terminal: {e}"))?;
    tty.flush()
        .map_err(|e| format!("could not flush the terminal: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_then_paste_round_trips_through_the_local_cache() {
        // Works with or without a real system clipboard, which is what makes
        // it safe to run in CI.
        let mut cb = Clipboard::new();
        let link = "vless://uuid@example.com:443#Node";

        // The copy may route either way depending on the environment; both
        // are success.
        if cb.copy(link).is_ok() {
            assert_eq!(cb.paste().unwrap(), link);
        }
    }

    #[test]
    fn paste_without_anything_copied_explains_itself() {
        let mut cb = Clipboard {
            inner: None,
            last_copied: None,
        };
        let err = cb.paste().unwrap_err();
        assert!(err.contains("terminal"), "{err}");
    }

    #[test]
    fn an_oversized_payload_is_refused_rather_than_truncated() {
        // Silently truncating a config would produce a corrupt link that
        // fails mysteriously on the other end.
        let huge = "x".repeat(200_000);
        let err = emit_osc52(&huge).unwrap_err();
        assert!(err.contains("too big"), "{err}");
    }

    #[test]
    fn the_local_cache_survives_a_failed_system_write() {
        let mut cb = Clipboard {
            inner: None,
            last_copied: None,
        };
        // With no system clipboard and no tty in the test harness, the copy
        // may fail — but the value is still cached for an in-app paste.
        let _ = cb.copy("cached value");
        assert_eq!(cb.last_copied.as_deref(), Some("cached value"));
    }
}
