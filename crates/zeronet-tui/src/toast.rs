//! Toast notifications.
//!
//! Ephemeral messages that expire on their own. The manager reports whether
//! an expiry actually removed anything ([`ToastManager::prune`]) so the frame
//! loop can treat a vanishing toast as a reason to redraw — and only then.

use ratatui::style::Color;
use std::time::{Duration, Instant};

/// How long a toast stays on screen.
const TOAST_LIFETIME: Duration = Duration::from_secs(5);
/// Notices that can be muted stay longer, so there is time to reach the
/// button.
const NOTICE_LIFETIME: Duration = Duration::from_secs(10);
/// Most toasts visible at once; older ones are dropped.
const MAX_VISIBLE: usize = 4;
/// How long a new toast takes to slide in from the right edge.
pub const TOAST_ENTER: Duration = Duration::from_millis(240);
/// How long a toast takes to fade out at the end of its life.
pub const TOAST_EXIT: Duration = Duration::from_millis(280);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    /// Start of the current lifetime. Refreshed when the same message is
    /// pushed again, which extends how long it stays up.
    pub created_at: Instant,
    /// When the toast first appeared. Not refreshed, so a repeated message
    /// does not replay its entrance.
    pub shown_at: Instant,
    pub duration: Duration,
    /// Set on a notice the user can silence for good: the key its "Don't
    /// show again" choice is remembered under.
    pub notice: Option<&'static str>,
}

impl Toast {
    fn expires_at(&self) -> Instant {
        self.created_at + self.duration
    }

    /// Slide-in progress, `0.0..=1.0`, eased so it decelerates into place.
    pub fn enter_progress(&self, now: Instant) -> f64 {
        let t =
            now.saturating_duration_since(self.shown_at).as_secs_f64() / TOAST_ENTER.as_secs_f64();
        ease_out_cubic(t)
    }

    /// Opacity while fading out, `1.0` until the last [`TOAST_EXIT`] of the
    /// toast's life and then easing down to `0.0`.
    pub fn exit_opacity(&self, now: Instant) -> f64 {
        let left = self.expires_at().saturating_duration_since(now);
        if left >= TOAST_EXIT {
            return 1.0;
        }
        ease_out_cubic(left.as_secs_f64() / TOAST_EXIT.as_secs_f64())
    }
}

fn ease_out_cubic(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

#[derive(Default, Clone)]
pub struct ToastManager {
    toasts: Vec<Toast>,
    /// Notices the user asked never to see again.
    muted: std::collections::BTreeSet<String>,
    /// Whether toasts slide in and fade out. Off by default so a snapshot of
    /// a frame shows every toast fully in place; the app turns it on when the
    /// terminal can afford animation.
    animated: bool,
}

impl ToastManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Turn the entrance and exit animations on or off.
    pub fn set_animated(&mut self, animated: bool) {
        self.animated = animated;
    }

    pub fn animated(&self) -> bool {
        self.animated
    }

    /// Whether a toast is mid-entrance or mid-fade at `now`, and so needs a
    /// frame drawn.
    pub fn is_animating(&self, now: Instant) -> bool {
        self.animated
            && self.toasts.iter().any(|t| {
                now.saturating_duration_since(t.shown_at) < TOAST_ENTER
                    || t.expires_at().saturating_duration_since(now) < TOAST_EXIT
            })
    }

    /// The next moment the toast stack changes on its own: an expiry, or the
    /// start of a fade-out. `None` with no toasts up.
    ///
    /// The frame loop sleeps until this rather than polling, so an idle
    /// screen with a toast on it wakes exactly once, when the toast goes.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.toasts
            .iter()
            .map(|t| {
                let expiry = t.expires_at();
                let fade = expiry.checked_sub(TOAST_EXIT).unwrap_or(expiry);
                if self.animated && fade > now {
                    fade
                } else {
                    expiry
                }
            })
            .min()
    }

    pub fn push(&mut self, message: impl Into<String>, kind: ToastKind) {
        let message = message.into();
        // Repeating the same message (a toggle pressed twice, a retry loop)
        // should refresh the existing toast rather than stack duplicates.
        if let Some(existing) = self
            .toasts
            .iter_mut()
            .find(|t| t.message == message && t.kind == kind)
        {
            existing.created_at = Instant::now();
            return;
        }

        let now = Instant::now();
        self.toasts.push(Toast {
            message,
            kind,
            created_at: now,
            shown_at: now,
            // Errors linger: they carry information the user may need to act
            // on, and losing one after four seconds means losing the only
            // explanation of why a connection failed.
            duration: if kind == ToastKind::Error {
                TOAST_LIFETIME * 2
            } else {
                TOAST_LIFETIME
            },
            notice: None,
        });

        while self.toasts.len() > MAX_VISIBLE {
            self.toasts.remove(0);
        }
    }

    /// Show a notice that carries a "Don't show again" button, unless the
    /// user has already chosen not to see the one filed under `key`.
    pub fn notice(&mut self, key: &'static str, message: impl Into<String>, kind: ToastKind) {
        if self.muted.contains(key) {
            return;
        }
        self.push(message, kind);
        if let Some(toast) = self.toasts.last_mut() {
            toast.notice = Some(key);
            toast.duration = toast.duration.max(NOTICE_LIFETIME);
        }
    }

    /// Replace the set of silenced notices (loaded from settings).
    pub fn set_muted<I, S>(&mut self, keys: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.muted = keys.into_iter().map(Into::into).collect();
    }

    /// The silenced notices, for saving.
    pub fn muted(&self) -> impl Iterator<Item = &str> {
        self.muted.iter().map(String::as_str)
    }

    /// "Don't show again" on the toast at `index`: dismiss it and remember
    /// its key. Returns whether anything was muted.
    pub fn mute(&mut self, index: usize) -> bool {
        let Some(key) = self.toasts.get(index).and_then(|t| t.notice) else {
            return false;
        };
        self.muted.insert(key.to_string());
        self.toasts.remove(index);
        true
    }

    pub fn success(&mut self, message: impl Into<String>) {
        self.push(message, ToastKind::Success);
    }

    pub fn info(&mut self, message: impl Into<String>) {
        self.push(message, ToastKind::Info);
    }

    pub fn warning(&mut self, message: impl Into<String>) {
        self.push(message, ToastKind::Warning);
    }

    pub fn error(&mut self, message: impl Into<String>) {
        self.push(message, ToastKind::Error);
    }

    /// Drop expired toasts, reporting whether anything was removed.
    ///
    /// The frame loop uses the return value to decide whether an otherwise
    /// idle tick needs a redraw.
    pub fn prune(&mut self) -> bool {
        let before = self.toasts.len();
        let now = Instant::now();
        self.toasts
            .retain(|t| now.duration_since(t.created_at) < t.duration);
        self.toasts.len() != before
    }

    pub fn active_toasts(&mut self) -> &[Toast] {
        self.prune();
        &self.toasts
    }

    pub fn len(&self) -> usize {
        self.toasts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.toasts.is_empty()
    }

    pub fn dismiss(&mut self, index: usize) {
        if index < self.toasts.len() {
            self.toasts.remove(index);
        }
    }

    /// The colour a toast of this kind is drawn in, from the active theme.
    pub fn color_for(kind: ToastKind, theme: &crate::theme::Theme) -> Color {
        match kind {
            ToastKind::Success => theme.ok,
            ToastKind::Info => theme.info,
            ToastKind::Warning => theme.warn,
            ToastKind::Error => theme.err,
        }
    }

    pub fn icon_for(kind: ToastKind) -> &'static str {
        match kind {
            ToastKind::Success => "✔ SUCCESS",
            ToastKind::Info => "ℹ INFO",
            ToastKind::Warning => "⚠ WARNING",
            ToastKind::Error => "✖ ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_muted_notice_is_dismissed_and_never_shown_again() {
        let mut t = ToastManager::new();
        t.notice("startup.hint", "a hint", ToastKind::Info);
        t.info("plain");
        assert_eq!(t.len(), 2);
        assert!(!t.mute(1), "an ordinary toast has nothing to mute");
        assert!(t.mute(0));
        assert_eq!(t.len(), 1);
        assert_eq!(t.muted().collect::<Vec<_>>(), ["startup.hint"]);
        t.notice("startup.hint", "a hint", ToastKind::Info);
        assert_eq!(t.len(), 1, "a muted notice came back");

        let mut fresh = ToastManager::new();
        fresh.set_muted(["startup.hint"]);
        fresh.notice("startup.hint", "a hint", ToastKind::Info);
        fresh.notice("other", "another", ToastKind::Info);
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn toasts_accumulate_and_dismiss() {
        let mut t = ToastManager::new();
        t.success("Connected");
        t.error("Failed");
        assert_eq!(t.active_toasts().len(), 2);

        t.dismiss(0);
        let left = t.active_toasts();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].message, "Failed");
    }

    #[test]
    fn identical_messages_refresh_instead_of_stacking() {
        let mut t = ToastManager::new();
        t.info("TUN on");
        t.info("TUN on");
        t.info("TUN on");
        assert_eq!(t.len(), 1, "duplicate toasts should collapse");
    }

    #[test]
    fn only_the_newest_toasts_are_kept() {
        let mut t = ToastManager::new();
        for i in 0..8 {
            t.info(format!("message {i}"));
        }
        assert_eq!(t.len(), MAX_VISIBLE);
        assert_eq!(t.active_toasts()[0].message, "message 4");
    }

    #[test]
    fn errors_outlive_ordinary_toasts() {
        let mut t = ToastManager::new();
        t.info("routine");
        t.error("connection refused");
        let toasts = t.active_toasts();
        let info = toasts.iter().find(|x| x.kind == ToastKind::Info).unwrap();
        let error = toasts.iter().find(|x| x.kind == ToastKind::Error).unwrap();
        assert!(error.duration > info.duration);
    }

    #[test]
    fn prune_reports_whether_it_changed_anything() {
        let mut t = ToastManager::new();
        assert!(!t.prune(), "nothing to prune on an empty manager");

        t.toasts.push(Toast {
            notice: None,
            message: "stale".into(),
            kind: ToastKind::Info,
            created_at: Instant::now() - Duration::from_secs(60),
            shown_at: Instant::now() - Duration::from_secs(60),
            duration: TOAST_LIFETIME,
        });
        assert!(t.prune(), "an expired toast should report a change");
        assert!(!t.prune(), "a second prune has nothing left to do");
        assert!(t.is_empty());
    }

    #[test]
    fn a_new_toast_slides_in_and_an_old_one_fades_out() {
        let mut t = ToastManager::new();
        t.set_animated(true);
        t.info("hello");
        let toast = t.active_toasts()[0].clone();
        let born = toast.shown_at;

        assert!(toast.enter_progress(born) < 0.01);
        assert!((toast.enter_progress(born + TOAST_ENTER) - 1.0).abs() < 1e-9);
        // Eased: well past halfway at the halfway mark.
        assert!(toast.enter_progress(born + TOAST_ENTER / 2) > 0.8);

        let expiry = toast.created_at + toast.duration;
        assert_eq!(toast.exit_opacity(expiry - TOAST_EXIT * 2), 1.0);
        assert!(toast.exit_opacity(expiry - TOAST_EXIT / 2) < 1.0);
        assert!(toast.exit_opacity(expiry) < 1e-9);

        assert!(t.is_animating(born));
        assert!(!t.is_animating(born + TOAST_ENTER + Duration::from_millis(1)));
    }

    #[test]
    fn a_refreshed_toast_does_not_replay_its_entrance() {
        let mut t = ToastManager::new();
        t.info("again");
        let shown = t.active_toasts()[0].shown_at;
        std::thread::sleep(Duration::from_millis(2));
        t.info("again");
        let toast = &t.active_toasts()[0];
        assert_eq!(toast.shown_at, shown);
        assert!(toast.created_at > shown, "the lifetime was not extended");
    }

    #[test]
    fn the_next_deadline_is_the_earliest_change() {
        let mut t = ToastManager::new();
        let now = Instant::now();
        assert_eq!(t.next_deadline(now), None);

        t.info("short");
        t.error("long");
        let info = t.active_toasts()[0].clone();
        // Without animation the only change is the expiry itself.
        assert_eq!(t.next_deadline(now), Some(info.created_at + info.duration));

        // With it, the fade-out starts a little earlier.
        t.set_animated(true);
        assert_eq!(
            t.next_deadline(now),
            Some(info.created_at + info.duration - TOAST_EXIT)
        );
    }

    #[test]
    fn every_kind_has_a_distinct_colour_and_icon() {
        let kinds = [
            ToastKind::Success,
            ToastKind::Info,
            ToastKind::Warning,
            ToastKind::Error,
        ];
        for id in crate::theme::ThemeId::ALL {
            let theme = crate::theme::Theme::new(id, crate::caps::ColorDepth::TrueColor);
            let colors: std::collections::HashSet<_> = kinds
                .iter()
                .map(|k| format!("{:?}", ToastManager::color_for(*k, &theme)))
                .collect();
            assert_eq!(colors.len(), kinds.len(), "{id:?}");
        }
    }
}
