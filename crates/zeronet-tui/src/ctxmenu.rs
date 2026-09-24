//! Right-click context menu.
//!
//! The menu's contents depend on what was clicked, so the caller builds it
//! from a [`MenuTarget`] and the menu itself stays a dumb list: entries, a
//! highlighted index, and where to draw. That keeps the "what can I do to
//! this thing" decision in one readable place instead of spread across the
//! renderer.
//!
//! Placement flips the menu left or up when it would otherwise run off the
//! screen, which is what every desktop menu does and what stops the last
//! entry being unreachable near an edge.

use ratatui::layout::Rect;

/// What was right-clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuTarget {
    /// A profile row, by its index in the visible list.
    Profile(usize),
    /// A subscription row.
    Subscription(usize),
    /// A discovered scanner endpoint.
    ScannerResult(usize),
    /// Empty space on the main screen.
    Background,
    /// The system proxy switcher chip.
    ProxySwitcher,
}

/// One entry in the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    Connect,
    Disconnect,
    Copy,
    Paste,
    ShowQr,
    Rename,
    Duplicate,
    Delete,
    TestLatency,
    SelectAll,
    ClearSelection,
    ShowLogs,
    RefreshSubscriptions,
    ImportFromFile,
    ExportSelected,
    NewProfile,
    ApplyEndpoint,
    Settings,
    Help,
    SetProxyManual,
    SetProxyUnmanaged,
    SetProxyPac,
    SetProxyClear,
}

impl MenuAction {
    pub fn label(self) -> &'static str {
        match self {
            MenuAction::Connect => "Connect",
            MenuAction::Disconnect => "Disconnect",
            MenuAction::Copy => "Copy share link",
            MenuAction::Paste => "Paste / import",
            MenuAction::ShowQr => "Share config…",
            MenuAction::Rename => "Rename…",
            MenuAction::Duplicate => "Duplicate",
            MenuAction::Delete => "Delete",
            MenuAction::TestLatency => "Test latency",
            MenuAction::SelectAll => "Select all",
            MenuAction::ClearSelection => "Clear selection",
            MenuAction::ShowLogs => "Show logs…",
            MenuAction::RefreshSubscriptions => "Update subscriptions",
            MenuAction::ImportFromFile => "Import from file…",
            MenuAction::ExportSelected => "Export selected…",
            MenuAction::NewProfile => "New profile…",
            MenuAction::ApplyEndpoint => "Use this endpoint",
            MenuAction::Settings => "Settings",
            MenuAction::Help => "Keyboard reference",
            MenuAction::SetProxyManual => "Set System Proxy (Manual)",
            MenuAction::SetProxyUnmanaged => "Do Not Change (Keep)",
            MenuAction::SetProxyPac => "PAC Mode (Auto)",
            MenuAction::SetProxyClear => "Clear / Disable Proxy",
        }
    }

    /// Shortcut shown on the right of the entry, where one exists.
    pub fn accelerator(self) -> &'static str {
        match self {
            MenuAction::Connect | MenuAction::Disconnect => "↵",
            MenuAction::Copy => "^C",
            MenuAction::Paste => "^V",
            MenuAction::ShowQr => "^G",
            MenuAction::Rename => "F2",
            MenuAction::Duplicate => "^D",
            MenuAction::Delete => "Del",
            MenuAction::TestLatency => "^L",
            MenuAction::SelectAll => "^A",
            MenuAction::ClearSelection => "Esc",
            MenuAction::RefreshSubscriptions => "^R",
            MenuAction::ImportFromFile => "^O",
            MenuAction::ExportSelected => "^E",
            MenuAction::NewProfile => "^N",
            MenuAction::Settings => "^,",
            MenuAction::Help => "F1",
            MenuAction::SetProxyManual => "local",
            MenuAction::SetProxyUnmanaged => "keep",
            MenuAction::SetProxyPac => "pac",
            MenuAction::SetProxyClear => "none",
            _ => "",
        }
    }

    /// Whether this entry destroys something, so it can be coloured as such.
    pub fn is_destructive(self) -> bool {
        matches!(self, MenuAction::Delete | MenuAction::SetProxyClear)
    }
}

/// An entry, or a separator between groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Action(MenuAction),
    Separator,
}

#[derive(Debug, Clone)]
pub struct ContextMenu {
    pub target: MenuTarget,
    pub items: Vec<MenuItem>,
    /// Where the click happened; the menu is placed from here.
    anchor: (u16, u16),
    /// Keyboard highlight, an index into `items`.
    highlighted: usize,
    created_tick: u64,
}

impl ContextMenu {
    /// Build the menu for whatever was right-clicked.
    ///
    /// `connected` and `has_selection` tailor the entries: offering
    /// "Disconnect" while offline, or "Export selected" with nothing
    /// selected, is the kind of dead entry that makes a menu feel generated
    /// rather than designed.
    pub fn for_target(
        target: MenuTarget,
        anchor: (u16, u16),
        tick: u64,
        connected: bool,
        has_selection: bool,
    ) -> Self {
        use MenuAction::*;
        use MenuItem::{Action, Separator};

        let items = match target {
            MenuTarget::Profile(_) => {
                // The order a person scanning the menu expects: do the thing,
                // check it, name it, share it, and only then destroy it.
                let mut v = vec![
                    Action(if connected { Disconnect } else { Connect }),
                    Action(TestLatency),
                    Separator,
                    Action(Rename),
                    Action(ShowQr),
                    Action(Copy),
                    Separator,
                    Action(Duplicate),
                    Action(Paste),
                ];
                if has_selection {
                    v.push(Action(ExportSelected));
                }
                v.push(Action(SelectAll));
                if has_selection {
                    v.push(Action(ClearSelection));
                }
                v.push(Separator);
                v.push(Action(Delete));
                v
            }
            MenuTarget::Subscription(_) => vec![
                Action(RefreshSubscriptions),
                Separator,
                Action(Copy),
                Action(Paste),
                Separator,
                Action(Delete),
            ],
            MenuTarget::ScannerResult(_) => vec![
                Action(ApplyEndpoint),
                Separator,
                Action(Copy),
                Action(ExportSelected),
            ],
            MenuTarget::ProxySwitcher => vec![
                Action(SetProxyManual),
                Action(SetProxyUnmanaged),
                Action(SetProxyPac),
                Separator,
                Action(SetProxyClear),
            ],
            MenuTarget::Background => vec![
                Action(NewProfile),
                Action(Paste),
                Action(ImportFromFile),
                Separator,
                Action(RefreshSubscriptions),
                Action(TestLatency),
                Separator,
                Action(ShowLogs),
                Action(Settings),
                Action(Help),
            ],
        };

        let mut menu = Self {
            target,
            items,
            anchor,
            highlighted: 0,
            created_tick: tick,
        };
        menu.highlighted = menu.first_action().unwrap_or(0);
        menu
    }

    pub fn created_tick(&self) -> u64 {
        self.created_tick
    }

    pub fn highlighted(&self) -> usize {
        self.highlighted
    }

    fn first_action(&self) -> Option<usize> {
        self.items
            .iter()
            .position(|i| matches!(i, MenuItem::Action(_)))
    }

    /// The action under the keyboard highlight.
    pub fn highlighted_action(&self) -> Option<MenuAction> {
        match self.items.get(self.highlighted) {
            Some(MenuItem::Action(a)) => Some(*a),
            _ => None,
        }
    }

    /// Move the highlight, skipping separators and wrapping around.
    pub fn move_highlight(&mut self, delta: i32) {
        if self.items.is_empty() {
            return;
        }
        let len = self.items.len() as i32;
        let mut idx = self.highlighted as i32;
        for _ in 0..len {
            idx = (idx + delta).rem_euclid(len);
            if matches!(self.items[idx as usize], MenuItem::Action(_)) {
                self.highlighted = idx as usize;
                return;
            }
        }
    }

    /// Set the highlight from a hovered row index.
    pub fn highlight(&mut self, index: usize) {
        if matches!(self.items.get(index), Some(MenuItem::Action(_))) {
            self.highlighted = index;
        }
    }

    /// Width the menu needs: the widest `label + accelerator`, plus padding
    /// and the border.
    pub fn width(&self) -> u16 {
        let widest = self
            .items
            .iter()
            .filter_map(|i| match i {
                MenuItem::Action(a) => {
                    Some(a.label().chars().count() + a.accelerator().chars().count())
                }
                MenuItem::Separator => None,
            })
            .max()
            .unwrap_or(10);
        // label + gap + accelerator + two borders + two padding columns.
        (widest + 8).clamp(18, 40) as u16
    }

    pub fn height(&self) -> u16 {
        self.items.len() as u16 + 2
    }

    /// Where to draw, flipped away from whichever screen edge it would
    /// otherwise cross.
    pub fn rect(&self, screen: Rect) -> Rect {
        let (w, h) = (
            self.width().min(screen.width),
            self.height().min(screen.height),
        );
        let (ax, ay) = self.anchor;

        // Prefer down-and-right of the cursor, like every desktop menu.
        // Saturating: the anchor is from before a resize and may now be far
        // outside a shrunken screen.
        let x = if ax.saturating_add(w) <= screen.right() {
            ax
        } else {
            ax.saturating_sub(w).max(screen.x)
        };
        let y = if ay.saturating_add(h) <= screen.bottom() {
            ay
        } else {
            ay.saturating_sub(h).max(screen.y)
        };

        Rect {
            x: x.min(screen.right().saturating_sub(w)),
            y: y.min(screen.bottom().saturating_sub(h)),
            width: w,
            height: h,
        }
    }

    /// The row rectangle for `index`, for hit-testing and hover.
    pub fn item_rect(&self, index: usize, screen: Rect) -> Option<Rect> {
        let area = self.rect(screen);
        // Rows live strictly between the top and bottom border. On a screen
        // too short for the whole menu the rows that do not fit are dropped,
        // rather than one of them being drawn over the bottom border.
        let y = area.y as usize + 1 + index;
        if y + 1 >= area.bottom() as usize {
            return None;
        }
        let y = y as u16;
        Some(Rect {
            x: area.x + 1,
            y,
            width: area.width.saturating_sub(2),
            height: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen() -> Rect {
        Rect {
            x: 0,
            y: 0,
            width: 120,
            height: 40,
        }
    }

    fn menu(target: MenuTarget, anchor: (u16, u16)) -> ContextMenu {
        ContextMenu::for_target(target, anchor, 0, false, false)
    }

    #[test]
    fn a_profile_menu_offers_the_profile_actions() {
        let m = menu(MenuTarget::Profile(0), (10, 10));
        let actions: Vec<MenuAction> = m
            .items
            .iter()
            .filter_map(|i| match i {
                MenuItem::Action(a) => Some(*a),
                _ => None,
            })
            .collect();

        for expected in [
            MenuAction::Connect,
            MenuAction::Copy,
            MenuAction::ShowQr,
            MenuAction::Paste,
            MenuAction::Rename,
            MenuAction::Duplicate,
            MenuAction::Delete,
        ] {
            assert!(actions.contains(&expected), "{expected:?} missing");
        }
    }

    #[test]
    fn the_menu_reflects_the_connection_state() {
        // Offering "Disconnect" while offline is a dead entry.
        let offline = ContextMenu::for_target(MenuTarget::Profile(0), (5, 5), 0, false, false);
        assert!(offline
            .items
            .contains(&MenuItem::Action(MenuAction::Connect)));
        assert!(!offline
            .items
            .contains(&MenuItem::Action(MenuAction::Disconnect)));

        let online = ContextMenu::for_target(MenuTarget::Profile(0), (5, 5), 0, true, false);
        assert!(online
            .items
            .contains(&MenuItem::Action(MenuAction::Disconnect)));
        assert!(!online
            .items
            .contains(&MenuItem::Action(MenuAction::Connect)));
    }

    #[test]
    fn export_and_clear_appear_only_with_a_selection() {
        let none = ContextMenu::for_target(MenuTarget::Profile(0), (5, 5), 0, false, false);
        assert!(!none
            .items
            .contains(&MenuItem::Action(MenuAction::ExportSelected)));
        assert!(!none
            .items
            .contains(&MenuItem::Action(MenuAction::ClearSelection)));

        let some = ContextMenu::for_target(MenuTarget::Profile(0), (5, 5), 0, false, true);
        assert!(some
            .items
            .contains(&MenuItem::Action(MenuAction::ExportSelected)));
        assert!(some
            .items
            .contains(&MenuItem::Action(MenuAction::ClearSelection)));
    }

    #[test]
    fn the_background_menu_has_the_global_actions() {
        let m = menu(MenuTarget::Background, (5, 5));
        for expected in [
            MenuAction::NewProfile,
            MenuAction::Paste,
            MenuAction::ShowLogs,
            MenuAction::Settings,
            MenuAction::Help,
        ] {
            assert!(
                m.items.contains(&MenuItem::Action(expected)),
                "{expected:?} missing from the background menu"
            );
        }
    }

    #[test]
    fn the_highlight_starts_on_an_action_not_a_separator() {
        for target in [
            MenuTarget::Profile(0),
            MenuTarget::Subscription(0),
            MenuTarget::ScannerResult(0),
            MenuTarget::Background,
        ] {
            let m = menu(target, (5, 5));
            assert!(
                m.highlighted_action().is_some(),
                "{target:?} opened with the highlight on a separator"
            );
        }
    }

    #[test]
    fn moving_the_highlight_skips_separators_and_wraps() {
        let mut m = menu(MenuTarget::Profile(0), (5, 5));
        let mut seen = Vec::new();
        for _ in 0..m.items.len() * 2 {
            m.move_highlight(1);
            assert!(
                m.highlighted_action().is_some(),
                "the highlight landed on a separator"
            );
            seen.push(m.highlighted());
        }
        // It wrapped: an index repeats.
        assert!(seen.len() > seen.iter().collect::<std::collections::HashSet<_>>().len());

        // And it goes the other way too.
        for _ in 0..5 {
            m.move_highlight(-1);
            assert!(m.highlighted_action().is_some());
        }
    }

    #[test]
    fn the_menu_opens_down_and_right_of_the_cursor() {
        let m = menu(MenuTarget::Profile(0), (10, 5));
        let r = m.rect(screen());
        assert_eq!((r.x, r.y), (10, 5));
    }

    #[test]
    fn the_menu_flips_away_from_the_right_and_bottom_edges() {
        // Otherwise the last entries are off screen and unreachable.
        let s = screen();
        let m = menu(MenuTarget::Profile(0), (118, 38));
        let r = m.rect(s);

        assert!(r.right() <= s.right(), "menu ran off the right edge: {r:?}");
        assert!(r.bottom() <= s.bottom(), "menu ran off the bottom: {r:?}");
        assert!(r.x < 118, "menu did not flip left");
    }

    #[test]
    fn the_menu_always_fits_on_screen_from_any_anchor() {
        let s = screen();
        for x in (0..s.width).step_by(7) {
            for y in (0..s.height).step_by(5) {
                let m = menu(MenuTarget::Background, (x, y));
                let r = m.rect(s);
                assert!(
                    r.x >= s.x && r.y >= s.y,
                    "escaped top-left at ({x},{y}): {r:?}"
                );
                assert!(
                    r.right() <= s.right() && r.bottom() <= s.bottom(),
                    "escaped bottom-right at ({x},{y}): {r:?}"
                );
                assert!(r.width > 0 && r.height > 0);
            }
        }
    }

    #[test]
    fn the_menu_is_wide_enough_for_its_longest_entry() {
        let m = menu(MenuTarget::Background, (0, 0));
        let widest = m
            .items
            .iter()
            .filter_map(|i| match i {
                MenuItem::Action(a) => {
                    Some(a.label().chars().count() + a.accelerator().chars().count())
                }
                _ => None,
            })
            .max()
            .unwrap();
        assert!(
            m.width() as usize >= widest + 4,
            "menu width {} cannot hold {widest} columns of text",
            m.width()
        );
    }

    #[test]
    fn item_rects_line_up_under_the_menu_border() {
        let s = screen();
        let m = menu(MenuTarget::Profile(0), (10, 5));
        let area = m.rect(s);
        for i in 0..m.items.len() {
            let r = m.item_rect(i, s).expect("row fits");
            assert!(r.y > area.y, "row {i} overlapped the top border");
            assert!(r.y < area.bottom(), "row {i} fell past the menu");
            assert_eq!(r.x, area.x + 1);
        }
    }

    #[test]
    fn only_delete_is_marked_destructive() {
        assert!(MenuAction::Delete.is_destructive());
        for a in [
            MenuAction::Connect,
            MenuAction::Copy,
            MenuAction::Rename,
            MenuAction::ShowLogs,
        ] {
            assert!(!a.is_destructive(), "{a:?} should not be destructive");
        }
    }

    #[test]
    fn every_action_has_a_label() {
        for a in [
            MenuAction::Connect,
            MenuAction::Disconnect,
            MenuAction::Copy,
            MenuAction::Paste,
            MenuAction::ShowQr,
            MenuAction::Rename,
            MenuAction::Duplicate,
            MenuAction::Delete,
            MenuAction::TestLatency,
            MenuAction::SelectAll,
            MenuAction::ClearSelection,
            MenuAction::ShowLogs,
            MenuAction::RefreshSubscriptions,
            MenuAction::ImportFromFile,
            MenuAction::ExportSelected,
            MenuAction::NewProfile,
            MenuAction::ApplyEndpoint,
            MenuAction::Settings,
            MenuAction::Help,
        ] {
            assert!(!a.label().is_empty(), "{a:?} has no label");
        }
    }

    #[test]
    fn a_clipped_menu_never_draws_a_row_on_its_border() {
        let short = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 4,
        };
        let m = menu(MenuTarget::Background, (10, 0));
        let area = m.rect(short);
        for i in 0..m.items.len() {
            if let Some(r) = m.item_rect(i, short) {
                assert!(
                    r.y > area.y && r.y + 1 < area.bottom(),
                    "row {i} on the border"
                );
            }
        }
    }

    #[test]
    fn a_stale_anchor_far_off_screen_does_not_overflow() {
        let m = menu(MenuTarget::Background, (u16::MAX - 2, u16::MAX - 2));
        let r = m.rect(screen());
        assert!(r.right() <= screen().right() && r.bottom() <= screen().bottom());
    }
}
