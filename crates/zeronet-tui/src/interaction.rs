//! Mouse hit-testing and hover state.
//!
//! Each frame the renderer clears the hit list and re-registers a region for
//! every interactive component. Two things make this more than a list of
//! rectangles:
//!
//! * **Shapes.** The connect orb is a circle drawn inside a rectangular
//!   panel. Hit-testing its bounding box would make the empty corners of the
//!   panel clickable, so it registers an ellipse instead (an ellipse, not a
//!   circle, because a terminal cell is roughly twice as tall as it is wide).
//! * **Layers.** While a modal is open the rest of the screen must not accept
//!   clicks. The renderer marks where the modal's own regions begin, and
//!   hit-testing below that mark is refused — so a click that lands outside
//!   the dialog hits nothing rather than whatever happens to be underneath.

use ratatui::layout::Rect;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentId {
    // Header & Logo
    LogoButton,
    TunToggle,
    FeedbackButton,

    // Navigation
    NavDashboard,
    NavSubscriptions,
    NavScanner,
    NavSettings,
    NavActivity,
    FooterUsage,
    ActivitySortCpu,
    ActivitySortMemory,

    // Main Actions
    ConnectButton,
    ModeToggle,

    // Subscriptions
    RefreshSubsButton,
    AddConfigButton,
    AddManualConfigButton,
    AddSubButton,
    SubItem(usize),
    ConfigItem(usize),
    /// Per-row share button in the profile list.
    ConfigShare(usize),
    /// The always-present filter box.
    FilterBox,
    /// A row of the right-click menu.
    ContextMenuItem(usize),

    // Scanner
    RunScannerButton,
    ExportScannerButton,
    ScannerItem(usize),

    // Settings Interactive Controls (Click to change / edit number)
    SettingTunToggle,
    SettingTunMtu,
    SettingSocksPort,
    SettingHttpPort,
    SettingDnsCycle,
    SettingCustomDns,
    SettingAntiSanctionCycle,
    SettingFragmentMinus,
    SettingFragmentPlus,
    SettingFragmentValue,
    SettingJitterMinus,
    SettingJitterPlus,
    SettingJitterValue,
    SettingConcurrencyMinus,
    SettingConcurrencyPlus,
    SettingConcurrencyValue,
    SettingCleanIpToggle,
    SettingMuxToggle,
    SettingMuxConcurrency,
    SettingSniffingToggle,
    SettingDomainStrategyCycle,
    SettingTcpCongestionCycle,
    SettingAntiCensorshipCycle,
    SettingIpv6Toggle,
    SettingKeepaliveSecs,
    SettingSubUpdateHours,
    SettingAutoReconnectToggle,
    SettingAnimationsToggle,
    SettingThemeCycle,
    SettingUsageToggle,
    SettingMutedNotices,
    SettingSystemProxyCycle,
    SettingPacPort,
    /// The heading that folds the advanced settings.
    SettingAdvancedToggle,

    // Core engine settings carried over from v2rayN's option dialog.
    SettingLogLevelCycle,
    SettingAllowLanToggle,
    SettingUdpToggle,
    SettingSniffRouteOnlyToggle,
    SettingFingerprintCycle,
    SettingFragmentToggle,
    SettingTunDeviceName,
    SettingTunAutoRouteToggle,
    SettingTunStrictRouteToggle,

    // Cloudflare edge scanner
    SettingScannerModeCycle,
    SettingScannerPort,
    SettingScannerTries,
    SettingScannerTimeout,
    SettingScannerTargetCount,
    SettingScannerSni,
    SettingScannerRequireWsToggle,
    SettingScannerWsPath,
    SettingScannerNeighborsToggle,
    SettingScannerIpv4Toggle,
    SettingScannerIpv6Toggle,
    SettingScannerSpeedBytes,

    // Header
    SystemProxyChip,

    // Manual Profile Form
    ManualField(usize),
    ManualFormSave,
    ManualFormCancel,

    // Number Edit Modal
    NumberInputConfirm,
    NumberInputCancel,

    // Administrator password dialog
    SudoConfirm,
    SudoCancel,

    // Ashes Warning Modal
    AshesWarningDismiss,

    // Quit Confirmation Guardrail
    QuitConfirmYes,
    QuitConfirmNo,

    // Footer Shortcuts (Clickable)
    FooterTab,
    FooterConnect,
    FooterAddConfig,
    FooterAddSub,
    FooterFeedback,
    FooterShowQr,
    FooterFind,
    FooterHelp,
    FooterQuit,

    // Share dialog
    ShareCopyLink,
    ShareCopySubscription,

    // Modal Generic
    ModalConfirm,
    ModalCancel,
    /// The dialog's close button.
    ModalClose,
    /// The dimmed area outside the dialog.
    ModalBackdrop,
    /// The dialog's own body. Inert, but it must sit above the backdrop so a
    /// click on the dialog is not read as a click outside it.
    ModalSurface,

    // Toast
    ToastClose(usize),
    /// "Don't show again" on a toast that can be muted.
    ToastMute(usize),

    /// A piece of a scrollbar. `which` picks the list, `part` is 0 for the
    /// track above the thumb, 1 for the thumb, 2 for the track below it.
    Scrollbar {
        which: u8,
        part: u8,
    },
}

/// The clickable region of a component.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HitShape {
    Rect(Rect),
    /// Centre and radii in terminal cells. `ry` is expressed in rows, so a
    /// visually round orb has `ry` roughly half of `rx`.
    Ellipse {
        cx: f32,
        cy: f32,
        rx: f32,
        ry: f32,
    },
}

impl HitShape {
    pub fn contains(&self, x: u16, y: u16) -> bool {
        match *self {
            HitShape::Rect(rect) => {
                x >= rect.x
                    && x < rect.x.saturating_add(rect.width)
                    && y >= rect.y
                    && y < rect.y.saturating_add(rect.height)
            }
            HitShape::Ellipse { cx, cy, rx, ry } => {
                if rx <= 0.0 || ry <= 0.0 {
                    return false;
                }
                // Sample the centre of the cell, not its top-left corner, or
                // the hit area sits half a cell up and to the left of the
                // drawn orb.
                let dx = (x as f32 + 0.5 - cx) / rx;
                let dy = (y as f32 + 0.5 - cy) / ry;
                dx * dx + dy * dy <= 1.0
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct InteractionEngine {
    pub mouse_x: u16,
    pub mouse_y: u16,
    pub hovered_component: Option<ComponentId>,
    pub clicked_component: Option<ComponentId>,
    /// The control the button went down on. Cleared on release. Renderers
    /// use it to draw the pressed state for the one frame it matters.
    pub pressed: Option<ComponentId>,
    hit_regions: Vec<(ComponentId, HitShape)>,
    /// Index into `hit_regions` at which the topmost modal's regions begin.
    /// Anything registered before it is inert for as long as the modal is up.
    modal_floor: Option<usize>,
    /// Whether the terminal has reported a pointer position yet. Until it
    /// has, `mouse_x/mouse_y` are a meaningless `(0, 0)` and must not make
    /// whatever sits in the top-left corner look hovered.
    pointer_seen: bool,
    /// Set when a re-test after a frame found the pointer over a different
    /// component than the one that frame was drawn with.
    hover_stale: bool,
}

impl InteractionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear_hit_boxes(&mut self) {
        self.hit_regions.clear();
        self.modal_floor = None;
    }

    pub fn register_hit_box(&mut self, id: ComponentId, rect: Rect) {
        self.hit_regions.push((id, HitShape::Rect(rect)));
    }

    /// Register a round region — used by the connect orb so only the circle
    /// itself is clickable, not the panel corners around it.
    pub fn register_hit_ellipse(&mut self, id: ComponentId, cx: f32, cy: f32, rx: f32, ry: f32) {
        self.hit_regions
            .push((id, HitShape::Ellipse { cx, cy, rx, ry }));
    }

    /// Everything registered from here on belongs to a modal; everything
    /// registered before it stops responding to the mouse.
    ///
    /// Called by the renderer immediately before it draws a dialog, so the
    /// blocking is derived from what is actually on screen rather than
    /// tracked separately and allowed to drift.
    pub fn begin_modal_layer(&mut self) {
        self.modal_floor = Some(self.hit_regions.len());
    }

    /// Whether a modal layer is currently capturing the mouse.
    pub fn modal_layer_active(&self) -> bool {
        self.modal_floor.is_some()
    }

    pub fn update_mouse_position(&mut self, x: u16, y: u16) {
        self.mouse_x = x;
        self.mouse_y = y;
        self.pointer_seen = true;
        self.hovered_component = self.hit_test(x, y);
    }

    /// Forget the pointer, e.g. when the terminal loses focus: nothing
    /// should stay lit under a cursor that is now somewhere else entirely.
    pub fn clear_pointer(&mut self) {
        self.pointer_seen = false;
        self.hovered_component = None;
    }

    /// Re-test the pointer against the regions registered this frame.
    ///
    /// Hover is otherwise only recomputed when the mouse moves, against the
    /// *previous* frame's regions. When the layout moves under a still
    /// pointer — a toast appears, the list scrolls, a dialog opens — the
    /// highlight would stay on whatever used to be there. The renderer calls
    /// this after registering everything; a change marks the frame stale
    /// (see [`Self::take_hover_stale`]) so the loop draws once more with the
    /// right component lit.
    pub fn refresh_hover(&mut self) {
        let next = if self.pointer_seen {
            self.hit_test(self.mouse_x, self.mouse_y)
        } else {
            None
        };
        if next != self.hovered_component {
            self.hovered_component = next;
            self.hover_stale = true;
        }
    }

    /// Whether the last frame was drawn with a hover state that has since
    /// been corrected, clearing the flag.
    pub fn take_hover_stale(&mut self) -> bool {
        std::mem::take(&mut self.hover_stale)
    }

    pub fn handle_click(&mut self, x: u16, y: u16) -> Option<ComponentId> {
        self.mouse_x = x;
        self.mouse_y = y;
        let hit = self.hit_test(x, y);
        self.clicked_component = hit;
        hit
    }

    pub fn hit_test(&self, x: u16, y: u16) -> Option<ComponentId> {
        let floor = self.modal_floor.unwrap_or(0);
        // Reverse order so the most recently drawn (topmost) region wins.
        for (id, shape) in self.hit_regions[floor..].iter().rev() {
            if shape.contains(x, y) {
                return Some(*id);
            }
        }
        None
    }

    pub fn is_hovered(&self, id: ComponentId) -> bool {
        self.hovered_component == Some(id)
    }

    pub fn is_pressed(&self, id: ComponentId) -> bool {
        self.pressed == Some(id)
    }

    /// The rectangle registered for `id` this frame, if it is a rectangle.
    ///
    /// Used by the scrollbar gesture, which has to know where the thumb was
    /// drawn in order to keep the grab point under the pointer.
    pub fn region(&self, id: ComponentId) -> Option<Rect> {
        self.hit_regions
            .iter()
            .rev()
            .find_map(|(hit, shape)| match shape {
                HitShape::Rect(rect) if *hit == id => Some(*rect),
                _ => None,
            })
    }

    /// Number of regions registered this frame — used by tests and by the
    /// redraw check.
    pub fn region_count(&self) -> usize {
        self.hit_regions.len()
    }

    /// Returns whether any `ComponentId::ConfigItem` regions were registered.
    pub fn has_config_item_regions(&self) -> bool {
        self.hit_regions
            .iter()
            .any(|(id, _)| matches!(id, ComponentId::ConfigItem(_)))
    }

    /// Returns the indices of all `ComponentId::ConfigItem(i)` whose rectangles
    /// intersect the given rubber-band rectangle.
    pub fn swept_config_items(&self, drag_rect: Rect) -> Vec<usize> {
        let floor = self.modal_floor.unwrap_or(0);
        let mut items = Vec::new();
        for (id, shape) in &self.hit_regions[floor..] {
            if let ComponentId::ConfigItem(idx) = id {
                if let HitShape::Rect(rect) = shape {
                    if rects_intersect(*rect, drag_rect) {
                        items.push(*idx);
                    }
                }
            }
        }
        items.sort_unstable();
        items.dedup();
        items
    }
}

/// Whether two rectangles intersect.
pub fn rects_intersect(a: Rect, b: Rect) -> bool {
    a.x < b.x.saturating_add(b.width)
        && a.x.saturating_add(a.width) > b.x
        && a.y < b.y.saturating_add(b.height)
        && a.y.saturating_add(a.height) > b.y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_hit_testing_respects_bounds() {
        let shape = HitShape::Rect(Rect {
            x: 10,
            y: 5,
            width: 4,
            height: 2,
        });
        assert!(shape.contains(10, 5));
        assert!(shape.contains(13, 6));
        assert!(!shape.contains(14, 6));
        assert!(!shape.contains(13, 7));
    }

    #[test]
    fn ellipse_rejects_the_corners_of_its_bounding_box() {
        let mut engine = InteractionEngine::new();
        engine.register_hit_ellipse(ComponentId::ConnectButton, 20.0, 10.0, 10.0, 5.0);

        // Dead centre hits.
        assert_eq!(engine.hit_test(20, 10), Some(ComponentId::ConnectButton));
        // On the horizontal axis, inside the radius.
        assert_eq!(engine.hit_test(26, 10), Some(ComponentId::ConnectButton));
        // The corner of the bounding box is outside the circle.
        assert_eq!(engine.hit_test(29, 14), None);
        // Well outside.
        assert_eq!(engine.hit_test(40, 10), None);
    }

    #[test]
    fn modal_layer_blocks_everything_beneath_it() {
        let mut engine = InteractionEngine::new();
        let background = Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        };
        engine.register_hit_box(ComponentId::ConnectButton, background);

        // Without a modal, the background is live.
        assert_eq!(engine.hit_test(5, 5), Some(ComponentId::ConnectButton));

        engine.begin_modal_layer();
        engine.register_hit_box(
            ComponentId::ModalConfirm,
            Rect {
                x: 30,
                y: 10,
                width: 10,
                height: 3,
            },
        );

        // The dialog's own button still works...
        assert_eq!(engine.hit_test(32, 11), Some(ComponentId::ModalConfirm));
        // ...but a click anywhere else is swallowed instead of falling
        // through to the connect button behind the dialog.
        assert_eq!(engine.hit_test(5, 5), None);
        assert_eq!(engine.hit_test(70, 20), None);
    }

    #[test]
    fn clearing_resets_the_modal_layer() {
        let mut engine = InteractionEngine::new();
        engine.begin_modal_layer();
        assert!(engine.modal_layer_active());
        engine.clear_hit_boxes();
        assert!(!engine.modal_layer_active());
    }

    #[test]
    fn topmost_registration_wins_on_overlap() {
        let mut engine = InteractionEngine::new();
        let r = Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        };
        engine.register_hit_box(ComponentId::ConfigItem(0), r);
        engine.register_hit_box(ComponentId::ToastClose(0), r);
        assert_eq!(engine.hit_test(5, 5), Some(ComponentId::ToastClose(0)));
    }

    #[test]
    fn hover_follows_the_layout_under_a_still_pointer() {
        let mut engine = InteractionEngine::new();
        let row = |y| Rect {
            x: 0,
            y,
            width: 10,
            height: 1,
        };
        engine.register_hit_box(ComponentId::ConfigItem(0), row(3));
        engine.update_mouse_position(2, 3);
        assert!(engine.is_hovered(ComponentId::ConfigItem(0)));

        // Next frame the list has scrolled: a different row is under the
        // pointer, which has not moved.
        engine.clear_hit_boxes();
        engine.register_hit_box(ComponentId::ConfigItem(1), row(3));
        engine.refresh_hover();
        assert!(engine.is_hovered(ComponentId::ConfigItem(1)));
        assert!(engine.take_hover_stale());
        assert!(!engine.take_hover_stale(), "the flag is one-shot");

        // An unchanged frame is not stale.
        engine.refresh_hover();
        assert!(!engine.take_hover_stale());
    }

    #[test]
    fn an_unseen_pointer_hovers_nothing() {
        let mut engine = InteractionEngine::new();
        engine.register_hit_box(
            ComponentId::LogoButton,
            Rect {
                x: 0,
                y: 0,
                width: 5,
                height: 5,
            },
        );
        engine.refresh_hover();
        assert_eq!(engine.hovered_component, None);
        assert!(!engine.take_hover_stale());
    }

    #[test]
    fn swept_config_items_finds_intersecting_rows() {
        let mut engine = InteractionEngine::new();
        for i in 0..5 {
            engine.register_hit_box(
                ComponentId::ConfigItem(i),
                Rect {
                    x: 10,
                    y: 10 + i as u16,
                    width: 50,
                    height: 1,
                },
            );
        }
        // Rubber-band spanning rows 11 to 13
        let band = Rect {
            x: 15,
            y: 11,
            width: 20,
            height: 3,
        };
        let swept = engine.swept_config_items(band);
        assert_eq!(swept, vec![1, 2, 3]);

        // Band entirely outside to the right
        let outside = Rect {
            x: 70,
            y: 11,
            width: 10,
            height: 3,
        };
        assert!(engine.swept_config_items(outside).is_empty());
    }
}
