//! Rendering for ZeroNet TUI.
//!
//! Layout is a header strip, a sidebar plus workspace, and a footer of key
//! caps. A few conventions hold throughout:
//!
//! * Every panel uses [`BorderType::Rounded`] and the theme's faint border
//!   grey, so structure reads without competing with content.
//! * Header chips are all drawn by one helper, so TUN, privileges and the
//!   status pill share a single visual language instead of three.
//! * When a dialog is open the workspace behind it is dimmed and its hit
//!   regions are switched off — see [`InteractionEngine::begin_modal_layer`].
//! * The ZeroNet wordmark is *not* a button. It never takes on button chrome;
//!   it glows and shifts gold→orange→gold on hover, and a click sets off a
//!   chromatic wave from the clicked cell.

use crate::caps::TerminalCaps;
use crate::connect_orb::{self, OrbState};
use crate::daemon::{ConnectionStatus, DaemonStats};
use crate::db::{AppSettings, ConfigRecord, SubscriptionRecord};
use crate::effects::VisualEffects;
use crate::interaction::{ComponentId, InteractionEngine};
use crate::modal::ModalState;
use crate::ping::latency_bar;
use crate::scrollbar::{self, ScrollTarget};
use crate::theme::Theme;
use crate::toast::ToastManager;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Table, TableState,
};
use ratatui::Frame;
use throbber_widgets_tui::{Throbber, ThrobberState, BRAILLE_SIX};
use tui_big_text::{BigText, PixelSize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Dashboard,
    Subscriptions,
    IpScanner,
    Settings,
    Activity,
}

const SIDEBAR_WIDTH: u16 = 24;
/// Smallest terminal the full layout is drawn on: the sidebar plus a
/// workspace wide enough for the node table, and the header, orb and list.
pub const MIN_WIDTH: u16 = 64;
/// See [`MIN_WIDTH`].
pub const MIN_HEIGHT: u16 = 18;
/// Rows the header strip occupies.
const HEADER_HEIGHT: u16 = 3;
/// Width of the ping bar drawn beside each latency reading.
const PING_BAR_WIDTH: usize = 6;
/// Width of the per-row share button.
const SHARE_BUTTON_WIDTH: u16 = 9;

pub struct UiRenderer<'a> {
    pub theme: &'a Theme,
    pub caps: &'a TerminalCaps,
    pub interaction: &'a mut InteractionEngine,
    pub effects: &'a mut VisualEffects,
    pub settings: &'a AppSettings,
    pub stats: &'a DaemonStats,
    pub active_tab: ActiveTab,
    pub configs: &'a [ConfigRecord],
    pub subscriptions: &'a [SubscriptionRecord],
    pub selected_config_idx: usize,
    pub node_scroll: usize,
    /// Profiles ticked for a bulk action.
    pub marked: &'a std::collections::HashSet<i64>,
    /// Current list filter text.
    pub filter: &'a str,
    /// Whether the filter box has keyboard focus.
    pub filter_focused: bool,
    /// Advanced settings are folded until the user opens them.
    pub advanced_open: bool,
    /// Whether all text in filter box is selected (e.g. via Ctrl+A).
    pub filter_select_all: bool,
    /// Inline profile rename state if active.
    pub inline_rename: Option<&'a crate::InlineRename>,
    /// The system proxy mode currently applied.
    pub system_proxy: crate::sysproxy::SystemProxyMode,
    /// Open/close animation state for the dialog on screen.
    pub modal_anim: crate::modal_anim::ModalAnimator,
    /// Scroll position of the settings page.
    pub settings_scroll: crate::scroll::ScrollState,
    /// Scroll position of the help overlay.
    pub help_scroll: crate::scroll::ScrollState,
    /// Tick of the last profile selection, so a fresh click flashes.
    pub selection_tick: u64,
    /// The right-click menu, when one is open.
    pub context_menu: Option<&'a crate::ctxmenu::ContextMenu>,
    /// An in-progress rubber-band selection.
    pub drag: Option<crate::dragselect::DragSelect>,
    pub latency_history: &'a [f64],
    pub is_elevated: bool,
    pub elevation_prompt: Option<&'a str>,
    pub modal_state: &'a ModalState,
    /// The image behind an open `ImageView` dialog, if any. Mutable because
    /// the terminal graphics protocol caches its encoding per area.
    pub image_view: Option<&'a mut crate::imageview::TerminalImage>,
    pub throbber_state: &'a mut ThrobberState,
    pub scanner_tested: u64,
    pub scanner_healthy: u64,
    pub scanner_speed: f64,
    pub is_scanning: bool,
    pub scanner_results: &'a [zero_scanner::types::ProbeResult],
    pub toasts: &'a mut ToastManager,
    /// CPU and memory figures for the Activity page and the status bar.
    pub usage: crate::ui_activity::UsageView<'a>,
    /// Frame statistics, when the F12 overlay is open.
    pub perf: Option<PerfHud>,
    /// How long the current session has been up.
    pub session: Option<std::time::Duration>,
    /// Upload and download rates, one sample a second, newest last.
    pub speed_history: (&'a [u64], &'a [u64]),
}

/// What the F12 overlay shows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerfHud {
    /// Frames drawn in the last second. Zero at rest, which is the point.
    pub fps: u32,
    pub avg_draw: std::time::Duration,
    pub worst_draw: std::time::Duration,
    pub total_frames: u64,
}

impl<'a> UiRenderer<'a> {
    pub fn render(&mut self, frame: &mut Frame) {
        self.interaction.clear_hit_boxes();
        let size = frame.area();
        // Wave lifetimes are derived from the screen size, so the effects
        // need to know it before anything is drawn.
        self.effects.set_viewport(size.width, size.height);
        // Tracked on every tab, so coming back to the dashboard shows the
        // current state rather than replaying a change that happened
        // elsewhere.
        self.effects
            .note_orb_state(OrbState::from(self.stats.status));

        frame.render_widget(
            Block::default().style(Style::default().bg(self.theme.bg)),
            size,
        );

        // Below this the sidebar and workspace cannot both fit, and every
        // panel collapses into overlapping fragments. Say so plainly, like
        // any desktop app with a minimum window size, instead of drawing a
        // broken screen that still takes clicks in the wrong places.
        if size.width < MIN_WIDTH || size.height < MIN_HEIGHT {
            self.render_too_small(frame, size);
            self.interaction.refresh_hover();
            return;
        }

        let main_chunks = Self::screen_chunks(size);

        self.render_header(frame, main_chunks[0]);
        self.render_body(frame, main_chunks[1]);
        self.render_footer(frame, main_chunks[2]);

        // The chromatic wave is painted over the finished frame so it washes
        // across every panel rather than being clipped to one.
        if self.effects.rainbow_active() {
            self.paint_rainbow(frame, size);
        }

        if self.modal_state.is_active() {
            // Dim first, then mark the modal layer: everything registered
            // before this point stops responding to the mouse, so a click
            // that lands outside the dialog does nothing instead of falling
            // through to whatever is behind it.
            self.dim_background(frame, size);
            self.interaction.begin_modal_layer();

            // The backdrop goes down first, so the dialog's own regions sit
            // on top of it. A click that reaches the backdrop is by
            // definition outside the dialog.
            self.interaction
                .register_hit_box(ComponentId::ModalBackdrop, size);

            // The dialog's own body sits above the backdrop. Without it, a
            // click on the dialog's empty space fell through to the backdrop
            // and dismissed the very dialog being clicked.
            let target = self.modal_target_rect(size);
            self.interaction
                .register_hit_box(ComponentId::ModalSurface, target);

            self.render_modal(frame, size);
        }

        // The band sits under the menu but over the list, so a drag is
        // visible while it happens.
        self.render_drag_band(frame, size);
        self.render_toasts(frame, size);

        // The context menu is always topmost, and its own layer, so a click
        // anywhere else dismisses it rather than acting on what is beneath.
        if self.context_menu.is_some() {
            self.interaction.begin_modal_layer();
            self.interaction
                .register_hit_box(ComponentId::ModalBackdrop, size);
            self.render_context_menu(frame, size);
        }

        if let Some(hud) = self.perf {
            self.render_perf_hud(frame, size, hud);
        }

        // Everything is registered: check the pointer against what was
        // actually drawn this frame, not the frame before.
        self.interaction.refresh_hover();
    }

    /// The F12 frame-stats box, bottom-right above the status bar.
    fn render_perf_hud(&self, frame: &mut Frame, screen: Rect, hud: PerfHud) {
        let lines = [
            format!(" {:>3} fps", hud.fps),
            format!(" avg {:>5.2} ms", hud.avg_draw.as_secs_f64() * 1000.0),
            format!(" max {:>5.2} ms", hud.worst_draw.as_secs_f64() * 1000.0),
            format!(" {:>9} frames", hud.total_frames),
        ];
        let width = 20u16;
        let height = lines.len() as u16 + 2;
        if screen.width < width + 2 || screen.height < height + 2 {
            return;
        }
        let area = Rect {
            x: screen.right() - width - 1,
            y: screen.bottom() - height - 1,
            width,
            height,
        };
        let block = Block::default()
            .title(" frames ")
            .title_style(Style::default().fg(self.theme.muted))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.surface));
        let fps_color = if hud.fps == 0 {
            self.theme.ok
        } else {
            self.theme.accent
        };
        let text: Vec<Line> = lines
            .iter()
            .enumerate()
            .map(|(i, l)| {
                Line::styled(
                    l.clone(),
                    Style::default().fg(if i == 0 { fps_color } else { self.theme.text }),
                )
            })
            .collect();
        frame.render_widget(Clear, area);
        frame.render_widget(Paragraph::new(text).block(block), area);
    }

    /// The notice shown when the terminal is below the minimum size.
    fn render_too_small(&self, frame: &mut Frame, size: Rect) {
        if size.width == 0 || size.height == 0 {
            return;
        }
        let lines = vec![
            Line::from(Span::styled(
                "Terminal too small",
                Style::default()
                    .fg(self.theme.accent_bright)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!(
                    "{}×{}, needs {MIN_WIDTH}×{MIN_HEIGHT}",
                    size.width, size.height
                ),
                Style::default().fg(self.theme.muted),
            )),
        ];
        let height = (lines.len() as u16).min(size.height);
        let area = Rect {
            x: size.x,
            y: size.y + size.height.saturating_sub(height) / 2,
            width: size.width,
            height,
        };
        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .wrap(ratatui::widgets::Wrap { trim: true }),
            area,
        );
    }

    /// Push the whole screen towards the background colour so the dialog on
    /// top of it is unmistakably the only live thing.
    ///
    /// Terminals cannot blur, so this is the equivalent move: every cell
    /// behind the dialog is repainted in a dim grey on the page background,
    /// which drops contrast sharply while leaving the layout legible.
    fn dim_background(&self, frame: &mut Frame, area: Rect) {
        let buf = frame.buffer_mut();
        for y in area.y..area.y.saturating_add(area.height) {
            for x in area.x..area.x.saturating_add(area.width) {
                let cell = &mut buf[(x, y)];
                cell.set_fg(self.theme.border);
                cell.set_bg(self.theme.bg);
                cell.modifier = Modifier::DIM;
            }
        }
    }

    /// Soft rings around the connect orb.
    ///
    /// The orb itself is a circle of braille. These are the cells just
    /// outside that circle, tinted and faded by distance, which is as close
    /// to a bloom as a cell grid can get. The centre is left alone so the
    /// label stays readable.
    fn paint_orb_glow(
        &self,
        frame: &mut Frame,
        area: Rect,
        geo: connect_orb::OrbGeometry,
        tint: Color,
    ) {
        if !self.effects.animations_enabled() || geo.radius_x < 2.0 || geo.radius_y < 1.0 {
            return;
        }
        // Arriving at "connected" blooms: the halo flares and reaches further
        // out, then settles back into the slow breath.
        let bloom = self.effects.orb_bloom() as f32;
        let breathe = (0.55 + 0.45 * self.effects.pulse_phase(0.07)) as f32 + 0.6 * bloom;
        let reach = 0.53 + 0.45 * bloom;
        let buf = frame.buffer_mut();
        let area = area.intersection(buf.area);
        for y in area.y..area.y.saturating_add(area.height) {
            for x in area.x..area.x.saturating_add(area.width) {
                let dx = (x as f32 + 0.5 - geo.center_x) / geo.radius_x;
                let dy = (y as f32 + 0.5 - geo.center_y) / geo.radius_y;
                let r2 = dx * dx + dy * dy;
                // Inside the ring the label lives; past the reach there is
                // nothing left to tint. Compared squared so the common case —
                // a cell nowhere near the halo — costs no square root.
                let outer = 1.02 + reach;
                if !(1.02 * 1.02..=outer * outer).contains(&r2) {
                    continue;
                }
                let r = r2.sqrt();
                let falloff = (1.0 - (r - 1.02) / reach).clamp(0.0, 1.0);
                let glow = (falloff * falloff * breathe).min(1.0) as f64;
                let cell = &mut buf[(x, y)];
                cell.set_bg(self.theme.adapt(blend(cell.bg, tint, glow * 0.72)));
            }
        }
    }

    fn paint_rainbow(&self, frame: &mut Frame, area: Rect) {
        let buf = frame.buffer_mut();
        let area = area.intersection(buf.area);
        for y in area.y..area.y.saturating_add(area.height) {
            for x in area.x..area.x.saturating_add(area.width) {
                if let Some(color) = self.effects.rainbow_color_at(x, y) {
                    let cell = &mut buf[(x, y)];
                    // Recolour what is already drawn rather than overwriting
                    // it, so the wave reads as light passing over the UI.
                    if cell.symbol() == " " {
                        cell.set_symbol("·");
                    }
                    cell.set_fg(color);
                }
            }
        }
    }

    // --------------------------------------------------------------- header

    fn render_header(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(SIDEBAR_WIDTH),
                Constraint::Min(16),
                Constraint::Length(54),
            ])
            .split(area);

        self.render_logo(frame, chunks[0]);
        self.render_status_pill(frame, chunks[1]);
        self.render_header_chips(frame, chunks[2]);
    }

    /// The ZeroNet wordmark.
    ///
    /// Deliberately chrome-free: no border, no fill, no hover background. The
    /// only hover feedback is that the mark glows harder and its gold→orange
    /// breathing speeds up, which says "alive" without saying "button".
    fn render_logo(&mut self, frame: &mut Frame, area: Rect) {
        self.interaction
            .register_hit_box(ComponentId::LogoButton, area);
        let hovered = self.interaction.is_hovered(ComponentId::LogoButton);

        let mark = self.effects.logo_color(hovered);
        let trail = self.effects.logo_trail_color(hovered);

        let logo_text = vec![Line::from(vec![
            Span::styled(
                " ⚡ ZERO",
                Style::default().fg(mark).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "NET ",
                Style::default()
                    .fg(if hovered { mark } else { self.theme.text })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("CORE", Style::default().fg(trail)),
        ])];

        // Only the separating rules, never a box: the mark keeps the same
        // silhouette whether the pointer is over it or not.
        let block = Block::default()
            .borders(Borders::BOTTOM | Borders::RIGHT)
            .border_style(Style::default().fg(self.theme.border))
            .style(Style::default().bg(self.theme.bg));
        frame.render_widget(Paragraph::new(logo_text).block(block), area);
    }

    /// Connection state as a coloured pill, with a spinner while dialling.
    fn render_status_pill(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(self.theme.border));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let (label, color) = match self.stats.status {
            ConnectionStatus::Connected => ("CONNECTED", self.effects.emerald_glow()),
            ConnectionStatus::Connecting => ("CONNECTING", self.effects.amber_glow()),
            ConnectionStatus::Reconnecting => ("RECONNECTING", self.effects.amber_glow()),
            ConnectionStatus::Disconnected => ("DISCONNECTED", self.theme.err),
            ConnectionStatus::Error => ("ERROR", self.theme.err),
        };

        let pill_text = format!(" {label} ");
        let pill_width = pill_text.chars().count() as u16;

        let mut spans = vec![
            Span::raw(" "),
            Span::styled(
                pill_text,
                Style::default()
                    .bg(color)
                    .fg(self.theme.bg)
                    .add_modifier(Modifier::BOLD),
            ),
        ];

        if matches!(
            self.stats.status,
            ConnectionStatus::Connecting | ConnectionStatus::Reconnecting
        ) {
            let throbber = Throbber::default()
                .throbber_set(BRAILLE_SIX)
                .throbber_style(Style::default().fg(color));
            spans.push(Span::raw(" "));
            spans.push(throbber.to_symbol_span(self.throbber_state));
        }

        let connected = matches!(
            self.stats.status,
            ConnectionStatus::Connected | ConnectionStatus::Reconnecting
        );
        if connected {
            if let Some(active) = self.configs.iter().find(|c| c.is_active) {
                spans.push(Span::styled(
                    format!("  {}", active.protocol.to_uppercase()),
                    Style::default()
                        .fg(self.theme.info)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        }
        spans.push(Span::styled(
            "  Node: ",
            Style::default().fg(self.theme.muted),
        ));
        spans.push(Span::styled(
            &self.stats.active_node_name,
            Style::default().fg(self.theme.text),
        ));
        if let (true, Some(session)) = (connected, self.session) {
            spans.push(Span::styled(
                format!("  session {}", format_session(session)),
                Style::default().fg(self.theme.muted),
            ));
        }

        let pill_line = Line::from(spans);
        let mut lines = vec![pill_line];

        // The failure reason gets its own row rather than being squeezed onto
        // the end of the pill line, where a narrow header truncated it away.
        if let Some(err) = self.stats.error_msg.as_deref() {
            if self.stats.status == ConnectionStatus::Error {
                lines.push(Line::from(vec![
                    Span::styled("   ↳ ", Style::default().fg(self.theme.err)),
                    Span::styled(
                        truncate(err, inner.width.saturating_sub(6) as usize),
                        Style::default().fg(self.theme.err),
                    ),
                ]));
            }
        }

        frame.render_widget(Paragraph::new(lines), inner);

        // The sheen sweeps across the status pill itself, strictly confined
        // to the pill's bounds so it never spills over the node name or margins.
        self.paint_bar_sweep(frame, sweep_area(inner, pill_width), color);
    }

    /// A glossy highlight sheen travelling left to right inside the status bar.
    fn paint_bar_sweep(&self, frame: &mut Frame, area: Rect, tint: Color) {
        let strength = self.effects.sheen_strength();
        if area.width < 4 || !self.effects.animations_enabled() || strength < 0.01 {
            return;
        }
        let phase = self.effects.sheen_phase();
        let width = area.width as f64;
        let buf = frame.buffer_mut();
        let area = area.intersection(buf.area);
        let highlight = blend(tint, Color::Rgb(255, 255, 255), 0.55);
        for x in 0..area.width {
            let along = x as f64 / width;
            let delta = (along - phase + 1.0).fract();
            let glow = if delta < 0.34 {
                (1.0 - delta / 0.34).powi(2) * strength
            } else {
                0.0
            };
            if glow < 0.04 {
                continue;
            }
            let cell = &mut buf[(area.x + x, area.y)];
            let empty = cell.symbol().trim().is_empty();
            if empty {
                cell.set_symbol(" ");
            }
            if cell.bg == tint || cell.bg != self.theme.bg {
                cell.set_bg(self.theme.adapt(blend(cell.bg, highlight, glow * 0.7)));
            } else {
                cell.set_bg(self.theme.adapt(blend(cell.bg, tint, glow * 0.9)));
                if !empty {
                    cell.set_fg(self.theme.adapt(blend(cell.fg, tint, glow * 0.45)));
                }
            }
        }
    }

    /// TUN, privileges and feedback, all drawn as the same kind of chip.
    fn render_header_chips(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(13),
                Constraint::Length(13),
                Constraint::Length(13),
                Constraint::Length(15),
            ])
            .split(area);

        // TUN: on when enabled *and* actually up. Enabled-but-failed is its
        // own state, because a user who granted no privileges would otherwise
        // read a green "TUN ON" while their traffic was not tunnelled.
        let tun_hover = self.interaction.is_hovered(ComponentId::TunToggle);
        self.interaction
            .register_hit_box(ComponentId::TunToggle, chunks[0]);
        let (tun_label, tun_color) = match (self.settings.tun_enabled, self.stats.tun_active) {
            (false, _) => ("TUN OFF", self.theme.muted),
            (true, true) => ("TUN ON", self.theme.ok),
            (true, false) if self.stats.status == ConnectionStatus::Connected => {
                ("TUN FAILED", self.theme.err)
            }
            (true, false) => ("TUN ARMED", self.theme.accent),
        };
        self.chip(frame, chunks[0], tun_label, tun_color, tun_hover);

        // System proxy: the single most consequential thing a user needs to
        // see at a glance, because it decides whether anything on the machine
        // is actually using the tunnel.
        let proxy_hover = self.interaction.is_hovered(ComponentId::SystemProxyChip);
        self.interaction
            .register_hit_box(ComponentId::SystemProxyChip, chunks[1]);
        let proxy_color = match self.system_proxy {
            // Two quiet states with different meanings: "keep" is hands-off,
            // "none" is a proxy we actively forced off.
            crate::sysproxy::SystemProxyMode::Unmanaged => self.theme.muted,
            crate::sysproxy::SystemProxyMode::Clear => self.theme.warn,
            crate::sysproxy::SystemProxyMode::Manual => self.theme.ok,
            crate::sysproxy::SystemProxyMode::Pac => self.theme.info,
        };
        let proxy_label = self.system_proxy.chip_label();
        self.chip(frame, chunks[1], proxy_label, proxy_color, proxy_hover);

        let (priv_label, priv_color) = if self.is_elevated {
            ("PRIV OK", self.theme.ok)
        } else {
            ("NO PRIV", self.theme.err)
        };
        self.chip(frame, chunks[2], priv_label, priv_color, false);

        let fb_hover = self.interaction.is_hovered(ComponentId::FeedbackButton);
        self.interaction
            .register_hit_box(ComponentId::FeedbackButton, chunks[3]);
        self.chip(frame, chunks[3], "✉ FEEDBACK", self.theme.accent, fb_hover);
    }

    /// One chip: rounded border, label centred, filled when hovered.
    pub(crate) fn chip(
        &self,
        frame: &mut Frame,
        area: Rect,
        label: &str,
        color: Color,
        hovered: bool,
    ) {
        let (text_style, border_color) = if hovered {
            (
                Style::default()
                    .bg(color)
                    .fg(self.theme.bg)
                    .add_modifier(Modifier::BOLD),
                color,
            )
        } else {
            (
                Style::default().fg(color).add_modifier(Modifier::BOLD),
                self.theme.border,
            )
        };

        let widget = Paragraph::new(label)
            .alignment(Alignment::Center)
            .style(text_style)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(border_color)),
            );
        frame.render_widget(widget, area);
    }

    // ----------------------------------------------------------------- body

    fn render_body(&mut self, frame: &mut Frame, area: Rect) {
        let body_chunks = Self::body_chunks(area);

        self.render_sidebar(frame, body_chunks[0]);

        match self.active_tab {
            ActiveTab::Dashboard => self.render_dashboard(frame, body_chunks[1]),
            ActiveTab::Subscriptions => self.render_subscriptions(frame, body_chunks[1]),
            ActiveTab::IpScanner => self.render_scanner(frame, body_chunks[1]),
            ActiveTab::Settings => self.render_settings(frame, body_chunks[1]),
            ActiveTab::Activity => self.render_activity(frame, body_chunks[1]),
        }
    }

    fn render_sidebar(&mut self, frame: &mut Frame, area: Rect) {
        let items = [
            (
                ActiveTab::Dashboard,
                ComponentId::NavDashboard,
                " ❖ Dashboard",
            ),
            (
                ActiveTab::Subscriptions,
                ComponentId::NavSubscriptions,
                // Not the ☵ trigram: Unicode 16 made U+2630..U+2637 wide, so
                // current terminals draw it two columns while ratatui's width
                // table counts one, and every redraw of the row lands shifted.
                " ≡ Subscriptions",
            ),
            (
                ActiveTab::IpScanner,
                ComponentId::NavScanner,
                " ⌖ IP Scanner",
            ),
            (ActiveTab::Activity, ComponentId::NavActivity, " ∿ Activity"),
            (ActiveTab::Settings, ComponentId::NavSettings, " ⚙ Settings"),
        ];

        frame.render_widget(
            Block::default()
                .borders(Borders::RIGHT)
                .border_style(Style::default().fg(self.theme.border))
                .style(Style::default().bg(self.theme.bg)),
            area,
        );

        for (i, (tab, comp_id, label)) in items.iter().enumerate() {
            let item_rect = Rect {
                x: area.x + 1,
                y: area.y + 1 + (i as u16 * 2),
                width: area.width.saturating_sub(2),
                height: 2,
            };
            if item_rect.y + item_rect.height > area.y + area.height {
                break;
            }
            self.interaction.register_hit_box(*comp_id, item_rect);

            let selected = self.active_tab == *tab;
            let hovered = self.interaction.is_hovered(*comp_id);

            let (prefix, style) = if selected {
                (
                    "▌ ",
                    Style::default()
                        .bg(self.theme.surface)
                        .fg(self.theme.accent_bright)
                        .add_modifier(Modifier::BOLD),
                )
            } else if hovered {
                (
                    "┆ ",
                    Style::default()
                        .bg(self.theme.surface_hi)
                        .fg(self.theme.accent)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                ("  ", Style::default().fg(self.theme.text))
            };

            let line = Line::from(vec![
                Span::styled(prefix, Style::default().fg(self.theme.accent)),
                Span::styled(*label, style),
            ]);
            frame.render_widget(Paragraph::new(vec![line, Line::from("")]), item_rect);
        }
    }

    /// Metrics row, orb, and node list, top to bottom.
    fn dashboard_chunks(area: Rect) -> std::rc::Rc<[Rect]> {
        // The orb wants vertical room to stay round; give it what is spare
        // after the metrics row and a workable node list.
        let orb_height = area.height.saturating_sub(5 + 9).clamp(9, 19);
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(orb_height),
                Constraint::Min(6),
            ])
            .split(area)
    }

    fn screen_chunks(size: Rect) -> std::rc::Rc<[Rect]> {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(HEADER_HEIGHT),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(size)
    }

    fn body_chunks(area: Rect) -> std::rc::Rc<[Rect]> {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(40)])
            .split(area)
    }

    fn node_panel_chunks(area: Rect) -> std::rc::Rc<[Rect]> {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
            .split(area)
    }

    /// Filter box above, table below.
    fn node_table_chunks(area: Rect) -> std::rc::Rc<[Rect]> {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(3)])
            .split(area)
    }

    /// How many profile rows the dashboard shows on a terminal of this size.
    ///
    /// Runs the same layout the renderer does, so keyboard navigation and
    /// scroll bounds agree exactly with what is on screen — an estimate here
    /// let the highlight walk off the bottom of the list.
    pub fn profile_list_rows(width: u16, height: u16) -> usize {
        let screen = Rect::new(0, 0, width, height);
        let body = Self::screen_chunks(screen)[1];
        let workspace = Self::body_chunks(body)[1];
        let nodes = Self::dashboard_chunks(workspace)[2];
        let table = Self::node_table_chunks(Self::node_panel_chunks(nodes)[0])[1];
        // Panel border top and bottom, then the column header row.
        (table.height.saturating_sub(2) as usize).saturating_sub(1)
    }

    fn render_dashboard(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Self::dashboard_chunks(area);

        self.render_metrics_panel(frame, chunks[0]);
        self.render_connect_hero(frame, chunks[1]);
        self.render_nodes_and_latency(frame, chunks[2]);
    }

    fn render_metrics_panel(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 4); 4])
            .split(area);

        let cards = [
            (
                "▲ UPLOAD",
                format_speed(self.stats.upload_speed_bps),
                self.theme.info,
            ),
            (
                "▼ DOWNLOAD",
                format_speed(self.stats.download_speed_bps),
                self.theme.ok,
            ),
            (
                "▲ SENT",
                format_bytes(self.stats.upload_bytes),
                self.theme.muted,
            ),
            (
                "▼ RECEIVED",
                format_bytes(self.stats.download_bytes),
                self.theme.muted,
            ),
        ];

        for (i, (title, val, color)) in cards.iter().enumerate() {
            let block = Block::default()
                .title(*title)
                .title_style(
                    Style::default()
                        .fg(self.theme.muted)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(self.theme.border))
                .style(self.theme.card_style());

            // The two rate cards carry a minute of history under the value.
            let history = match i {
                0 => self.speed_history.0,
                1 => self.speed_history.1,
                _ => &[],
            };
            let graph_width = chunks[i].width.saturating_sub(4) as usize;
            let graph = if history.is_empty() {
                String::new()
            } else {
                let values: Vec<f64> = history.iter().map(|v| *v as f64).collect();
                crate::ui_activity::spark(&values, graph_width, 64.0 * 1024.0)
            };
            let text = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    val.as_str(),
                    Style::default().fg(*color).add_modifier(Modifier::BOLD),
                )]),
                Line::styled(
                    graph,
                    Style::default().fg(self.theme.adapt(crate::theme::lerp_color(
                        *color,
                        self.theme.surface,
                        0.35,
                    ))),
                ),
            ];
            frame.render_widget(
                Paragraph::new(text)
                    .block(block)
                    .alignment(Alignment::Center),
                chunks[i],
            );
        }
    }

    /// The connect orb plus its label.
    fn render_connect_hero(&mut self, frame: &mut Frame, area: Rect) {
        let state = OrbState::from(self.stats.status);
        let hovered = self.interaction.is_hovered(ComponentId::ConnectButton);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(self.theme.border_style(hovered))
            .style(self.theme.card_style());
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let geo = connect_orb::render(frame, inner, state, hovered, self.theme, self.effects);
        let glow = match state {
            OrbState::Connected => self.effects.emerald_glow(),
            OrbState::Connecting => self.effects.amber_glow(),
            OrbState::Error => self.theme.err,
            OrbState::Idle => {
                if hovered {
                    self.theme.accent_bright
                } else {
                    self.theme.accent
                }
            }
        };
        self.paint_orb_glow(frame, inner, geo, glow);

        // Hit-test the circle, not the panel: the corners of this box are
        // empty and clicking them should do nothing.
        self.interaction.register_hit_ellipse(
            ComponentId::ConnectButton,
            geo.center_x,
            geo.center_y,
            geo.radius_x,
            geo.radius_y,
        );

        self.render_orb_label(frame, inner, state, hovered);
        self.paint_ring_sheen(frame, inner, geo, glow);
    }

    /// The same corner-to-corner sheen, kept to the ring so the label in the
    /// middle stays a solid readable colour.
    fn paint_ring_sheen(
        &self,
        frame: &mut Frame,
        area: Rect,
        geo: connect_orb::OrbGeometry,
        tint: Color,
    ) {
        let strength = self.effects.sheen_strength();
        if area.width == 0
            || area.height == 0
            || !self.effects.animations_enabled()
            || strength < 0.01
        {
            return;
        }
        let phase = self.effects.sheen_phase();
        let span = area.width as f64 + 2.0 * area.height as f64;
        let buf = frame.buffer_mut();
        let area = area.intersection(buf.area);
        for y in 0..area.height {
            for x in 0..area.width {
                let cx = area.x + x;
                let cy = area.y + y;
                let dx = (cx as f32 + 0.5 - geo.center_x) / geo.radius_x.max(0.5);
                let dy = (cy as f32 + 0.5 - geo.center_y) / geo.radius_y.max(0.5);
                let r = (dx * dx + dy * dy).sqrt();
                if !(0.72..=1.08).contains(&r) {
                    continue;
                }
                let along = (x as f64 + 2.0 * y as f64) / span;
                let delta = (along - phase + 1.0).fract();
                let glow = if delta < 0.22 {
                    (1.0 - delta / 0.22).powi(2) * strength
                } else {
                    0.0
                };
                if glow < 0.08 {
                    continue;
                }
                let cell = &mut buf[(cx, cy)];
                cell.set_fg(self.theme.adapt(blend(cell.fg, tint, glow)));
            }
        }
    }

    /// Large state text centred inside the ring, with a hint beneath it.
    fn render_orb_label(&mut self, frame: &mut Frame, inner: Rect, state: OrbState, hovered: bool) {
        let color = match state {
            OrbState::Connected => self.effects.emerald_glow(),
            OrbState::Connecting => self.effects.amber_glow(),
            OrbState::Error => self.theme.err,
            OrbState::Idle => {
                if hovered {
                    self.theme.accent_bright
                } else {
                    self.theme.accent
                }
            }
        };

        let label = state.label();
        // `HalfHeight` glyphs are 8 rows tall in full size, 4 here; anything
        // narrower than the text needs the plain fallback.
        let big_w = label.len() as u16 * 8;
        let big_h = 4u16;

        if inner.width >= big_w + 2 && inner.height >= big_h + 3 {
            let big_area = Rect {
                x: inner.x + (inner.width.saturating_sub(big_w)) / 2,
                y: inner.y + (inner.height.saturating_sub(big_h)) / 2,
                width: big_w.min(inner.width),
                height: big_h,
            };
            let big = BigText::builder()
                .pixel_size(PixelSize::HalfHeight)
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .lines(vec![Line::from(label)])
                .centered()
                .build();
            frame.render_widget(big, big_area);
        } else if inner.height > 0 {
            let mid = Rect {
                x: inner.x,
                y: inner.y + inner.height / 2,
                width: inner.width,
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(label)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
                mid,
            );
        }
    }

    // ------------------------------------------------------------ node list

    fn render_nodes_and_latency(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Self::node_panel_chunks(area);

        self.render_node_table(frame, chunks[0]);
        self.render_latency_panel(frame, chunks[1]);
    }

    fn render_node_table(&mut self, frame: &mut Frame, area: Rect) {
        // The filter box is always on screen: a search field that only
        // appears once it already has focus is a field nobody can find.
        let rows = Self::node_table_chunks(area);
        self.render_filter_box(frame, rows[0]);
        let area = rows[1];

        // Indices into `self.configs` of the rows the filter lets through,
        // in one pass. Owned indices rather than references: a borrow of
        // `self.configs` held across the loop would block the `&mut` the
        // hit-region registration needs.
        let configs: &'a [ConfigRecord] = self.configs;
        let visible = filtered_indices(configs, self.filter);
        let title = if !self.marked.is_empty() {
            format!(" SERVERS · {} selected ", self.marked.len())
        } else if !self.filter.trim().is_empty() {
            format!(" SERVERS · {}/{} match ", visible.len(), self.configs.len())
        } else {
            " SERVERS ".to_string()
        };

        let block = Block::default()
            .title(title)
            .title_style(self.theme.title_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style());
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.height < 2 || visible.is_empty() {
            if self.configs.is_empty() {
                self.render_empty_profiles(frame, inner);
            } else {
                frame.render_widget(
                    Paragraph::new("No profiles match this filter.")
                        .style(Style::default().fg(self.theme.muted)),
                    inner,
                );
            }
            return;
        }

        // Reserve the last column for the scrollbar so rows never draw under it.
        let table_area = Rect {
            width: inner.width.saturating_sub(1),
            ..inner
        };
        let visible_rows = table_area.height.saturating_sub(1) as usize;
        // Address and transport columns, v2rayN style, once the panel is
        // wide enough that the name column keeps a useful width beside them.
        let wide = table_area.width >= 104;
        // Never scrolled so far that the panel is half empty: the last page
        // is a full page.
        let first = self
            .node_scroll
            .min(visible.len().saturating_sub(visible_rows.max(1)));

        // Names that repeat across a subscription are indistinguishable on
        // their own; append the endpoint so two "Iran Clean Edge" rows can be
        // told apart.
        let duplicate_names = duplicate_remarks(configs, &visible);

        let mut rows = Vec::with_capacity(visible_rows);
        for (i, cfg_idx) in visible.iter().enumerate().skip(first).take(visible_rows) {
            let cfg = &configs[*cfg_idx];
            let row_rect = Rect {
                x: table_area.x,
                y: table_area.y + 1 + (i - first) as u16,
                width: table_area.width,
                height: 1,
            };
            if row_rect.y >= table_area.y + table_area.height {
                break;
            }
            // The share button sits at the right-hand end of the row, with
            // the row itself taking the rest. Registered first so the button
            // wins the overlap.
            let share_rect = Rect {
                x: row_rect.x + row_rect.width.saturating_sub(SHARE_BUTTON_WIDTH),
                y: row_rect.y,
                width: SHARE_BUTTON_WIDTH.min(row_rect.width),
                height: 1,
            };
            self.interaction
                .register_hit_box(ComponentId::ConfigItem(i), row_rect);
            if row_rect.width > SHARE_BUTTON_WIDTH + 12 {
                self.interaction
                    .register_hit_box(ComponentId::ConfigShare(i), share_rect);
            }

            let hovered = self.interaction.is_hovered(ComponentId::ConfigItem(i))
                || self.interaction.is_hovered(ComponentId::ConfigShare(i));
            let selected = i == self.selected_config_idx;
            let active = cfg.is_active;
            let ticked = self.marked.contains(&cfg.id);
            let is_selected = if !self.marked.is_empty() {
                ticked
            } else {
                selected
            };

            let mut row_style = Style::default().fg(self.theme.text);
            if active {
                row_style = row_style
                    .fg(self.theme.accent_bright)
                    .add_modifier(Modifier::BOLD);
            }
            // Selection is a filled row, not a star in the margin — it reads
            // at a glance from across the panel.
            // When multiple are ticked/selected, highlight ALL of them!
            if is_selected {
                let fresh = selected
                    && self
                        .effects
                        .current_tick()
                        .saturating_sub(self.selection_tick)
                        < 6;
                row_style = row_style.bg(if fresh {
                    self.theme.accent
                } else {
                    self.theme.surface_hi
                });
                if ticked || fresh {
                    row_style = row_style
                        .fg(if fresh {
                            self.theme.bg
                        } else {
                            self.theme.accent_bright
                        })
                        .add_modifier(Modifier::BOLD);
                }
            }
            if hovered {
                row_style = row_style
                    .bg(self.theme.surface_hi)
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD);
            }

            // Two distinct marks: a tick is "chosen for a bulk action", a
            // filled dot is "this is the profile in use".
            let marker = match (ticked, active) {
                (true, _) => "✓",
                (false, true) => "●",
                (false, false) => " ",
            };

            let is_renaming = self.inline_rename.as_ref().map(|r| r.config_id) == Some(cfg.id);
            let name_cell = if is_renaming {
                let r = self.inline_rename.as_ref().unwrap();
                let cursor = r.cursor.min(r.buffer.chars().count());
                let chars: Vec<char> = r.buffer.chars().collect();
                let before: String = chars[..cursor].iter().collect();
                let after: String = chars[cursor..].iter().collect();
                let spans = if r.select_all {
                    vec![
                        Span::styled(
                            &r.buffer,
                            Style::default()
                                .bg(self.theme.accent)
                                .fg(self.theme.bg)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("█", Style::default().fg(self.theme.accent_bright)),
                        Span::styled(
                            " [↵ save · Esc cancel]",
                            Style::default().fg(self.theme.muted),
                        ),
                    ]
                } else {
                    vec![
                        Span::styled(
                            before,
                            Style::default()
                                .fg(self.theme.accent_bright)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("█", Style::default().fg(self.theme.accent_bright)),
                        Span::styled(after, Style::default().fg(self.theme.text)),
                        Span::styled(
                            " [↵ save · Esc cancel]",
                            Style::default().fg(self.theme.muted),
                        ),
                    ]
                };
                Cell::from(Line::from(spans))
            } else {
                let name = if duplicate_names.contains(cfg.remark.as_str()) {
                    format!("{} · {}:{}", cfg.remark, cfg.address, cfg.port)
                } else {
                    cfg.remark.clone()
                };
                Cell::from(name)
            };

            let ping_text = cfg
                .ping_ms
                .map(|p| format!("{p:>4.0}ms"))
                .unwrap_or_else(|| "   ---".into());
            let ping_color = self.theme.latency_color(cfg.ping_ms);

            let wide_cells = wide.then(|| {
                (
                    Cell::from(truncate(&format!("{}:{}", cfg.address, cfg.port), 21))
                        .style(Style::default().fg(self.theme.muted)),
                    Cell::from(truncate(&cached_transport(cfg), 14))
                        .style(Style::default().fg(self.theme.muted)),
                )
            });

            let share_hovered = self.interaction.is_hovered(ComponentId::ConfigShare(i));
            let share_cell = Cell::from(" ⇪ share ").style(if share_hovered {
                Style::default()
                    .bg(self.theme.accent_bright)
                    .fg(self.theme.bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.theme.accent_dim)
            });

            let mut cells = vec![
                Cell::from(marker).style(Style::default().fg(if ticked {
                    self.theme.ok
                } else {
                    self.theme.accent
                })),
                name_cell,
                Cell::from(cfg.protocol.to_uppercase()).style(
                    Style::default()
                        .fg(self.theme.info)
                        .add_modifier(Modifier::BOLD),
                ),
            ];
            if let Some((address, transport)) = wide_cells {
                cells.push(address);
                cells.push(transport);
            }
            cells.extend([
                Cell::from(latency_bar(cfg.ping_ms, PING_BAR_WIDTH))
                    .style(Style::default().fg(ping_color)),
                Cell::from(ping_text).style(Style::default().fg(ping_color)),
                share_cell,
            ]);
            rows.push(Row::new(cells).style(row_style));
        }

        let mut headings = vec!["", "Profile", "Proto"];
        let mut widths = vec![
            Constraint::Length(1),
            // Fill, so long profile names stop being truncated the moment
            // the panel has room for them.
            Constraint::Fill(1),
            Constraint::Length(6),
        ];
        if wide {
            headings.extend(["Address", "Transport"]);
            widths.extend([Constraint::Length(21), Constraint::Length(14)]);
        }
        headings.extend(["Link", "Ping", ""]);
        widths.extend([
            Constraint::Length(PING_BAR_WIDTH as u16),
            Constraint::Length(7),
            Constraint::Length(SHARE_BUTTON_WIDTH),
        ]);
        let header = Row::new(headings).style(
            Style::default()
                .fg(self.theme.accent)
                .add_modifier(Modifier::BOLD),
        );

        let table = Table::new(rows, widths).header(header).column_spacing(1);

        frame.render_stateful_widget(table, table_area, &mut TableState::default());

        if visible.len() > visible_rows && visible_rows > 0 {
            let track = Rect {
                x: inner.x + inner.width.saturating_sub(1),
                y: inner.y,
                width: 1,
                height: inner.height,
            };
            let max = visible.len().saturating_sub(visible_rows);
            self.paint_scrollbar(
                frame,
                ScrollTarget::Profiles,
                scrollbar::layout(track, first, max, visible.len(), visible_rows.max(1)),
            );
        }
    }

    /// What a first launch shows instead of an empty table.
    fn render_empty_profiles(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(area);
        frame.render_widget(
            Paragraph::new("No profiles yet. Start with one of these:").style(
                Style::default()
                    .fg(self.theme.text)
                    .add_modifier(Modifier::BOLD),
            ),
            rows[0],
        );
        self.empty_action(
            frame,
            rows[1],
            ComponentId::AddConfigButton,
            "Paste a share link",
        );
        self.empty_action(
            frame,
            rows[2],
            ComponentId::AddManualConfigButton,
            "Add a server manually",
        );
        self.empty_action(
            frame,
            rows[3],
            ComponentId::AddSubButton,
            "Add a subscription",
        );
    }

    fn empty_action(&mut self, frame: &mut Frame, area: Rect, id: ComponentId, label: &str) {
        if area.height == 0 || area.width < 4 {
            return;
        }
        let width = (label.len() as u16 + 4).min(area.width);
        let rect = Rect {
            width,
            height: 1,
            ..area
        };
        self.interaction.register_hit_box(id, rect);
        let hot = self.interaction.is_hovered(id) || self.interaction.is_pressed(id);
        let style = if hot {
            Style::default()
                .fg(self.theme.bg)
                .bg(self.theme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.theme.accent_bright)
        };
        frame.render_widget(Paragraph::new(format!("  {label} ")).style(style), rect);
    }

    /// Draw a scrollbar and register its thumb and track as hit targets.
    ///
    /// The thumb is the same rectangle the gesture code drags, so what is
    /// drawn and what is clickable cannot drift apart.
    pub(crate) fn paint_scrollbar(
        &mut self,
        frame: &mut Frame,
        target: ScrollTarget,
        laid: Option<scrollbar::ScrollLayout>,
    ) {
        let Some(laid) = laid else {
            return;
        };
        let which = match target {
            ScrollTarget::Profiles => 0,
            ScrollTarget::Settings => 1,
            ScrollTarget::Help => 2,
        };
        let thumb_hot = self
            .interaction
            .is_hovered(ComponentId::Scrollbar { which, part: 1 })
            || self
                .interaction
                .is_pressed(ComponentId::Scrollbar { which, part: 1 });
        for hit in scrollbar::hits(target, laid) {
            let part = match hit.part {
                scrollbar::ScrollPart::TrackUp => 0,
                scrollbar::ScrollPart::Thumb => 1,
                scrollbar::ScrollPart::TrackDown => 2,
            };
            self.interaction
                .register_hit_box(ComponentId::Scrollbar { which, part }, hit.rect);
        }
        let mut state =
            ScrollbarState::new(laid.max_offset).position(laid.offset.min(laid.max_offset));
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::default().fg(if thumb_hot {
                    self.theme.accent_bright
                } else {
                    self.theme.accent
                }))
                .track_style(Style::default().fg(self.theme.border)),
            laid.track,
            &mut state,
        );
    }

    /// The always-present search box.
    ///
    /// Click it to type into it; clicking anywhere else gives focus back to
    /// the list. Focus is visible in the caret and the accent colour, so it
    /// is never ambiguous where typing will go — which is what made pasting
    /// a subscription URL land in the filter instead of the dialog.
    fn render_filter_box(&mut self, frame: &mut Frame, area: Rect) {
        self.interaction
            .register_hit_box(ComponentId::FilterBox, area);
        let hovered = self.interaction.is_hovered(ComponentId::FilterBox);

        let accent = if self.filter_focused {
            self.theme.accent_bright
        } else if hovered {
            self.theme.accent
        } else {
            self.theme.muted
        };

        let hint = if self.filter_focused {
            "   typing filters the list · Esc to clear"
        } else if self.filter.is_empty() {
            "   click or press Ctrl+F to search"
        } else {
            "   Esc to clear"
        };

        let mut spans = vec![Span::styled(
            " 🔍 ",
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        )];
        if self.filter.is_empty() && !self.filter_focused {
            spans.push(Span::styled(
                "Search profiles",
                Style::default().fg(self.theme.muted),
            ));
        } else if self.filter_select_all && !self.filter.is_empty() {
            spans.push(Span::styled(
                self.filter,
                Style::default()
                    .bg(self.theme.accent)
                    .fg(self.theme.bg)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                self.filter,
                Style::default().fg(self.theme.text),
            ));
        }
        if self.filter_focused {
            spans.push(Span::styled("█", Style::default().fg(accent)));
        }
        spans.push(Span::styled(hint, Style::default().fg(self.theme.muted)));

        frame.render_widget(
            Paragraph::new(vec![Line::from(spans)]).style(if hovered && !self.filter_focused {
                Style::default().bg(self.theme.surface_hi)
            } else {
                Style::default()
            }),
            area,
        );
    }

    fn render_latency_panel(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" REALTIME PING ")
            .title_style(self.theme.title_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style());
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let avg = if self.latency_history.is_empty() {
            None
        } else {
            Some(self.latency_history.iter().sum::<f64>() / self.latency_history.len() as f64)
        };
        let spark = VisualEffects::format_sparkline(self.latency_history, inner.width as usize);

        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(" Average ", Style::default().fg(self.theme.muted)),
                Span::styled(
                    avg.map(|a| format!("{a:.1} ms"))
                        .unwrap_or_else(|| "—".into()),
                    Style::default()
                        .fg(self.theme.latency_color(avg))
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                spark,
                Style::default()
                    .fg(self.theme.accent_bright)
                    .add_modifier(Modifier::BOLD),
            )]),
        ];
        frame.render_widget(Paragraph::new(text), inner);
    }

    // ---------------------------------------------------------- other tabs

    fn render_subscriptions(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(8)])
            .split(area);

        let btn_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(24),
                Constraint::Length(22),
                Constraint::Length(22),
                Constraint::Min(20),
            ])
            .split(chunks[0]);

        self.action_button(
            frame,
            btn_chunks[0],
            ComponentId::AddSubButton,
            "+ Add Sub URL",
            self.theme.accent,
        );
        self.action_button(
            frame,
            btn_chunks[1],
            ComponentId::RefreshSubsButton,
            "↻ Refresh Feeds",
            self.theme.ok,
        );
        self.action_button(
            frame,
            btn_chunks[2],
            ComponentId::AddManualConfigButton,
            "✦ Create Node",
            self.theme.accent,
        );

        let total_nodes: usize = self.subscriptions.iter().map(|s| s.node_count).sum();
        let summary = Paragraph::new(vec![Line::from(vec![
            Span::styled(" Feeds: ", Style::default().fg(self.theme.muted)),
            Span::styled(
                self.subscriptions.len().to_string(),
                Style::default()
                    .fg(self.theme.accent_bright)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Nodes: ", Style::default().fg(self.theme.muted)),
            Span::styled(
                total_nodes.to_string(),
                Style::default()
                    .fg(self.theme.ok)
                    .add_modifier(Modifier::BOLD),
            ),
        ])])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(self.theme.border)),
        );
        frame.render_widget(summary, btn_chunks[3]);

        let block = Block::default()
            .title(" SUBSCRIPTION SOURCES ")
            .title_style(self.theme.title_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style());
        let inner = block.inner(chunks[1]);
        frame.render_widget(block, chunks[1]);

        let mut rows = Vec::new();
        for (i, sub) in self.subscriptions.iter().enumerate() {
            if i + 1 >= inner.height as usize {
                break;
            }
            let row_rect = Rect {
                x: inner.x,
                y: inner.y + 1 + i as u16,
                width: inner.width,
                height: 1,
            };
            self.interaction
                .register_hit_box(ComponentId::SubItem(i), row_rect);
            let hovered = self.interaction.is_hovered(ComponentId::SubItem(i));

            rows.push(
                Row::new(vec![
                    Cell::from(format!("{:>2}", i + 1))
                        .style(Style::default().fg(self.theme.accent)),
                    Cell::from(sub.remark.as_str()),
                    Cell::from(sub.node_count.to_string())
                        .style(Style::default().fg(self.theme.ok)),
                    Cell::from(sub.url.as_str()).style(Style::default().fg(self.theme.muted)),
                ])
                .style(if hovered {
                    self.theme.card_hover_style()
                } else {
                    Style::default().fg(self.theme.text)
                }),
            );
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Length(26),
                Constraint::Length(6),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec!["#", "Feed", "Nodes", "URL"]).style(
                Style::default()
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .column_spacing(1);
        frame.render_stateful_widget(table, inner, &mut TableState::default());
    }

    fn render_scanner(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(8)])
            .split(area);

        let ctrl = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(24),
                Constraint::Length(24),
                Constraint::Min(25),
            ])
            .split(chunks[0]);

        let (scan_label, scan_color) = if self.is_scanning {
            ("⏹ STOP SCANNER", self.theme.warn)
        } else {
            ("▶ START SCANNER", self.theme.accent)
        };
        self.action_button(
            frame,
            ctrl[0],
            ComponentId::RunScannerButton,
            scan_label,
            scan_color,
        );
        self.action_button(
            frame,
            ctrl[1],
            ComponentId::ExportScannerButton,
            "⤓ EXPORT",
            self.theme.ok,
        );

        let mut stats_spans = vec![
            Span::styled(" Tested ", Style::default().fg(self.theme.muted)),
            Span::styled(
                format!("{} ", self.scanner_tested),
                Style::default()
                    .fg(self.theme.text)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Healthy ", Style::default().fg(self.theme.muted)),
            Span::styled(
                format!("{} ", self.scanner_healthy),
                Style::default()
                    .fg(self.theme.ok)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Rate ", Style::default().fg(self.theme.muted)),
            Span::styled(
                format!("{:.1} ip/s ", self.scanner_speed),
                Style::default().fg(self.theme.accent_bright),
            ),
        ];
        if self.is_scanning {
            let throbber = Throbber::default()
                .throbber_set(BRAILLE_SIX)
                .throbber_style(Style::default().fg(self.theme.accent_bright));
            stats_spans.push(throbber.to_symbol_span(self.throbber_state));
        }
        frame.render_widget(
            Paragraph::new(vec![Line::from(stats_spans)]).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(self.theme.border)),
            ),
            ctrl[2],
        );

        let block = Block::default()
            .title(format!(
                " CLEAN ENDPOINTS ({}) ",
                self.scanner_results.len()
            ))
            .title_style(self.theme.title_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style());
        let inner = block.inner(chunks[1]);
        frame.render_widget(block, chunks[1]);

        let mut rows = Vec::new();
        for (i, r) in self.scanner_results.iter().enumerate() {
            if i + 1 >= inner.height as usize {
                break;
            }
            let row_rect = Rect {
                x: inner.x,
                y: inner.y + 1 + i as u16,
                width: inner.width,
                height: 1,
            };
            self.interaction
                .register_hit_box(ComponentId::ScannerItem(i), row_rect);
            let hovered = self.interaction.is_hovered(ComponentId::ScannerItem(i));
            let latency = r.avg_latency_ms();

            rows.push(
                Row::new(vec![
                    Cell::from(format!("{:>2}", i + 1))
                        .style(Style::default().fg(self.theme.accent)),
                    Cell::from(format!("{}:{}", r.ip, r.port)),
                    Cell::from(format!("{latency:>6.1}ms"))
                        .style(Style::default().fg(self.theme.latency_color(Some(latency)))),
                    Cell::from(format!("{:>3.0}%", r.packet_loss_percent()))
                        .style(Style::default().fg(self.theme.muted)),
                    Cell::from(r.colo.as_deref().unwrap_or("---"))
                        .style(Style::default().fg(self.theme.accent_bright)),
                    Cell::from(r.isp.as_deref().unwrap_or("Cloudflare"))
                        .style(Style::default().fg(self.theme.muted)),
                ])
                .style(if hovered {
                    self.theme.card_hover_style()
                } else {
                    Style::default().fg(self.theme.text)
                }),
            );
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Length(21),
                Constraint::Length(9),
                Constraint::Length(5),
                Constraint::Length(6),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec!["#", "Endpoint", "Latency", "Loss", "Colo", "ISP"]).style(
                Style::default()
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .column_spacing(1);
        frame.render_stateful_widget(table, inner, &mut TableState::default());
    }

    /// A labelled, rounded action button with hover fill.
    fn action_button(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        id: ComponentId,
        label: &str,
        color: Color,
    ) {
        self.interaction.register_hit_box(id, area);
        let hovered = self.interaction.is_hovered(id);
        self.chip(frame, area, label, color, hovered);
    }

    // ------------------------------------------------------------- footer

    /// Shortcut hints drawn as key caps: the key is a filled cap, the label
    /// beside it is dimmed.
    fn render_footer(&mut self, frame: &mut Frame, area: Rect) {
        use unicode_width::UnicodeWidthStr;

        // The right end is a status strip, as in a desktop proxy client:
        // the local ports and, when enabled, what this app itself costs.
        let ports = format!(
            " SOCKS {}  HTTP {} ",
            self.settings.socks_port, self.settings.http_port
        );
        let usage = self
            .usage
            .snapshot
            .filter(|_| self.settings.show_usage)
            .map(|s| format!(" {} ", usage_label(s)));
        let status_width = (ports.width() + usage.as_ref().map_or(0, |u| u.width() + 1)) as u16;
        let area = if area.width >= status_width + 60 {
            let status = Rect {
                x: area.x + area.width - status_width,
                width: status_width,
                ..area
            };
            let mut x = status.x;
            frame.render_widget(
                Paragraph::new(Span::styled(
                    ports.as_str(),
                    Style::default().fg(self.theme.muted),
                )),
                Rect {
                    x,
                    width: ports.width() as u16,
                    ..status
                },
            );
            x += ports.width() as u16;
            if let Some(usage) = &usage {
                frame.render_widget(
                    Paragraph::new(Span::styled("│", Style::default().fg(self.theme.border))),
                    Rect {
                        x,
                        width: 1,
                        ..status
                    },
                );
                x += 1;
                let rect = Rect {
                    x,
                    width: usage.width() as u16,
                    ..status
                };
                self.interaction
                    .register_hit_box(ComponentId::FooterUsage, rect);
                let style = if self.interaction.is_hovered(ComponentId::FooterUsage) {
                    Style::default()
                        .bg(self.theme.surface_hi)
                        .fg(self.theme.accent_bright)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(self.theme.accent)
                };
                frame.render_widget(Paragraph::new(Span::styled(usage.as_str(), style)), rect);
            }
            Rect {
                width: area.width - status_width,
                ..area
            }
        } else {
            area
        };

        // Sharing and finding live on the rows and in the filter box now, so
        // the footer keeps only what has nowhere else to be.
        let items: [(ComponentId, &str, &str); 5] = [
            (ComponentId::FooterConnect, "↵", "Connect"),
            (ComponentId::FooterAddConfig, "^V", "Paste"),
            (ComponentId::FooterAddSub, "^R", "Update subs"),
            (ComponentId::FooterHelp, "F1", "Help"),
            (ComponentId::FooterQuit, "^Q", "Quit"),
        ];

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 5); 5])
            .split(area);

        for (i, (id, key, label)) in items.iter().enumerate() {
            self.interaction.register_hit_box(*id, chunks[i]);
            let hovered = self.interaction.is_hovered(*id);

            let cap_style = if hovered {
                Style::default()
                    .bg(self.theme.accent_bright)
                    .fg(self.theme.bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .bg(self.theme.surface_hi)
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD)
            };
            let label_style = if hovered {
                Style::default().fg(self.theme.text)
            } else {
                Style::default().fg(self.theme.muted)
            };

            let line = Line::from(vec![
                Span::styled(format!(" {key} "), cap_style),
                Span::styled(format!(" {label}"), label_style),
            ]);
            frame.render_widget(
                Paragraph::new(vec![line]).alignment(Alignment::Center),
                chunks[i],
            );
        }
    }

    // -------------------------------------------------------------- toasts

    fn render_toasts(&mut self, frame: &mut Frame, area: Rect) {
        // Below this a toast cannot hold even its title; the header chips
        // and the status pill already carry the essentials.
        const MIN_TOAST_WIDTH: u16 = 16;

        let now = std::time::Instant::now();
        let animated = self.toasts.animated() && self.effects.animations_enabled();
        let toasts = self.toasts.active_toasts();
        if toasts.is_empty() {
            return;
        }

        let toast_width = 46u16.min(area.width.saturating_sub(4));
        if toast_width < MIN_TOAST_WIDTH {
            return;
        }
        let text_width = toast_width.saturating_sub(4) as usize;
        // Right-aligned with a two-column margin.
        let home_x = area.x + area.width.saturating_sub(toast_width + 2);
        // Below the header: the status chips in the top-right are the most
        // important thing on screen and a toast landing on them hid whether
        // the system proxy was even active.
        let mut y = area.y.saturating_add(HEADER_HEIGHT + 1);
        let bottom = area.bottom();

        for (i, t) in toasts.iter().enumerate() {
            // Each toast is as tall as its message needs. A fixed three rows
            // silently truncated anything longer than one line, which is most
            // error messages.
            let lines = wrap_width(&t.message, text_width);
            let body_height = lines.len().clamp(1, 8) as u16
                // A mutable notice gets a row for its button.
                + u16::from(t.notice.is_some());
            let toast_height = body_height + 2;

            if y.saturating_add(toast_height) > bottom {
                // No room for the rest; say how many are hidden rather than
                // drawing them off screen.
                let remaining = toasts.len() - i;
                if y < bottom {
                    frame.render_widget(
                        Paragraph::new(format!("  +{remaining} more…"))
                            .style(Style::default().fg(self.theme.muted))
                            .alignment(Alignment::Right),
                        Rect {
                            x: home_x,
                            y,
                            width: toast_width,
                            height: 1,
                        },
                    );
                }
                break;
            }

            // Entrance: slide in from the right edge, decelerating into
            // place. Exit: the colours sink into the surface behind them.
            let (slide, opacity) = if animated {
                (1.0 - t.enter_progress(now), t.exit_opacity(now))
            } else {
                (0.0, 1.0)
            };
            let offset = (slide * (toast_width + 2) as f64).round() as u16;
            let x = home_x.saturating_add(offset);
            let toast_area = Rect {
                x,
                y,
                width: toast_width,
                height: toast_height,
            }
            .intersection(area);
            y += toast_height + 1;
            if toast_area.is_empty() {
                continue;
            }

            let fade = |c: Color| {
                if opacity >= 1.0 {
                    c
                } else {
                    self.theme
                        .adapt(crate::theme::lerp_color(self.theme.surface, c, opacity))
                }
            };
            let color = fade(ToastManager::color_for(t.kind, self.theme));

            frame.render_widget(Clear, toast_area);
            let block = Block::default()
                .title(format!(" {} ", ToastManager::icon_for(t.kind)))
                .title_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(color))
                .style(Style::default().bg(self.theme.surface));

            frame.render_widget(
                Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>())
                    .style(Style::default().fg(fade(self.theme.text)))
                    .block(block),
                toast_area,
            );

            // The close button only exists once the toast has landed: a
            // target that slides away from the pointer is not a target.
            if offset > 0 || toast_area.width < toast_width {
                continue;
            }
            let close_rect = Rect {
                x: toast_area.x + toast_width.saturating_sub(5),
                y: toast_area.y,
                width: 4,
                height: 1,
            }
            .intersection(toast_area);
            self.interaction
                .register_hit_box(ComponentId::ToastClose(i), close_rect);
            let close_hover = self.interaction.is_hovered(ComponentId::ToastClose(i));
            let close_style = if close_hover {
                Style::default()
                    .bg(self.theme.err)
                    .fg(self.theme.text)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(fade(self.theme.muted))
                    .add_modifier(Modifier::BOLD)
            };
            frame.render_widget(Paragraph::new("[✕]").style(close_style), close_rect);

            if t.notice.is_some() {
                const LABEL: &str = " Don't show again ";
                let width = (LABEL.len() as u16).min(toast_area.width.saturating_sub(2));
                let button = Rect {
                    x: toast_area.right().saturating_sub(width + 2),
                    y: toast_area.bottom().saturating_sub(2),
                    width,
                    height: 1,
                }
                .intersection(toast_area);
                self.interaction
                    .register_hit_box(ComponentId::ToastMute(i), button);
                let style = if self.interaction.is_hovered(ComponentId::ToastMute(i)) {
                    Style::default()
                        .bg(self.theme.accent_bright)
                        .fg(self.theme.bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .bg(self.theme.surface_hi)
                        .fg(fade(self.theme.text))
                };
                frame.render_widget(Paragraph::new(LABEL).style(style), button);
            }
        }
    }

    // ------------------------------------------------------ context menu

    /// The right-click menu, drawn above everything else.
    fn render_context_menu(&mut self, frame: &mut Frame, screen: Rect) {
        use crate::ctxmenu::MenuItem;

        let Some(menu) = self.context_menu else {
            return;
        };
        let area = menu.rect(screen);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(self.theme.accent))
                .style(Style::default().bg(self.theme.surface)),
            area,
        );

        for (i, item) in menu.items.iter().enumerate() {
            let Some(row) = menu.item_rect(i, screen) else {
                continue;
            };
            match item {
                MenuItem::Separator => {
                    frame.render_widget(
                        Paragraph::new("─".repeat(row.width as usize))
                            .style(Style::default().fg(self.theme.border)),
                        row,
                    );
                }
                MenuItem::Action(action) => {
                    self.interaction
                        .register_hit_box(ComponentId::ContextMenuItem(i), row);
                    let hovered = self.interaction.is_hovered(ComponentId::ContextMenuItem(i))
                        || menu.highlighted() == i;

                    let fg = if action.is_destructive() {
                        self.theme.err
                    } else {
                        self.theme.text
                    };
                    let style = if hovered {
                        Style::default()
                            .bg(self.theme.surface_hi)
                            .fg(if action.is_destructive() {
                                self.theme.err
                            } else {
                                self.theme.accent_bright
                            })
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(fg)
                    };

                    let accel = action.accelerator();
                    let gap = (row.width as usize)
                        .saturating_sub(action.label().chars().count() + accel.chars().count() + 2);
                    let line = Line::from(vec![
                        Span::styled(format!(" {}", action.label()), style),
                        Span::raw(" ".repeat(gap)),
                        Span::styled(format!("{accel} "), Style::default().fg(self.theme.muted)),
                    ]);
                    frame.render_widget(Paragraph::new(vec![line]).style(style), row);
                }
            }
        }
    }

    /// The rubber-band rectangle of an in-progress drag selection.
    fn render_drag_band(&self, frame: &mut Frame, screen: Rect) {
        let Some(drag) = self.drag else {
            return;
        };
        if !drag.is_active() {
            return;
        }
        let band = drag.rect();
        let buf = frame.buffer_mut();
        for y in band.y..band.bottom().min(screen.bottom()) {
            for x in band.x..band.right().min(screen.right()) {
                let cell = &mut buf[(x, y)];
                cell.set_bg(self.theme.surface_hi);
                cell.set_fg(self.theme.accent_bright);
            }
        }
    }
}

/// Whether a profile passes the list filter. `needle` is the filter already
/// lower-cased.
///
/// Same semantics as `str::to_lowercase().contains()` — the key handler
/// uses exactly that to map a row index back to a profile, and the two must
/// agree or a click would act on the wrong row — but without allocating for
/// the common all-ASCII field.
pub fn profile_matches(cfg: &ConfigRecord, needle: &str) -> bool {
    fn contains_folded(hay: &str, needle: &str) -> bool {
        if hay.is_ascii() {
            // ASCII lower-casing is exactly what `to_lowercase` does to an
            // ASCII string, so a byte-window compare is equivalent.
            let (h, n) = (hay.as_bytes(), needle.as_bytes());
            n.is_empty()
                || (n.len() <= h.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n)))
        } else {
            hay.to_lowercase().contains(needle)
        }
    }
    contains_folded(&cfg.remark, needle)
        || contains_folded(&cfg.address, needle)
        || contains_folded(&cfg.protocol, needle)
}

/// Indices of the profiles the filter lets through, in list order.
pub fn filtered_indices(configs: &[ConfigRecord], filter: &str) -> Vec<usize> {
    if filter.trim().is_empty() {
        return (0..configs.len()).collect();
    }
    let needle = filter.to_lowercase();
    configs
        .iter()
        .enumerate()
        .filter(|(_, c)| profile_matches(c, &needle))
        .map(|(i, _)| i)
        .collect()
}

/// Profile names that appear more than once among the shown rows.
fn duplicate_remarks<'c>(
    configs: &'c [ConfigRecord],
    visible: &[usize],
) -> std::collections::HashSet<&'c str> {
    let mut seen = std::collections::HashMap::<&str, u32>::with_capacity(visible.len());
    for &i in visible {
        *seen.entry(configs[i].remark.as_str()).or_insert(0) += 1;
    }
    seen.into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name)
        .collect()
}

/// Mix `tint` into `base` by `amount`.
///
/// Truecolor blends exactly; xterm-256 indices blend through RGB and land on
/// the nearest index, so glows and sheens still read on a 256-colour
/// terminal. Named ANSI colours have no known RGB value, and these are
/// subtle overlays, so on them the base is left untouched.
fn blend(base: Color, tint: Color, amount: f64) -> Color {
    match (base, tint) {
        (Color::Rgb(..) | Color::Indexed(16..=255), Color::Rgb(..) | Color::Indexed(16..=255)) => {
            crate::theme::lerp_color(base, tint, amount)
        }
        _ => base,
    }
}

pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

/// `4:07`, `1:02:33`: a session length the way a VPN client shows it.
pub fn format_session(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// The status bar's readout of this app's own cost.
pub fn usage_label(snapshot: &crate::usage::UsageSnapshot) -> String {
    format!(
        "CPU {}  RAM {}",
        crate::usage::format_cpu(snapshot.self_cpu),
        crate::usage::format_memory(snapshot.self_memory)
    )
}

/// A profile's transport label, parsed once per distinct profile body.
///
/// Profiles are JSON; parsing every visible row on every animation frame
/// would be wasted work for a value that only changes on edit.
fn cached_transport(cfg: &ConfigRecord) -> String {
    use std::collections::HashMap;
    use std::hash::{Hash, Hasher};
    thread_local! {
        static CACHE: std::cell::RefCell<HashMap<i64, (u64, String)>> =
            std::cell::RefCell::new(HashMap::new());
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cfg.raw_content.hash(&mut hasher);
    let fingerprint = hasher.finish();
    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((seen, label)) = cache.get(&cfg.id) {
            if *seen == fingerprint {
                return label.clone();
            }
        }
        if cache.len() > 4096 {
            cache.clear();
        }
        let label =
            crate::sharelink::transport_label(&cfg.raw_content).unwrap_or_else(|| "—".to_string());
        cache.insert(cfg.id, (fingerprint, label.clone()));
        label
    })
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_speed(bps: u64) -> String {
    format!("{}/s", format_bytes(bps))
}

/// Terminal columns `s` occupies.
///
/// Not `chars().count()`: a CJK ideograph or most emoji take two columns and
/// a combining accent takes none, so counting chars misaligns every column
/// that follows a name written in anything but ASCII.
pub fn display_width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
}

fn char_width(c: char) -> usize {
    unicode_width::UnicodeWidthChar::width(c).unwrap_or(0)
}

/// Break `text` into lines no wider than `width` columns, splitting on spaces
/// and falling back to a hard break for anything unbreakable.
///
/// Used by toasts: share links and engine errors are long and have no spaces,
/// and a message the user cannot read in full is a message that did not
/// arrive.
pub fn wrap_width(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_w = 0usize;

    for word in text.split_whitespace() {
        let word_w = display_width(word);

        if word_w > width {
            // An unbreakable run — a URL, a UUID — is split hard rather than
            // being allowed to overflow. It starts on its own line so the
            // split points are predictable.
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
                current_w = 0;
            }
            for c in word.chars() {
                let cw = char_width(c);
                if current_w + cw > width && !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                    current_w = 0;
                }
                current.push(c);
                current_w += cw;
            }
            continue;
        }

        let needed = if current.is_empty() {
            word_w
        } else {
            current_w + 1 + word_w
        };
        if needed > width {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
            current_w = word_w;
        } else {
            if !current.is_empty() {
                current.push(' ');
                current_w += 1;
            }
            current.push_str(word);
            current_w += word_w;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Cut `s` to at most `max` terminal columns, marking the cut with `…`.
pub fn truncate(s: &str, max: usize) -> String {
    if display_width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let budget = max - 1; // the ellipsis takes one column
    let mut out = String::with_capacity(s.len().min(max * 4));
    let mut used = 0usize;
    for c in s.chars() {
        let cw = char_width(c);
        if used + cw > budget {
            break;
        }
        out.push(c);
        used += cw;
    }
    out.push('…');
    out
}

/// The single row and horizontal bounds a status sweep is allowed to travel across.
///
/// The sweep must stay strictly inside the status bar/pill itself: starting after
/// the leading margin space, covering the pill width, and never extending beyond it
/// into the node name or empty header.
pub(crate) fn sweep_area(inner: Rect, pill_width: u16) -> Rect {
    if inner.width <= 1 || inner.height == 0 {
        return Rect {
            x: inner.x,
            y: inner.y,
            width: 0,
            height: 0,
        };
    }
    Rect {
        x: inner.x.saturating_add(1),
        y: inner.y,
        width: pill_width.min(inner.width.saturating_sub(1)),
        height: 1.min(inner.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sweep_never_runs_past_the_text_it_belongs_to() {
        let header = Rect {
            x: 24,
            y: 0,
            width: 120,
            height: 2,
        };
        // Status pill for DISCONNECTED is 14 cells wide.
        let bar = sweep_area(header, 14);
        assert_eq!((bar.x, bar.y), (25, 0));
        assert_eq!(bar.width, 14, "the band escaped the status bar");
        assert_eq!(bar.height, 1, "the sweep is a single row");
    }

    #[test]
    fn a_sweep_is_clamped_to_the_panel_when_the_text_overflows() {
        let narrow = Rect {
            x: 4,
            y: 3,
            width: 20,
            height: 1,
        };
        let bar = sweep_area(narrow, 200);
        assert_eq!(bar.x, 5);
        assert_eq!(bar.width, 19);
        assert!(bar.x + bar.width <= narrow.x + narrow.width);
    }

    #[test]
    fn a_zero_height_panel_gets_no_row_to_sweep() {
        let collapsed = Rect {
            x: 0,
            y: 0,
            width: 40,
            height: 0,
        };
        assert_eq!(sweep_area(collapsed, 10).height, 0);
        assert_eq!(sweep_area(collapsed, 10).width, 0);
    }

    #[test]
    fn truncate_adds_an_ellipsis_only_when_it_cuts() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly-10", 10), "exactly-10");
        assert_eq!(truncate("much-longer-name", 8), "much-lo…");
    }

    #[test]
    fn byte_formatting_switches_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert!(format_bytes(5 * 1024 * 1024).ends_with("MB"));
        assert!(format_bytes(3 * 1024 * 1024 * 1024).ends_with("GB"));
        assert!(format_speed(1024).ends_with("/s"));
    }

    #[test]
    fn centered_rect_is_centred_and_sized() {
        let full = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 40,
        };
        let inner = centered_rect(50, 50, full);
        assert_eq!(inner.width, 50);
        assert_eq!(inner.height, 20);
        assert_eq!(inner.x, 25);
        assert_eq!(inner.y, 10);
    }
}
