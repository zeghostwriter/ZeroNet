//! Drawing of the "My server" page (state and keys are in `servers`).
//!
//! The page is laid out like a desktop app: a title bar, a row of steps while
//! a server is being set up, panes with cards in them, buttons, and a bar of
//! key chips along the bottom that always says what the keys do on the screen
//! in front of you. Everything is plain words: no jargon a person who has only
//! just rented a server would not know.
//!
//! How this works: `render_servers` picks the screen, draws its pane into the
//! body area, then runs the settle-in fade over it (a new screen's text fades
//! up row by row, see `srv_widgets::fade_in`). Each screen is one method that
//! draws straight into a `Rect`; the small reusable pieces (text boxes,
//! sparklines, progress bars) are in `srv_widgets` and have their own tests.
//! Motion comes from the effects clock, so with animation switched off the
//! page is simply still.

use crate::caret::Caret;
use crate::qr::{self, QrStyle};
use crate::servers::{DnsStatus, Field, Form, ProgressView, Screen, ServersState, StepState};
use crate::srv_widgets::{
    clip, human_bytes, input_spans, progress_bar, rates, sparkline, spinner, width_of, InputColors,
    InputView,
};
use crate::theme::lerp_color;
use crate::ui::UiRenderer;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use std::time::Instant;
use zero_provision::install::{Note, Preset, Step};
use zero_provision::manage::InboundUsage;
use zero_provision::record::{ServerRecord, Service};

/// What a note means, in a sentence.
pub fn note_text(note: &Note) -> String {
    match note {
        Note::PortMoved { wanted, used, held_by } => format!(
            "Port {wanted} was already used by {held_by}, so port {used} is used instead."
        ),
        Note::FirewallOpened { which } => {
            format!("The ports were opened in the server's firewall ({which}).")
        }
        Note::ProviderFirewall { tcp, udp } => {
            let list = |ports: &[u16], kind: &str| {
                (!ports.is_empty()).then(|| {
                    let p: Vec<String> = ports.iter().map(u16::to_string).collect();
                    format!("{kind} {}", p.join(", "))
                })
            };
            let parts: Vec<String> = [list(tcp, "TCP"), list(udp, "UDP")]
                .into_iter()
                .flatten()
                .collect();
            format!(
                "Your hosting provider may have its own firewall. If nothing connects, open {} in its panel.",
                parts.join(" and ")
            )
        }
        Note::Unverified => {
            "The server program was uploaded from this app and was not checked against the signed list.".into()
        }
        Note::KeyNotWorking => {
            "The app could not log back in with its own key, so it will ask for the password next time.".into()
        }
    }
}

/// The plain name of an install step.
fn step_name(step: Step, preset: Option<Preset>) -> String {
    let what = match preset {
        Some(Preset::Reality) => " (REALITY)",
        Some(Preset::Xhttp) => " (XHTTP)",
        Some(Preset::Zerov1) => " (ZeroV1)",
        Some(Preset::MasterDns) => " (MasterDNS)",
        None => "",
    };
    let base = match step {
        Step::Check => "Checking the server",
        Step::Packages => "Getting what it needs",
        Step::Download => "Downloading and verifying",
        Step::Install => "Installing",
        Step::Configure => "Writing the settings",
        Step::Start => "Starting",
        Step::Firewall => "Opening the ports",
        Step::Access => "Saving this app's access",
    };
    format!("{base}{what}")
}

/// A service's short name for a card.
fn short_name(service: &Service) -> &'static str {
    match service {
        Service::Reality(_) => "VLESS",
        Service::Xhttp(_) => "XHTTP",
        Service::Zerov1(_) => "ZeroV1",
        Service::MasterDns(_) => "MasterDNS",
    }
}

/// How a server looks at a glance.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Health {
    /// Somebody is connected right now.
    Busy,
    /// Read, and answering, with nobody on it.
    Quiet,
    /// The last read failed.
    Trouble,
    /// Not read yet.
    Unknown,
}

impl UiRenderer<'_> {
    // ------------------------------------------------------------ the frame

    pub(crate) fn render_servers(&mut self, frame: &mut Frame, area: Rect) {
        let state = self.servers;
        let now = Instant::now();
        let animated = self.effects.animations_enabled();
        let settled = if animated { state.settled(now) } else { 1.0 };

        let chips = self.chips_for(state);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(area);

        let count = state.records.len();
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .title(Line::from(vec![
                Span::styled(
                    " ⌂ ",
                    Style::default()
                        .fg(self.theme.accent_bright)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "My servers ",
                    Style::default()
                        .fg(self.theme.accent_bright)
                        .add_modifier(Modifier::BOLD),
                ),
            ]))
            .title(
                Line::from(Span::styled(
                    if count == 0 {
                        " none yet ".to_string()
                    } else {
                        format!(" {count} set up ")
                    },
                    Style::default().fg(self.theme.muted),
                ))
                .alignment(Alignment::Right),
            );
        let inner = block.inner(rows[0]);
        frame.render_widget(block, rows[0]);
        // A little air inside the frame.
        let inner = inset(inner, 1, 0);

        match &state.screen {
            Screen::List => self.draw_list(frame, inner, state),
            Screen::Busy(text) => self.draw_busy(frame, inner, text),
            Screen::Form(form) => self.draw_form(frame, inner, form),
            Screen::Identity {
                checked, key, form, ..
            } => {
                let body = self.stepper_and_body(frame, inner, form.masterdns, 1);
                self.draw_identity(frame, body, &checked.address, &key.fingerprint);
            }
            Screen::Dns {
                records,
                status,
                checked,
                ..
            } => {
                let body = self.stepper_and_body(frame, inner, true, 2);
                self.draw_dns(
                    frame,
                    body,
                    records,
                    status,
                    &checked.address,
                    checked.domain.as_deref().unwrap_or(""),
                );
            }
            Screen::Progress(view) => {
                let body = self.stepper_and_body(frame, inner, false, 2);
                self.draw_progress(frame, body, view);
            }
            Screen::Result {
                record,
                notes,
                shown,
            } => {
                let body = self.stepper_and_body(frame, inner, false, 3);
                self.draw_result(frame, body, state, record, notes, *shown, settled);
            }
            Screen::Server { id, shown } => match state.record(id) {
                Some(record) => self.draw_server(frame, inner, state, record, *shown),
                None => self.draw_centered_note(frame, inner, "This server is gone.", "Esc  back"),
            },
            Screen::ConfirmRemove { id, typed } => {
                self.draw_confirm(frame, inner, state, id, typed)
            }
        }

        crate::srv_widgets::fade_in(frame.buffer_mut(), inner, settled, self.theme.bg);

        // The status row: the last thing that happened, and on a server's
        // page a pulsing "live" light.
        let status_text = match &state.notice {
            Some(notice) if matches!(state.screen, Screen::List | Screen::Server { .. }) => {
                Span::styled(
                    format!(
                        " ⓘ {}",
                        clip(notice, rows[1].width.saturating_sub(14) as usize)
                    ),
                    Style::default().fg(self.theme.info),
                )
            }
            _ => Span::raw(""),
        };
        let mut status = vec![status_text];
        if matches!(state.screen, Screen::Server { .. }) {
            let pulse = self.effects.pulse_phase(2.4);
            let light = lerp_color(self.theme.muted, self.theme.ok, 0.4 + pulse * 0.6);
            let used = width_of(&status[0].content);
            let pad = (rows[1].width as usize).saturating_sub(used + 8);
            status.push(Span::raw(" ".repeat(pad)));
            status.push(Span::styled("● ", Style::default().fg(light)));
            status.push(Span::styled("live ", Style::default().fg(self.theme.muted)));
        }
        frame.render_widget(Paragraph::new(Line::from(status)), rows[1]);
        frame.render_widget(
            Paragraph::new(self.chip_line(&chips, rows[2].width)),
            rows[2],
        );
    }

    // ---------------------------------------------------------------- chips

    /// The keys that do something on the screen in front of you.
    fn chips_for(&self, state: &ServersState) -> Vec<(&'static str, &'static str)> {
        match &state.screen {
            Screen::List if state.records.is_empty() => vec![("a", "add a server")],
            Screen::List => vec![
                ("a", "add"),
                ("↑↓", "choose"),
                ("Enter", "open"),
                ("Space", "tick"),
                ("Ctrl+A", "select all"),
                ("c", "copy configs"),
                ("r", "refresh"),
            ],
            Screen::Busy(_) => vec![("Esc", "cancel")],
            Screen::Form(form) if form.typing() => vec![
                ("Tab", "next"),
                ("Ctrl+A", "select all"),
                ("Ctrl+V", "paste"),
                ("Ctrl+X", "cut"),
                ("Ctrl+U", "clear"),
                ("Ctrl+R", "show password"),
                ("Ctrl+S", "connect"),
                ("Esc", "back"),
            ],
            Screen::Form(_) => vec![
                ("Tab", "next"),
                ("Space", "tick"),
                ("Ctrl+A", "tick all"),
                ("Enter", "choose"),
                ("Ctrl+S", "connect"),
                ("Esc", "back"),
            ],
            Screen::Identity { .. } => vec![("Enter", "yes, it matches"), ("Esc", "no, go back")],
            Screen::Dns { .. } => vec![
                ("1-4", "copy"),
                ("c", "check"),
                ("Enter", "install"),
                ("Esc", "back"),
            ],
            Screen::Progress(view) if view.failed.is_some() => vec![("Enter", "go back")],
            Screen::Progress(_) => vec![("", "this takes a minute or two")],
            Screen::Result { .. } => vec![
                ("←→", "other config"),
                ("Ctrl+A", "select all"),
                ("c", "copy"),
                ("o", "big code"),
                ("s", "save files"),
                ("Enter", "server page"),
            ],
            Screen::Server { .. } => vec![
                ("←→", "config"),
                ("Ctrl+A", "select all"),
                ("c", "copy"),
                ("o", "big code"),
                ("s", "save"),
                ("r", "refresh"),
                ("t", "test"),
                ("d", "remove"),
                ("Esc", "back"),
            ],
            Screen::ConfirmRemove { .. } => vec![
                ("Enter", "confirm"),
                ("Ctrl+A", "select"),
                ("Esc", "cancel"),
            ],
        }
    }

    /// The chips as one line: a key in a small raised box, then what it does.
    /// Chips that do not fit are dropped from the end rather than cut.
    fn chip_line(&self, chips: &[(&str, &str)], width: u16) -> Line<'static> {
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut used = 0usize;
        for (key, label) in chips {
            let need = if key.is_empty() {
                label.chars().count() + 2
            } else {
                key.chars().count() + label.chars().count() + 6
            };
            if used + need > width as usize {
                break;
            }
            used += need;
            if key.is_empty() {
                spans.push(Span::styled(
                    format!(" {label} "),
                    Style::default().fg(self.theme.muted),
                ));
                continue;
            }
            spans.push(Span::styled(
                format!(" {key} "),
                Style::default()
                    .fg(self.theme.accent_bright)
                    .bg(self.theme.surface_hi)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                format!(" {label}  "),
                Style::default().fg(self.theme.muted),
            ));
        }
        Line::from(spans)
    }

    // -------------------------------------------------------------- stepper

    /// The row of steps along the top of a set-up flow, then the body below.
    /// `dns` says whether the domain step exists; `at` is the step in progress.
    fn stepper_and_body(&self, frame: &mut Frame, area: Rect, dns: bool, at: usize) -> Rect {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(3)])
            .split(area);
        let names: Vec<&str> = if dns {
            vec!["Details", "Verify", "Domain", "Install", "Ready"]
        } else {
            vec!["Details", "Verify", "Install", "Ready"]
        };
        let pulse = self.effects.pulse_phase(3.0);
        let mut spans: Vec<Span<'static>> = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let (glyph, color, bold) = if i < at {
                ("✓", self.theme.ok, false)
            } else if i == at {
                (
                    "●",
                    lerp_color(self.theme.accent, self.theme.accent_bright, pulse),
                    true,
                )
            } else {
                ("○", self.theme.muted, false)
            };
            let mut style = Style::default().fg(color);
            if bold {
                style = style.add_modifier(Modifier::BOLD);
            }
            spans.push(Span::styled(format!("{glyph} {name}"), style));
            if i + 1 < names.len() {
                let line_color = if i < at {
                    self.theme.ok
                } else {
                    self.theme.border
                };
                spans.push(Span::styled(" ───── ", Style::default().fg(line_color)));
            }
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), rows[0]);
        rows[1]
    }

    // ------------------------------------------------------------- helpers

    fn input_colors(&self, focused: bool) -> InputColors {
        InputColors {
            text: self.theme.text,
            placeholder: self.theme.muted,
            background: if focused {
                self.theme.surface_hi
            } else {
                self.theme.surface
            },
            selection_bg: self.theme.accent,
            selection_fg: self.theme.bg,
        }
    }

    /// A card: a rounded box with a title, returning the room inside it.
    fn card(&self, frame: &mut Frame, area: Rect, title: &str, border: Color) -> Rect {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border))
            .title(Span::styled(
                format!(" {title} "),
                Style::default()
                    .fg(self.theme.text)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        inset(inner, 1, 0)
    }

    fn dim(&self, text: impl Into<String>) -> Line<'static> {
        Line::styled(text.into(), Style::default().fg(self.theme.muted))
    }

    fn strong(&self, text: impl Into<String>) -> Line<'static> {
        Line::styled(
            text.into(),
            Style::default()
                .fg(self.theme.accent_bright)
                .add_modifier(Modifier::BOLD),
        )
    }

    /// `── Title ───────`: a heading that divides a form into parts.
    fn section(&self, title: &str, width: usize) -> Line<'static> {
        let used = title.chars().count() + 4;
        Line::from(vec![
            Span::styled("── ", Style::default().fg(self.theme.border)),
            Span::styled(
                title.to_string(),
                Style::default()
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}", "─".repeat(width.saturating_sub(used))),
                Style::default().fg(self.theme.border),
            ),
        ])
    }

    /// A button: filled with its colour when it has focus, a quiet box when not.
    fn button(&self, label: &str, focused: bool, color: Color) -> Vec<Span<'static>> {
        if focused {
            vec![Span::styled(
                format!("  {label}  "),
                Style::default()
                    .fg(self.theme.bg)
                    .bg(color)
                    .add_modifier(Modifier::BOLD),
            )]
        } else {
            vec![Span::styled(
                format!("  {label}  "),
                Style::default()
                    .fg(self.theme.text)
                    .bg(self.theme.surface_hi),
            )]
        }
    }

    /// The light that says how a server is doing; it breathes while busy.
    fn health_dot(&self, health: Health) -> Span<'static> {
        let (color, glyph) = match health {
            Health::Busy => {
                let pulse = self.effects.pulse_phase(2.6);
                (
                    lerp_color(self.theme.ok, self.theme.accent_bright, pulse * 0.5),
                    "●",
                )
            }
            Health::Quiet => (self.theme.ok, "●"),
            Health::Trouble => (self.theme.err, "●"),
            Health::Unknown => (self.theme.muted, "○"),
        };
        Span::styled(glyph, Style::default().fg(color))
    }

    fn health_of(&self, state: &ServersState, record: &ServerRecord) -> Health {
        if state.usage_error.contains_key(&record.id) && !state.usage.contains_key(&record.id) {
            return Health::Trouble;
        }
        match state.usage.get(&record.id) {
            Some((usage, _)) if usage.devices_now() > 0 => Health::Busy,
            Some(_) => Health::Quiet,
            None => Health::Unknown,
        }
    }

    // ----------------------------------------------------------------- list

    fn draw_list(&self, frame: &mut Frame, area: Rect, state: &ServersState) {
        if state.records.is_empty() {
            self.draw_welcome(frame, area);
            return;
        }
        let wide = area.width >= 78;
        let (left, right) = if wide {
            let left_width = (area.width * 2 / 5).clamp(34, 48);
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(left_width), Constraint::Min(30)])
                .spacing(1)
                .split(area);
            (cols[0], Some(cols[1]))
        } else {
            (area, None)
        };

        let title = if state.marked.is_empty() {
            "Servers".to_string()
        } else {
            format!("Servers · {} selected", state.marked.len())
        };
        let inner = self.card(frame, left, &title, self.theme.border_focus);
        let card_height = 4u16;
        let per_page = (inner.height / card_height).max(1) as usize;
        let first = state.selected.saturating_sub(per_page - 1);
        let mut y = inner.y;
        for (i, record) in state.records.iter().enumerate().skip(first).take(per_page) {
            let rect = Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: card_height.min(inner.y + inner.height - y),
            };
            self.draw_server_card(frame, rect, state, record, i == state.selected);
            y += card_height;
        }
        if state.records.len() > per_page {
            let hint = format!("{}/{}", state.selected + 1, state.records.len());
            let at = Rect {
                x: left.x + left.width.saturating_sub(hint.len() as u16 + 3),
                y: left.y + left.height.saturating_sub(1),
                width: hint.len() as u16 + 2,
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(Span::styled(
                    format!(" {hint} "),
                    Style::default().fg(self.theme.muted),
                )),
                at,
            );
        }

        if let (Some(right), Some(record)) = (right, state.records.get(state.selected)) {
            self.draw_preview(frame, right, state, record);
        }
    }

    /// One server in the list: a status light, its name, address, services and
    /// how many are connected, with a little graph of recent use.
    fn draw_server_card(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        record: &ServerRecord,
        selected: bool,
    ) {
        let width = area.width as usize;
        let bg = if selected {
            self.theme.surface_hi
        } else {
            self.theme.bg
        };
        let base = Style::default().bg(bg);
        let bar = if selected {
            Span::styled("▌", Style::default().fg(self.theme.accent_bright).bg(bg))
        } else {
            Span::styled(" ", base)
        };
        let marked = state.marked.contains(&record.id);
        let tick = if marked {
            Span::styled(
                " ◼",
                Style::default()
                    .fg(self.theme.ok)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            )
        } else if !state.marked.is_empty() {
            Span::styled(" ◻", Style::default().fg(self.theme.muted).bg(bg))
        } else {
            Span::styled("  ", base)
        };
        let health = self.health_of(state, record);
        let name_width = width.saturating_sub(7);
        let name = clip(&record.name, name_width);
        let name_fill = name_width.saturating_sub(width_of(&name));
        let line1 = Line::from(vec![
            bar.clone(),
            Span::styled(" ", base),
            self.health_dot(health).style(Style::default().bg(bg)),
            Span::styled(" ", base),
            Span::styled(
                format!("{name}{}", " ".repeat(name_fill)),
                Style::default()
                    .fg(if selected {
                        self.theme.accent_bright
                    } else {
                        self.theme.text
                    })
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            tick,
        ]);
        let pad_to = |text: String| {
            let shown = clip(&text, width.saturating_sub(4));
            let fill = width.saturating_sub(4 + width_of(&shown));
            format!("{shown}{}", " ".repeat(fill))
        };
        let line2 = Line::from(vec![
            bar.clone(),
            Span::styled("   ", base),
            Span::styled(
                pad_to(format!("{} · {}", record.host, record.os)),
                Style::default().fg(self.theme.muted).bg(bg),
            ),
        ]);
        let services: Vec<&str> = record.services.iter().map(short_name).collect();
        let line3 = Line::from(vec![
            bar.clone(),
            Span::styled("   ", base),
            Span::styled(
                pad_to(services.join(" · ")),
                Style::default().fg(self.theme.text).bg(bg),
            ),
        ]);
        let connected = state
            .usage
            .get(&record.id)
            .map(|(u, _)| u.devices_now().to_string());
        let history: Vec<u64> = state.history(&record.id).iter().map(|h| h.0).collect();
        let graph = sparkline(&history, 14.min(width.saturating_sub(18)));
        let label = match &connected {
            Some(n) => format!("{n} connected"),
            None => "not read yet".to_string(),
        };
        let fill = width.saturating_sub(4 + label.chars().count() + 1 + graph.chars().count());
        let line4 = Line::from(vec![
            bar,
            Span::styled("   ", base),
            Span::styled(
                label,
                Style::default()
                    .fg(if health == Health::Busy {
                        self.theme.ok
                    } else {
                        self.theme.muted
                    })
                    .bg(bg),
            ),
            Span::styled(" ".repeat(fill + 1), base),
            Span::styled(graph, Style::default().fg(self.theme.accent).bg(bg)),
        ]);
        frame.render_widget(Paragraph::new(vec![line1, line2, line3, line4]), area);
    }

    /// The pane beside the list: the highlighted server at a glance.
    fn draw_preview(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        record: &ServerRecord,
    ) {
        let inner = self.card(frame, area, &record.name, self.theme.border);
        let health = self.health_of(state, record);
        let (headline, color) = match (health, state.usage.get(&record.id)) {
            (Health::Busy, Some((u, _))) => (
                format!("{} connected right now", u.devices_now()),
                self.theme.ok,
            ),
            (Health::Quiet, _) => ("Nobody connected right now".to_string(), self.theme.muted),
            (Health::Trouble, _) => (
                state
                    .usage_error
                    .get(&record.id)
                    .cloned()
                    .unwrap_or_else(|| "Could not be read".into()),
                self.theme.err,
            ),
            _ => ("Reading…".to_string(), self.theme.muted),
        };
        let mut lines = vec![
            Line::from(vec![
                self.health_dot(health),
                Span::styled(
                    format!("  {headline}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            ]),
            self.dim(format!(
                "{}   {}   Zray {}",
                record.host,
                record.os,
                if record.zray_version == "local build" {
                    "(uploaded from this app)"
                } else {
                    &record.zray_version
                }
            )),
            Line::raw(""),
        ];
        let history = state.history(&record.id);
        let devices: Vec<u64> = history.iter().map(|h| h.0).collect();
        let totals: Vec<u64> = history.iter().map(|h| h.1).collect();
        let graph_width = (inner.width as usize).saturating_sub(12).min(48);
        lines.push(Line::from(vec![
            Span::styled("devices  ", Style::default().fg(self.theme.muted)),
            Span::styled(
                sparkline(&devices, graph_width),
                Style::default().fg(self.theme.ok),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("traffic  ", Style::default().fg(self.theme.muted)),
            Span::styled(
                sparkline(&rates(&totals), graph_width),
                Style::default().fg(self.theme.accent),
            ),
        ]));
        lines.push(Line::raw(""));
        lines.push(self.section("Services", inner.width as usize));
        for service in &record.services {
            let (port, users) = match service {
                Service::Reality(r) => (Some(r.port), r.users.len()),
                Service::Xhttp(x) => (Some(x.port), x.users.len()),
                Service::Zerov1(z) => (Some(z.port), z.users.len()),
                Service::MasterDns(_) => (None, 1),
            };
            lines.push(Line::from(vec![
                Span::styled("  ◆ ", Style::default().fg(self.theme.accent)),
                Span::styled(
                    service.title().to_string(),
                    Style::default()
                        .fg(self.theme.text)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    match port {
                        Some(p) => format!("   port {p}   {users} config(s)"),
                        None => "   UDP 53".to_string(),
                    },
                    Style::default().fg(self.theme.muted),
                ),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(self.dim("Enter  open this server"));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    /// The first thing someone sees, with nothing set up yet.
    fn draw_welcome(&self, frame: &mut Frame, area: Rect) {
        let box_area = centered(area, 86, 17, 1);
        let inner = self.card(frame, box_area, "Welcome", self.theme.border_focus);
        let pulse = self.effects.pulse_phase(2.2);
        let glow = lerp_color(self.theme.accent, self.theme.accent_bright, pulse);
        let mut lines = vec![
            Line::raw(""),
            Line::styled(
                "Run your own server in a minute",
                Style::default().fg(glow).add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(
                "Rent a small server (a VPS), then press  a  and type its address and password.",
            ),
            Line::raw(
                "Zray installs and starts everything for you, then shows the configs to use.",
            ),
            Line::raw(""),
        ];
        let mut button = vec![Span::raw("  ")];
        button.extend(self.button("+  Add a server", true, glow));
        button.push(Span::styled(
            "   or press  a",
            Style::default().fg(self.theme.muted),
        ));
        lines.push(Line::from(button));
        lines.push(Line::raw(""));
        lines.push(self.section("What you get", inner.width as usize));
        for (glyph, title, text) in [
            (
                "⚡",
                "Quick set-up",
                "no commands to type: Zray logs in and does it all",
            ),
            (
                "◉",
                "Live counts",
                "how many devices are connected, updating while you watch",
            ),
            ("◆", "Your keys", "the password is used once and never kept"),
        ] {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {glyph}  "),
                    Style::default().fg(self.theme.accent),
                ),
                Span::styled(
                    format!("{title:<14}"),
                    Style::default()
                        .fg(self.theme.text)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(text.to_string(), Style::default().fg(self.theme.muted)),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(self.dim("Only counts are shown: no addresses or anything that points at a person is ever shown or stored."));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    // ----------------------------------------------------------------- busy

    fn draw_busy(&self, frame: &mut Frame, area: Rect, text: &str) {
        let width = area.width.min(54);
        let height = 5.min(area.height);
        let rect = Rect {
            x: area.x + (area.width - width) / 2,
            y: area.y + area.height.saturating_sub(height) / 2,
            width,
            height,
        };
        let inner = self.card(frame, rect, "Please wait", self.theme.border_focus);
        let frame_glyph = spinner(self.effects.current_time());
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!("{frame_glyph}  "),
                    Style::default().fg(self.theme.accent_bright),
                ),
                Span::raw(text.to_string()),
            ])),
            inner,
        );
    }

    fn draw_centered_note(&self, frame: &mut Frame, area: Rect, text: &str, hint: &str) {
        let rect = Rect {
            x: area.x,
            y: area.y + area.height / 3,
            width: area.width,
            height: 3.min(area.height),
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(text.to_string()),
                self.dim(hint.to_string()),
            ])
            .alignment(Alignment::Center),
            rect,
        );
    }

    // ----------------------------------------------------------------- form

    fn draw_form(&self, frame: &mut Frame, area: Rect, form: &Form) {
        let body = self.stepper_and_body(frame, area, form.masterdns, 0);
        let wide = body.width >= 108;
        let (main, side) = if wide {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(60), Constraint::Length(36)])
                .spacing(2)
                .split(body);
            (cols[0], Some(cols[1]))
        } else {
            (body, None)
        };
        let width = main.width as usize;
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut focus_row = 0usize;
        let label_width = 15usize;
        let box_width = width.saturating_sub(label_width + 4).clamp(16, 52);

        // One labelled text box on a row of its own.
        let field = |lines: &mut Vec<Line<'static>>,
                     focus_row: &mut usize,
                     label: &str,
                     value: &str,
                     masked: bool,
                     placeholder: &str,
                     which: Field| {
            let focused = form.focus == which;
            if focused {
                *focus_row = lines.len();
            }
            let mut spans = vec![
                Span::styled(
                    if focused { "▌ " } else { "  " },
                    Style::default().fg(self.theme.accent_bright),
                ),
                Span::styled(
                    format!("{label:<label_width$}"),
                    Style::default().fg(if focused {
                        self.theme.accent_bright
                    } else {
                        self.theme.muted
                    }),
                ),
            ];
            spans.extend(input_spans(
                &InputView {
                    text: value,
                    masked,
                    focused,
                    caret: if focused {
                        form.caret
                    } else {
                        Caret::default()
                    },
                    width: box_width,
                    placeholder,
                },
                &self.input_colors(focused),
            ));
            lines.push(Line::from(spans));
        };

        lines.push(self.section("Your server", width));
        field(
            &mut lines,
            &mut focus_row,
            "Name",
            &form.name,
            false,
            "My server",
            Field::Name,
        );
        field(
            &mut lines,
            &mut focus_row,
            "Server address",
            &form.address,
            false,
            "203.0.113.7",
            Field::Address,
        );
        field(
            &mut lines,
            &mut focus_row,
            "SSH port",
            &form.port,
            false,
            "22",
            Field::SshPort,
        );
        lines.push(Line::raw(""));
        lines.push(self.section("Log in", width));
        field(
            &mut lines,
            &mut focus_row,
            "Login user",
            &form.user,
            false,
            "root",
            Field::User,
        );
        field(
            &mut lines,
            &mut focus_row,
            if form.key_file.trim().is_empty() {
                "Password"
            } else {
                "Key passphrase"
            },
            &form.password,
            !form.show_password,
            "",
            Field::Password,
        );
        field(
            &mut lines,
            &mut focus_row,
            "SSH key file",
            &form.key_file,
            false,
            "optional: ~/.ssh/id_ed25519",
            Field::KeyFile,
        );
        lines.push(
            self.dim("                 Replaces the password. Pick the private key, not the .pub."),
        );
        lines.push(Line::raw(""));
        lines.push(self.section("What to install", width));
        lines.push(self.dim("  Space ticks a tile.  Ctrl+A ticks them all."));

        // The tiles: two columns when there is room, one line each otherwise.
        let tiles: [(&str, &str, bool, Field); 4] = [
            (
                "VLESS + REALITY",
                "fast, looks like a normal website",
                form.reality,
                Field::Reality,
            ),
            (
                "VLESS + XHTTP",
                "REALITY too, another traffic shape",
                form.xhttp,
                Field::Xhttp,
            ),
            (
                "ZeroV1 + REALITY",
                "our own protocol, REALITY too",
                form.zerov1,
                Field::Zerov1,
            ),
            (
                "MasterDnsVPN",
                "works over DNS only, needs a domain",
                form.masterdns,
                Field::MasterDns,
            ),
        ];
        let pulse = self.effects.pulse_phase(3.2);
        let two_columns = width >= 76;
        if two_columns {
            let tile_width = (width.saturating_sub(2) / 2).saturating_sub(1).max(24);
            for pair in tiles.chunks(2) {
                let rows = pair
                    .iter()
                    .map(|(title, text, on, which)| {
                        self.tile_lines(title, text, *on, form.focus == *which, tile_width, pulse)
                    })
                    .collect::<Vec<_>>();
                if pair.iter().any(|t| form.focus == t.3) {
                    focus_row = lines.len() + 1;
                }
                for row in 0..4 {
                    let mut spans = vec![Span::raw("  ")];
                    for (n, tile) in rows.iter().enumerate() {
                        if n > 0 {
                            spans.push(Span::raw(" "));
                        }
                        spans.extend(tile[row].clone());
                    }
                    lines.push(Line::from(spans));
                }
            }
        } else {
            for (title, text, on, which) in tiles {
                let focused = form.focus == which;
                if focused {
                    focus_row = lines.len();
                }
                lines.push(Line::from(vec![
                    Span::styled(
                        if focused { "▌ " } else { "  " },
                        Style::default().fg(self.theme.accent_bright),
                    ),
                    Span::styled(
                        if on { "◉ " } else { "○ " },
                        Style::default().fg(if on { self.theme.ok } else { self.theme.muted }),
                    ),
                    Span::styled(
                        format!("{title:<18}"),
                        Style::default()
                            .fg(if focused {
                                self.theme.accent_bright
                            } else {
                                self.theme.text
                            })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        clip(text, width.saturating_sub(24)),
                        Style::default().fg(self.theme.muted),
                    ),
                ]));
            }
        }
        if form.masterdns {
            lines.push(Line::raw(""));
            field(
                &mut lines,
                &mut focus_row,
                "Tunnel domain",
                &form.domain,
                false,
                "t.example.com",
                Field::Domain,
            );
            lines.push(
                self.dim(
                    "                 A subdomain you own. The next screens show what to set.",
                ),
            );
        }
        lines.push(Line::raw(""));
        if let Some(error) = &form.error {
            lines.push(Line::from(vec![
                Span::styled(" ✖ ", Style::default().fg(self.theme.bg).bg(self.theme.err)),
                Span::styled(format!(" {error}"), Style::default().fg(self.theme.err)),
            ]));
            lines.push(Line::raw(""));
        }
        let mut buttons = vec![Span::raw("  ")];
        let connect_focused = form.focus == Field::Connect;
        let cancel_focused = form.focus == Field::Cancel;
        if connect_focused || cancel_focused {
            focus_row = lines.len();
        }
        buttons.extend(self.button("Connect and install", connect_focused, self.theme.ok));
        buttons.push(Span::raw("  "));
        buttons.extend(self.button("Cancel", cancel_focused, self.theme.muted));
        lines.push(Line::from(buttons));

        // Scroll so the focused row is always on screen.
        let visible = main.height as usize;
        let offset = if focus_row + 3 >= visible {
            (focus_row + 4).saturating_sub(visible)
        } else {
            0
        }
        .min(lines.len().saturating_sub(visible));
        frame.render_widget(Paragraph::new(lines).scroll((offset as u16, 0)), main);

        if let Some(side) = side {
            let inner = self.card(frame, side, "Good to know", self.theme.border);
            let tips = vec![
                self.strong("Safe by design"),
                Line::raw("The password logs in once. Zray then puts its own key on the server and forgets the password."),
                Line::raw(""),
                self.strong("Next you will see"),
                Line::raw("The server's fingerprint, to compare with your hosting panel. Nothing secret is sent before you agree."),
                Line::raw(""),
                self.strong("Which to pick"),
                Line::raw("REALITY works for most people. Add ZeroV1 or XHTTP for another shape of traffic on its own port, or MasterDNS as a last resort."),
                Line::raw(""),
                self.dim("Tip: Ctrl+A in a box selects its text; typing replaces it."),
            ];
            frame.render_widget(Paragraph::new(tips).wrap(Wrap { trim: false }), inner);
        }
    }

    /// One service tile, four rows tall: a box with a tick, a title and a line
    /// of what it is. The focused tile's border glows.
    fn tile_lines(
        &self,
        title: &str,
        text: &str,
        on: bool,
        focused: bool,
        width: usize,
        pulse: f64,
    ) -> Vec<Vec<Span<'static>>> {
        let border = if focused {
            lerp_color(self.theme.accent, self.theme.accent_bright, pulse)
        } else if on {
            self.theme.ok
        } else {
            self.theme.border
        };
        let edge = Style::default().fg(border);
        let inside = width.saturating_sub(2);
        let row = |content: Vec<Span<'static>>| {
            let used: usize = content.iter().map(|s| width_of(&s.content)).sum();
            let mut spans = vec![Span::styled("│", edge)];
            spans.extend(content);
            spans.push(Span::raw(" ".repeat(inside.saturating_sub(used))));
            spans.push(Span::styled("│", edge));
            spans
        };
        vec![
            vec![Span::styled(format!("╭{}╮", "─".repeat(inside)), edge)],
            row(vec![
                Span::styled(
                    if on { " ◉ " } else { " ○ " },
                    Style::default().fg(if on { self.theme.ok } else { self.theme.muted }),
                ),
                Span::styled(
                    clip(title, inside.saturating_sub(4)),
                    Style::default()
                        .fg(if focused {
                            self.theme.accent_bright
                        } else {
                            self.theme.text
                        })
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            row(vec![Span::styled(
                format!("   {}", clip(text, inside.saturating_sub(4))),
                Style::default().fg(self.theme.muted),
            )]),
            vec![Span::styled(format!("╰{}╯", "─".repeat(inside)), edge)],
        ]
    }

    // ------------------------------------------------------------- identity

    fn draw_identity(&self, frame: &mut Frame, area: Rect, address: &str, fingerprint: &str) {
        let width = area.width.min(88);
        let lines = vec![
            Line::raw(format!("Connected to {address}. Its identity is:")),
            Line::raw(""),
            Line::styled(
                format!("  {fingerprint}"),
                Style::default()
                    .fg(self.theme.accent_bright)
                    .bg(self.theme.surface_hi)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw("Compare it with the one in your hosting panel (many show it in the server's page or console)."),
            Line::raw("If it is the same, press Enter. If it is different or you cannot check, press Esc: someone may be between you and the server."),
            Line::raw(""),
            self.dim("Nothing secret has been sent yet."),
            Line::raw(""),
            {
                let mut spans = vec![Span::raw("  ")];
                spans.extend(self.button("Yes, it matches", true, self.theme.ok));
                spans.push(Span::raw("  "));
                spans.extend(self.button("No, go back", false, self.theme.muted));
                Line::from(spans)
            },
        ];
        let height = wrapped_height(&lines, width.saturating_sub(4)) + 2;
        let rect = centered(area, width, height, 1);
        let inner = self.card(frame, rect, "Is this your server?", self.theme.border_focus);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    // ------------------------------------------------------------------ dns

    fn draw_dns(
        &self,
        frame: &mut Frame,
        area: Rect,
        records: &[zero_provision::guide::DnsRecord],
        status: &DnsStatus,
        address: &str,
        domain: &str,
    ) {
        let inner = self.card(
            frame,
            area,
            "Point your domain at the server",
            self.theme.border_focus,
        );
        let mut lines = vec![
            self.strong("Do this once in Cloudflare (about two minutes)"),
            Line::raw("1. Open dash.cloudflare.com, pick your domain, then  DNS  >  Records  >  Add record."),
            Line::raw("2. Add these two records. Keep the cloud GREY (\"DNS only\"), never orange:"),
            Line::raw(""),
        ];
        for (i, r) in records.iter().enumerate() {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {} ", i + 1),
                    Style::default().fg(self.theme.bg).bg(self.theme.accent),
                ),
                Span::styled(
                    format!(
                        "  Type {:<3} Name {:<10} {}",
                        r.kind,
                        r.name,
                        if r.kind == "NS" {
                            "Nameserver"
                        } else {
                            "Value"
                        }
                    ),
                    Style::default().fg(self.theme.text),
                ),
                Span::styled(
                    format!(" {}", r.value),
                    Style::default().fg(self.theme.accent_bright),
                ),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(self.dim(format!(
            "Keys: 1 copy first name, 2 its value, 3 second name, 4 its value.   Domain: {domain}"
        )));
        if address.parse::<std::net::IpAddr>().is_err() {
            lines.push(Line::styled(
                "You typed a name, not an IP: use the server's IP address as the value of the first record.",
                Style::default().fg(self.theme.warn),
            ));
        }
        lines.push(Line::raw("3. Press  c  to check. It can take a few minutes to spread; you can also install now and test later."));
        lines.push(Line::raw(""));
        let (badge, text, color) = match status {
            DnsStatus::NotChecked => ("  ?  ".to_string(), "Not checked yet.", self.theme.muted),
            DnsStatus::Checking => (
                format!(" {} ", spinner(self.effects.current_time())),
                "Checking…",
                self.theme.info,
            ),
            DnsStatus::Right => (
                "  ✓  ".to_string(),
                "The record points at your server. Good.",
                self.theme.ok,
            ),
            DnsStatus::Wrong => (
                "  !  ".to_string(),
                "The name resolves, but not to this server. Check the first record's value.",
                self.theme.warn,
            ),
            DnsStatus::Unknown => (
                "  …  ".to_string(),
                "Not visible yet. If you just added it, wait a few minutes and check again.",
                self.theme.warn,
            ),
        };
        lines.push(Line::from(vec![
            Span::styled(badge, Style::default().fg(self.theme.bg).bg(color)),
            Span::styled(format!("  {text}"), Style::default().fg(color)),
        ]));
        lines.push(Line::raw(""));
        lines.push(self.dim("Not on Cloudflare? Any registrar works: add the same two records."));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    // ------------------------------------------------------------- progress

    fn draw_progress(&self, frame: &mut Frame, area: Rect, view: &ProgressView) {
        let width = area.width.min(84);
        let title = if view.failed.is_some() {
            "It stopped"
        } else {
            "Setting things up"
        };
        let color = if view.failed.is_some() {
            self.theme.err
        } else {
            self.theme.border_focus
        };
        let time = self.effects.current_time();
        let done = view
            .steps
            .iter()
            .filter(|(_, _, s)| *s == StepState::Done)
            .count();
        let fraction = if view.of == 0 {
            0.0
        } else {
            done as f64 / view.of as f64
        };
        let bar_width = (width as usize).saturating_sub(16).min(60);
        // The bright patch drifts along the bar while work goes on.
        let glow = if view.failed.is_none() && self.effects.animations_enabled() {
            (time / 60.0).fract()
        } else {
            0.0
        };
        let mut bar = vec![Span::raw("  ")];
        bar.extend(progress_bar(
            fraction,
            bar_width,
            if view.failed.is_some() {
                self.theme.err
            } else {
                self.theme.accent
            },
            self.theme.accent_bright,
            self.theme.border,
            glow,
        ));
        bar.push(Span::styled(
            format!("  {:>3}%", (fraction * 100.0).round() as u32),
            Style::default().fg(self.theme.muted),
        ));
        let mut lines = vec![Line::from(bar), Line::raw("")];
        for (step, preset, state) in &view.steps {
            let (mark, color) = match state {
                StepState::Done => ("✓".to_string(), self.theme.ok),
                StepState::Running if view.failed.is_some() => ("✖".to_string(), self.theme.err),
                StepState::Running => (spinner(time).to_string(), self.theme.accent_bright),
                StepState::Waiting => ("○".to_string(), self.theme.muted),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {mark}  "), Style::default().fg(color)),
                Span::styled(
                    step_name(*step, *preset),
                    Style::default().fg(if *state == StepState::Waiting {
                        self.theme.muted
                    } else {
                        self.theme.text
                    }),
                ),
            ]));
        }
        if let Some(failed) = &view.failed {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "It stopped:",
                Style::default()
                    .fg(self.theme.err)
                    .add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::styled(
                failed.clone(),
                Style::default().fg(self.theme.err),
            ));
            lines.push(Line::raw(""));
            lines.push(
                self.dim("Nothing half-finished is left running. Fix the cause and try again."),
            );
        } else if !view.detail.is_empty() {
            lines.push(Line::raw(""));
            lines.push(self.dim(view.detail.clone()));
        }
        let height = wrapped_height(&lines, width.saturating_sub(4)) + 2;
        let rect = centered(area, width, height, 1);
        let inner = self.card(frame, rect, title, color);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    // --------------------------------------------------------------- result

    #[allow(clippy::too_many_arguments)]
    fn draw_result(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        record: &ServerRecord,
        notes: &[Note],
        shown: usize,
        settled: f64,
    ) {
        let note_rows = notes.len() as u16 * 2;
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(8),
                Constraint::Length(note_rows.min(area.height / 3)),
            ])
            .split(area);
        let tick = lerp_color(self.theme.muted, self.theme.ok, settled);
        frame.render_widget(
            Paragraph::new(vec![Line::from(vec![
                Span::styled(
                    "✓  ",
                    Style::default().fg(tick).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} ({}) is running.", record.name, record.host),
                    Style::default()
                        .fg(self.theme.ok)
                        .add_modifier(Modifier::BOLD),
                ),
            ])]),
            rows[0],
        );
        self.draw_configs(frame, rows[1], state, record, shown);
        let note_lines: Vec<Line<'static>> = notes
            .iter()
            .flat_map(|note| {
                [
                    Line::from(vec![
                        Span::styled(
                            " ! ",
                            Style::default().fg(self.theme.bg).bg(self.theme.warn),
                        ),
                        Span::styled(
                            format!(" {}", note_text(note)),
                            Style::default().fg(self.theme.warn),
                        ),
                    ]),
                    Line::raw(""),
                ]
            })
            .collect();
        frame.render_widget(
            Paragraph::new(note_lines).wrap(Wrap { trim: false }),
            rows[2],
        );
    }

    // --------------------------------------------------------------- configs

    /// The configs of a server as a tabbed card: a tab for each, the link of
    /// the one in front, and its QR code. With every config selected (Ctrl+A)
    /// all the links are listed, lit, ready to copy.
    fn draw_configs(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        record: &ServerRecord,
        shown: usize,
    ) {
        let configs = record.client_configs();
        let title = if state.all_configs {
            format!("All {} configs selected", configs.len())
        } else {
            format!("Config {} of {}", shown + 1, configs.len().max(1))
        };
        let border = if state.all_configs {
            self.theme.accent_bright
        } else {
            self.theme.border
        };
        let inner = self.card(frame, area, &title, border);
        if configs.is_empty() {
            frame.render_widget(Paragraph::new(self.dim("No configs yet.")), inner);
            return;
        }
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(2)])
            .split(inner);

        // The tab strip, scrolled so the open tab is always in view.
        let tab_text = |i: usize| {
            let config = &configs[i];
            format!(" {} · {} ", config.user, config.service)
        };
        let shown = shown.min(configs.len() - 1);
        let mut start = 0usize;
        let budget = rows[0].width as usize;
        while start < shown
            && (start..=shown)
                .map(|i| tab_text(i).chars().count() + 1)
                .sum::<usize>()
                > budget
        {
            start += 1;
        }
        let mut tabs: Vec<Span<'static>> = Vec::new();
        let mut used = 0usize;
        for i in start..configs.len() {
            let text = tab_text(i);
            used += text.chars().count() + 1;
            if used > budget {
                break;
            }
            let style = if state.all_configs {
                Style::default()
                    .fg(self.theme.bg)
                    .bg(self.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else if i == shown {
                Style::default()
                    .fg(self.theme.bg)
                    .bg(self.theme.accent_bright)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(self.theme.muted)
                    .bg(self.theme.surface_hi)
            };
            tabs.push(Span::styled(text, style));
            tabs.push(Span::raw(" "));
        }
        frame.render_widget(Paragraph::new(Line::from(tabs)), rows[0]);

        let body = rows[1];
        let code = self.current_qr(state);
        // The big code takes the whole body, so it is large enough to scan.
        if let Some(c) = code.as_ref().filter(|_| state.show_qr) {
            if body.width < c.width_cells as u16 || body.height < c.height_cells as u16 {
                frame.render_widget(
                    Paragraph::new("The window is too small for the code. Make it bigger, or copy the link with c.")
                        .wrap(Wrap { trim: false }),
                    body,
                );
            } else {
                let w = c.width_cells as u16;
                let at = Rect {
                    x: body.x + body.width.saturating_sub(w) / 2,
                    y: body.y,
                    width: w,
                    height: c.height_cells as u16,
                };
                self.draw_qr(frame, at, c);
            }
            return;
        }
        let link_length = configs
            .get(shown)
            .and_then(|c| c.link.as_ref())
            .map_or(0, |l| l.chars().count());
        let (text_area, qr_area) = match &code {
            // Beside the link when there is the width for both…
            Some(c)
                if !state.all_configs
                    && body.width >= c.width_cells as u16 + 40
                    && body.height >= c.height_cells as u16 =>
            {
                let cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Min(30),
                        Constraint::Length(c.width_cells as u16 + 2),
                    ])
                    .split(body);
                (cols[0], Some(cols[1]))
            }
            // …under it when there is the height.
            Some(c) if !state.all_configs => {
                let text_rows = (link_length as u16).div_ceil(body.width.max(1)) + 4;
                if body.height >= text_rows + c.height_cells as u16 {
                    let rows = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(text_rows),
                            Constraint::Min(c.height_cells as u16),
                        ])
                        .split(body);
                    (rows[0], Some(rows[1]))
                } else {
                    (body, None)
                }
            }
            _ => (body, None),
        };
        let mut lines: Vec<Line<'static>> = Vec::new();
        if state.all_configs {
            let lit = Style::default().fg(self.theme.bg).bg(self.theme.accent);
            for (i, config) in configs.iter().enumerate() {
                lines.push(Line::styled(
                    format!("{} · {}", config.user, config.service),
                    Style::default().fg(self.theme.muted),
                ));
                let text = config
                    .link
                    .clone()
                    .or_else(|| config.files.first().map(|f| format!("(file) {}", f.name)))
                    .unwrap_or_default();
                lines.push(Line::styled(text, lit));
                if i + 1 < configs.len() {
                    lines.push(Line::raw(""));
                }
            }
            lines.push(Line::raw(""));
            lines.push(self.dim("Press c to copy all of them, one per line. Esc to clear."));
        } else if let Some(config) = configs.get(shown) {
            if let Some(link) = &config.link {
                lines.push(Line::styled(
                    link.clone(),
                    Style::default()
                        .fg(self.theme.text)
                        .bg(self.theme.surface_hi),
                ));
                lines.push(Line::raw(""));
                lines.push(
                    self.dim("Scan the code with the Zray app, or press c to copy the link."),
                );
            }
            if !config.files.is_empty() {
                let names: Vec<&str> = config.files.iter().map(|f| f.name.as_str()).collect();
                lines.push(Line::raw(format!("Files: {}", names.join(", "))));
                lines.push(
                    self.dim("Press s to save them, then give them to the MasterDNS client."),
                );
            }
            if crate::servers::copy_text(record, shown).is_none() {
                lines.push(self.dim("This config has no link."));
            }
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), text_area);
        if let (Some(code), Some(area)) = (&code, qr_area) {
            self.draw_qr(frame, area, code);
        }
    }

    fn draw_qr(&self, frame: &mut Frame, area: Rect, code: &qr::RenderedQr) {
        let lines: Vec<Line> = code
            .lines
            .iter()
            .map(|l| Line::styled(l.as_str(), Style::default().fg(self.theme.text)))
            .collect();
        frame.render_widget(Clear, area);
        frame.render_widget(Paragraph::new(lines), area);
    }

    /// The QR of the config being shown, when it has a link.
    fn current_qr(&self, state: &ServersState) -> Option<qr::RenderedQr> {
        let (record, shown) = match &state.screen {
            Screen::Result { record, shown, .. } => (&**record, *shown),
            Screen::Server { id, shown } => (state.record(id)?, *shown),
            _ => return None,
        };
        let link = record.client_configs().get(shown)?.link.clone()?;
        qr::render(&link, QrStyle::HalfBlock).ok()
    }

    // --------------------------------------------------------------- server

    fn draw_server(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        record: &ServerRecord,
        shown: usize,
    ) {
        // The big code replaces everything else, as before.
        if state.show_qr {
            self.draw_configs(frame, area, state, record, shown);
            return;
        }
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(8)])
            .split(area);
        let health = self.health_of(state, record);
        let (pill, pill_color) = match health {
            Health::Busy => (" IN USE ", self.theme.ok),
            Health::Quiet => (" ONLINE ", self.theme.ok),
            Health::Trouble => (" CAN'T READ ", self.theme.err),
            Health::Unknown => (" READING ", self.theme.muted),
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    self.health_dot(health),
                    Span::styled(
                        format!("  {}   {}", record.name, record.host),
                        Style::default()
                            .fg(self.theme.accent_bright)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("   "),
                    Span::styled(
                        pill,
                        Style::default()
                            .fg(self.theme.bg)
                            .bg(pill_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                self.dim(format!(
                    "{}   Zray server {}",
                    record.os,
                    if record.zray_version == "local build" {
                        "(uploaded from this app)"
                    } else {
                        &record.zray_version
                    }
                )),
            ]),
            rows[0],
        );
        let wide = rows[1].width >= 100;
        if wide {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .spacing(1)
                .split(rows[1]);
            self.draw_usage(frame, cols[0], state, record);
            self.draw_configs(frame, cols[1], state, record, shown);
        } else {
            let stack = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(rows[1]);
            self.draw_usage(frame, stack[0], state, record);
            self.draw_configs(frame, stack[1], state, record, shown);
        }
    }

    /// Live use: a graph of devices and traffic over the last minutes, then
    /// each service's own figures.
    fn draw_usage(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        record: &ServerRecord,
    ) {
        let inner = self.card(frame, area, "Live use", self.theme.border);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let Some((usage, at)) = state.usage.get(&record.id) else {
            lines.push(match state.usage_error.get(&record.id) {
                Some(error) => Line::styled(error.clone(), Style::default().fg(self.theme.warn)),
                None => Line::from(vec![
                    Span::styled(
                        format!("{}  ", spinner(self.effects.current_time())),
                        Style::default().fg(self.theme.accent_bright),
                    ),
                    Span::styled("Reading…", Style::default().fg(self.theme.muted)),
                ]),
            });
            frame.render_widget(Paragraph::new(lines), inner);
            return;
        };
        let history = state.history(&record.id);
        let devices: Vec<u64> = history.iter().map(|h| h.0).collect();
        let totals: Vec<u64> = history.iter().map(|h| h.1).collect();
        let graph_width = (inner.width as usize).saturating_sub(24).clamp(8, 40);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>3}", usage.devices_now()),
                Style::default()
                    .fg(if usage.devices_now() > 0 {
                        self.theme.ok
                    } else {
                        self.theme.muted
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" connected  ", Style::default().fg(self.theme.muted)),
            Span::styled(
                sparkline(&devices, graph_width),
                Style::default().fg(self.theme.ok),
            ),
        ]));
        let down: u64 = usage.inbounds.iter().map(|i| i.downlink).sum();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>9}", human_bytes(down)),
                Style::default()
                    .fg(self.theme.text)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" down  ", Style::default().fg(self.theme.muted)),
            Span::styled(
                sparkline(&rates(&totals), graph_width),
                Style::default().fg(self.theme.accent),
            ),
        ]));
        lines.push(Line::raw(""));
        for service in &record.services {
            let row: Option<&InboundUsage> = usage.inbounds.iter().find(|i| i.tag == service.tag());
            let (now, recent, sessions, traffic) = match row {
                Some(r) => (
                    r.devices_now.to_string(),
                    r.devices_recent.to_string(),
                    r.sessions.to_string(),
                    format!(
                        "up {}  down {}",
                        human_bytes(r.uplink),
                        human_bytes(r.downlink)
                    ),
                ),
                None => ("0".into(), "0".into(), "0".into(), String::new()),
            };
            lines.push(Line::from(vec![
                Span::styled("◆ ", Style::default().fg(self.theme.accent)),
                Span::styled(
                    service.title().to_string(),
                    Style::default()
                        .fg(self.theme.text)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::raw(format!(
                "  connected now {now}   in the last {} min {recent}",
                usage.window_secs / 60
            )));
            lines.push(self.dim(format!("  open sessions {sessions}")));
            if !traffic.is_empty() {
                lines.push(self.dim(format!("  since start: {traffic}")));
            } else if matches!(service, Service::MasterDns(_)) {
                lines.push(self.dim(
                    "  counted from the server's log: up to 5 minutes behind, no traffic figure.",
                ));
            }
        }
        if let Some(error) = state.usage_error.get(&record.id) {
            lines.push(Line::styled(
                error.clone(),
                Style::default().fg(self.theme.warn),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(self.dim(format!("updated {} s ago.", at.elapsed().as_secs())));
        lines.push(self.dim("Counts only: no addresses are kept or sent."));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    // -------------------------------------------------------------- confirm

    fn draw_confirm(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &ServersState,
        id: &str,
        typed: &str,
    ) {
        let name = state.record(id).map_or("this server", |r| r.name.as_str());
        let width = area.width.min(86);
        let matches = typed
            .trim()
            .eq_ignore_ascii_case(crate::servers::CONFIRM_WORD);
        let mut input = vec![
            Span::styled("  Type  ", Style::default().fg(self.theme.text)),
            Span::styled(
                crate::servers::CONFIRM_WORD,
                Style::default()
                    .fg(self.theme.warn)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  and press Enter:  ", Style::default().fg(self.theme.text)),
        ];
        input.extend(input_spans(
            &InputView {
                text: typed,
                masked: false,
                focused: true,
                caret: state.confirm_caret,
                width: 20,
                placeholder: "",
            },
            &self.input_colors(true),
        ));
        input.push(Span::styled(
            if matches { "  ✓" } else { "" },
            Style::default()
                .fg(self.theme.ok)
                .add_modifier(Modifier::BOLD),
        ));
        let lines = vec![
            Line::styled(
                format!("This takes Zray off {name}."),
                Style::default()
                    .fg(self.theme.warn)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::raw("It stops and deletes the server program and its settings, closes the"),
            Line::raw("ports it opened, and removes this app's key from the server."),
            Line::raw(
                "Everything else on the server stays. Configs you gave to people stop working.",
            ),
            Line::raw(""),
            Line::from(input),
            Line::raw(""),
            {
                let mut spans = vec![Span::raw("  ")];
                spans.extend(self.button("Remove everything", matches, self.theme.err));
                spans.push(Span::raw("  "));
                spans.extend(self.button("Cancel  (Esc)", false, self.theme.muted));
                Line::from(spans)
            },
        ];
        let height = wrapped_height(&lines, width.saturating_sub(4)) + 2;
        let rect = centered(area, width, height, area.height.saturating_sub(height) / 3);
        let inner = self.card(frame, rect, "Remove everything?", self.theme.err);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// The rows `lines` take when wrapped to `width` columns.
fn wrapped_height(lines: &[Line], width: u16) -> u16 {
    let width = width.max(1) as usize;
    lines
        .iter()
        .map(|line| {
            width_of(
                &line
                    .spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>(),
            )
            .div_ceil(width)
            .max(1)
        })
        .sum::<usize>() as u16
}

/// A card `width` by `height` (clamped to `area`), centred across `area` and
/// starting `top` rows down.
fn centered(area: Rect, width: u16, height: u16, top: u16) -> Rect {
    let width = width.min(area.width);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + top.min(area.height.saturating_sub(1)),
        width,
        height: height.min(area.height.saturating_sub(top)),
    }
}

/// `area` shrunk by `x` columns on each side and `y` rows top and bottom.
fn inset(area: Rect, x: u16, y: u16) -> Rect {
    Rect {
        x: area.x + x.min(area.width / 2),
        y: area.y + y.min(area.height / 2),
        width: area.width.saturating_sub(x * 2),
        height: area.height.saturating_sub(y * 2),
    }
}
