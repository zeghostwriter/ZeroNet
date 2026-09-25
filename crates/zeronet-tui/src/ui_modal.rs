//! Dialog rendering.
//!
//! Every dialog is drawn the same way: clear its rectangle, draw a rounded
//! panel, fill in the body, then lay the opening ember animation over the
//! border. The caller has already dimmed the screen behind it and marked the
//! modal hit layer, so nothing registered here can be clicked *through* —
//! and nothing registered before it can be clicked at all.

use crate::interaction::ComponentId;
use crate::manual_profile::{FLOWS, PROTOCOLS, SECURITIES, TRANSPORTS};
use crate::modal::ModalState;
use crate::qr::RenderedQr;
use crate::ui::{centered_rect, truncate, UiRenderer};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

/// The typed value of a number dialog, plus whether it is all selected.
struct NumberField<'a> {
    buffer: &'a str,
    select_all: bool,
}

/// Label padding plus the value's `[ ... ]` chrome in a manual field.
const MANUAL_FIELD_CHROME_WIDTH: usize = 19;

impl UiRenderer<'_> {
    /// Where a dialog sits when fully open, and how it is titled.
    ///
    /// Shared by the renderer and by the hit-region registration, so the
    /// clickable surface can never drift from the drawn panel.
    pub(crate) fn modal_layout(&self, area: Rect) -> (Rect, &'static str) {
        match self.modal_state {
            ModalState::None => (Rect::default(), ""),
            ModalState::TextInput { .. } => (centered_rect(65, 45, area), "TEXT"),
            ModalState::NumberEdit { .. } => (centered_rect(52, 34, area), "NUMBER"),
            ModalState::AshesWarning { .. } => (centered_rect(58, 30, area), "WARNING"),
            ModalState::QuitConfirmation { .. } => (centered_rect(60, 28, area), "QUIT"),
            ModalState::ManualProfile { .. } => (centered_rect(78, 84, area), "FORM"),
            ModalState::Confirm { .. } => (centered_rect(62, 32, area), "CONFIRM"),
            ModalState::ShareConfig { code, .. } => (
                share_dialog_rect(area, code.width_cells as u16, code.height_cells as u16),
                "SHARE",
            ),
            ModalState::SudoPassword { .. } => (centered_rect(64, 46, area), "PASSWORD"),
            ModalState::Help { .. } => (centered_rect(74, 86, area), "HELP"),
            ModalState::ImageView { .. } => (centered_rect(70, 80, area), "IMAGE"),
            ModalState::Update { release, .. } => {
                (update_dialog_rect(area, release.notes.len()), "UPDATE")
            }
        }
    }

    /// The rectangle a click must land in to count as "inside the dialog".
    pub(crate) fn modal_target_rect(&self, area: Rect) -> Rect {
        self.modal_layout(area).0
    }

    pub(crate) fn render_modal(&mut self, frame: &mut Frame, area: Rect) {
        if !self.modal_state.is_active() {
            return;
        }
        let modal_area = self.modal_target_rect(area);
        let title: &str = match self.modal_state {
            ModalState::TextInput { title, .. }
            | ModalState::NumberEdit { title, .. }
            | ModalState::AshesWarning { title, .. }
            | ModalState::Confirm { title, .. }
            | ModalState::ImageView { title, .. } => title.as_str(),
            ModalState::QuitConfirmation { .. } => "EXIT CONFIRMATION",
            ModalState::ManualProfile { .. } => "MANUAL NODE CREATOR",
            ModalState::ShareConfig { .. } => "SHARE CONFIG",
            ModalState::SudoPassword { .. } => "ADMINISTRATOR PASSWORD",
            ModalState::Help { .. } => "KEYBOARD REFERENCE",
            ModalState::Update { .. } => "UPDATE",
            ModalState::None => return,
        };
        let accent = match self.modal_state {
            ModalState::TextInput { .. } => self.effects.amber_glow(),
            ModalState::AshesWarning { .. } => self.theme.err,
            ModalState::SudoPassword { error, .. } => {
                if error.is_some() {
                    self.theme.err
                } else {
                    self.theme.warn
                }
            }
            ModalState::Confirm { .. } => self.theme.warn,
            ModalState::Update { phase, .. } => match phase {
                crate::modal::UpdatePhase::Installed => self.theme.ok,
                crate::modal::UpdatePhase::Failed(_) => self.theme.err,
                _ => self.theme.accent_bright,
            },
            ModalState::QuitConfirmation { .. } | ModalState::Help { .. } => self.theme.accent,
            _ => self.theme.accent_bright,
        };

        // The animator owns the geometry: `modal_area` is where the dialog
        // lives when fully open, and this is where it is *this frame*.
        let tick = self.effects.current_tick();
        let drawn_area = self.modal_anim.rect(modal_area, tick);
        if drawn_area.width == 0 || drawn_area.height == 0 {
            return;
        }

        // A backdrop click on a dialog holding typed input flashes the border
        // instead of discarding the input.
        let nudge = self.modal_anim.nudge_intensity(tick);
        let accent = if nudge > 0.0 {
            crate::theme::lerp_color(accent, self.theme.err, nudge)
        } else {
            accent
        };

        frame.render_widget(Clear, drawn_area);

        // While the panel is still a slit there is nothing to frame, so draw
        // the growing aperture as a solid accent bar. It reads as light
        // spilling out before the dialog exists.
        if drawn_area.height <= 1 {
            frame.render_widget(
                Block::default().style(Style::default().bg(accent)),
                drawn_area,
            );
            return;
        }

        let showing_content = self.modal_anim.shows_content(tick);

        // The title only appears once the panel is wide enough to hold it,
        // otherwise ratatui clips it mid-word while the box is still moving.
        let titled = showing_content && drawn_area.width as usize > title.len() + 8;
        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(accent))
            .style(Style::default().bg(self.theme.surface));
        if titled {
            block = block
                .title(format!(" {title} "))
                .title_style(Style::default().fg(accent).add_modifier(Modifier::BOLD));
        }
        frame.render_widget(block, drawn_area);

        // Mid-animation the dialog is only a frame; its contents and controls
        // wait until it has settled.
        if !showing_content {
            return;
        }

        self.render_modal_close_button(frame, drawn_area, accent);
        let modal_area = drawn_area;

        let inner = modal_area.inner(Margin {
            horizontal: 2,
            vertical: 1,
        });

        // The dialog state is borrowed for the renderer's lifetime, not from
        // `self`, so its fields can be passed to `&mut self` methods without
        // cloning them every frame.
        let modal: &ModalState = self.modal_state;
        match modal {
            ModalState::TextInput {
                prompt,
                buffer,
                select_all,
                ..
            } => self.render_text_input(frame, inner, prompt, buffer, *select_all),
            ModalState::NumberEdit {
                setting_key,
                min,
                max,
                buffer,
                select_all,
                ..
            } => self.render_number_edit(
                frame,
                inner,
                setting_key,
                *min,
                *max,
                &NumberField {
                    buffer,
                    select_all: *select_all,
                },
            ),
            ModalState::AshesWarning { message, .. } => self.render_warning(frame, inner, message),
            ModalState::QuitConfirmation { .. } => self.render_quit_confirm(frame, inner),
            ModalState::ManualProfile { form, .. } => {
                self.render_manual_profile(frame, inner, form)
            }
            ModalState::Confirm { message, .. } => self.render_confirm(frame, inner, message),
            ModalState::ShareConfig {
                profile, uri, code, ..
            } => self.render_share_config(frame, inner, profile, uri, code),
            ModalState::SudoPassword {
                prompt,
                buffer,
                error,
                ..
            } => self.render_sudo_password(
                frame,
                inner,
                prompt,
                buffer.chars().count(),
                error.as_deref(),
            ),
            ModalState::Help { .. } => self.render_help(frame, inner),
            ModalState::ImageView { findings, .. } => {
                self.render_image_view(frame, inner, findings)
            }
            ModalState::Update { release, phase, .. } => {
                self.render_update(frame, inner, release, phase)
            }
            ModalState::None => {}
        }

        // The border crystallises out of embers over the dialog's first few
        // frames and then leaves no residue — see `ashes_border_overlay`.
        //
        // Skipped for the QR dialog: its embers use the same full block as a
        // QR module, and anything that alters the code's surround risks a
        // scanner misreading it.
        if matches!(self.modal_state, ModalState::ShareConfig { .. }) {
            return;
        }
        let elapsed = tick.saturating_sub(self.modal_state.created_tick());
        let embers = self.effects.ashes_border_overlay(modal_area, elapsed);
        // Straight into the buffer: a `Paragraph` per ember cost a String and
        // a layout pass for every one of a few hundred cells, every frame.
        let buf = frame.buffer_mut();
        let bounds = buf.area;
        for (x, y, glyph, color) in embers {
            if bounds.contains(ratatui::layout::Position { x, y }) {
                buf[(x, y)]
                    .set_char(glyph)
                    .set_fg(color)
                    .modifier
                    .insert(Modifier::BOLD);
            }
        }
    }

    /// An `✕` in the top-right of the dialog's border.
    ///
    /// Sits *on* the border rather than inside the content area, so every
    /// dialog gets one without any of them having to budget space for it.
    fn render_modal_close_button(&mut self, frame: &mut Frame, area: Rect, accent: Color) {
        if area.width < 8 {
            return;
        }
        let button = Rect {
            x: area.x + area.width.saturating_sub(5),
            y: area.y,
            width: 4,
            height: 1,
        };
        self.interaction
            .register_hit_box(ComponentId::ModalClose, button);
        let hovered = self.interaction.is_hovered(ComponentId::ModalClose);

        let style = if hovered {
            Style::default()
                .bg(self.theme.err)
                .fg(self.theme.text)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .bg(self.theme.surface)
                .fg(accent)
                .add_modifier(Modifier::BOLD)
        };
        frame.render_widget(Paragraph::new("[✕]").style(style), button);
    }

    fn render_text_input(
        &mut self,
        frame: &mut Frame,
        inner: Rect,
        prompt: &str,
        buffer: &str,
        select_all: bool,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(3)])
            .split(inner);

        let paragraph = if select_all && !buffer.is_empty() {
            Paragraph::new(vec![Line::from(vec![
                Span::styled(
                    buffer,
                    Style::default()
                        .bg(self.theme.accent)
                        .fg(self.theme.bg)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("█", Style::default().fg(self.theme.accent_bright)),
            ])])
        } else {
            Paragraph::new(format!("{buffer}█")).style(Style::default().fg(self.theme.text))
        };

        frame.render_widget(
            paragraph.wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(format!(
                        " {} ",
                        truncate(prompt, (inner.width as usize).saturating_sub(4))
                    ))
                    .title_style(Style::default().fg(self.theme.muted))
                    .border_style(Style::default().fg(self.theme.accent)),
            ),
            chunks[0],
        );

        self.confirm_cancel(
            frame,
            chunks[1],
            ComponentId::ModalConfirm,
            "✔ Confirm (Enter)",
            ComponentId::ModalCancel,
            "✖ Cancel (Esc)",
        );
    }

    fn render_number_edit(
        &mut self,
        frame: &mut Frame,
        inner: Rect,
        setting_key: &str,
        min: u64,
        max: u64,
        field: &NumberField<'_>,
    ) {
        let buffer = field.buffer;
        let select_all = field.select_all;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(3),
                Constraint::Min(3),
            ])
            .split(inner);

        frame.render_widget(
            Paragraph::new(vec![Line::from(vec![
                Span::styled(
                    format!("{setting_key}  "),
                    Style::default().fg(self.theme.text),
                ),
                Span::styled(
                    format!("allowed {min}–{max}"),
                    Style::default().fg(self.theme.accent),
                ),
            ])]),
            chunks[0],
        );

        // Flag an out-of-range value while it is being typed, rather than
        // waiting for Enter to reject it.
        let parsed = buffer.parse::<u64>().ok();
        let valid = parsed.is_some_and(|v| (min..=max).contains(&v));
        let field_color = if buffer.is_empty() {
            self.theme.muted
        } else if valid {
            self.theme.ok
        } else {
            self.theme.err
        };

        let paragraph = if select_all && !buffer.is_empty() {
            Paragraph::new(vec![Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    buffer,
                    Style::default()
                        .bg(self.theme.accent)
                        .fg(self.theme.bg)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("█", Style::default().fg(self.theme.accent_bright)),
            ])])
        } else {
            Paragraph::new(format!("  {buffer}█")).style(
                Style::default()
                    .fg(field_color)
                    .add_modifier(Modifier::BOLD),
            )
        };

        frame.render_widget(
            paragraph.block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(field_color))
                    .title(" value ")
                    .title_style(Style::default().fg(self.theme.muted)),
            ),
            chunks[1],
        );

        self.confirm_cancel(
            frame,
            Rect {
                height: 3.min(chunks[2].height),
                ..chunks[2]
            },
            ComponentId::NumberInputConfirm,
            "✔ Save (Enter)",
            ComponentId::NumberInputCancel,
            "✖ Cancel (Esc)",
        );
    }

    /// The administrator password dialog.
    ///
    /// Only the *length* of the buffer is passed in, not the buffer: nothing
    /// in the renderer has any business holding the password, and a masked
    /// field needs nothing more than a count. That also rules out the classic
    /// leak of a password ending up in a rendered-frame dump.
    fn render_sudo_password(
        &mut self,
        frame: &mut Frame,
        inner: Rect,
        prompt: &str,
        typed: usize,
        error: Option<&str>,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Length(3),
                Constraint::Length(2),
                Constraint::Min(3),
            ])
            .split(inner);

        let wrap_width = inner.width.max(8) as usize;
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![Span::styled(
                    "🔒 TUN mode needs administrator rights",
                    Style::default()
                        .fg(self.theme.warn)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    truncate(prompt, wrap_width * 2),
                    Style::default().fg(self.theme.muted),
                )]),
            ])
            .wrap(Wrap { trim: true }),
            chunks[0],
        );

        // Masked, and with a cap on how many bullets are drawn so a long
        // passphrase cannot overflow the field and push the layout around.
        let shown = typed.min(chunks[1].width.saturating_sub(6) as usize);
        let mut field = "•".repeat(shown);
        if shown < typed {
            field.push('…');
        }
        let border = if error.is_some() {
            self.theme.err
        } else if typed > 0 {
            self.theme.ok
        } else {
            self.theme.accent
        };
        frame.render_widget(
            Paragraph::new(format!("  {field}█"))
                .style(Style::default().fg(self.theme.text))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(border))
                        .title(" password ")
                        .title_style(Style::default().fg(self.theme.muted)),
                ),
            chunks[1],
        );

        let note = match error {
            Some(error) => Line::from(vec![Span::styled(
                format!(" ✖ {}", truncate(error, wrap_width.saturating_sub(4))),
                Style::default().fg(self.theme.err),
            )]),
            None => Line::from(vec![Span::styled(
                " Not stored or logged. It goes straight to sudo.",
                Style::default().fg(self.theme.muted),
            )]),
        };
        frame.render_widget(Paragraph::new(vec![note]), chunks[2]);

        self.confirm_cancel(
            frame,
            Rect {
                height: 3.min(chunks[3].height),
                ..chunks[3]
            },
            ComponentId::SudoConfirm,
            "✔ Unlock (Enter)",
            ComponentId::SudoCancel,
            "✖ Proxy only (Esc)",
        );
    }

    fn render_warning(&mut self, frame: &mut Frame, inner: Rect, message: &str) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(inner);

        let lines = vec![
            Line::from(vec![Span::styled(
                "⚠ OUT OF RANGE",
                Style::default()
                    .fg(self.theme.err)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                message,
                Style::default().fg(self.theme.text),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "The value was rejected to keep the engine in a valid state.",
                Style::default().fg(self.theme.muted),
            )]),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            chunks[0],
        );

        self.modal_button(
            frame,
            chunks[1],
            ComponentId::AshesWarningDismiss,
            "✖ Dismiss (Enter / Esc)",
            self.theme.err,
        );
    }

    /// The update dialog: a headline with a light sweeping across it, the
    /// version change as a rail a pulse runs along, what changed, and then
    /// whatever the update is doing.
    fn render_update(
        &mut self,
        frame: &mut Frame,
        inner: Rect,
        release: &crate::update::Release,
        phase: &crate::modal::UpdatePhase,
    ) {
        use crate::modal::UpdatePhase;
        let theme = self.theme;
        let moving = self.caps.animations && self.effects.animations_enabled();
        let tick = if moving {
            self.effects.current_tick()
        } else {
            0
        };
        let done = *phase == UpdatePhase::Installed;
        let hue = if done { theme.ok } else { theme.accent_bright };

        let notes = release.notes.len() as u16;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // breathing room
                Constraint::Length(1), // headline
                Constraint::Length(1),
                Constraint::Length(1), // version rail
                Constraint::Length(1),
                Constraint::Min(0),    // what's new
                Constraint::Length(3), // status
                Constraint::Length(3), // buttons
            ])
            .split(inner);

        // Headline, with a band of light sweeping across it.
        let headline = if done {
            format!("✔  ZeroNet {} is installed", release.version)
        } else {
            format!("⬆  ZeroNet {} is out", release.version)
        };
        let len = headline.chars().count();
        let spans: Vec<Span> = headline
            .chars()
            .enumerate()
            .map(|(i, ch)| {
                let glow = if moving {
                    sweep(tick, i, len, 0.7)
                } else {
                    0.0
                };
                Span::styled(
                    ch.to_string(),
                    Style::default()
                        .fg(crate::theme::lerp_color(hue, theme.text, glow * 0.85))
                        .add_modifier(Modifier::BOLD),
                )
            })
            .collect();
        frame.render_widget(
            Paragraph::new(Line::from(spans)).alignment(Alignment::Center),
            chunks[1],
        );

        // Old version, a rail, new version. A pulse runs along the rail
        // towards the new version; once installed the rail is lit through.
        let from = crate::update::CURRENT_VERSION;
        let to = release.version.as_str();
        let rail_len = (chunks[3].width as usize)
            .saturating_sub(from.len() + to.len() + 8)
            .clamp(4, 28);
        let mut rail: Vec<Span> = vec![Span::styled(
            format!("{from}  "),
            Style::default().fg(theme.muted),
        )];
        for i in 0..rail_len {
            let color = if done {
                theme.ok
            } else {
                let pulse = if moving {
                    sweep(tick, i, rail_len, 0.45)
                } else {
                    0.0
                };
                crate::theme::lerp_color(theme.accent_dim, theme.accent_bright, pulse)
            };
            rail.push(Span::styled("━", Style::default().fg(color)));
        }
        rail.push(Span::styled("▶  ", Style::default().fg(hue)));
        rail.push(Span::styled(
            to.to_string(),
            Style::default().fg(hue).add_modifier(Modifier::BOLD),
        ));
        frame.render_widget(
            Paragraph::new(Line::from(rail)).alignment(Alignment::Center),
            chunks[3],
        );

        // What changed.
        if notes > 0 && chunks[5].height >= 2 {
            let width = (chunks[5].width as usize).saturating_sub(4);
            let mut lines = vec![Line::from(Span::styled(
                "WHAT'S NEW",
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::BOLD),
            ))];
            for note in release.notes.iter().take(chunks[5].height as usize - 1) {
                lines.push(Line::from(vec![
                    Span::styled("• ", Style::default().fg(theme.accent)),
                    Span::styled(truncate(note, width), Style::default().fg(theme.text)),
                ]));
            }
            frame.render_widget(Paragraph::new(lines), chunks[5]);
        }

        // Status: size, progress, result.
        let status = chunks[6];
        match phase {
            UpdatePhase::Available => {
                let size = release
                    .asset
                    .as_ref()
                    .filter(|a| a.size > 0)
                    .map(|a| format!("{} download. ", megabytes(a.size)))
                    .unwrap_or_default();
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::from(""),
                        Line::from(Span::styled(
                            format!("{size}Your profiles and settings stay as they are."),
                            Style::default().fg(theme.muted),
                        )),
                    ])
                    .alignment(Alignment::Center),
                    status,
                );
            }
            UpdatePhase::Downloading { received, total } => {
                self.render_update_progress(frame, status, *received, *total, tick, moving);
            }
            UpdatePhase::Installed => {
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::from(""),
                        Line::from(Span::styled(
                            "Restart ZeroNet to start using it.",
                            Style::default().fg(theme.text),
                        )),
                    ])
                    .alignment(Alignment::Center),
                    status,
                );
            }
            UpdatePhase::Manual(message) | UpdatePhase::Failed(message) => {
                let color = if matches!(phase, UpdatePhase::Failed(_)) {
                    theme.err
                } else {
                    theme.warn
                };
                frame.render_widget(
                    Paragraph::new(message.as_str())
                        .style(Style::default().fg(color))
                        .alignment(Alignment::Center)
                        .wrap(Wrap { trim: true }),
                    status,
                );
            }
        }

        let (primary, primary_color, secondary) = match phase {
            UpdatePhase::Available => ("⬇ Update now (Enter)", theme.accent_bright, "Later (Esc)"),
            UpdatePhase::Downloading { .. } => ("Downloading…", theme.muted, "Hide (Esc)"),
            UpdatePhase::Installed => ("↻ Restart now (Enter)", theme.ok, "Later (Esc)"),
            UpdatePhase::Manual(_) => (
                "Open release page (Enter)",
                theme.accent_bright,
                "Close (Esc)",
            ),
            UpdatePhase::Failed(_) => ("↻ Try again (Enter)", theme.accent_bright, "Close (Esc)"),
        };
        self.confirm_cancel_colored(
            frame,
            chunks[7],
            ComponentId::UpdatePrimary,
            primary,
            primary_color,
            ComponentId::UpdateSecondary,
            secondary,
            theme.muted,
        );
    }

    /// A progress bar with eighth-cell precision, shading from the dim to
    /// the bright accent, with a sheen travelling over the filled part.
    fn render_update_progress(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        received: u64,
        total: u64,
        tick: u64,
        moving: bool,
    ) {
        const PARTIAL: [&str; 8] = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
        let theme = self.theme;
        let fraction = if total > 0 {
            (received as f64 / total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let width = (area.width as usize).saturating_sub(12).max(4);
        let eighths = (fraction * width as f64 * 8.0).round() as usize;
        let (full, partial) = (eighths / 8, eighths % 8);

        let mut bar: Vec<Span> = vec![Span::styled("▕", Style::default().fg(theme.border))];
        for i in 0..width {
            let base = crate::theme::lerp_color(
                theme.accent_dim,
                theme.accent_bright,
                i as f64 / width.max(1) as f64,
            );
            if i < full {
                let sheen = if moving {
                    sweep(tick, i, full.max(1), 0.8)
                } else {
                    0.0
                };
                bar.push(Span::styled(
                    "█",
                    Style::default().fg(crate::theme::lerp_color(base, theme.text, sheen * 0.6)),
                ));
            } else if i == full && partial > 0 {
                bar.push(Span::styled(PARTIAL[partial], Style::default().fg(base)));
            } else {
                bar.push(Span::styled("·", Style::default().fg(theme.border)));
            }
        }
        bar.push(Span::styled("▏", Style::default().fg(theme.border)));
        bar.push(Span::styled(
            format!(" {:>3}%", (fraction * 100.0).floor() as u32),
            Style::default()
                .fg(theme.accent_bright)
                .add_modifier(Modifier::BOLD),
        ));

        let detail = if total > 0 {
            format!("{} of {}", megabytes(received), megabytes(total))
        } else {
            megabytes(received)
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(bar),
                Line::from(Span::styled(detail, Style::default().fg(theme.muted))),
            ])
            .alignment(Alignment::Center),
            area,
        );
    }

    fn render_quit_confirm(&mut self, frame: &mut Frame, inner: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(inner);

        let lines = vec![
            Line::from(vec![Span::styled(
                "🛡 Quit ZeroNet?",
                Style::default()
                    .fg(self.theme.accent_bright)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Active proxy streams and the TUN interface will be",
                Style::default().fg(self.theme.text),
            )]),
            Line::from(vec![Span::styled(
                "dismantled and the default gateway restored.",
                Style::default().fg(self.theme.muted),
            )]),
        ];
        frame.render_widget(
            Paragraph::new(lines).alignment(Alignment::Center),
            chunks[0],
        );

        self.confirm_cancel_colored(
            frame,
            chunks[1],
            ComponentId::QuitConfirmYes,
            "✖ Exit (Enter)",
            self.theme.err,
            ComponentId::QuitConfirmNo,
            "✔ Stay (Esc)",
            self.theme.ok,
        );
    }

    fn render_manual_profile(
        &mut self,
        frame: &mut Frame,
        inner: Rect,
        form: &crate::manual_profile::ManualProfileForm,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(12), Constraint::Length(3)])
            .split(inner);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[0]);

        let field_rows = |area: Rect| -> Vec<Rect> {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2); 6])
                .split(area)
                .to_vec()
        };
        let left = field_rows(cols[0]);
        let right = field_rows(cols[1]);

        let port = form.port.to_string();
        let proto = PROTOCOLS[form.protocol_idx % PROTOCOLS.len()].to_uppercase();
        let sec = SECURITIES[form.security_idx % SECURITIES.len()].to_uppercase();
        let flow = FLOWS[form.flow_idx % FLOWS.len()].to_uppercase();
        let transport = TRANSPORTS[form.transport_idx % TRANSPORTS.len()].to_uppercase();
        let uuid = truncate(&form.uuid_or_password, 16);
        let pbk = truncate(&form.pbk, 16);

        let fields: [(usize, &str, &str, Rect); 12] = [
            (0, "Remark", form.remark.as_str(), left[0]),
            (1, "Protocol", proto.as_str(), left[1]),
            (2, "Server Host", form.address.as_str(), left[2]),
            (3, "Server Port", port.as_str(), left[3]),
            (4, "UUID / Pass", uuid.as_str(), left[4]),
            (5, "Security", sec.as_str(), left[5]),
            (6, "SNI / Host", form.sni.as_str(), right[0]),
            (7, "Reality PBK", pbk.as_str(), right[1]),
            (8, "Reality SID", form.sid.as_str(), right[2]),
            (9, "TCP Flow", flow.as_str(), right[3]),
            (10, "Transport", transport.as_str(), right[4]),
            (11, "WS Path", form.ws_path.as_str(), right[5]),
        ];

        for (idx, label, value, rect) in fields {
            self.interaction
                .register_hit_box(ComponentId::ManualField(idx), rect);
            let focused = form.focused_field == idx;
            let hovered = self.interaction.is_hovered(ComponentId::ManualField(idx));

            // Match the caret used by the search box and the other text
            // dialogs. The form is the source of truth for its values, so
            // derive editability from the focused field rather than from a
            // stale modal flag; this keeps the caret visible immediately when
            // the form opens and after clicking or tabbing to another field.
            //
            // The label occupies 15 columns (` {label:<13} `), and the value
            // brackets/spaces occupy another 4. Reserve the final value cell
            // for the caret so a long remark or address cannot push it out of
            // the field at the supported minimum terminal width.
            let value_width = (rect.width as usize).saturating_sub(MANUAL_FIELD_CHROME_WIDTH);
            let display = if focused && form.focused_field_is_text() {
                format!("{}█", truncate(value, value_width.saturating_sub(1)))
            } else {
                truncate(value, value_width)
            };

            let line = Line::from(vec![
                Span::styled(
                    format!(" {label:<13} "),
                    if focused {
                        Style::default()
                            .fg(self.theme.accent_bright)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(self.theme.text)
                    },
                ),
                Span::styled(
                    format!("[ {display} ]"),
                    if focused {
                        Style::default()
                            .fg(self.theme.ok)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(self.theme.text)
                    },
                ),
            ]);
            frame.render_widget(
                Paragraph::new(vec![line]).style(if hovered {
                    self.theme.card_hover_style()
                } else {
                    Style::default()
                }),
                rect,
            );
        }

        self.confirm_cancel_colored(
            frame,
            chunks[1],
            ComponentId::ManualFormSave,
            "✔ Save & Connect",
            self.theme.ok,
            ComponentId::ManualFormCancel,
            "✖ Cancel (Esc)",
            self.theme.err,
        );
    }

    /// A destructive yes/no question.
    ///
    /// The destructive choice is on the left and coloured red, and Esc — the
    /// key people hit reflexively — is the safe one.
    fn render_confirm(&mut self, frame: &mut Frame, inner: Rect, message: &str) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(inner);

        let lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                message,
                Style::default().fg(self.theme.text),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "This cannot be undone.",
                Style::default().fg(self.theme.muted),
            )]),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            chunks[0],
        );

        self.confirm_cancel_colored(
            frame,
            chunks[1],
            ComponentId::QuitConfirmYes,
            "\u{2716} Delete (Enter)",
            self.theme.err,
            ComponentId::QuitConfirmNo,
            "\u{2714} Keep (Esc)",
            self.theme.ok,
        );
    }

    /// Share a profile: the QR code on the left, the link on the right.
    ///
    /// The link is drawn as plain wrapped text in its own panel with nothing
    /// overlaid, so the terminal's own click-and-drag selection works on it —
    /// that is what makes it feel copyable rather than merely displayed.
    fn render_share_config(
        &mut self,
        frame: &mut Frame,
        inner: Rect,
        profile: &str,
        uri: &str,
        code: &RenderedQr,
    ) {
        let code_w = code.width_cells as u16;

        // Side by side when there is room; stacked on a narrow terminal.
        let side_by_side = inner.width >= code_w + 34;
        let (qr_area, text_area) = if side_by_side {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(code_w + 2), Constraint::Min(30)])
                .split(inner);
            (cols[0], cols[1])
        } else {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(code.height_cells as u16),
                    Constraint::Min(5),
                ])
                .split(inner);
            (rows[0], rows[1])
        };

        self.render_qr_block(frame, qr_area, code);
        self.render_share_text(frame, text_area, profile, uri);
    }

    /// The code itself, centred and never scaled.
    fn render_qr_block(&mut self, frame: &mut Frame, area: Rect, code: &RenderedQr) {
        let width = (code.width_cells as u16).min(area.width);
        let code_area = Rect {
            x: area.x + area.width.saturating_sub(width) / 2,
            y: area.y,
            width,
            height: (code.height_cells as u16).min(area.height),
        };
        let lines: Vec<Line> = code
            .lines
            .iter()
            .map(|l| {
                Line::from(Span::styled(
                    l.as_str(),
                    Style::default().fg(self.theme.text),
                ))
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), code_area);
    }

    /// The link, plus the copy actions.
    fn render_share_text(&mut self, frame: &mut Frame, area: Rect, profile: &str, uri: &str) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(4),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(area);

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![Span::styled(
                    profile,
                    Style::default()
                        .fg(self.theme.accent_bright)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(vec![Span::styled(
                    "Scan the code, or copy the link below.",
                    Style::default().fg(self.theme.muted),
                )]),
            ]),
            rows[0],
        );

        // A bordered panel of nothing but the link. No cursor, no decoration
        // inside the text — drag-select in the terminal picks up exactly the
        // link and nothing else.
        frame.render_widget(
            Paragraph::new(uri)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(self.theme.text))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(self.theme.border))
                        .title(" share link ")
                        .title_style(Style::default().fg(self.theme.muted)),
                ),
            rows[1],
        );

        let buttons = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[2]);
        self.modal_button(
            frame,
            buttons[0],
            ComponentId::ShareCopyLink,
            "\u{2398} Copy link",
            self.theme.ok,
        );
        self.modal_button(
            frame,
            buttons[1],
            ComponentId::ShareCopySubscription,
            "\u{2398} Copy as sub",
            self.theme.info,
        );

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " Ctrl+C ",
                    Style::default()
                        .bg(self.theme.surface_hi)
                        .fg(self.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" copy   ", Style::default().fg(self.theme.muted)),
                Span::styled(
                    " Esc ",
                    Style::default()
                        .bg(self.theme.surface_hi)
                        .fg(self.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" close", Style::default().fg(self.theme.muted)),
            ])),
            rows[3],
        );
    }

    /// An image, with whatever was decoded out of it underneath.
    fn render_image_view(&mut self, frame: &mut Frame, inner: Rect, findings: &[String]) {
        // Findings get two lines each plus a heading; the image takes what is
        // left, so a long list never pushes the picture off screen.
        let text_rows = (findings.len() as u16 * 2 + 2).min(inner.height / 2);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(text_rows)])
            .split(inner);

        match self.image_view.as_mut() {
            Some(image) => crate::imageview::render(frame, chunks[0], image),
            None => frame.render_widget(
                Paragraph::new("This terminal cannot display images.")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(self.theme.muted)),
                chunks[0],
            ),
        }

        let mut lines = Vec::new();
        if findings.is_empty() {
            lines.push(Line::from(vec![Span::styled(
                "No config found in this image.",
                Style::default().fg(self.theme.warn),
            )]));
        } else {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "Found {} {}:",
                    findings.len(),
                    if findings.len() == 1 {
                        "config"
                    } else {
                        "configs"
                    }
                ),
                Style::default()
                    .fg(self.theme.ok)
                    .add_modifier(Modifier::BOLD),
            )]));
            for finding in findings {
                lines.push(Line::from(vec![Span::styled(
                    truncate(finding, inner.width.saturating_sub(2) as usize),
                    Style::default().fg(self.theme.text),
                )]));
            }
        }
        lines.push(Line::from(vec![Span::styled(
            "Enter to import · Esc to close",
            Style::default().fg(self.theme.muted),
        )]));

        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(self.theme.border)),
            ),
            chunks[1],
        );
    }

    /// Lines the keyboard reference occupies, for scroll bounds.
    pub fn help_content_height() -> usize {
        crate::keymap::help_sections()
            .iter()
            .map(|(_, bindings)| bindings.len() + 2)
            .sum::<usize>()
            + 1
    }

    /// Height of the help modal's interior scroll viewport.
    pub fn help_viewport_height(terminal_height: u16) -> usize {
        let modal_height = (terminal_height as usize * 86) / 100;
        modal_height.saturating_sub(2).max(1)
    }

    /// The keyboard reference, grouped by what the keys are for.
    fn render_help(&mut self, frame: &mut Frame, inner: Rect) {
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let mut lines: Vec<Line> = Vec::new();

        for (section, bindings) in crate::keymap::help_sections() {
            lines.push(Line::from(vec![Span::styled(
                section,
                Style::default()
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )]));
            for binding in bindings {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<16}", binding.keys),
                        Style::default()
                            .fg(self.theme.accent_bright)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        binding.command.label(),
                        Style::default().fg(self.theme.text),
                    ),
                ]));
            }
            lines.push(Line::from(""));
        }

        lines.push(Line::from(vec![Span::styled(
            "Selecting a server never connects. Press Enter to connect.",
            Style::default().fg(self.theme.muted),
        )]));

        let max = crate::scroll::max_offset(Self::help_content_height(), inner.height as usize);
        let base_offset =
            (self.help_scroll.smooth_offset().round().max(0.0) as usize).min(max) as u16;

        let overscroll = self.help_scroll.overscroll();
        let top_bounce = (-overscroll.min(0.0)).round() as u16;
        let bottom_bounce = overscroll.max(0.0).round() as u16;

        // Reserve the rightmost column for the scrollbar track so content
        // never draws under or past the scrollbar.
        // For overscroll at the top (top_bounce > 0), drop `body.y` and shrink
        // `body.height` so content moves downward leaving space under the top
        // border, while its bottom never exceeds `inner.bottom()`.
        // For overscroll at the bottom (bottom_bounce > 0), keep `body` bounded
        // inside `inner` and increase the paragraph scroll offset, lifting
        // content upward like an elastic band.
        let body = Rect {
            x: inner.x,
            y: inner.y.saturating_add(top_bounce.min(inner.height)),
            width: inner.width.saturating_sub(1),
            height: inner.height.saturating_sub(top_bounce),
        };

        let scroll_y = base_offset.saturating_add(bottom_bounce);

        frame.render_widget(
            Paragraph::new(lines)
                .scroll((scroll_y, 0))
                .wrap(Wrap { trim: false }),
            body,
        );

        // A scrollbar, so the overlay says how much more there is.
        if max > 0 {
            let track = Rect {
                x: inner.x + inner.width.saturating_sub(1),
                y: inner.y,
                width: 1,
                height: inner.height,
            };
            self.paint_scrollbar(
                frame,
                crate::scrollbar::ScrollTarget::Help,
                crate::scrollbar::layout(
                    track,
                    self.help_scroll.smooth_offset().round().max(0.0) as usize,
                    max,
                    Self::help_content_height(),
                    inner.height as usize,
                ),
            );
        }
    }

    // ------------------------------------------------------------- buttons

    fn confirm_cancel(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        confirm: ComponentId,
        confirm_label: &str,
        cancel: ComponentId,
        cancel_label: &str,
    ) {
        self.confirm_cancel_colored(
            frame,
            area,
            confirm,
            confirm_label,
            self.theme.ok,
            cancel,
            cancel_label,
            self.theme.err,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn confirm_cancel_colored(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        confirm: ComponentId,
        confirm_label: &str,
        confirm_color: Color,
        cancel: ComponentId,
        cancel_label: &str,
        cancel_color: Color,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        self.modal_button(frame, chunks[0], confirm, confirm_label, confirm_color);
        self.modal_button(frame, chunks[1], cancel, cancel_label, cancel_color);
    }

    fn modal_button(
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
}

/// The update dialog, sized to its contents: a line per release note, and
/// never larger than the screen.
fn update_dialog_rect(area: Rect, notes: usize) -> Rect {
    // Borders 2, headline and rail 5, notes (heading, lines, gap), status
    // 3, buttons 3.
    let notes_rows = if notes > 0 { notes as u16 + 2 } else { 0 };
    let want_h = (13 + notes_rows).min(area.height.saturating_sub(2));
    let want_w = 68.min(area.width.saturating_sub(4));
    Rect {
        x: area.x + area.width.saturating_sub(want_w) / 2,
        y: area.y + area.height.saturating_sub(want_h) / 2,
        width: want_w,
        height: want_h,
    }
}

/// `12.4 MB`.
fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// Brightness of a light band sweeping along a row of `len` cells, at cell
/// `i` on frame `tick`: 0 away from the band, 1 at its centre.
fn sweep(tick: u64, i: usize, len: usize, speed: f64) -> f64 {
    let period = len as f64 + 18.0;
    let centre = (tick as f64 * speed) % period - 6.0;
    let d = (i as f64 - centre).abs();
    (-(d * d) / 8.0).exp()
}

/// Size the share dialog around the code itself.
///
/// The code is never scaled to fit — a resampled QR stops scanning — so the
/// dialog takes the room the code needs, plus a column for the link.
fn share_dialog_rect(area: Rect, code_width: u16, code_height: u16) -> Rect {
    /// Width reserved for the link panel and its buttons.
    const TEXT_COLUMN: u16 = 42;

    let want_w = (code_width + TEXT_COLUMN + 6).min(area.width);
    // Stacked layout needs the code's height plus the text block; side by
    // side needs only the taller of the two.
    let want_h = if want_w >= code_width + 34 {
        (code_height + 4).min(area.height)
    } else {
        (code_height + 12).min(area.height)
    };
    Rect {
        x: area.x + area.width.saturating_sub(want_w) / 2,
        y: area.y + area.height.saturating_sub(want_h) / 2,
        width: want_w,
        height: want_h,
    }
}

#[cfg(test)]
mod tests {
    use crate::modal::ModalState;

    #[test]
    fn every_modal_reports_its_creation_tick() {
        // The opening animation is driven by `current_tick - created_tick`,
        // so a variant that reported zero would animate forever.
        let modals = [
            ModalState::TextInput {
                title: "t".into(),
                prompt: "p".into(),
                buffer: String::new(),
                purpose: crate::modal::TextPurpose::ImportConfig,
                created_tick: 7,
                select_all: false,
            },
            ModalState::NumberEdit {
                title: "t".into(),
                setting_key: "k".into(),
                min: 1,
                max: 2,
                buffer: String::new(),
                created_tick: 7,
                select_all: false,
            },
            ModalState::AshesWarning {
                title: "t".into(),
                message: "m".into(),
                created_tick: 7,
            },
            ModalState::QuitConfirmation { created_tick: 7 },
        ];
        for m in modals {
            assert_eq!(m.created_tick(), 7, "{m:?}");
            assert!(m.is_active());
        }
        assert!(!ModalState::None.is_active());
    }
}
