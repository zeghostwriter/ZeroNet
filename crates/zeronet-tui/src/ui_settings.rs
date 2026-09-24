//! The Settings screen.
//!
//! Every row is one of three shapes — a toggle, a cycler, or a value you
//! click to edit — so they are all drawn by the same three helpers rather
//! than twenty near-identical blocks. That is what keeps the column widths,
//! hover treatment and hint text consistent down the page.

use crate::interaction::ComponentId;
use crate::ui::{truncate, UiRenderer};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

/// Width reserved for a row's label, so every value in a column lines up. (25% bigger)
const LABEL_WIDTH: usize = 28;
/// Width reserved for a row's value. (25% bigger)
const VALUE_WIDTH: usize = 20;

/// Rows when Advanced is folded: four headings plus the everyday settings.
pub(crate) const SETTINGS_ROWS_BASIC: usize = 25;
/// Rows when Advanced is open, including the edge-scanner block.
pub(crate) const SETTINGS_ROWS: usize = 54;

impl UiRenderer<'_> {
    /// Total lines the settings page needs, for the scrollbar.
    pub fn settings_content_height_for(advanced_open: bool) -> usize {
        let rows = if advanced_open {
            SETTINGS_ROWS
        } else {
            SETTINGS_ROWS_BASIC
        };
        rows * 2 + 1
    }

    pub fn settings_content_height() -> usize {
        Self::settings_content_height_for(false)
    }

    pub(crate) fn render_settings(&mut self, frame: &mut Frame, area: Rect) {
        let content_h = Self::settings_content_height_for(self.advanced_open);
        let scrollable = content_h > area.height.saturating_sub(2) as usize;

        let block = Block::default()
            .title(if scrollable {
                " ⚙ SETTINGS · scroll for more "
            } else {
                " ⚙ SETTINGS "
            })
            .title_style(self.theme.title_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style());
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width < 10 || inner.height < 2 {
            return;
        }

        // Rows are positioned relative to the scroll offset and skipped when
        // they fall outside the panel, which keeps every rectangle in
        // unsigned space and means a row's hit region always matches what is
        // actually drawn.
        let shift = self.settings_scroll.smooth_offset().round() as i32
            + self.settings_scroll.overscroll().round() as i32;

        let body = Rect {
            width: inner.width.saturating_sub(1),
            ..inner
        };

        self.render_settings_list(frame, body, shift);

        if scrollable {
            let max = crate::scroll::max_offset(content_h, inner.height as usize);
            let track = Rect {
                x: inner.x + inner.width.saturating_sub(1),
                y: inner.y,
                width: 1,
                height: inner.height,
            };
            self.paint_scrollbar(
                frame,
                crate::scrollbar::ScrollTarget::Settings,
                crate::scrollbar::layout(
                    track,
                    self.settings_scroll.smooth_offset().round().max(0.0) as usize,
                    max,
                    content_h,
                    inner.height as usize,
                ),
            );
        }
    }

    fn render_settings_list(&mut self, frame: &mut Frame, area: Rect, shift: i32) {
        let count = if self.advanced_open {
            SETTINGS_ROWS
        } else {
            SETTINGS_ROWS_BASIC
        };
        let rows = rows_for(area, count, shift);
        let mut n = 0usize;
        let mut row = || {
            let r = rows[n];
            n += 1;
            r
        };

        self.group_heading(frame, row(), "CONNECTION");
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingTunToggle,
            "TUN Interface",
            self.settings.tun_enabled,
            "ENABLED",
            "DISABLED",
        );
        let proxy_mode = crate::sysproxy::SystemProxyMode::parse(&self.settings.system_proxy_mode)
            .unwrap_or_default();
        self.value_row(
            frame,
            row(),
            ComponentId::SettingSystemProxyCycle,
            "System Proxy",
            proxy_mode.label(),
            match proxy_mode {
                crate::sysproxy::SystemProxyMode::Unmanaged => self.theme.muted,
                crate::sysproxy::SystemProxyMode::Clear => self.theme.warn,
                crate::sysproxy::SystemProxyMode::Pac => self.theme.info,
                crate::sysproxy::SystemProxyMode::Manual => self.theme.ok,
            },
            proxy_mode.describe(),
        );
        self.value_row(
            frame,
            row(),
            ComponentId::SettingSocksPort,
            "SOCKS5 Port",
            &self.settings.socks_port.to_string(),
            self.theme.ok,
            "click to edit",
        );
        self.value_row(
            frame,
            row(),
            ComponentId::SettingHttpPort,
            "HTTP Proxy Port",
            &self.settings.http_port.to_string(),
            self.theme.info,
            "click to edit",
        );
        // Spelled out rather than "ENABLED": binding the proxy to every
        // interface is the one setting on this page that other machines can
        // see, and the value ought to say which of the two it is.
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingAllowLanToggle,
            "Allow LAN Connections",
            self.settings.allow_lan,
            "0.0.0.0 (LAN)",
            "127.0.0.1 only",
        );
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingUdpToggle,
            "UDP over SOCKS",
            self.settings.udp_enabled,
            "ENABLED",
            "DISABLED",
        );

        self.group_heading(frame, row(), "NETWORK");
        self.value_row(
            frame,
            row(),
            ComponentId::SettingDnsCycle,
            "Remote DNS",
            &self.settings.remote_dns.to_uppercase(),
            self.theme.accent_bright,
            "click to cycle",
        );
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingIpv6Toggle,
            "IPv6 Routing",
            self.settings.ipv6_enabled,
            "ENABLED",
            "DISABLED",
        );
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingSniffingToggle,
            "Sniffing",
            self.settings.sniffing_enabled,
            "TLS/HTTP/QUIC",
            "DISABLED",
        );
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingSniffRouteOnlyToggle,
            "Sniff Route-Only",
            self.settings.sniffing_route_only,
            "ROUTE ONLY",
            "REWRITE DEST",
        );
        self.value_row(
            frame,
            row(),
            ComponentId::SettingDomainStrategyCycle,
            "Domain Strategy",
            &self.settings.domain_strategy.to_uppercase(),
            self.theme.accent_bright,
            "click to cycle",
        );
        self.value_row(
            frame,
            row(),
            ComponentId::SettingFingerprintCycle,
            "uTLS Fingerprint",
            &self.settings.utls_fingerprint.to_uppercase(),
            self.theme.accent,
            "ClientHello shape",
        );
        self.value_row(
            frame,
            row(),
            ComponentId::SettingLogLevelCycle,
            "Engine Log Level",
            &self.settings.log_level.to_uppercase(),
            self.theme.muted,
            "click to cycle",
        );

        self.group_heading(frame, row(), "SUBSCRIPTIONS");
        self.value_row(
            frame,
            row(),
            ComponentId::SettingSubUpdateHours,
            "Sub Auto-Update",
            &format!("{} hrs", self.settings.sub_update_interval_hours),
            self.theme.accent_bright,
            "click to edit",
        );
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingAutoReconnectToggle,
            "Auto-Reconnect",
            self.settings.auto_reconnect,
            "ENABLED",
            "DISABLED",
        );

        self.group_heading(frame, row(), "APPEARANCE");
        self.theme_row(frame, row());
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingAnimationsToggle,
            "Animations",
            self.effects.animations_enabled(),
            "ON",
            "OFF",
        );
        self.toggle_row(
            frame,
            row(),
            ComponentId::SettingUsageToggle,
            "CPU / RAM in Status Bar",
            self.settings.show_usage,
            "SHOWN",
            "HIDDEN",
        );
        let muted = self
            .settings
            .muted_notices
            .split(',')
            .filter(|key| !key.is_empty())
            .count();
        self.value_row(
            frame,
            row(),
            ComponentId::SettingMutedNotices,
            "Muted Notices",
            &if muted == 0 {
                "NONE".to_string()
            } else {
                format!("{muted} HIDDEN")
            },
            if muted == 0 {
                self.theme.muted
            } else {
                self.theme.accent_bright
            },
            if muted == 0 {
                "\"Don't show again\" choices"
            } else {
                "click to show them again"
            },
        );

        let advanced_label = if self.advanced_open {
            "ADVANCED"
        } else {
            "ADVANCED  ▸ click to show"
        };
        self.group_heading_hit(
            frame,
            row(),
            advanced_label,
            Some(ComponentId::SettingAdvancedToggle),
        );

        if self.advanced_open {
            self.value_row(
                frame,
                row(),
                ComponentId::SettingTunDeviceName,
                "TUN Device Name",
                &truncate(&self.settings.tun_device_name, 18),
                self.theme.text,
                "click to edit",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingTunMtu,
                "Device MTU",
                &self.settings.tun_mtu.to_string(),
                self.theme.accent_bright,
                "click to edit",
            );
            self.toggle_row(
                frame,
                row(),
                ComponentId::SettingTunAutoRouteToggle,
                "TUN Auto-Route",
                self.settings.tun_auto_route,
                "ENABLED",
                "DISABLED",
            );
            // Strict routing has no meaning without auto-routing — there are
            // no routes to be strict about — and the engine refuses the pair,
            // so the row says so instead of showing an ON that is a lie.
            let strict_hint = if self.settings.tun_auto_route {
                "blocks traffic leaving around the tunnel"
            } else {
                "needs Auto-Route"
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingTunStrictRouteToggle,
                "TUN Strict Route",
                if !self.settings.tun_strict_route {
                    "DISABLED"
                } else if self.settings.tun_auto_route {
                    "ENABLED"
                } else {
                    "INERT"
                },
                if self.settings.tun_strict_route && self.settings.tun_auto_route {
                    self.theme.ok
                } else if self.settings.tun_strict_route {
                    self.theme.warn
                } else {
                    self.theme.muted
                },
                strict_hint,
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingPacPort,
                "PAC Port",
                &self.settings.pac_port.to_string(),
                self.theme.info,
                "click to edit",
            );
            let custom_dns = if self.settings.custom_dns.is_empty() {
                "none (preset)".to_string()
            } else {
                truncate(&self.settings.custom_dns, 18)
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingCustomDns,
                "Custom DNS",
                &custom_dns,
                self.theme.text,
                "blank = preset resolvers",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingAntiSanctionCycle,
                "Anti-Sanction DNS",
                &self.settings.anti_sanction.to_uppercase(),
                self.theme.accent,
                "click to cycle",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingAntiCensorshipCycle,
                "Censorship Evasion",
                &self.settings.anti_censorship_level.to_uppercase(),
                self.theme.ok,
                "preset: sets Shredding + Keepalive",
            );
            self.toggle_row(
                frame,
                row(),
                ComponentId::SettingFragmentToggle,
                "TLS Fragmentation",
                self.settings.fragment_enabled,
                "ACTIVE",
                "INACTIVE",
            );
            self.stepper_row(
                frame,
                row(),
                "TLS Shredding",
                &format!("{}B", self.settings.tls_fragment_size),
                ComponentId::SettingFragmentMinus,
                ComponentId::SettingFragmentValue,
                ComponentId::SettingFragmentPlus,
                self.theme.text,
                // The size is only in force while fragmentation is on, and
                // saying so beats a number the engine is ignoring.
                if self.settings.fragment_enabled {
                    "splits the ClientHello"
                } else {
                    "needs TLS Fragmentation"
                },
            );
            self.stepper_row(
                frame,
                row(),
                "Jitter Delay",
                &format!("{}ms", self.settings.jitter_delay_ms),
                ComponentId::SettingJitterMinus,
                ComponentId::SettingJitterValue,
                ComponentId::SettingJitterPlus,
                self.theme.text,
                "between scanner probes",
            );
            let keepalive_value = if self.settings.keepalive_interval_secs == 0 {
                "off".to_string()
            } else {
                format!("{}s", self.settings.keepalive_interval_secs)
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingKeepaliveSecs,
                "Keepalive Idle",
                &keepalive_value,
                self.theme.accent_bright,
                "0 = off",
            );
            let mux_label = if self.settings.mux_enabled {
                format!("ON ({}x)", self.settings.mux_concurrency)
            } else {
                "OFF".to_string()
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingMuxToggle,
                "Multiplexing",
                &mux_label,
                if self.settings.mux_enabled {
                    self.theme.ok
                } else {
                    self.theme.muted
                },
                "click to toggle",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingTcpCongestionCycle,
                "Congestion Control",
                &self.settings.tcp_congestion.to_uppercase(),
                self.theme.info,
                "Linux kernel may decline",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingCleanIpToggle,
                "Clean IP Rotation",
                if self.settings.clean_ip_rotation {
                    "ACTIVE"
                } else {
                    "INACTIVE"
                },
                if self.settings.clean_ip_rotation {
                    self.theme.ok
                } else {
                    self.theme.muted
                },
                "ranks scanner-clean edges",
            );

            // The scanner's own knobs. These are the CLI's flags, which the
            // page used to hard-code: a probe that only ever ran HTTP on 443
            // with two tries cannot find a working edge for anything else.
            self.group_heading(frame, row(), "EDGE SCANNER");
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerModeCycle,
                "Probe Mode",
                &self.settings.scanner_mode.to_uppercase(),
                self.theme.accent_bright,
                "tcp → tls → http",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerPort,
                "Probe Port",
                &self.settings.scanner_port.to_string(),
                self.theme.ok,
                "click to edit",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerTries,
                "Probes per IP",
                &self.settings.scanner_tries.to_string(),
                self.theme.text,
                "more tries = loss & jitter",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerTimeout,
                "Probe Timeout",
                &format!("{}s", self.settings.scanner_timeout_secs),
                self.theme.text,
                "click to edit",
            );
            let target = if self.settings.scanner_target_count == 0 {
                "unlimited".to_string()
            } else {
                self.settings.scanner_target_count.to_string()
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerTargetCount,
                "Candidates",
                &target,
                self.theme.accent,
                "0 = until stopped",
            );
            let sni = if self.settings.scanner_sni.is_empty() {
                "rotate known SNIs".to_string()
            } else {
                truncate(&self.settings.scanner_sni, 18)
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerSni,
                "Probe SNI",
                &sni,
                self.theme.text,
                "blank to rotate",
            );
            self.toggle_row(
                frame,
                row(),
                ComponentId::SettingScannerRequireWsToggle,
                "Require WebSocket",
                self.settings.scanner_require_ws,
                "REQUIRED",
                "OPTIONAL",
            );
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerWsPath,
                "WebSocket Path",
                &truncate(&self.settings.scanner_ws_path, 18),
                self.theme.text,
                "click to edit",
            );
            self.toggle_row(
                frame,
                row(),
                ComponentId::SettingScannerNeighborsToggle,
                "Neighbour Sweep",
                self.settings.scanner_neighbors,
                "ACTIVE",
                "INACTIVE",
            );
            // At least one family has to stay on, or the scanner would have
            // nothing to draw candidates from — the click handler enforces it.
            self.toggle_row(
                frame,
                row(),
                ComponentId::SettingScannerIpv4Toggle,
                "Scan IPv4 Ranges",
                self.settings.scanner_ipv4,
                "ENABLED",
                "DISABLED",
            );
            self.toggle_row(
                frame,
                row(),
                ComponentId::SettingScannerIpv6Toggle,
                "Scan IPv6 Ranges",
                self.settings.scanner_ipv6,
                "ENABLED",
                "DISABLED",
            );
            let sample = if self.settings.scanner_speed_bytes == 0 {
                "off".to_string()
            } else {
                format!("{} KB", self.settings.scanner_speed_bytes / 1024)
            };
            self.value_row(
                frame,
                row(),
                ComponentId::SettingScannerSpeedBytes,
                "Speed Sample",
                &sample,
                if self.settings.scanner_speed_bytes == 0 {
                    self.theme.muted
                } else {
                    self.theme.info
                },
                "0 = skip throughput",
            );
            self.stepper_row(
                frame,
                row(),
                "Scanner Workers",
                &self.settings.scanner_concurrency.to_string(),
                ComponentId::SettingConcurrencyMinus,
                ComponentId::SettingConcurrencyValue,
                ComponentId::SettingConcurrencyPlus,
                self.theme.ok,
                "parallel probes",
            );
        }

        let caps_line = Line::from(vec![
            Span::styled(
                format!(" {:<LABEL_WIDTH$}", "Terminal"),
                Style::default().fg(self.theme.muted),
            ),
            Span::styled(self.caps.describe(), Style::default().fg(self.theme.muted)),
        ]);
        let last = row();
        if last.height > 0 {
            frame.render_widget(Paragraph::new(vec![caps_line]), last);
        }
        debug_assert_eq!(n, count);
    }

    fn group_heading(&mut self, frame: &mut Frame, area: Rect, title: &str) {
        self.group_heading_hit(frame, area, title, None);
    }

    fn group_heading_hit(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        title: &str,
        id: Option<ComponentId>,
    ) {
        if area.height == 0 {
            return;
        }
        if let Some(id) = id {
            self.interaction.register_hit_box(id, area);
        }
        frame.render_widget(
            Paragraph::new(title).style(
                Style::default()
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            area,
        );
    }

    /// The palette picker: its name, then a strip of the palette itself, so
    /// the choice can be judged before committing to it.
    fn theme_row(&mut self, frame: &mut Frame, area: Rect) {
        if area.height == 0 {
            return;
        }
        let id = ComponentId::SettingThemeCycle;
        self.interaction.register_hit_box(id, area);
        let hovered = self.interaction.is_hovered(id);
        let theme = self.theme;
        let swatch = |c: Color| Span::styled("██", Style::default().fg(c));
        let mut spans = vec![
            Span::styled(
                format!(" {:<LABEL_WIDTH$}", "Theme"),
                Style::default().fg(if hovered {
                    theme.accent_bright
                } else {
                    theme.text
                }),
            ),
            Span::styled(
                format!("{:<VALUE_WIDTH$}", theme.id.label()),
                Style::default()
                    .fg(theme.accent_bright)
                    .add_modifier(Modifier::BOLD),
            ),
        ];
        if hint_width(area) >= 12 {
            spans.extend([
                swatch(theme.accent),
                swatch(theme.ok),
                swatch(theme.info),
                swatch(theme.warn),
                swatch(theme.err),
                Span::raw("  "),
            ]);
            spans.push(Span::styled(
                truncate(theme.id.blurb(), hint_width(area).saturating_sub(12)),
                Style::default().fg(theme.muted),
            ));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(if hovered {
                Style::default().bg(theme.surface_hi)
            } else {
                Style::default()
            }),
            area,
        );
    }

    /// A row whose value is a binary state.
    ///
    /// The on/off labels differ per setting ("ENABLED"/"DISABLED" for TUN,
    /// "TLS/HTTP/QUIC"/"DISABLED" for sniffing), so they are passed in rather
    /// than hard-coded.
    #[allow(clippy::too_many_arguments)]
    fn toggle_row(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        id: ComponentId,
        label: &str,
        on: bool,
        on_text: &str,
        off_text: &str,
    ) {
        let color = if on { self.theme.ok } else { self.theme.muted };
        let text = if on { on_text } else { off_text };
        self.setting_line(frame, area, id, label, text, color, "click to toggle");
    }

    /// A row whose value is clicked to edit or cycle.
    #[allow(clippy::too_many_arguments)]
    fn value_row(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        id: ComponentId,
        label: &str,
        value: &str,
        color: Color,
        hint: &str,
    ) {
        self.setting_line(frame, area, id, label, value, color, hint);
    }

    #[allow(clippy::too_many_arguments)]
    fn setting_line(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        id: ComponentId,
        label: &str,
        value: &str,
        color: Color,
        hint: &str,
    ) {
        if area.height == 0 {
            return;
        }
        self.interaction.register_hit_box(id, area);
        let hovered = self.interaction.is_hovered(id);

        let line = Line::from(vec![
            Span::styled(
                format!(" {label:<LABEL_WIDTH$}"),
                Style::default().fg(if hovered {
                    self.theme.accent_bright
                } else {
                    self.theme.text
                }),
            ),
            Span::styled(
                format!("{value:<VALUE_WIDTH$}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            // Truncated rather than clipped: a hint cut mid-word by the panel
            // edge reads as a rendering fault, an ellipsis reads as "there is
            // more".
            Span::styled(
                truncate(hint, hint_width(area)),
                Style::default().fg(self.theme.muted),
            ),
        ]);

        frame.render_widget(
            Paragraph::new(vec![line]).style(if hovered {
                Style::default().bg(self.theme.surface_hi)
            } else {
                Style::default()
            }),
            area,
        );
    }

    /// A row with `[-] value [+]` controls.
    ///
    /// Takes three component ids because each of the three controls is
    /// separately clickable; bundling them into a struct would only move the
    /// same information one level down.
    #[allow(clippy::too_many_arguments)]
    fn stepper_row(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        label: &str,
        value: &str,
        minus: ComponentId,
        value_id: ComponentId,
        plus: ComponentId,
        color: Color,
        hint: &str,
    ) {
        if area.height == 0 {
            return;
        }
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(LABEL_WIDTH as u16 + 1),
                Constraint::Length(4),
                Constraint::Length(11),
                Constraint::Length(4),
                Constraint::Min(0),
            ])
            .split(area);

        self.interaction.register_hit_box(minus, chunks[1]);
        self.interaction.register_hit_box(value_id, chunks[2]);
        self.interaction.register_hit_box(plus, chunks[3]);

        frame.render_widget(
            Paragraph::new(format!(" {label}")).style(Style::default().fg(self.theme.text)),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new("[-]").style(self.stepper_style(minus)),
            chunks[1],
        );
        frame.render_widget(
            Paragraph::new(format!("{value:^9}")).style(if self.interaction.is_hovered(value_id) {
                self.theme.card_hover_style()
            } else {
                Style::default().fg(color).add_modifier(Modifier::BOLD)
            }),
            chunks[2],
        );
        frame.render_widget(
            Paragraph::new("[+]").style(self.stepper_style(plus)),
            chunks[3],
        );
        frame.render_widget(
            Paragraph::new(truncate(hint, hint_width(area)))
                .style(Style::default().fg(self.theme.muted)),
            chunks[4],
        );
    }

    fn stepper_style(&self, id: ComponentId) -> Style {
        if self.interaction.is_hovered(id) {
            Style::default()
                .bg(self.theme.accent)
                .fg(self.theme.bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.theme.accent)
        }
    }
}

/// Columns left for a settings row's hint text, after its label and value.
fn hint_width(area: Rect) -> usize {
    (area.width as usize).saturating_sub(LABEL_WIDTH + 1 + VALUE_WIDTH)
}

/// Position `count` single-line rows inside `area`, scrolled by `shift`.
///
/// Rows are always double-spaced: cramming them together to fit was what made
/// the settings page unreadable, and the page scrolls instead.
///
/// A row that falls outside the panel comes back zero-height, which every
/// renderer here treats as "skip" — so nothing is drawn or made clickable
/// outside the panel.
fn rows_for(area: Rect, count: usize, shift: i32) -> Vec<Rect> {
    const SPACING: i32 = 2;
    let hidden = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 0,
    };

    (0..count)
        .map(|i| {
            let y = area.y as i32 + i as i32 * SPACING - shift;
            if y < area.y as i32 || y >= (area.y + area.height) as i32 {
                hidden
            } else {
                Rect {
                    x: area.x,
                    y: y as u16,
                    width: area.width,
                    height: 1,
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area() -> Rect {
        Rect {
            x: 2,
            y: 3,
            width: 40,
            height: 24,
        }
    }

    #[test]
    fn rows_are_always_double_spaced() {
        // Squeezing rows together to fit is what made the page unreadable.
        let rows = rows_for(area(), SETTINGS_ROWS, 0);
        assert_eq!(rows.len(), SETTINGS_ROWS);
        assert_eq!(rows[0].y, 3);
        assert_eq!(rows[1].y, 5);
        assert!(rows.iter().all(|r| r.height <= 1));
    }

    #[test]
    fn scrolling_moves_the_rows_up() {
        let rows = rows_for(area(), SETTINGS_ROWS, 4);
        // The first two rows have scrolled off the top.
        assert_eq!(rows[0].height, 0);
        assert_eq!(rows[1].height, 0);
        assert_eq!(rows[2].y, 3, "the third row should now be at the top");
    }

    #[test]
    fn rows_outside_the_panel_are_collapsed_not_clipped() {
        // A zero-height rect is skipped by the renderers rather than drawing
        // outside the panel or registering a hit region there.
        let short = Rect {
            height: 5,
            ..area()
        };
        let rows = rows_for(short, SETTINGS_ROWS, 0);
        assert!(rows.iter().any(|r| r.height == 0));
        for r in &rows {
            assert!(
                r.height == 0 || (r.y >= short.y && r.y < short.y + short.height),
                "row escaped the panel: {r:?}"
            );
        }
    }

    #[test]
    fn every_row_is_reachable_by_scrolling() {
        // The page must not hide a setting with no way to reach it.
        let short = Rect {
            height: 6,
            ..area()
        };
        let max = crate::scroll::max_offset(
            UiRenderer::settings_content_height_for(true),
            short.height as usize,
        );
        let mut seen = std::collections::HashSet::new();
        for shift in 0..=max as i32 {
            for (i, r) in rows_for(short, SETTINGS_ROWS, shift).iter().enumerate() {
                if r.height > 0 {
                    seen.insert(i);
                }
            }
        }
        assert_eq!(
            seen.len(),
            SETTINGS_ROWS,
            "only {} of {SETTINGS_ROWS} rows can be scrolled to",
            seen.len()
        );
    }
}
