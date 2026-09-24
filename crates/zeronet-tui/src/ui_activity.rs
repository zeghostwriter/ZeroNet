//! The Activity page: what the client costs, next to everything else.
//!
//! Four cards across the top (this client's CPU and memory with their
//! recent history, then the machine's), one plain sentence placing the
//! client among the running apps, and the app list itself with the client's
//! row always visible and marked.

use crate::interaction::ComponentId;
use crate::ui::{truncate, UiRenderer};
use crate::usage::{format_cpu, format_memory, AppUsage, SystemUsage};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

/// Which column the app list is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivitySort {
    #[default]
    Cpu,
    Memory,
}

/// Everything the Activity page and the status bar read, borrowed from the
/// monitor so tests can hand in fixed numbers.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageView<'a> {
    pub snapshot: Option<&'a crate::usage::UsageSnapshot>,
    pub cpu_history: &'a [f32],
    pub memory_history: &'a [u64],
    pub system_history: &'a [f32],
    pub sort: ActivitySort,
}

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// A one-row bar graph of `values`, newest on the right, scaled to `ceiling`
/// (or to the largest value when that is higher).
pub(crate) fn spark(values: &[f64], width: usize, ceiling: f64) -> String {
    if width == 0 {
        return String::new();
    }
    let recent = &values[values.len().saturating_sub(width)..];
    let top = recent
        .iter()
        .copied()
        .fold(ceiling, f64::max)
        .max(f64::EPSILON);
    let mut out = String::with_capacity(width * 3);
    for _ in recent.len()..width {
        out.push(' ');
    }
    for v in recent {
        let level = ((v / top) * (BARS.len() - 1) as f64).round() as usize;
        out.push(BARS[level.min(BARS.len() - 1)]);
    }
    out
}

/// `━━━━━━────` filled to `fraction`, as two spans so the parts can differ
/// in colour.
fn meter(fraction: f64, width: usize, fill: Color, rest: Color) -> Vec<Span<'static>> {
    let filled = ((fraction.clamp(0.0, 1.0)) * width as f64).round() as usize;
    vec![
        Span::styled("━".repeat(filled), Style::default().fg(fill)),
        Span::styled(
            "─".repeat(width - filled.min(width)),
            Style::default().fg(rest),
        ),
    ]
}

impl UiRenderer<'_> {
    pub(crate) fn render_activity(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),
                Constraint::Length(2),
                Constraint::Min(5),
            ])
            .split(area);
        self.render_usage_cards(frame, chunks[0]);
        self.render_usage_summary(frame, chunks[1]);
        self.render_app_list(frame, chunks[2]);
    }

    fn usage_card(&self, title: &str) -> Block<'static> {
        Block::default()
            .title(format!(" {title} "))
            .title_style(
                Style::default()
                    .fg(self.theme.muted)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style())
    }

    fn render_usage_cards(&mut self, frame: &mut Frame, area: Rect) {
        let cards = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 4); 4])
            .split(area);
        let view = self.usage;
        let snapshot = view.snapshot;
        let system = snapshot.and_then(|s| s.system.as_ref());
        let pending = || Line::styled("measuring…", Style::default().fg(self.theme.muted));

        // This client's CPU, with its history.
        let block = self.usage_card("ZERONET · CPU");
        let inner = block.inner(cards[0]);
        frame.render_widget(block, cards[0]);
        let width = inner.width.saturating_sub(2) as usize;
        let lines = match snapshot {
            Some(s) => {
                let history: Vec<f64> = view.cpu_history.iter().map(|v| *v as f64).collect();
                vec![
                    Line::styled(
                        format_cpu(s.self_cpu),
                        Style::default()
                            .fg(self.theme.accent_bright)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::styled(
                        "of the whole machine",
                        Style::default().fg(self.theme.muted),
                    ),
                    Line::from(""),
                    Line::styled(
                        spark(&history, width, 5.0),
                        Style::default().fg(self.theme.accent),
                    ),
                ]
            }
            None => vec![pending()],
        };
        frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);

        // This client's memory.
        let block = self.usage_card("ZERONET · MEMORY");
        let inner = block.inner(cards[1]);
        frame.render_widget(block, cards[1]);
        let width = inner.width.saturating_sub(2) as usize;
        let lines = match snapshot {
            Some(s) => {
                let history: Vec<f64> = view.memory_history.iter().map(|v| *v as f64).collect();
                let detail = match s.self_threads {
                    Some(threads) => format!("{threads} threads"),
                    None => "resident".to_string(),
                };
                vec![
                    Line::styled(
                        format_memory(s.self_memory),
                        Style::default()
                            .fg(self.theme.info)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::styled(detail, Style::default().fg(self.theme.muted)),
                    Line::from(""),
                    Line::styled(
                        spark(&history, width, 0.0),
                        Style::default().fg(self.theme.info),
                    ),
                ]
            }
            None => vec![pending()],
        };
        frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);

        // The machine's CPU.
        let block = self.usage_card("SYSTEM · CPU");
        let inner = block.inner(cards[2]);
        frame.render_widget(block, cards[2]);
        let width = inner.width.saturating_sub(2) as usize;
        let lines = match system {
            Some(sys) => {
                let history: Vec<f64> = view.system_history.iter().map(|v| *v as f64).collect();
                vec![
                    Line::styled(
                        format_cpu(sys.cpu),
                        Style::default()
                            .fg(self.load_color(sys.cpu as f64 / 100.0))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::styled(
                        format!("{} cores · {} processes", sys.cores, sys.process_count),
                        Style::default().fg(self.theme.muted),
                    ),
                    Line::from(""),
                    Line::styled(
                        spark(&history, width, 100.0),
                        Style::default().fg(self.theme.muted),
                    ),
                ]
            }
            None => vec![pending()],
        };
        frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);

        // The machine's memory.
        let block = self.usage_card("SYSTEM · MEMORY");
        let inner = block.inner(cards[3]);
        frame.render_widget(block, cards[3]);
        let width = inner.width.saturating_sub(2) as usize;
        let lines = match system {
            Some(sys) => {
                let fraction = if sys.memory_total == 0 {
                    0.0
                } else {
                    sys.memory_used as f64 / sys.memory_total as f64
                };
                vec![
                    Line::styled(
                        format!("{:.0}%", fraction * 100.0),
                        Style::default()
                            .fg(self.load_color(fraction))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::styled(
                        format!(
                            "{} of {}",
                            format_memory(sys.memory_used),
                            format_memory(sys.memory_total)
                        ),
                        Style::default().fg(self.theme.muted),
                    ),
                    Line::from(""),
                    Line::from(meter(
                        fraction,
                        width,
                        self.load_color(fraction),
                        self.theme.border,
                    )),
                ]
            }
            None => vec![pending()],
        };
        frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
    }

    /// Green while there is headroom, amber when busy, red when saturated.
    fn load_color(&self, fraction: f64) -> Color {
        if fraction < 0.6 {
            self.theme.ok
        } else if fraction < 0.85 {
            self.theme.warn
        } else {
            self.theme.err
        }
    }

    fn render_usage_summary(&mut self, frame: &mut Frame, area: Rect) {
        let system = self.usage.snapshot.and_then(|s| s.system.as_ref());
        let text = match system.and_then(SystemUsage::self_rank) {
            Some((by_cpu, by_memory, apps)) => {
                format!(" ZeroNet is #{by_cpu} of {apps} apps by CPU and #{by_memory} by memory.")
            }
            None => " Reading the process list…".to_string(),
        };
        let traffic = format!(
            "Tunnel  ▲ {}  ▼ {} ",
            crate::ui::format_speed(self.stats.upload_speed_bps),
            crate::ui::format_speed(self.stats.download_speed_bps)
        );
        let room = (area.width as usize).saturating_sub(traffic.width() + 2);
        let line = Line::from(vec![
            Span::styled(
                format!("{:<room$}", truncate(&text, room)),
                Style::default().fg(self.theme.text),
            ),
            Span::styled(traffic, Style::default().fg(self.theme.muted)),
        ]);
        frame.render_widget(Paragraph::new(vec![Line::from(""), line]), area);
    }

    fn render_app_list(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" APPS ")
            .title_style(self.theme.title_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border))
            .style(self.theme.card_style());
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height < 2 || inner.width < 30 {
            return;
        }

        let Some(system) = self.usage.snapshot.and_then(|s| s.system.as_ref()) else {
            frame.render_widget(
                Paragraph::new(Line::styled(
                    "Waiting for the first sample.",
                    Style::default().fg(self.theme.muted),
                ))
                .alignment(Alignment::Center),
                inner,
            );
            return;
        };

        // Columns: name | bar | cpu | memory | processes.
        let cpu_w = 7usize;
        let mem_w = 10usize;
        let proc_w = 6usize;
        let fixed = cpu_w + mem_w + proc_w + 4;
        let rest = (inner.width as usize).saturating_sub(fixed);
        let bar_w = (rest / 3).clamp(4, 24);
        let name_w = rest.saturating_sub(bar_w + 1).max(8);

        let sort = self.usage.sort;
        let header_y = inner.y;
        let arrow = |col: ActivitySort| if sort == col { " ▼" } else { "  " };
        let head_style = Style::default()
            .fg(self.theme.muted)
            .add_modifier(Modifier::BOLD);
        let cpu_head_x = inner.x + (1 + name_w + 1 + bar_w) as u16;
        let mem_head_x = cpu_head_x + cpu_w as u16 + 1;
        let cpu_head = Rect::new(cpu_head_x, header_y, cpu_w as u16 + 1, 1);
        let mem_head = Rect::new(mem_head_x, header_y, mem_w as u16 + 1, 1);
        self.interaction
            .register_hit_box(ComponentId::ActivitySortCpu, cpu_head.intersection(inner));
        self.interaction.register_hit_box(
            ComponentId::ActivitySortMemory,
            mem_head.intersection(inner),
        );
        let hot = |id: ComponentId, this: &Self| {
            if this.interaction.is_hovered(id) {
                head_style.fg(this.theme.accent_bright)
            } else {
                head_style
            }
        };
        let header = Line::from(vec![
            Span::styled(format!(" {:<name_w$} {:<bar_w$}", "Name", ""), head_style),
            Span::styled(
                format!(
                    "{:>w$}",
                    format!("CPU{}", arrow(ActivitySort::Cpu)),
                    w = cpu_w
                ),
                hot(ComponentId::ActivitySortCpu, self),
            ),
            Span::raw(" "),
            Span::styled(
                format!(
                    "{:>w$}",
                    format!("Memory{}", arrow(ActivitySort::Memory)),
                    w = mem_w
                ),
                hot(ComponentId::ActivitySortMemory, self),
            ),
            Span::styled(format!(" {:>proc_w$}", "Procs"), head_style),
        ]);
        frame.render_widget(
            Paragraph::new(header),
            Rect::new(inner.x, header_y, inner.width, 1),
        );

        let mut ordered: Vec<&AppUsage> = system.apps.iter().collect();
        if sort == ActivitySort::Memory {
            ordered.sort_by(|a, b| b.memory.cmp(&a.memory).then_with(|| a.name.cmp(&b.name)));
        }
        let rows = (inner.height - 1) as usize;
        let self_at = ordered.iter().position(|a| a.is_self);
        // The client's own row stays on screen even when it ranks far down:
        // the last visible row is given to it, after a gap marker.
        let pin_self = matches!(self_at, Some(i) if i >= rows) && rows >= 3;
        let shown = if pin_self { rows - 2 } else { rows };

        let top_cpu = ordered.iter().map(|a| a.cpu as f64).fold(1.0, f64::max);
        let top_mem = ordered.iter().map(|a| a.memory as f64).fold(1.0, f64::max);
        let mut y = header_y + 1;
        let draw = |app: &AppUsage, y: u16, this: &mut Self, frame: &mut Frame| {
            let (value, top, fill) = match sort {
                ActivitySort::Cpu => (app.cpu as f64, top_cpu, this.theme.accent),
                ActivitySort::Memory => (app.memory as f64, top_mem, this.theme.info),
            };
            let name_style = if app.is_self {
                Style::default()
                    .fg(this.theme.accent_bright)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(this.theme.text)
            };
            let label = if app.is_self {
                format!("{}  ◂ this app", app.name)
            } else {
                app.name.clone()
            };
            let mut spans = vec![Span::styled(
                format!(" {:<name_w$} ", truncate(&label, name_w)),
                name_style,
            )];
            spans.extend(meter(value / top, bar_w, fill, this.theme.surface_hi));
            spans.push(Span::styled(
                format!("{:>cpu_w$}", format_cpu(app.cpu)),
                Style::default().fg(this.theme.text),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                format!("{:>mem_w$}", format_memory(app.memory)),
                Style::default().fg(this.theme.text),
            ));
            spans.push(Span::styled(
                format!(" {:>proc_w$}", app.processes),
                Style::default().fg(this.theme.muted),
            ));
            let row_style = if app.is_self {
                Style::default().bg(this.theme.surface_hi)
            } else {
                Style::default()
            };
            frame.render_widget(
                Paragraph::new(Line::from(spans)).style(row_style),
                Rect::new(inner.x, y, inner.width, 1),
            );
        };
        for app in ordered.iter().take(shown) {
            draw(app, y, self, frame);
            y += 1;
        }
        if pin_self {
            if let Some(i) = self_at {
                frame.render_widget(
                    Paragraph::new(Line::styled(
                        format!(" ⋮  {} more", i - shown),
                        Style::default().fg(self.theme.muted),
                    )),
                    Rect::new(inner.x, y, inner.width, 1),
                );
                draw(ordered[i], y + 1, self, frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spark_is_exactly_as_wide_as_asked() {
        assert_eq!(spark(&[], 5, 1.0), "     ");
        assert_eq!(spark(&[1.0, 2.0], 5, 0.0).chars().count(), 5);
        let long: Vec<f64> = (0..100).map(|v| v as f64).collect();
        let s = spark(&long, 10, 0.0);
        assert_eq!(s.chars().count(), 10);
        assert!(s.ends_with('█'), "the newest, largest value is full height");
    }

    #[test]
    fn a_quiet_history_stays_low_against_its_ceiling() {
        let s = spark(&[0.1, 0.2, 0.1], 3, 5.0);
        assert!(s.chars().all(|c| c == '▁'), "{s}");
    }

    #[test]
    fn a_meter_never_overflows() {
        let spans = meter(3.0, 10, Color::Red, Color::Gray);
        let width: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        assert_eq!(width, 10);
        let spans = meter(-1.0, 10, Color::Red, Color::Gray);
        let width: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        assert_eq!(width, 10);
    }
}
