//! Rendering smoke tests.
//!
//! Drives the real renderer against a `TestBackend` so layout regressions and
//! panics are caught without a terminal. Set `ZERONET_DUMP_FRAMES=<dir>` to
//! write each rendered frame out as text for eyeballing.

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use throbber_widgets_tui::ThrobberState;

use zeronet_tui::caps::{ColorDepth, TerminalCaps};
use zeronet_tui::daemon::{ConnectionStatus, DaemonStats};
use zeronet_tui::db::{AppSettings, ConfigRecord, SubscriptionRecord};
use zeronet_tui::effects::VisualEffects;
use zeronet_tui::interaction::{ComponentId, InteractionEngine};
use zeronet_tui::modal::ModalState;
use zeronet_tui::theme::Theme;
use zeronet_tui::toast::ToastManager;
use zeronet_tui::ui::{ActiveTab, UiRenderer};

/// Everything a frame needs, owned, so tests can tweak one field at a time.
struct Harness {
    caps: TerminalCaps,
    theme: Theme,
    interaction: InteractionEngine,
    effects: VisualEffects,
    toasts: ToastManager,
    throbber: ThrobberState,
    settings: AppSettings,
    stats: DaemonStats,
    configs: Vec<ConfigRecord>,
    subscriptions: Vec<SubscriptionRecord>,
    modal_state: ModalState,
    active_tab: ActiveTab,
    selected_config_idx: usize,
    latency_history: Vec<f64>,
    marked: std::collections::HashSet<i64>,
    filter: String,
    filter_focused: bool,
    advanced_open: bool,
    system_proxy: zeronet_tui::sysproxy::SystemProxyMode,
    modal_anim: zeronet_tui::modal_anim::ModalAnimator,
    settings_scroll: zeronet_tui::scroll::ScrollState,
    help_scroll: zeronet_tui::scroll::ScrollState,
    context_menu: Option<zeronet_tui::ctxmenu::ContextMenu>,
    drag: Option<zeronet_tui::dragselect::DragSelect>,
    usage: Option<zeronet_tui::usage::UsageSnapshot>,
    cpu_history: Vec<f32>,
    activity_sort: zeronet_tui::ui_activity::ActivitySort,
    finder_status: Option<String>,
}

impl Harness {
    fn new() -> Self {
        let caps = TerminalCaps {
            depth: ColorDepth::TrueColor,
            animations: true,
            remote: false,
        };
        Self {
            caps,
            theme: Theme::from_caps(&caps),
            interaction: InteractionEngine::new(),
            effects: VisualEffects::with_caps(caps.depth, caps.animations),
            toasts: ToastManager::new(),
            throbber: ThrobberState::default(),
            settings: AppSettings::default(),
            stats: DaemonStats::default(),
            configs: sample_configs(),
            subscriptions: Vec::new(),
            modal_state: ModalState::None,
            active_tab: ActiveTab::Dashboard,
            selected_config_idx: 0,
            latency_history: vec![42.0, 51.0, 38.0, 77.0, 45.0],
            marked: std::collections::HashSet::new(),
            filter: String::new(),
            filter_focused: false,
            advanced_open: false,
            system_proxy: zeronet_tui::sysproxy::SystemProxyMode::Unmanaged,
            // Settled by default, so a test that only cares about layout does
            // not have to drive the animation to completion first.
            modal_anim: zeronet_tui::modal_anim::ModalAnimator::default(),
            settings_scroll: zeronet_tui::scroll::ScrollState::new(),
            help_scroll: zeronet_tui::scroll::ScrollState::new(),
            context_menu: None,
            drag: None,
            usage: None,
            cpu_history: Vec::new(),
            activity_sort: Default::default(),
            finder_status: None,
        }
    }

    /// Render one frame into an existing `Frame`, for tests that need the
    /// buffer's colours rather than its text.
    fn render_into(&mut self, frame: &mut ratatui::Frame) {
        let mut renderer = UiRenderer {
            theme: &self.theme,
            caps: &self.caps,
            interaction: &mut self.interaction,
            effects: &mut self.effects,
            settings: &self.settings,
            stats: &self.stats,
            active_tab: self.active_tab,
            configs: &self.configs,
            subscriptions: &self.subscriptions,
            selected_config_idx: self.selected_config_idx,
            node_scroll: 0,
            marked: &self.marked,
            filter: &self.filter,
            filter_focused: self.filter_focused,
            advanced_open: self.advanced_open,
            filter_select_all: false,
            inline_rename: None,
            system_proxy: self.system_proxy,
            modal_anim: self.modal_anim,
            settings_scroll: self.settings_scroll,
            help_scroll: self.help_scroll,
            selection_tick: 0,
            context_menu: self.context_menu.as_ref(),
            drag: self.drag,
            latency_history: &self.latency_history,
            is_elevated: false,
            elevation_prompt: None,
            modal_state: &self.modal_state,
            image_view: None,
            throbber_state: &mut self.throbber,
            scanner_tested: 1280,
            scanner_healthy: 37,
            scanner_speed: 91.4,
            is_scanning: false,
            scanner_results: &[],
            toasts: &mut self.toasts,
            usage: zeronet_tui::ui_activity::UsageView {
                snapshot: self.usage.as_ref(),
                cpu_history: &self.cpu_history,
                memory_history: &[],
                system_history: &[],
                sort: self.activity_sort,
            },
            perf: None,
            session: None,
            speed_history: (&[], &[]),
            update_status: &zeronet_tui::update::Status::Idle,
            finder_status: self.finder_status.clone(),
        };
        renderer.render(frame);
    }

    fn draw(&mut self, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                let mut renderer = UiRenderer {
                    theme: &self.theme,
                    caps: &self.caps,
                    interaction: &mut self.interaction,
                    effects: &mut self.effects,
                    settings: &self.settings,
                    stats: &self.stats,
                    active_tab: self.active_tab,
                    configs: &self.configs,
                    subscriptions: &self.subscriptions,
                    selected_config_idx: self.selected_config_idx,
                    node_scroll: 0,
                    marked: &self.marked,
                    filter: &self.filter,
                    filter_focused: self.filter_focused,
                    advanced_open: self.advanced_open,
                    filter_select_all: false,
                    inline_rename: None,
                    system_proxy: self.system_proxy,
                    modal_anim: self.modal_anim,
                    settings_scroll: self.settings_scroll,
                    help_scroll: self.help_scroll,
                    selection_tick: 0,
                    context_menu: self.context_menu.as_ref(),
                    drag: self.drag,
                    latency_history: &self.latency_history,
                    is_elevated: false,
                    elevation_prompt: None,
                    modal_state: &self.modal_state,
                    image_view: None,
                    throbber_state: &mut self.throbber,
                    scanner_tested: 1280,
                    scanner_healthy: 37,
                    scanner_speed: 91.4,
                    is_scanning: false,
                    scanner_results: &[],
                    toasts: &mut self.toasts,
                    usage: zeronet_tui::ui_activity::UsageView {
                        snapshot: self.usage.as_ref(),
                        cpu_history: &self.cpu_history,
                        memory_history: &[],
                        system_history: &[],
                        sort: self.activity_sort,
                    },
                    perf: None,
                    session: None,
                    speed_history: (&[], &[]),
                    update_status: &zeronet_tui::update::Status::Idle,
            finder_status: self.finder_status.clone(),
                };
                renderer.render(frame);
            })
            .unwrap();

        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }
}

fn config(id: i64, remark: &str, address: &str, port: u16, ping: Option<f64>) -> ConfigRecord {
    ConfigRecord {
        id,
        remark: remark.into(),
        protocol: "vless".into(),
        address: address.into(),
        port,
        raw_content: "{}".into(),
        is_active: id == 1,
        subscription_id: None,
        ping_ms: ping,
        last_used: None,
        origin: if id == 3 { "found".into() } else { "user".into() },
    }
}

fn sample_configs() -> Vec<ConfigRecord> {
    vec![
        config(
            1,
            "AmneziaVPN (VLESS-Reality)",
            "155.117.13.26",
            443,
            Some(48.0),
        ),
        // Two rows with the same name, which the table must disambiguate.
        config(2, "Iran Clean Edge", "104.16.132.229", 443, Some(180.0)),
        config(3, "Iran Clean Edge", "172.67.140.194", 8443, Some(410.0)),
        config(4, "Germany Edge 01", "104.21.45.10", 443, None),
    ]
}

fn dump(name: &str, frame: &str) {
    if let Ok(dir) = std::env::var("ZERONET_DUMP_FRAMES") {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(format!("{dir}/{name}.txt"), frame);
    }
}

#[test]
fn dashboard_renders_at_a_standard_size() {
    let mut h = Harness::new();
    let frame = h.draw(120, 40);
    dump("dashboard_idle", &frame);

    assert!(frame.contains("ZERONET"), "wordmark missing");
    assert!(frame.contains("DISCONNECTED"), "status pill missing");
    assert!(frame.contains(" SERVERS "));
    // The footer key caps.
    assert!(frame.contains("Connect"));
    assert!(frame.contains("Quit"));
}

#[test]
fn connected_state_shows_the_connected_orb_and_pill() {
    let mut h = Harness::new();
    h.stats.status = ConnectionStatus::Connected;
    h.stats.active_node_name = "AmneziaVPN".into();
    h.stats.tun_active = true;
    let frame = h.draw(120, 40);
    dump("dashboard_connected", &frame);

    assert!(frame.contains("CONNECTED"));
    assert!(frame.contains("TUN ON"));
    assert!(
        !frame.contains("click the ring"),
        "the orb hint should be gone"
    );
}

#[test]
fn tun_enabled_but_inactive_is_reported_as_failed_while_connected() {
    // The honest-reporting case: the proxy is up but TUN never came up, so
    // the chip must not claim the system is tunnelled.
    let mut h = Harness::new();
    h.settings.tun_enabled = true;
    h.stats.status = ConnectionStatus::Connected;
    h.stats.tun_active = false;
    let frame = h.draw(120, 40);
    dump("dashboard_tun_failed", &frame);
    assert!(
        frame.contains("TUN FAILED"),
        "expected an explicit TUN failure chip"
    );
}

#[test]
fn error_state_surfaces_the_reason_in_the_header() {
    let mut h = Harness::new();
    h.stats.status = ConnectionStatus::Error;
    h.stats.error_msg = Some("Address already in use (os error 98)".into());
    let frame = h.draw(120, 40);
    dump("dashboard_error", &frame);

    assert!(frame.contains("ERROR"));
    assert!(
        frame.contains("Address already in use"),
        "the failure reason must be visible, not just stored"
    );
}

#[test]
fn duplicate_profile_names_are_disambiguated_by_endpoint() {
    let mut h = Harness::new();
    let frame = h.draw(140, 40);
    dump("nodes_duplicates", &frame);

    // Both "Iran Clean Edge" rows carry their own host so they can be told
    // apart; the unique names are left clean.
    assert!(
        frame.contains("104.16.132.229"),
        "first duplicate not labelled"
    );
    assert!(
        frame.contains("172.67.140.194"),
        "second duplicate not labelled"
    );
    assert!(
        !frame.contains("155.117.13.26"),
        "a unique name should not be cluttered with its host"
    );
}

#[test]
fn latency_readings_and_bars_are_rendered() {
    let mut h = Harness::new();
    let frame = h.draw(140, 40);
    assert!(frame.contains("48ms"), "fast node's ping missing");
    assert!(frame.contains("180ms"));
    assert!(frame.contains("410ms"));
    assert!(frame.contains("---"), "unmeasured node should show a dash");
    assert!(frame.contains('▇'), "latency bar glyphs missing");
}

#[test]
fn an_open_dialog_blocks_the_ui_behind_it() {
    let mut h = Harness::new();

    // Baseline: with no dialog, the connect orb is clickable.
    h.draw(120, 40);
    let orb_hit = h
        .interaction
        .hit_test(60, 20)
        .or_else(|| h.interaction.hit_test(60, 18));
    assert!(
        orb_hit.is_some(),
        "expected something clickable in the middle of the dashboard"
    );

    h.modal_state = ModalState::TextInput {
        title: "Import Config".into(),
        prompt: "Paste a share link".into(),
        buffer: "vless://example".into(),
        purpose: zeronet_tui::modal::TextPurpose::ImportConfig,
        created_tick: 0,
        select_all: false,
    };
    let frame = h.draw(120, 40);
    dump("modal_text_input", &frame);
    assert!(frame.contains("Import Config"));

    // A click in the top-left corner is behind the dialog. It reaches the
    // backdrop — which dismisses the dialog — and never the sidebar beneath.
    assert_eq!(
        h.interaction.hit_test(2, 5),
        Some(ComponentId::ModalBackdrop),
        "clicks behind an open dialog must be captured by the backdrop"
    );
    assert_ne!(
        h.interaction.hit_test(2, 5),
        Some(ComponentId::NavDashboard)
    );
    // The dialog's own confirm button still works.
    assert!(h.interaction.modal_layer_active());
    let confirm_found = (0..40)
        .flat_map(|y| (0..120).map(move |x| (x, y)))
        .any(|(x, y)| h.interaction.hit_test(x, y) == Some(ComponentId::ModalConfirm));
    assert!(confirm_found, "the dialog's confirm button is unreachable");
}

#[test]
fn quit_confirmation_renders_both_choices() {
    let mut h = Harness::new();
    h.modal_state = ModalState::QuitConfirmation { created_tick: 0 };
    let frame = h.draw(120, 40);
    dump("modal_quit", &frame);
    assert!(frame.contains("Quit ZeroNet?"));
    assert!(frame.contains("Exit"));
    assert!(frame.contains("Stay"));
}

fn update_dialog(phase: zeronet_tui::modal::UpdatePhase) -> ModalState {
    ModalState::Update {
        release: Box::new(zeronet_tui::update::Release {
            version: "9.9.9".into(),
            page: "https://github.com/zeghostwriter/ZeroNet/releases/tag/v9.9.9".into(),
            notes: vec![
                "Server tests: survive forged DNS".into(),
                "README: fix right-to-left layout".into(),
            ],
            asset: Some(zeronet_tui::update::Asset {
                name: "ZeroNet-Linux-x64".into(),
                url: "https://example.invalid/ZeroNet-Linux-x64".into(),
                size: 20 * 1024 * 1024,
                sha256: None,
            }),
        }),
        phase,
        created_tick: 0,
    }
}

#[test]
fn update_dialog_offers_the_new_version_and_what_changed() {
    use zeronet_tui::modal::UpdatePhase;
    let mut h = Harness::new();
    h.modal_state = update_dialog(UpdatePhase::Available);
    let frame = h.draw(120, 40);
    dump("modal_update", &frame);
    assert!(frame.contains("ZeroNet 9.9.9 is out"));
    assert!(frame.contains(zeronet_tui::update::CURRENT_VERSION));
    assert!(frame.contains("WHAT'S NEW"));
    assert!(frame.contains("Server tests: survive forged DNS"));
    assert!(frame.contains("20.0 MB download"));
    assert!(frame.contains("Update now"));
    assert!(frame.contains("Later"));
}

#[test]
fn update_dialog_follows_the_download_to_the_restart() {
    use zeronet_tui::modal::UpdatePhase;
    let mut h = Harness::new();
    h.modal_state = update_dialog(UpdatePhase::Downloading {
        received: 5 * 1024 * 1024,
        total: 20 * 1024 * 1024,
    });
    let frame = h.draw(120, 40);
    dump("modal_update_downloading", &frame);
    assert!(frame.contains(" 25%"));
    assert!(frame.contains("5.0 MB of 20.0 MB"));
    assert!(frame.contains("Hide"));

    h.modal_state = update_dialog(UpdatePhase::Installed);
    let frame = h.draw(120, 40);
    assert!(frame.contains("ZeroNet 9.9.9 is installed"));
    assert!(frame.contains("Restart now"));

    h.modal_state = update_dialog(UpdatePhase::Failed("the download is damaged".into()));
    let frame = h.draw(120, 40);
    assert!(frame.contains("the download is damaged"));
    assert!(frame.contains("Try again"));
}

#[test]
fn update_dialog_fits_a_small_terminal() {
    use zeronet_tui::modal::UpdatePhase;
    for (w, h_) in [(64, 18), (72, 20), (80, 24)] {
        let mut h = Harness::new();
        h.modal_state = update_dialog(UpdatePhase::Downloading {
            received: 1,
            total: 3,
        });
        let frame = h.draw(w, h_);
        assert!(frame.contains("9.9.9"), "{w}x{h_} lost the version");
    }
}

#[test]
fn settings_tab_renders_every_column() {
    let mut h = Harness::new();
    h.active_tab = ActiveTab::Settings;
    h.advanced_open = true;
    let frame = h.draw(140, 40);
    dump("settings", &frame);

    assert!(frame.contains("⚙ SETTINGS"));
    assert!(frame.contains("TUN Interface"));
    assert!(frame.contains("SOCKS5 Port"));

    // One column, so later rows sit below the fold and have to be scrolled to.
    let max = zeronet_tui::scroll::max_offset(
        zeronet_tui::ui::UiRenderer::settings_content_height_for(true),
        40 - 6,
    );
    h.settings_scroll.step(max as i32, max);
    let bottom = h.draw(140, 40);
    dump("settings_bottom", &bottom);
    assert!(bottom.contains("Scanner Workers"));
    let everything = settings_text(&mut h, 140, 40);
    assert!(everything.contains("Animations"));
    assert!(everything.contains("Theme"));
    assert!(everything.contains("GOLDEN DARK"));
    assert!(everything.contains("CPU / RAM in Status Bar"));
    // The read-only capability line.
    assert!(bottom.contains("truecolor"));
}

#[test]
fn scanner_and_subscription_tabs_render() {
    for tab in [ActiveTab::IpScanner, ActiveTab::Subscriptions] {
        let mut h = Harness::new();
        h.active_tab = tab;
        let frame = h.draw(120, 40);
        dump(&format!("tab_{tab:?}"), &frame);
        assert!(!frame.trim().is_empty());
    }
}

/// Unicode 16 changed the trigram and digram symbols from narrow to wide.
/// Terminals that follow it draw them two columns wide, while ratatui's width
/// table still counts one, so the terminal and ratatui's diff buffer drift
/// apart on that row and stale cells are left behind (the sidebar once did
/// exactly this with ☵).
fn width_changed_in_unicode_16(c: char) -> bool {
    matches!(c, '\u{2630}'..='\u{2637}' | '\u{268A}'..='\u{268F}')
}

#[test]
fn no_screen_uses_a_glyph_whose_width_terminals_disagree_on() {
    for tab in [
        ActiveTab::Dashboard,
        ActiveTab::Subscriptions,
        ActiveTab::IpScanner,
        ActiveTab::Activity,
        ActiveTab::Settings,
    ] {
        let mut h = Harness::new();
        h.active_tab = tab;
        h.toasts.info("info toast");
        h.toasts.success("success toast");
        h.toasts.warning("warning toast");
        h.toasts.error("error toast");
        let frame = h.draw(140, 50);
        let bad: Vec<char> = frame
            .chars()
            .filter(|&c| width_changed_in_unicode_16(c))
            .collect();
        assert!(
            bad.is_empty(),
            "{tab:?} draws width-unstable glyphs {bad:?}"
        );
    }
}

#[test]
fn rendering_survives_extreme_terminal_sizes() {
    // Resizing a terminal must never panic the client, however cramped.
    for (w, h_) in [
        (20u16, 8u16),
        (40, 12),
        (60, 20),
        (80, 24),
        (200, 60),
        (300, 100),
    ] {
        let mut h = Harness::new();
        h.stats.status = ConnectionStatus::Connecting;
        let _ = h.draw(w, h_);

        let mut h = Harness::new();
        h.active_tab = ActiveTab::Settings;
        h.modal_state = ModalState::ManualProfile {
            form: zeronet_tui::manual_profile::ManualProfileForm::new(),
            editing_text: false,
            input_buffer: String::new(),
            created_tick: 0,
        };
        let _ = h.draw(w, h_);
    }
}

#[test]
fn the_logo_never_takes_on_button_chrome_when_hovered() {
    let mut h = Harness::new();
    let plain = h.draw(120, 40);

    // Put the pointer over the wordmark and redraw.
    h.draw(120, 40); // register hit boxes first
    h.interaction.update_mouse_position(6, 1);
    let hovered = h.draw(120, 40);

    let first_line = |s: &str| s.lines().next().unwrap_or_default().to_string();
    assert_eq!(
        first_line(&plain),
        first_line(&hovered),
        "hovering the wordmark must not change its silhouette — only its colour"
    );
}

#[test]
fn a_256_color_terminal_renders_the_same_layout() {
    let mut h = Harness::new();
    h.caps = TerminalCaps {
        depth: ColorDepth::Ansi256,
        animations: false,
        remote: true,
    };
    h.theme = Theme::from_caps(&h.caps);
    h.effects = VisualEffects::with_caps(h.caps.depth, h.caps.animations);

    let frame = h.draw(120, 40);
    dump("dashboard_256", &frame);
    assert!(frame.contains("ZERONET"));
    assert!(frame.contains(" SERVERS "));
}

#[test]
fn the_help_overlay_lists_the_conventional_bindings() {
    let mut h = Harness::new();
    h.modal_state = ModalState::Help {
        scroll: 0,
        created_tick: 0,
    };
    let frame = h.draw(120, 40);
    dump("modal_help", &frame);

    assert!(frame.contains("KEYBOARD REFERENCE"));
    // The bindings a desktop user already knows.
    assert!(frame.contains("Ctrl+A"), "select-all binding missing");
    assert!(frame.contains("Select all"));
    assert!(frame.contains("Ctrl+C"));
    assert!(frame.contains("Ctrl+V"));
    assert!(frame.contains("Delete"));
    assert!(frame.contains("F2"));
}

#[test]
fn help_modal_text_never_exits_outline_when_scrolling() {
    let mut h = Harness::new();
    h.modal_state = ModalState::Help {
        scroll: 0,
        created_tick: 0,
    };

    // Test multiple scroll states: at top with overscroll up, scrolled to bottom with overscroll down,
    // and mid-scroll.
    let max = zeronet_tui::scroll::max_offset(
        UiRenderer::help_content_height(),
        UiRenderer::help_viewport_height(40),
    );

    // 1. Normal at top vs Overscroll up (rubber band stretch past the top)
    h.help_scroll = zeronet_tui::scroll::ScrollState::new();
    let frame_norm = h.draw(120, 40);
    let lines_norm: Vec<&str> = frame_norm.lines().collect();
    let modal_top_row = lines_norm
        .iter()
        .position(|l| l.contains("KEYBOARD REFERENCE"))
        .expect("top border");
    // The help modal occupies 86% of the 40-row terminal (34 rows), centered vertically from row 3 to 36.
    let modal_bot_row = modal_top_row + 33;
    assert!(
        lines_norm[modal_top_row + 1].contains("Connection"),
        "first section should be at top interior row under normal scroll"
    );

    h.help_scroll.scroll(-1, max, 0);
    let frame_up = h.draw(120, 40);
    let lines_up: Vec<&str> = frame_up.lines().collect();

    // Overscroll up pushes content downward (creating space under top border)
    assert!(
        !lines_up[modal_top_row + 1].contains("Connection"),
        "content should bounce downward during overscroll up"
    );
    assert!(
        lines_up[modal_top_row + 2].contains("Connection"),
        "content dropped down within inner area"
    );

    // Row above modal and row below modal must NOT contain modal body content.
    assert!(
        !lines_up[modal_top_row - 1].contains("Connection"),
        "text exited top outline"
    );
    assert!(
        !lines_up[modal_top_row - 1].contains("Ctrl+"),
        "text exited top outline"
    );
    assert!(
        !lines_up[modal_bot_row + 1].contains("Selecting"),
        "text exited bottom outline"
    );
    assert!(
        !lines_up[modal_bot_row + 1].contains("Ctrl+"),
        "text exited bottom outline"
    );
    // Borders must be intact, not overwritten by body text
    assert!(
        !lines_up[modal_top_row].contains("Ctrl+L"),
        "body text overwrote top border"
    );
    assert!(
        !lines_up[modal_bot_row].contains("Ctrl+"),
        "body text overwrote bottom border"
    );

    // 2. Normal at bottom vs Overscroll down (rubber band stretch past the bottom - "lift")
    h.help_scroll = zeronet_tui::scroll::ScrollState::new();
    h.help_scroll.step(max as i32, max);
    let frame_bot = h.draw(120, 40);
    let lines_bot: Vec<&str> = frame_bot.lines().collect();
    assert!(
        lines_bot[modal_bot_row - 1].contains("Selecting"),
        "footer note should be at bottom interior row normally"
    );

    h.help_scroll.scroll(1, max, 100);
    let frame_down = h.draw(120, 40);
    let lines_down: Vec<&str> = frame_down.lines().collect();

    // Overscroll down lifts content upward (leaving space above bottom border)
    assert!(
        !lines_down[modal_bot_row - 1].contains("Selecting"),
        "content should lift upward during overscroll down"
    );
    assert!(
        lines_down[modal_bot_row - 2].contains("Selecting"),
        "content lifted up within inner area"
    );

    assert!(
        !lines_down[modal_top_row - 1].contains("Connection"),
        "text exited top outline"
    );
    assert!(
        !lines_down[modal_top_row - 1].contains("Ctrl+"),
        "text exited top outline"
    );
    assert!(
        !lines_down[modal_bot_row + 1].contains("Selecting"),
        "text exited bottom outline"
    );
    assert!(
        !lines_down[modal_bot_row + 1].contains("Ctrl+"),
        "text exited bottom outline"
    );
    assert!(
        lines_down[modal_top_row].contains("KEYBOARD REFERENCE"),
        "top border damaged"
    );
    assert!(
        !lines_down[modal_top_row].contains("Selecting"),
        "body text overwrote top border"
    );
    assert!(
        !lines_down[modal_bot_row].contains("Ctrl+"),
        "body text overwrote bottom border"
    );
    assert!(
        !lines_down[modal_bot_row].contains("Selecting"),
        "body text overwrote bottom border"
    );
}

const SHARE_LINK: &str = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&security=reality&sni=example.com#Node";

fn share_dialog(profile: &str) -> ModalState {
    let code = zeronet_tui::qr::render(SHARE_LINK, zeronet_tui::qr::QrStyle::HalfBlock).unwrap();
    ModalState::ShareConfig {
        profile: profile.into(),
        uri: SHARE_LINK.into(),
        code: Box::new(code),
        created_tick: 0,
    }
}

#[test]
fn the_share_dialog_puts_the_code_beside_the_link() {
    let mut h = Harness::new();
    h.modal_state = share_dialog("AmneziaVPN");
    let frame = h.draw(160, 60);
    dump("modal_share_config", &frame);

    assert!(frame.contains("SHARE CONFIG"));
    assert!(frame.contains("AmneziaVPN"), "the profile name is missing");
    assert!(frame.contains('█'), "no QR modules drawn");
    assert!(frame.contains("share link"), "the link panel is missing");
    assert!(
        frame.contains("vless://245abd35"),
        "the link text is missing"
    );
    assert!(frame.contains("Copy link"));
    assert!(frame.contains("Copy as sub"));
    assert!(frame.contains("Ctrl+C"));

    // Side by side: the code and the link panel share a row, so the link
    // must start to the right of where the code ends.
    let code_line = frame
        .lines()
        .find(|l| l.contains('█') && l.contains('│'))
        .unwrap_or_default();
    assert!(
        !code_line.is_empty(),
        "expected a row containing both the code and the link panel border"
    );
}

#[test]
fn the_share_dialog_stacks_on_a_narrow_terminal() {
    let mut h = Harness::new();
    h.modal_state = share_dialog("Node");
    // Too narrow for two columns; everything must still be present.
    let frame = h.draw(80, 50);
    dump("modal_share_narrow", &frame);

    assert!(frame.contains("SHARE CONFIG"));
    assert!(frame.contains('█'));
    assert!(frame.contains("Copy link"));
}

#[test]
fn the_share_dialogs_copy_buttons_are_clickable() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.modal_state = share_dialog("Node");
    h.draw(160, 60);

    let found = |id: ComponentId| {
        (0..60)
            .flat_map(|y| (0..160).map(move |x| (x, y)))
            .any(|(x, y)| h.interaction.hit_test(x, y) == Some(id))
    };
    assert!(
        found(ComponentId::ShareCopyLink),
        "Copy link is unreachable"
    );
    assert!(
        found(ComponentId::ShareCopySubscription),
        "Copy as sub is unreachable"
    );
}

#[test]
fn a_delete_confirmation_puts_the_safe_choice_on_escape() {
    let mut h = Harness::new();
    h.modal_state = ModalState::Confirm {
        title: "CONFIRM DELETE".into(),
        message: "Delete 3 profiles?".into(),
        action: zeronet_tui::modal::ConfirmAction::DeleteProfiles(vec![1, 2, 3]),
        created_tick: 0,
    };
    let frame = h.draw(120, 40);
    dump("modal_confirm_delete", &frame);

    assert!(frame.contains("Delete 3 profiles?"));
    assert!(frame.contains("cannot be undone"));
    assert!(
        frame.contains("Keep (Esc)"),
        "the safe choice must be on Esc"
    );
}

#[test]
fn filtering_narrows_the_list_and_reports_the_count() {
    let mut h = Harness::new();
    h.filter = "iran".into();
    h.filter_focused = true;
    let filtered = h.draw(140, 40);
    dump("nodes_filtered", &filtered);

    assert!(filtered.contains("typing filters the list"));
    // Only the matching rows survive, and the header says so.
    assert!(filtered.contains("2/4 match"), "filter count missing");
    assert!(filtered.contains("Iran Clean Edge"));
    assert!(!filtered.contains("Germany Edge 01"));
}

#[test]
fn marked_profiles_are_ticked_and_counted() {
    let mut h = Harness::new();
    h.marked.insert(2);
    h.marked.insert(3);
    let frame = h.draw(140, 40);
    dump("nodes_marked", &frame);

    assert!(frame.contains("2 selected"), "selection count missing");
    assert!(frame.contains('✓'), "ticks missing from marked rows");
}

#[test]
fn an_empty_list_says_how_to_add_one() {
    let mut h = Harness::new();
    h.configs.clear();
    let frame = h.draw(120, 40);
    assert!(frame.contains("Paste a share link"), "paste action missing");
    assert!(
        frame.contains("Add a server manually"),
        "manual action missing"
    );
    assert!(
        frame.contains("Add a subscription"),
        "subscription action missing"
    );
}

#[test]
fn a_filter_matching_nothing_says_so() {
    let mut h = Harness::new();
    h.filter = "zzzz-no-such-node".into();
    let frame = h.draw(120, 40);
    assert!(frame.contains("No profiles match"));
}

#[test]
fn the_footer_advertises_conventional_keys() {
    let mut h = Harness::new();
    let frame = h.draw(120, 40);
    // Ctrl+A must not be advertised as "add config" anywhere.
    assert!(!frame.contains("^A"), "stale Ctrl+A binding still shown");
    assert!(frame.contains("^V"));
    assert!(frame.contains("^Q"));
    assert!(frame.contains("F1"));
}

#[test]
fn an_expired_toast_leaves_no_text_behind() {
    // A toast is drawn over the metrics row with `Clear`. When it expires the
    // cells underneath must be repainted, not left holding fragments of the
    // old message.
    let mut h = Harness::new();
    h.toasts
        .success("Elevated privileges detected — TUN available.");
    let with_toast = h.draw(130, 44);
    assert!(with_toast.contains("Elevated privileges"));

    // Expire it the way the frame loop does.
    while !h.toasts.is_empty() {
        h.toasts.dismiss(0);
    }
    let without = h.draw(130, 44);

    assert!(
        !without.contains("Elevated"),
        "toast text survived its dismissal"
    );
    for fragment in ["privileges", "detected", "TUN available"] {
        assert!(
            !without.contains(fragment),
            "fragment {fragment:?} left behind after the toast expired"
        );
    }
}

#[test]
fn the_frame_under_a_toast_is_intact_once_it_clears() {
    let mut h = Harness::new();
    let clean = h.draw(130, 44);

    h.toasts.info("A message that covers the metric cards");
    h.draw(130, 44);
    while !h.toasts.is_empty() {
        h.toasts.dismiss(0);
    }
    let after = h.draw(130, 44);

    assert_eq!(
        clean, after,
        "the frame after a toast cleared differs from the frame before it appeared"
    );
}

/// Every `Ctrl`+letter shortcut the help screen advertises must resolve.
///
/// Two separate bugs made shortcuts silently do nothing: `Ctrl+I` was bound
/// to "scan QR image" but is byte-identical to Tab, and the image-protocol
/// probe left stdin unable to deliver control bytes at all. Neither showed up
/// in a unit test of the keymap alone, so this walks the advertised bindings.
#[test]
fn every_advertised_ctrl_shortcut_resolves_to_a_command() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use zeronet_tui::keymap::{self, Command, InputContext, RESERVED_CONTROL_KEYS};

    let expectations: [(char, Command); 11] = [
        ('a', Command::SelectAll),
        ('b', Command::Feedback),
        ('c', Command::Copy),
        ('d', Command::Duplicate),
        ('e', Command::ExportAll),
        ('f', Command::Find),
        ('g', Command::ShowQrCode),
        ('k', Command::ScanQrImage),
        ('l', Command::TestLatency),
        ('n', Command::NewProfile),
        ('o', Command::OpenFile),
    ];

    for (letter, expected) in expectations {
        assert!(
            !RESERVED_CONTROL_KEYS.contains(&letter),
            "Ctrl+{letter} is a reserved control byte and cannot be bound"
        );
        let key = KeyEvent::new(KeyCode::Char(letter), KeyModifiers::CONTROL);
        assert_eq!(
            keymap::resolve(key, InputContext::Browsing),
            Some(expected),
            "Ctrl+{letter} did not resolve to {expected:?}"
        );
    }
}

#[test]
fn reserved_control_bytes_keep_their_original_meaning() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use zeronet_tui::keymap::{self, Command, InputContext};

    // Tab must still switch views, and Enter must still be the primary
    // action — binding Ctrl+I or Ctrl+M would have stolen both.
    assert_eq!(
        keymap::resolve(
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            InputContext::Browsing
        ),
        Some(Command::NextView)
    );
    assert_eq!(
        keymap::resolve(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            InputContext::Browsing
        ),
        Some(Command::ToggleConnection)
    );
}

#[test]
fn the_system_proxy_chip_reports_each_mode() {
    use zeronet_tui::sysproxy::SystemProxyMode;

    for (mode, expected) in [
        (SystemProxyMode::Unmanaged, "PROXY KEEP"),
        (SystemProxyMode::Manual, "PROXY SYS"),
        (SystemProxyMode::Pac, "PROXY PAC"),
        (SystemProxyMode::Clear, "PROXY NONE"),
    ] {
        let mut h = Harness::new();
        h.system_proxy = mode;
        let frame = h.draw(130, 44);
        assert!(
            frame.contains(expected),
            "{mode:?} should show {expected:?} in the header"
        );
    }
}

/// Everything the settings page draws, across every scroll position.
///
/// Asserting against a single screenful breaks whenever a row is added above
/// the one being checked, which says nothing about whether the setting is
/// reachable. This is the question the tests actually mean to ask.
fn settings_text(h: &mut Harness, width: u16, height: u16) -> String {
    let content = zeronet_tui::ui::UiRenderer::settings_content_height_for(h.advanced_open);
    let max = zeronet_tui::scroll::max_offset(content, height.saturating_sub(6) as usize);
    let mut seen = String::new();
    for offset in 0..=max {
        h.settings_scroll = zeronet_tui::scroll::ScrollState::new();
        h.settings_scroll.step(offset as i32, max);
        seen.push_str(&h.draw(width, height));
        seen.push('\n');
    }
    seen
}

#[test]
fn the_settings_screen_exposes_the_proxy_modes() {
    let mut h = Harness::new();
    h.active_tab = ActiveTab::Settings;
    h.advanced_open = true;
    h.settings.system_proxy_mode = "pac".into();
    let frame = h.draw(150, 44);
    dump("settings_proxy", &frame);

    assert!(frame.contains("System Proxy"));
    assert!(frame.contains("PAC MODE"));

    let all = settings_text(&mut h, 150, 44);
    assert!(all.contains("PAC Port"));
    assert!(all.contains("11080"), "the PAC port should be shown");

    // The hands-off mode must be reachable and clearly described.
    h.settings_scroll = zeronet_tui::scroll::ScrollState::new();
    h.settings.system_proxy_mode = "unmanaged".into();
    let frame = h.draw(150, 44);
    assert!(frame.contains("DO NOT CHANGE"));
    assert!(frame.contains("keeps your settings"));
}

/// The engine settings carried over from v2rayN, and the scanner's own
/// controls, all have to be on the page and reachable.
///
/// Each of these is wired to something the engine or the scanner reads, so a
/// row going missing means a setting silently stops being adjustable.
#[test]
fn every_core_and_scanner_setting_is_on_the_page() {
    let mut h = Harness::new();
    h.active_tab = ActiveTab::Settings;
    h.advanced_open = true;
    let all = settings_text(&mut h, 150, 30);

    for label in [
        // Core, in v2rayN's own terms.
        "Allow LAN Connections",
        "UDP over SOCKS",
        "Sniff Route-Only",
        "uTLS Fingerprint",
        "Engine Log Level",
        "TUN Device Name",
        "TUN Auto-Route",
        "TUN Strict Route",
        "TLS Fragmentation",
        // The scanner's core flags, which the page used to hard-code.
        "EDGE SCANNER",
        "Probe Mode",
        "Probe Port",
        "Probes per IP",
        "Probe Timeout",
        "Candidates",
        "Probe SNI",
        "Require WebSocket",
        "WebSocket Path",
        "Neighbour Sweep",
        "Scan IPv4 Ranges",
        "Scan IPv6 Ranges",
        "Speed Sample",
        "Scanner Workers",
    ] {
        assert!(all.contains(label), "{label:?} is not on the settings page");
    }
}

#[test]
fn strict_routing_reads_as_inert_when_auto_routing_is_off() {
    // The engine refuses the pair, so showing a plain "ENABLED" would be a
    // claim the connection then contradicts.
    let mut h = Harness::new();
    h.active_tab = ActiveTab::Settings;
    h.advanced_open = true;
    h.settings.tun_strict_route = true;
    h.settings.tun_auto_route = false;
    let all = settings_text(&mut h, 150, 30);
    assert!(all.contains("INERT"), "strict routing claimed to be on");
    assert!(all.contains("needs Auto-Route"));
}

#[test]
fn the_system_proxy_chip_is_clickable() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.draw(130, 44);
    let found = (0..44)
        .flat_map(|y| (0..130).map(move |x| (x, y)))
        .any(|(x, y)| h.interaction.hit_test(x, y) == Some(ComponentId::SystemProxyChip));
    assert!(found, "the proxy chip cannot be clicked");
}

#[test]
fn a_rainbow_wave_reaches_the_screen_edges_when_painted() {
    // The wave is composited over the finished frame, so this checks the
    // renderer actually carries it to the far corner rather than clipping it
    // to a panel.
    let mut h = Harness::new();
    h.draw(130, 44); // establishes the viewport
    h.effects.trigger_rainbow(6.0, 1.0);

    let mut edge_painted = false;
    for _ in 0..40 {
        h.effects.advance_tick();
        let frame = h.draw(130, 44);
        let last_line = frame.lines().nth(43).unwrap_or_default();
        // The wave fills empty cells with a marker dot as it passes.
        if last_line.contains('·') {
            edge_painted = true;
            break;
        }
    }
    assert!(edge_painted, "the wave never painted the bottom row");
}

#[test]
fn toasts_do_not_cover_the_header_chips() {
    // The chips say whether TUN and the system proxy are actually on. A toast
    // landing on them hid exactly the state a user needs to trust.
    let mut h = Harness::new();
    h.system_proxy = zeronet_tui::sysproxy::SystemProxyMode::Manual;
    h.toasts
        .success("System proxy → SYSTEM (KDE) · HTTP :10809 · SOCKS :10808");
    h.toasts.info("A second toast, to push the stack down");

    let frame = h.draw(130, 44);
    dump("toast_below_header", &frame);

    let lines: Vec<&str> = frame.lines().collect();
    // Header rows must still carry the chips.
    let header = lines[..3].join(" ");
    assert!(header.contains("TUN"), "TUN chip was covered: {header:?}");
    assert!(
        header.contains("PROXY SYS"),
        "proxy chip was covered: {header:?}"
    );
    assert!(header.contains("PRIV"), "privileges chip was covered");

    // And the toast is still on screen, just lower down.
    assert!(frame.contains("System proxy"));
}

// ------------------------------------------------- dialog open / close

fn help_modal() -> ModalState {
    ModalState::Help {
        scroll: 0,
        created_tick: 0,
    }
}

#[test]
fn a_dialog_has_a_close_button_in_its_border() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.modal_state = help_modal();
    let frame = h.draw(130, 44);
    dump("modal_close_button", &frame);

    assert!(frame.contains("[✕]"), "no close button drawn");
    let found = (0..44)
        .flat_map(|y| (0..130).map(move |x| (x, y)))
        .any(|(x, y)| h.interaction.hit_test(x, y) == Some(ComponentId::ModalClose));
    assert!(found, "the close button is not clickable");
}

#[test]
fn every_dialog_gets_a_close_button() {
    use zeronet_tui::interaction::ComponentId;

    let dialogs: Vec<(&str, ModalState)> = vec![
        ("help", help_modal()),
        ("share", share_dialog("Node")),
        (
            "text input",
            ModalState::TextInput {
                title: "Import".into(),
                prompt: "Paste".into(),
                buffer: String::new(),
                purpose: zeronet_tui::modal::TextPurpose::ImportConfig,
                created_tick: 0,
                select_all: false,
            },
        ),
        (
            "update",
            update_dialog(zeronet_tui::modal::UpdatePhase::Available),
        ),
        (
            "confirm",
            ModalState::Confirm {
                title: "CONFIRM DELETE".into(),
                message: "Delete?".into(),
                action: zeronet_tui::modal::ConfirmAction::DeleteProfiles(vec![1]),
                created_tick: 0,
            },
        ),
        ("quit", ModalState::QuitConfirmation { created_tick: 0 }),
        (
            "sudo password",
            ModalState::SudoPassword {
                prompt: "Zray needs to create the zeronet0 interface".into(),
                buffer: String::new(),
                error: None,
                created_tick: 0,
            },
        ),
        (
            "manual profile",
            ModalState::ManualProfile {
                form: zeronet_tui::manual_profile::ManualProfileForm::new(),
                editing_text: false,
                input_buffer: String::new(),
                created_tick: 0,
            },
        ),
    ];

    for (name, modal) in dialogs {
        let mut h = Harness::new();
        h.modal_state = modal;
        h.draw(150, 50);
        let found = (0..50)
            .flat_map(|y| (0..150).map(move |x| (x, y)))
            .any(|(x, y)| h.interaction.hit_test(x, y) == Some(ComponentId::ModalClose));
        assert!(found, "{name} has no close button");
    }
}

#[test]
fn the_area_outside_a_dialog_is_a_dismissable_backdrop() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.modal_state = help_modal();
    h.draw(130, 44);

    // A corner is outside any centred dialog.
    assert_eq!(
        h.interaction.hit_test(0, 43),
        Some(ComponentId::ModalBackdrop),
        "a click outside the dialog should reach the backdrop"
    );
    // ...and must not fall through to whatever is underneath.
    assert_ne!(
        h.interaction.hit_test(2, 5),
        Some(ComponentId::NavDashboard),
        "a backdrop click leaked through to the sidebar"
    );
}

#[test]
fn only_dialogs_without_typed_input_dismiss_on_a_backdrop_click() {
    // Discarding a hand-entered UUID because of a stray click is worse than
    // making someone reach for Esc.
    assert!(help_modal().dismiss_on_backdrop());
    assert!(share_dialog("n").dismiss_on_backdrop());
    assert!(ModalState::QuitConfirmation { created_tick: 0 }.dismiss_on_backdrop());
    assert!(!ModalState::ManualProfile {
        form: zeronet_tui::manual_profile::ManualProfileForm::new(),
        editing_text: false,
        input_buffer: String::new(),
        created_tick: 0,
    }
    .dismiss_on_backdrop());
}

#[test]
fn the_opening_animation_grows_the_panel_without_drawing_content() {
    use zeronet_tui::modal_anim::{ModalAnimator, OPEN_TICKS};

    let mut h = Harness::new();
    h.modal_state = help_modal();

    let mut widths = Vec::new();
    for tick in 0..=OPEN_TICKS {
        h.modal_anim = ModalAnimator::opening(0);
        // Drive the effects clock to `tick`.
        h.effects = VisualEffects::with_caps(h.caps.depth, h.caps.animations);
        for _ in 0..tick {
            h.effects.advance_tick();
        }
        let frame = h.draw(130, 44);
        if tick == 1 {
            dump("modal_opening_slit", &frame);
        }
        // Content must not appear while the panel is still moving.
        if tick < OPEN_TICKS / 2 {
            assert!(
                !frame.contains("Ctrl+A"),
                "help text appeared at tick {tick}, before the panel settled"
            );
        }
        widths.push(
            frame
                .lines()
                .map(|l| l.chars().filter(|c| *c == '─').count())
                .max()
                .unwrap_or(0),
        );
    }

    // The final frame is the widest.
    assert!(
        widths.last().copied().unwrap_or(0) >= widths[1],
        "the panel did not grow: {widths:?}"
    );
    // And the settled dialog does show its content.
    let settled = h.draw(130, 44);
    assert!(settled.contains("Ctrl+A"));
}

#[test]
fn a_closing_dialog_shrinks_and_then_disappears() {
    use zeronet_tui::modal_anim::{ModalAnimator, CLOSE_TICKS};

    let mut h = Harness::new();
    h.modal_state = help_modal();

    let mut anim = ModalAnimator::default();
    anim.begin_close(0);
    h.modal_anim = anim;

    for tick in 0..CLOSE_TICKS {
        h.effects = VisualEffects::with_caps(h.caps.depth, h.caps.animations);
        for _ in 0..tick {
            h.effects.advance_tick();
        }
        let frame = h.draw(130, 44);
        if tick == 2 {
            dump("modal_closing", &frame);
        }
        // Content drops out at once; only the shrinking frame remains.
        assert!(
            !frame.contains("Select all"),
            "content survived into the closing animation at tick {tick}"
        );
    }

    // Past the end the animator reports it is gone, which is the frame loop's
    // signal to drop the dialog.
    assert!(!h.modal_anim.is_visible(CLOSE_TICKS));
}

#[test]
fn a_nudged_dialog_flashes_without_closing() {
    use zeronet_tui::modal_anim::ModalAnimator;

    let mut h = Harness::new();
    h.modal_state = ModalState::ManualProfile {
        form: zeronet_tui::manual_profile::ManualProfileForm::new(),
        editing_text: false,
        input_buffer: String::new(),
        created_tick: 0,
    };

    let mut anim = ModalAnimator::default();
    anim.nudge(0);
    h.modal_anim = anim;

    let frame = h.draw(150, 50);
    dump("modal_nudge", &frame);

    // Still open, still showing its fields.
    assert!(frame.contains("MANUAL NODE CREATOR"));
    assert!(frame.contains("Server Host"));
    assert!(h.modal_anim.is_visible(1));
}

#[test]
fn the_manual_profile_shows_the_same_caret_as_other_text_fields() {
    let mut h = Harness::new();
    h.modal_state = ModalState::ManualProfile {
        form: zeronet_tui::manual_profile::ManualProfileForm::new(),
        // This is the state used by the real New Profile command.
        editing_text: false,
        input_buffer: String::new(),
        created_tick: 0,
    };

    let frame = h.draw(150, 50);
    assert!(
        frame.contains("My Custom Node█"),
        "the focused manual-profile field has no typing caret:\n{frame}"
    );

    // A stale scratch buffer must never replace the canonical form value.
    h.modal_state = ModalState::ManualProfile {
        form: zeronet_tui::manual_profile::ManualProfileForm::new(),
        editing_text: true,
        input_buffer: "stale value".into(),
        created_tick: 0,
    };
    let frame = h.draw(150, 50);
    assert!(frame.contains("My Custom Node█"), "{frame}");
    assert!(!frame.contains("stale value"), "{frame}");

    if let ModalState::ManualProfile { form, .. } = &mut h.modal_state {
        form.focused_field = 1; // Protocol, a cycler rather than a text field.
    } else {
        unreachable!()
    }
    let frame = h.draw(150, 50);
    assert!(
        !frame.contains("VLESS█"),
        "a cycler field must not show a text caret:\n{frame}"
    );

    if let ModalState::ManualProfile { form, .. } = &mut h.modal_state {
        form.focused_field = 0;
    } else {
        unreachable!()
    }
    if let ModalState::ManualProfile { form, .. } = &mut h.modal_state {
        form.remark = "a".repeat(100);
    } else {
        unreachable!()
    }
    let frame = h.draw(150, 50);
    assert!(
        frame.lines().any(|line| line.contains("…█")),
        "a long value must be truncated before the caret: {frame}"
    );

    for width in [64, 80] {
        let frame = h.draw(width, 24);
        let remark = frame
            .lines()
            .find(|line| line.contains("Remark"))
            .expect("remark row should be visible at the minimum supported width");
        assert!(
            remark.contains('█') && remark.contains('…'),
            "the caret must survive a narrow terminal at {width} columns without losing the value indicator: {remark:?}"
        );
    }
}

#[test]
fn the_opening_slit_is_painted_as_a_lit_bar() {
    // The slit has no glyphs — it is a background fill — so a text dump shows
    // it as blank. What matters is that those cells carry the accent colour.
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use zeronet_tui::modal_anim::ModalAnimator;

    let mut h = Harness::new();
    h.modal_state = help_modal();
    h.modal_anim = ModalAnimator::opening(0);
    h.effects.advance_tick(); // tick 1: mid-slit

    let mut terminal = Terminal::new(TestBackend::new(130, 44)).unwrap();
    terminal
        .draw(|frame| {
            let mut renderer = UiRenderer {
                theme: &h.theme,
                caps: &h.caps,
                interaction: &mut h.interaction,
                effects: &mut h.effects,
                settings: &h.settings,
                stats: &h.stats,
                active_tab: h.active_tab,
                configs: &h.configs,
                subscriptions: &h.subscriptions,
                selected_config_idx: 0,
                node_scroll: 0,
                marked: &h.marked,
                filter: &h.filter,
                filter_focused: false,
                advanced_open: h.advanced_open,
                filter_select_all: false,
                inline_rename: None,
                system_proxy: h.system_proxy,
                modal_anim: h.modal_anim,
                settings_scroll: h.settings_scroll,
                help_scroll: h.help_scroll,
                selection_tick: 0,
                context_menu: None,
                drag: None,
                latency_history: &h.latency_history,
                is_elevated: false,
                elevation_prompt: None,
                modal_state: &h.modal_state,
                image_view: None,
                throbber_state: &mut h.throbber,
                scanner_tested: 0,
                scanner_healthy: 0,
                scanner_speed: 0.0,
                is_scanning: false,
                scanner_results: &[],
                toasts: &mut h.toasts,
                usage: Default::default(),
                perf: None,
                session: None,
                speed_history: (&[], &[]),
                update_status: &zeronet_tui::update::Status::Idle,
            finder_status: None,
            };
            renderer.render(frame);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    // A contiguous run of cells sharing one non-background colour: the bar.
    let bar_cells = (0..44)
        .flat_map(|y| (0..130).map(move |x| (x, y)))
        .filter(|(x, y)| {
            let bg = buffer[(*x, *y)].bg;
            bg != h.theme.bg && bg != h.theme.surface && bg != h.theme.surface_hi
        })
        .count();
    assert!(
        bar_cells >= 10,
        "the opening slit painted only {bar_cells} coloured cells"
    );
}

// ------------------------------------------------ the new interaction bits

#[test]
fn clicking_inside_a_dialog_does_not_reach_the_backdrop() {
    use zeronet_tui::interaction::ComponentId;

    // The bug: a click on the dialog's own empty space fell through to the
    // backdrop and dismissed the very dialog being clicked.
    let mut h = Harness::new();
    h.modal_state = help_modal();
    h.draw(130, 44);

    let centre = h.interaction.hit_test(65, 22);
    assert_ne!(
        centre,
        Some(ComponentId::ModalBackdrop),
        "a click inside the dialog was treated as a click outside it"
    );
    assert!(centre.is_some(), "the dialog body absorbs nothing at all");

    // A corner is still the backdrop.
    assert_eq!(
        h.interaction.hit_test(1, 42),
        Some(ComponentId::ModalBackdrop)
    );
}

#[test]
fn the_filter_box_is_always_on_screen() {
    // A search field that only appears once focused is one nobody can find.
    let mut h = Harness::new();
    let frame = h.draw(130, 44);
    dump("filter_always_visible", &frame);
    assert!(frame.contains("Search profiles"));
    assert!(frame.contains("Ctrl+F"));
}

#[test]
fn the_filter_box_is_clickable_and_shows_focus() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.draw(130, 44);
    let found = (0..44)
        .flat_map(|y| (0..130).map(move |x| (x, y)))
        .any(|(x, y)| h.interaction.hit_test(x, y) == Some(ComponentId::FilterBox));
    assert!(found, "the filter box cannot be clicked");

    h.filter_focused = true;
    h.filter = "iran".into();
    let focused = h.draw(130, 44);
    assert!(focused.contains("iran"));
    assert!(focused.contains("typing filters the list"));
}

#[test]
fn every_profile_row_has_its_own_share_button() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    let frame = h.draw(150, 44);
    dump("rows_with_share", &frame);

    assert!(frame.contains("share"), "no share button on the rows");
    for i in 0..h.configs.len() {
        let found = (0..44)
            .flat_map(|y| (0..150).map(move |x| (x, y)))
            .any(|(x, y)| h.interaction.hit_test(x, y) == Some(ComponentId::ConfigShare(i)));
        assert!(found, "row {i} has no clickable share button");
    }
}

#[test]
fn the_footer_no_longer_carries_qr_or_find() {
    // They moved onto the rows and into the always-present filter box.
    let mut h = Harness::new();
    let frame = h.draw(130, 44);
    let footer = frame.lines().last().unwrap_or_default().to_string();
    assert!(
        !footer.contains("QR"),
        "footer still advertises QR: {footer:?}"
    );
    // The list filter (^F) lives in the filter box; the footer's "Find
    // server" is the config finder, a different thing.
    assert!(
        !footer.contains("^F"),
        "footer still advertises the filter: {footer:?}"
    );
    assert!(footer.contains("Find server"), "no finder button: {footer:?}");
    assert!(footer.contains("Connect"));
    assert!(footer.contains("Help"));
}

#[test]
fn the_finder_button_is_clickable_and_its_progress_shows_in_the_header() {
    let mut h = Harness::new();
    let frame = h.draw(130, 44);
    let clickable = (0..130).any(|x| h.interaction.hit_test(x, 43) == Some(ComponentId::FooterFindServers));
    assert!(clickable, "the footer's Find server is not clickable");
    assert!(!frame.contains("Finding servers"));

    h.finder_status = Some("Finding servers · 1 working · testing servers · 12 s · 1840 candidates · 96 reachable · 64 tested".into());
    let frame = h.draw(130, 44);
    dump("finder_progress", &frame);
    assert!(frame.contains("Finding servers · 1 working"), "no finder progress in the header");
}

#[test]
fn found_profiles_are_marked_apart_from_the_users_own() {
    let mut h = Harness::new();
    let frame = h.draw(130, 44);
    // Fixture profile 3 is a found one; the rest are the user's own.
    assert_eq!(frame.matches("◇ ").count(), 1, "exactly one found marker:\n{frame}");
}

#[test]
fn a_long_notification_is_shown_in_full() {
    // A fixed three-row toast silently truncated anything longer than one
    // line, which is most error messages.
    let long = "Connection failed: the profile has no server details — re-import it \
                from its share link, or delete it and paste a fresh one";
    let mut h = Harness::new();
    h.toasts.error(long);
    let frame = h.draw(130, 44);
    dump("toast_long", &frame);

    // Every word survives somewhere in the frame.
    for word in ["server", "details", "re-import", "share", "delete", "fresh"] {
        assert!(frame.contains(word), "{word:?} was cut off the toast");
    }
}

#[test]
fn an_unbreakable_link_still_wraps() {
    use zeronet_tui::ui::wrap_width;

    let link = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none";
    let lines = wrap_width(link, 20);
    assert!(lines.len() > 1, "a long link was not wrapped");
    assert!(
        lines.iter().all(|l| l.chars().count() <= 20),
        "a wrapped line overflowed: {lines:?}"
    );
    // Nothing is lost.
    assert_eq!(lines.concat(), link);
}

#[test]
fn wrapping_breaks_on_spaces_where_it_can() {
    use zeronet_tui::ui::wrap_width;

    let lines = wrap_width("the quick brown fox jumps over the lazy dog", 12);
    assert!(lines.iter().all(|l| l.chars().count() <= 12));
    assert!(lines[0].contains(' '), "did not pack words onto a line");
    assert!(!lines.iter().any(|l| l.starts_with(' ')));
}

#[test]
fn the_settings_page_scrolls_and_reaches_its_last_row() {
    let mut h = Harness::new();
    h.active_tab = ActiveTab::Settings;
    h.advanced_open = true;

    // A short terminal cannot show every row at once.
    let top = h.draw(150, 26);
    dump("settings_scrolled_top", &top);
    assert!(top.contains("TUN Interface"));
    assert!(
        top.contains("scroll for more"),
        "no scroll affordance shown"
    );

    // Scrolling reveals the rows that were below the fold.
    let max = zeronet_tui::scroll::max_offset(
        zeronet_tui::ui::UiRenderer::settings_content_height_for(true),
        26 - 6,
    );
    h.settings_scroll.step(max as i32, max);
    let bottom = h.draw(150, 26);
    dump("settings_scrolled_bottom", &bottom);
    assert!(
        bottom.contains("Scanner Workers") || bottom.contains("Speed Sample"),
        "the last settings rows are unreachable"
    );
    assert!(!bottom.contains("TUN Interface"), "the page did not scroll");
}

#[test]
fn a_context_menu_renders_where_it_was_opened() {
    use zeronet_tui::ctxmenu::{ContextMenu, MenuTarget};

    let mut h = Harness::new();
    h.context_menu = Some(ContextMenu::for_target(
        MenuTarget::Profile(0),
        (30, 12),
        0,
        false,
        false,
    ));
    let frame = h.draw(130, 44);
    dump("context_menu", &frame);

    assert!(frame.contains("Copy share link"));
    assert!(frame.contains("Share config"));
    assert!(frame.contains("Rename"));
    assert!(frame.contains("Delete"));
    // Accelerators are shown so the menu teaches the shortcuts.
    assert!(frame.contains("^C"));
    assert!(frame.contains("Del"));
}

#[test]
fn the_background_menu_offers_logs_and_settings() {
    use zeronet_tui::ctxmenu::{ContextMenu, MenuTarget};

    let mut h = Harness::new();
    h.context_menu = Some(ContextMenu::for_target(
        MenuTarget::Background,
        (20, 20),
        0,
        false,
        false,
    ));
    let frame = h.draw(130, 44);
    dump("context_menu_background", &frame);
    assert!(frame.contains("Show logs"));
    assert!(frame.contains("Settings"));
    assert!(frame.contains("Paste"));
}

#[test]
fn context_menu_rows_are_clickable() {
    use zeronet_tui::ctxmenu::{ContextMenu, MenuTarget};
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.context_menu = Some(ContextMenu::for_target(
        MenuTarget::Profile(0),
        (30, 12),
        0,
        false,
        false,
    ));
    h.draw(130, 44);

    let clickable = (0..44)
        .flat_map(|y| (0..130).map(move |x| (x, y)))
        .filter_map(|(x, y)| match h.interaction.hit_test(x, y) {
            Some(ComponentId::ContextMenuItem(i)) => Some(i),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    assert!(
        clickable.len() >= 6,
        "only {} menu rows are clickable",
        clickable.len()
    );
}

#[test]
fn a_drag_band_is_drawn_over_the_list() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use zeronet_tui::dragselect::DragSelect;

    // The band highlights cells rather than changing glyphs, so a text dump
    // is identical; what changes is the background colour.
    let mut h = Harness::new();
    let mut drag = DragSelect::press(30, 30, false);
    drag.moved(60, 34);
    h.drag = Some(drag);

    let mut terminal = Terminal::new(TestBackend::new(130, 44)).unwrap();
    terminal.draw(|frame| h.render_into(frame)).unwrap();

    let buffer = terminal.backend().buffer();
    let highlighted = (30..=34)
        .flat_map(|y| (30..=60).map(move |x| (x, y)))
        .filter(|(x, y)| buffer[(*x, *y)].bg == h.theme.surface_hi)
        .count();
    assert!(
        highlighted > 50,
        "the drag band highlighted only {highlighted} cells"
    );

    // And nothing outside the band was touched.
    assert_ne!(buffer[(10, 10)].bg, h.theme.surface_hi);
}

#[test]
fn drag_selection_sweeps_exact_intersected_rows() {
    use ratatui::layout::Rect;
    let mut h = Harness::new();
    let _ = h.draw(140, 44);

    let r0 = h
        .interaction
        .region(ComponentId::ConfigItem(0))
        .expect("config 0 hit box missing");
    let r1 = h
        .interaction
        .region(ComponentId::ConfigItem(1))
        .expect("config 1 hit box missing");

    // A drag rectangle crossing row 0 and row 1 horizontally and vertically
    let band = Rect {
        x: r0.x + 2,
        y: r0.y,
        width: 20,
        height: r1.bottom().saturating_sub(r0.y),
    };
    let swept = h.interaction.swept_config_items(band);
    assert_eq!(swept, vec![0, 1], "swept rows should be [0, 1]");

    // A drag rectangle to the right in the latency panel sweeps nothing
    let latency_band = Rect {
        x: r0.right() + 5,
        y: r0.y,
        width: 15,
        height: 5,
    };
    assert!(
        h.interaction.swept_config_items(latency_band).is_empty(),
        "drag outside configs should sweep nothing"
    );
}

#[test]
fn multi_selection_shows_ticks_and_clearing_deselects_all() {
    let mut h = Harness::new();
    h.selected_config_idx = 0;
    h.marked.insert(2);
    h.marked.insert(3);
    let frame = h.draw(140, 44);
    assert!(frame.contains("2 selected"));
    assert!(frame.contains('✓'));

    // Clicking elsewhere / deselecting clears the selection
    h.marked.clear();
    let frame_deselected = h.draw(140, 44);
    assert!(!frame_deselected.contains("selected"));
    assert!(!frame_deselected.contains('✓'));
}

// ------------------------------------------------- administrator password

fn sudo_dialog(typed: &str, error: Option<&str>) -> ModalState {
    ModalState::SudoPassword {
        prompt: "Zray needs to create the zeronet0 interface and install routes.".into(),
        buffer: typed.to_string(),
        error: error.map(str::to_owned),
        created_tick: 0,
    }
}

#[test]
fn the_password_dialog_explains_itself_and_offers_both_ways_out() {
    let mut h = Harness::new();
    h.modal_state = sudo_dialog("", None);
    let frame = h.draw(150, 44);
    dump("sudo_password", &frame);

    assert!(frame.contains("ADMINISTRATOR PASSWORD"));
    // Nobody should be typing a root password at an unexplained box.
    assert!(frame.contains("TUN mode needs administrator rights"));
    assert!(
        frame.contains("zeronet0"),
        "the dialog does not say what for"
    );
    assert!(
        frame.contains("Not stored or logged"),
        "the dialog does not say what happens to the password"
    );
    // Declining has to be an option, and it has to say what declining means.
    assert!(frame.contains("Unlock"));
    assert!(frame.contains("Proxy only"));
}

#[test]
fn the_password_field_never_echoes_what_was_typed() {
    // The frame buffer is the same thing a screen recording or a rendered
    // dump would capture.
    let mut h = Harness::new();
    h.modal_state = sudo_dialog("hunter2", None);
    let frame = h.draw(150, 44);

    assert!(!frame.contains("hunter2"), "the password was echoed");
    assert!(!frame.contains("hunter"), "part of the password was echoed");
    assert!(frame.contains("•••••••"), "no masked characters were drawn");
}

#[test]
fn a_long_passphrase_cannot_push_the_dialog_out_of_shape() {
    let mut h = Harness::new();
    h.modal_state = sudo_dialog(&"x".repeat(400), None);
    let frame = h.draw(80, 30);
    // "Proxy only" legitimately contains an x, so look for a run of them.
    assert!(!frame.contains("xxx"), "the password leaked into the frame");
    for line in frame.lines() {
        assert!(
            line.chars().count() <= 80,
            "a {} column line escaped an 80 column terminal",
            line.chars().count()
        );
    }
}

#[test]
fn a_refused_password_is_reported_on_the_dialog_itself() {
    // Closing the dialog and toasting the failure would lose the field the
    // user is about to retype into.
    let mut h = Harness::new();
    h.modal_state = sudo_dialog("", Some("That password was not accepted."));
    let frame = h.draw(150, 44);
    assert!(frame.contains("That password was not accepted."));
}

#[test]
fn the_password_dialog_buttons_are_clickable() {
    use zeronet_tui::interaction::ComponentId;

    let mut h = Harness::new();
    h.modal_state = sudo_dialog("abc", None);
    h.draw(150, 44);
    for (id, name) in [
        (ComponentId::SudoConfirm, "unlock"),
        (ComponentId::SudoCancel, "proxy only"),
    ] {
        let found = (0..44)
            .flat_map(|y| (0..150).map(move |x| (x, y)))
            .any(|(x, y)| h.interaction.hit_test(x, y) == Some(id));
        assert!(found, "the {name} button is not clickable");
    }
}

// -------------------------------------------------------- status bar sweep

#[test]
fn the_status_sweep_stays_over_the_text_it_reports_on() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut h = Harness::new();
    h.stats.status = ConnectionStatus::Connected;
    h.stats.active_node_name = "AmneziaVPN (VLESS-Reality)".into();

    let mut terminal = Terminal::new(TestBackend::new(200, 40)).unwrap();
    let mut furthest = 0u16;
    let mut nearest = u16::MAX;
    for _ in 0..40 {
        // 0.04 per tick, so forty ticks walk the phase right around.
        h.effects.advance_tick();
        terminal
            .draw(|frame| {
                h.render_into(frame);
                let buffer = frame.buffer_mut();
                // Column 199 is header chrome the sweep must never reach, so
                // its background is the untinted reference.
                let background = buffer[(199u16, 0u16)].bg;
                for x in 0..200u16 {
                    if buffer[(x, 0u16)].bg != background {
                        furthest = furthest.max(x);
                        nearest = nearest.min(x);
                    }
                }
            })
            .unwrap();
    }

    // The status pill " CONNECTED " occupies columns 25..=35 (x=24 is a leading space).
    // The sweep must stay strictly inside the pill and never touch the leading space,
    // the node name, or anything further to the right.
    assert!(
        furthest > 0,
        "no sweep was painted at all, so this proves nothing"
    );
    assert!(
        nearest >= 25,
        "the status sweep reached column {nearest}, spilling into the space before the pill"
    );
    assert!(
        furthest < 36,
        "the status sweep reached column {furthest} of 200, extending beyond the status bar"
    );
}

#[test]
fn the_status_sweep_stays_inside_disconnected_status_bar() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut h = Harness::new();
    h.stats.status = ConnectionStatus::Disconnected;
    h.stats.active_node_name = "AmneziaVPN (VLESS-Reality)".into();

    let mut terminal = Terminal::new(TestBackend::new(200, 40)).unwrap();
    let mut furthest = 0u16;
    let mut nearest = u16::MAX;
    for _ in 0..40 {
        h.effects.advance_tick();
        terminal
            .draw(|frame| {
                h.render_into(frame);
                let buffer = frame.buffer_mut();
                let background = buffer[(199u16, 0u16)].bg;
                for x in 0..200u16 {
                    if buffer[(x, 0u16)].bg != background {
                        furthest = furthest.max(x);
                        nearest = nearest.min(x);
                    }
                }
            })
            .unwrap();
    }

    // " DISCONNECTED " is 14 cells wide, columns 25..=38.
    assert!(furthest > 0);
    assert!(
        nearest >= 25,
        "the status sweep reached column {nearest}, spilling into the space before the pill"
    );
    assert!(
        furthest < 39,
        "the status sweep reached column {furthest} of 200, extending beyond the status bar"
    );
}

// ------------------------------------------------- tiny terminals & unicode

/// Every dialog the app can show, for sweeps that must cover all of them.
fn every_dialog() -> Vec<ModalState> {
    vec![
        ModalState::None,
        ModalState::TextInput {
            title: "IMPORT".into(),
            prompt: "Paste a share link".into(),
            buffer: "vless://ünïcødé-名前-🚀".into(),
            purpose: zeronet_tui::modal::TextPurpose::ImportConfig,
            created_tick: 0,
            select_all: false,
        },
        ModalState::NumberEdit {
            title: "MTU".into(),
            setting_key: "tun_mtu".into(),
            min: 576,
            max: 9000,
            buffer: "1500".into(),
            created_tick: 0,
            select_all: true,
        },
        ModalState::AshesWarning {
            title: "WARNING".into(),
            message: "سرور در دسترس نیست — 服务器不可用 🔥".into(),
            created_tick: 0,
        },
        ModalState::QuitConfirmation { created_tick: 0 },
        ModalState::Confirm {
            title: "DELETE".into(),
            message: "Delete 3 profiles?".into(),
            action: zeronet_tui::modal::ConfirmAction::DeleteProfiles(vec![1, 2, 3]),
            created_tick: 0,
        },
        ModalState::ManualProfile {
            form: zeronet_tui::manual_profile::ManualProfileForm::new(),
            editing_text: false,
            input_buffer: String::new(),
            created_tick: 0,
        },
        share_dialog("名前 🚀 Persian سرور"),
        sudo_dialog("hunter2", Some("Sorry, try again.")),
        help_modal(),
        ModalState::ImageView {
            title: "QR".into(),
            findings: vec!["vless://x@y:1".into()],
            created_tick: 0,
        },
    ]
}

fn unicode_configs() -> Vec<ConfigRecord> {
    vec![
        config(1, "🇩🇪 Germany ⚡ Fast", "1.1.1.1", 443, Some(40.0)),
        config(2, "東京 サーバー 高速ノード", "2.2.2.2", 443, Some(90.0)),
        config(3, "سرور ایران پرسرعت", "3.3.3.3", 443, None),
        config(4, "東京 サーバー 高速ノード", "4.4.4.4", 8443, Some(900.0)),
        config(5, "e\u{301}\u{301} combining", "5.5.5.5", 1, Some(1.0)),
    ]
}

#[test]
fn every_screen_survives_every_tiny_terminal_size() {
    // Resizing down to nothing must never panic: a Rect underflow or an
    // out-of-bounds buffer index anywhere in the draw path would take the
    // whole client (and the tunnel with it) down.
    let tabs = [
        ActiveTab::Dashboard,
        ActiveTab::Subscriptions,
        ActiveTab::IpScanner,
        ActiveTab::Settings,
    ];
    let dialogs = every_dialog();
    for w in 0..=14u16 {
        for h_ in 0..=14u16 {
            for tab in tabs {
                for dialog in &dialogs {
                    let mut h = Harness::new();
                    h.configs = unicode_configs();
                    h.active_tab = tab;
                    h.modal_state = dialog.clone();
                    h.stats.status = ConnectionStatus::Connected;
                    h.toasts
                        .error("a toast that needs wrapping on a tiny screen");
                    h.effects.trigger_rainbow(1.0, 1.0);
                    h.effects.advance_tick();
                    let _ = h.draw(w, h_);
                }
            }
        }
    }
    // The smallest sizes that get the real layout, where every panel is at
    // its most cramped, plus a few awkward in-between sizes where layouts
    // switch strategy.
    let mut sizes: Vec<(u16, u16)> = Vec::new();
    for w in (zeronet_tui::ui::MIN_WIDTH..=zeronet_tui::ui::MIN_WIDTH + 24).step_by(4) {
        for h_ in (zeronet_tui::ui::MIN_HEIGHT..=zeronet_tui::ui::MIN_HEIGHT + 12).step_by(2) {
            sizes.push((w, h_));
        }
    }
    sizes.extend([
        (15u16, 40u16),
        (200, 5),
        (5, 200),
        (23, 23),
        (25, 17),
        (41, 13),
        (61, 19),
    ]);
    for (w, h_) in sizes {
        for tab in tabs {
            for dialog in &dialogs {
                let mut h = Harness::new();
                h.configs = unicode_configs();
                h.active_tab = tab;
                h.modal_state = dialog.clone();
                let _ = h.draw(w, h_);
            }
        }
    }
}

#[test]
fn a_terminal_below_the_minimum_says_so_instead_of_drawing_fragments() {
    let mut h = Harness::new();
    let frame = h.draw(40, 12);
    assert!(frame.contains("Terminal too small"), "{frame}");
    assert!(frame.contains("40×12"));
    // Nothing behind the notice is clickable.
    assert_eq!(h.interaction.hit_test(5, 1), None);

    let frame = h.draw(zeronet_tui::ui::MIN_WIDTH, zeronet_tui::ui::MIN_HEIGHT);
    assert!(!frame.contains("Terminal too small"));
    assert!(frame.contains("ZERO"));
}

/// Render one frame and hand back the buffer, for tests that need cell
/// positions rather than text (a wide glyph fills two cells).
fn draw_buffer(h: &mut Harness, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| h.render_into(frame)).unwrap();
    terminal.backend().buffer().clone()
}

/// Cell columns at which `word` starts, one per row that contains it.
fn cell_columns_of(buf: &ratatui::buffer::Buffer, word: &str) -> Vec<u16> {
    let letters: Vec<String> = word.chars().map(String::from).collect();
    let mut cols = Vec::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width.saturating_sub(letters.len() as u16) {
            if letters
                .iter()
                .enumerate()
                .all(|(i, l)| buf[(x + i as u16, y)].symbol() == l)
            {
                cols.push(x);
                break;
            }
        }
    }
    cols
}

#[test]
fn unicode_profile_names_keep_the_table_columns_aligned() {
    // A CJK or emoji name is twice as wide as its char count. Measuring in
    // chars pushed the protocol and ping columns out of line.
    let mut h = Harness::new();
    h.configs = unicode_configs();
    let buf = draw_buffer(&mut h, 140, 44);
    let cols = cell_columns_of(&buf, "VLESS");
    assert!(cols.len() >= 4, "expected the unicode rows on screen");
    assert!(
        cols.windows(2).all(|w| w[0] == w[1]),
        "protocol column drifted between rows: {cols:?}"
    );
}

#[test]
fn a_toast_with_wide_characters_wraps_inside_its_box() {
    let mut h = Harness::new();
    h.toasts
        .info("連線成功 サーバーに接続しました 🚀🚀🚀 اتصال برقرار شد — 東京 高速ノード 経由");
    let buf = draw_buffer(&mut h, 120, 40);

    // The toast is 46 cells wide, two cells in from the right edge.
    let (left, right) = (120 - 48, 120 - 48 + 45);
    let rows: Vec<u16> = (0..40)
        .filter(|&y| buf[(left, y)].symbol() == "│")
        .collect();
    assert!(rows.len() >= 2, "the message should need several rows");
    for y in rows {
        assert_eq!(
            buf[(right, y)].symbol(),
            "│",
            "row {y}: text overflowed the toast's right border"
        );
    }
    let text: String = (0..40)
        .flat_map(|y| (0..120).map(move |x| (x, y)))
        .map(|p| buf[p].symbol().to_string())
        .collect();
    assert!(text.contains("連"), "the message is missing");
    // Wrapping measured in chars under-counted the rows a wide message
    // needs, and the toast cut its last line off.
    assert!(text.contains("経"), "the end of the message was cut off");
}

fn sample_usage(self_far_down: bool) -> zeronet_tui::usage::UsageSnapshot {
    let mut processes: Vec<(String, f32, u64, bool)> = (0..60)
        .map(|i| {
            (
                format!("app-{i:02}"),
                40.0 / (i as f32 + 1.0),
                1_000_000 * (60 - i),
                false,
            )
        })
        .collect();
    let own_cpu = if self_far_down { 0.01 } else { 30.0 };
    processes.push(("zeronet-tui".into(), own_cpu, 14 * 1024 * 1024, true));
    zeronet_tui::usage::UsageSnapshot {
        self_cpu: own_cpu,
        self_memory: 14 * 1024 * 1024,
        self_threads: Some(9),
        system: Some(zeronet_tui::usage::SystemUsage {
            cpu: 37.0,
            memory_used: 9 * 1024 * 1024 * 1024,
            memory_total: 32 * 1024 * 1024 * 1024,
            cores: 16,
            process_count: 61,
            apps: zeronet_tui::usage::group_apps(processes),
        }),
    }
}

#[test]
fn the_activity_page_waits_politely_before_the_first_sample() {
    let mut h = Harness::new();
    h.active_tab = ActiveTab::Activity;
    let frame = h.draw(120, 36);
    assert!(frame.contains("measuring"), "{frame}");
    assert!(frame.contains("Waiting for the first sample"));
}

#[test]
fn the_activity_page_always_shows_this_apps_row() {
    for far_down in [false, true] {
        let mut h = Harness::new();
        h.active_tab = ActiveTab::Activity;
        h.usage = Some(sample_usage(far_down));
        h.cpu_history = vec![0.1, 0.4, 0.2, 0.3];
        let frame = h.draw(120, 36);
        dump(&format!("activity_{far_down}"), &frame);
        assert!(frame.contains("this app"), "own row missing:\n{frame}");
        assert!(frame.contains("ZeroNet is #"), "{frame}");
        assert!(frame.contains("14.0 MB"));
        assert!(frame.contains("9 threads"));
        if far_down {
            assert!(frame.contains("more"), "gap marker missing:\n{frame}");
        }
    }
}

#[test]
fn the_activity_page_survives_tiny_and_huge_terminals() {
    for (w, hgt) in [(64u16, 18u16), (80, 24), (300, 100)] {
        let mut h = Harness::new();
        h.active_tab = ActiveTab::Activity;
        h.usage = Some(sample_usage(true));
        let _ = h.draw(w, hgt);
    }
}

#[test]
fn the_status_bar_shows_ports_and_this_apps_cost() {
    let mut h = Harness::new();
    h.usage = Some(sample_usage(false));
    let frame = h.draw(140, 40);
    let footer = frame.lines().last().unwrap();
    assert!(footer.contains("SOCKS 10808"), "{footer}");
    assert!(footer.contains("RAM 14.0 MB"), "{footer}");
    h.settings.show_usage = false;
    let frame = h.draw(140, 40);
    assert!(!frame.lines().last().unwrap().contains("RAM"));
}

#[test]
fn every_theme_renders_every_page() {
    for id in zeronet_tui::theme::ThemeId::ALL {
        for tab in [
            ActiveTab::Dashboard,
            ActiveTab::Activity,
            ActiveTab::Settings,
        ] {
            let mut h = Harness::new();
            h.theme = zeronet_tui::theme::Theme::new(id, h.caps.depth);
            h.active_tab = tab;
            h.usage = Some(sample_usage(false));
            let frame = h.draw(120, 36);
            assert!(!frame.trim().is_empty());
        }
    }
}

#[test]
fn a_live_session_shows_its_protocol_clock_and_speed_graphs() {
    let mut h = Harness::new();
    h.stats.status = ConnectionStatus::Connected;
    h.stats.active_node_name = "AmneziaVPN".into();
    h.stats.download_speed_bps = 2_400_000;
    let up: Vec<u64> = (0..40).map(|i| i * 10_000).collect();
    let down: Vec<u64> = (0..40).map(|i| i * 60_000).collect();
    let mut terminal = ratatui::Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal
        .draw(|frame| {
            let mut renderer = UiRenderer {
                theme: &h.theme,
                caps: &h.caps,
                interaction: &mut h.interaction,
                effects: &mut h.effects,
                settings: &h.settings,
                stats: &h.stats,
                active_tab: ActiveTab::Dashboard,
                configs: &h.configs,
                subscriptions: &h.subscriptions,
                selected_config_idx: 0,
                node_scroll: 0,
                marked: &h.marked,
                filter: "",
                filter_focused: false,
                advanced_open: false,
                filter_select_all: false,
                inline_rename: None,
                system_proxy: h.system_proxy,
                modal_anim: h.modal_anim,
                settings_scroll: h.settings_scroll,
                help_scroll: h.help_scroll,
                selection_tick: 0,
                context_menu: None,
                drag: None,
                latency_history: &h.latency_history,
                is_elevated: false,
                elevation_prompt: None,
                modal_state: &h.modal_state,
                image_view: None,
                throbber_state: &mut h.throbber,
                scanner_tested: 0,
                scanner_healthy: 0,
                scanner_speed: 0.0,
                is_scanning: false,
                scanner_results: &[],
                toasts: &mut h.toasts,
                usage: Default::default(),
                perf: None,
                session: Some(std::time::Duration::from_secs(3 * 3600 + 7 * 60 + 5)),
                speed_history: (&up, &down),
                update_status: &zeronet_tui::update::Status::Idle,
            finder_status: None,
            };
            renderer.render(frame);
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
                + "\n"
        })
        .collect();
    assert!(text.contains("session 3:07:05"), "{text}");
    assert!(text.contains("VLESS  Node:"), "{text}");
    assert!(text.contains('█'), "speed graph missing:\n{text}");
    // The v2rayN-style columns appear only once the table has room.
    assert!(!text.contains("Transport"), "{text}");
    let wide = h.draw(220, 50);
    assert!(
        wide.contains("Address") && wide.contains("Transport"),
        "{wide}"
    );
}
