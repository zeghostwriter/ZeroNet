#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;
    use zeronet_tui::db::Database;
    use zeronet_tui::effects::VisualEffects;
    use zeronet_tui::interaction::{ComponentId, InteractionEngine};
    use zeronet_tui::theme::Theme;
    use zeronet_tui::toast::ToastManager;

    #[test]
    fn test_sqlite_db_initialization_and_crud() {
        let temp_dir = std::env::temp_dir().join(format!(
            "zeronet_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db_path = temp_dir.join("test.db");
        let db = Database::open(&db_path).expect("database opens cleanly");

        // Insert config
        let id = db
            .insert_config("Test Node", "vless", "1.1.1.1", 443, "{}", None)
            .expect("insert config");
        assert!(id > 0);

        let configs = db.get_configs().expect("list configs");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].remark, "Test Node");

        // Set active
        db.set_active_config(id).expect("set active");
        let active = db
            .get_active_config()
            .expect("get active")
            .expect("some active");
        assert_eq!(active.id, id);
        assert!(active.is_active);

        // Ping update and metrics
        db.update_config_ping(id, 42.5).expect("update ping");
        let metrics = db.get_metrics_history(id, 10).expect("get metrics");
        assert_eq!(metrics, vec![42.5]);

        // Feedback
        let fid = db
            .insert_feedback(Some("test@example.com"), "Great app!")
            .expect("insert feedback");
        assert!(fid > 0);

        // Settings
        let mut settings = db.load_settings();
        settings.tun_enabled = true;
        settings.tls_fragment_size = 180;
        db.save_settings(&settings).expect("save settings");

        let reloaded = db.load_settings();
        assert!(reloaded.tun_enabled);
        assert_eq!(reloaded.tls_fragment_size, 180);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_toast_manager() {
        let mut toasts = ToastManager::new();
        toasts.success("Connected");
        toasts.error("Failed");
        let active = toasts.active_toasts();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_interaction_hit_boxes_and_hover() {
        let mut engine = InteractionEngine::new();
        let btn_rect = Rect {
            x: 10,
            y: 10,
            width: 20,
            height: 5,
        };
        engine.register_hit_box(ComponentId::ConnectButton, btn_rect);

        // Outside
        engine.update_mouse_position(5, 5);
        assert!(!engine.is_hovered(ComponentId::ConnectButton));

        // Inside
        engine.update_mouse_position(15, 12);
        assert!(engine.is_hovered(ComponentId::ConnectButton));
        assert_eq!(
            engine.handle_click(15, 12),
            Some(ComponentId::ConnectButton)
        );
    }

    #[test]
    fn test_effects_sparkline() {
        let sparkline = VisualEffects::format_sparkline(&[10.0, 50.0, 100.0, 25.0], 10);
        assert_eq!(sparkline.chars().count(), 4);
    }

    #[test]
    fn test_theme_colors() {
        let theme = Theme::default();
        assert_ne!(theme.accent, theme.bg);
    }

    #[tokio::test]
    async fn test_scanner_integration_and_export() {
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<zero_scanner::types::ProbeResult>();
        let hit = zero_scanner::types::ProbeResult {
            ip: "104.16.1.1".parse().unwrap(),
            port: 443,
            mode: zero_scanner::types::ProbeMode::Http,
            latencies_ms: vec![120.0],
            flags: zero_scanner::types::ResultFlags::HTTP_OK,
            http_status: 200,
            colo: Some("FRA".into()),
            throughput_mbps: 15.0,
            isp: Some("Cloudflare".into()),
            asn: Some(13335),
        };
        tx.send(hit).unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.port, 443);

        let exports = zero_scanner::export::generate_exports(&[received], None);
        assert!(exports.endpoints_text.contains("104.16.1.1:443"));
    }

    #[test]
    fn test_toast_dismiss_button() {
        let mut toasts = ToastManager::new();
        toasts.info("First");
        toasts.warning("Second");
        assert_eq!(toasts.active_toasts().len(), 2);

        // Dismiss first toast
        toasts.dismiss(0);
        let remaining = toasts.active_toasts();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].message, "Second");
    }

    #[test]
    fn test_amnezia_link_compilation_and_runnable() {
        let link = "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@155.117.13.26:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.googletagmanager.com&fp=chrome&pbk=F6PK1mARGsyeoVDKws76F0tNoIC1wd9sEG20c7yF2wY&sid=7963d08380d47375&type=tcp&headerType=none#AmneziaVPN";

        let runnable = zeronet_tui::daemon::prepare_runnable_config(link, false)
            .expect("prepare runnable config");
        let mut configs = zero_config::parse_config_array(&runnable).expect("parse config array");
        assert_eq!(configs.len(), 1);

        let (_, cfg, _) = configs.remove(0);
        let gen = zero_config::RuntimeGeneration::compile(cfg, zero_core::GenerationId(1))
            .expect("compile runtime generation");
        assert_eq!(gen.config.outbounds.len(), 3);
        assert_eq!(gen.config.outbounds[0].tag.as_ref(), "proxy");
        assert!(matches!(
            gen.config.outbounds[0].protocol,
            zero_config::OutboundProtocol::Vless(_)
        ));
    }

    #[test]
    fn test_manual_profile_form_to_json() {
        let form = zeronet_tui::manual_profile::ManualProfileForm::new();
        let json_str = form.to_json().expect("form converts to json");
        let parsed =
            zero_config::parse_config_array(&json_str).expect("parsed as valid config array");
        assert_eq!(parsed.len(), 1);
        let (_, cfg, _) = parsed.into_iter().next().unwrap();
        let gen = zero_config::RuntimeGeneration::compile(cfg, zero_core::GenerationId(1))
            .expect("compiled");
        assert_eq!(gen.config.outbounds[0].tag.as_ref(), "proxy");
    }

    #[test]
    fn test_rainbow_wave_and_ashes_effects() {
        let mut fx = VisualEffects::new();
        fx.trigger_rainbow(10.0, 10.0);
        fx.advance_tick();

        let color = fx.rainbow_color_at(11, 10);
        assert!(
            color.is_some(),
            "Rainbow wave produces color at adjacent cell"
        );

        let rect = Rect {
            x: 5,
            y: 5,
            width: 30,
            height: 15,
        };
        let sparks = fx.ashes_border_overlay(rect, 1);
        assert!(
            !sparks.is_empty(),
            "Ashes border overlay produces ember particles"
        );

        fx.emit_ashes_burst(rect, 20);
        assert!(
            !fx.current_ashes().is_empty(),
            "Ashes burst populates active particles"
        );
    }
}
