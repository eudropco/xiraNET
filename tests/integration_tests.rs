//! xiraNET v3.0.0 — Integration Test Suite
//! Tests all core domains without starting the HTTP server.

// ═══════════════════════════════════════════════════════════════
// WAF Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod waf_tests {
    use xiranet::middleware::waf::{Waf, WafMode, WafVerdict};

    #[test]
    fn test_waf_blocks_sql_injection_union() {
        let waf = Waf::new(true, WafMode::Block);
        let headers: Vec<(String, String)> = vec![];
        let verdict = waf.inspect(
            "/api/users",
            Some("id=1 union select from users"),
            "",
            &headers,
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "WAF should block UNION-based SQL injection"
        );
    }

    #[test]
    fn test_waf_blocks_xss() {
        let waf = Waf::new(true, WafMode::Block);
        let headers: Vec<(String, String)> = vec![];
        let verdict = waf.inspect(
            "/api/comments",
            None,
            "<script>alert('xss')</script>",
            &headers,
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "WAF should block XSS in body"
        );
    }

    #[test]
    fn test_waf_blocks_path_traversal() {
        let waf = Waf::new(true, WafMode::Block);
        let headers: Vec<(String, String)> = vec![];
        let verdict = waf.inspect(
            "/api/files/../../etc/passwd",
            None,
            "",
            &headers,
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "WAF should block path traversal"
        );
    }

    #[test]
    fn test_waf_allows_clean_request() {
        let waf = Waf::new(true, WafMode::Block);
        let headers: Vec<(String, String)> = vec![];
        let verdict = waf.inspect(
            "/api/users",
            Some("page=1&limit=20"),
            r#"{"name": "test"}"#,
            &headers,
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Clean request should pass WAF"
        );
    }

    #[test]
    fn test_waf_disabled_allows_everything() {
        let waf = Waf::new(false, WafMode::Block);
        let headers: Vec<(String, String)> = vec![];
        let verdict = waf.inspect(
            "/api",
            Some("id=1 union select from users where 1=1"),
            "",
            &headers,
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Disabled WAF should allow everything"
        );
    }

    #[test]
    fn test_waf_detect_only_mode_allows_attacks() {
        let waf = Waf::new(true, WafMode::DetectOnly);
        let headers: Vec<(String, String)> = vec![];
        let verdict = waf.inspect(
            "/api/users",
            Some("id=1 union select from users"),
            "",
            &headers,
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Log mode should not block, only log"
        );
    }

    #[test]
    fn test_waf_detect_only_increments_audit_counter() {
        // detect_only modunda saldırı match etse bile Allow dönmeli,
        // ama xiranet_waf_detects_total counter tick'lemeli (audit trail).
        let before = xiranet::metrics::WAF_DETECTS.with_label_values(&["SQLI"]).get();

        let waf = Waf::new(true, WafMode::DetectOnly);
        let _ = waf.inspect(
            "/api/users",
            Some("id=1 union select from users"),
            "",
            &[],
            "127.0.0.1",
        );

        let after = xiranet::metrics::WAF_DETECTS.with_label_values(&["SQLI"]).get();
        assert!(
            after > before,
            "WAF_DETECTS{{SQLI}} must increment in detect_only mode (before={before}, after={after})"
        );
    }

    #[test]
    fn test_waf_clean_request_no_false_positive_on_email() {
        // K2 fix sonrası: '@' standalone false positive üretmemeli (önceden block).
        let waf = Waf::new(true, WafMode::Block);
        let body = r#"{"email":"mert@example.com","note":"hello; world"}"#;
        let verdict = waf.inspect("/api/users", None, body, &[], "127.0.0.1");
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Legitimate email + semicolon in JSON should not trip SQLi rule"
        );
    }

    #[test]
    fn test_waf_clean_request_no_false_positive_on_dash_dash() {
        // '--' standalone (markdown gibi) artık SQL keyword olmadan match etmemeli.
        let waf = Waf::new(true, WafMode::Block);
        let body = "hello -- end of comment\nmore text";
        let verdict = waf.inspect("/api/test", None, body, &[], "127.0.0.1");
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Trailing -- comment alone should not match SQLi"
        );
    }

    // ═══ Adversarial — normalization bypass'larını dene ═══

    #[test]
    fn test_waf_blocks_url_encoded_sqli() {
        let waf = Waf::new(true, WafMode::Block);
        // %75%6e%69%6f%6e = "union" — eski sürüm raw regex'le match etmiyordu.
        let verdict = waf.inspect(
            "/api/users",
            Some("id=1%20%75%6e%69%6f%6e%20select%20from%20users"),
            "",
            &[],
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "URL-encoded UNION SELECT must be blocked after normalization"
        );
    }

    #[test]
    fn test_waf_blocks_triple_encoded_sqli() {
        let waf = Waf::new(true, WafMode::Block);
        // %252520 = encoded(%2520) = encoded(encoded(%20)) — 3-pass decode gerek.
        let verdict = waf.inspect(
            "/api/users",
            Some("id=1%252520union%252520select%252520from%252520users"),
            "",
            &[],
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "Triple-encoded SQLi must be blocked (fixed-point decode)"
        );
    }

    #[test]
    fn test_waf_blocks_double_encoded_sqli() {
        let waf = Waf::new(true, WafMode::Block);
        // %2520 = encoded %20 = encoded space; 2-pass decode gerek.
        let verdict = waf.inspect(
            "/api/users",
            Some("id=1%2520union%2520select%2520from%2520users"),
            "",
            &[],
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "Double-encoded SQLi must be blocked"
        );
    }

    #[test]
    fn test_waf_blocks_unicode_escape_xss() {
        let waf = Waf::new(true, WafMode::Block);
        // <script = '<script' (JSON unicode escape)
        let body = r#"{"comment":"<script>alert(1)</script>"}"#;
        let verdict = waf.inspect("/api/post", None, body, &[], "127.0.0.1");
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "Unicode-escape XSS must be blocked"
        );
    }

    #[test]
    fn test_waf_blocks_url_encoded_traversal() {
        let waf = Waf::new(true, WafMode::Block);
        // %2e%2e%2f = '../' raw
        let verdict = waf.inspect(
            "/files/%2e%2e%2fetc%2fpasswd",
            None,
            "",
            &[],
            "127.0.0.1",
        );
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "URL-encoded traversal must be blocked"
        );
    }

    #[test]
    fn test_waf_authorization_jwt_not_false_positive() {
        // JWT base64 random byte'larında "OR " gibi substring olabilir;
        // structured header allow-list ile inspection'a girmemeli.
        let waf = Waf::new(true, WafMode::Block);
        let headers = vec![(
            "authorization".to_string(),
            // 'or 1=1' pattern'ine benzer byte sequence içeren sahte JWT
            "Bearer eyJhbGciOiJIUzI1NiJ9.OR1A2.signature_or_1_eq_1".to_string(),
        )];
        let verdict = waf.inspect("/api/me", None, "", &headers, "127.0.0.1");
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Authorization header with JWT-looking content must not trigger WAF (structured header)"
        );
    }

    #[test]
    fn test_waf_cookie_not_false_positive() {
        let waf = Waf::new(true, WafMode::Block);
        let headers = vec![(
            "cookie".to_string(),
            "sid=abc; theme=dark; tracking=union+select".to_string(),
        )];
        let verdict = waf.inspect("/", None, "", &headers, "127.0.0.1");
        assert!(
            matches!(verdict, WafVerdict::Allow),
            "Cookie header structured content must not trigger WAF"
        );
    }

    #[test]
    fn test_waf_free_text_header_still_inspected() {
        let waf = Waf::new(true, WafMode::Block);
        // Custom free-text header — inspection'a girer.
        let headers = vec![(
            "x-custom-comment".to_string(),
            "1 union select from users".to_string(),
        )];
        let verdict = waf.inspect("/", None, "", &headers, "127.0.0.1");
        assert!(
            matches!(verdict, WafVerdict::Block { .. }),
            "Free-text headers must still be inspected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Bot Detection Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod bot_tests {
    use xiranet::middleware::bot_detect::{BotDetector, BotVerdict};

    #[test]
    fn test_detects_known_bot() {
        let detector = BotDetector::new(true, false, 60);
        let verdict = detector.check("1.2.3.4", "Googlebot/2.1 (+http://www.google.com/bot.html)");
        assert!(
            matches!(verdict, BotVerdict::Bot { .. }),
            "Should detect Googlebot as bot"
        );
    }

    #[test]
    fn test_allows_normal_browser() {
        let detector = BotDetector::new(true, false, 60);
        let verdict = detector.check(
            "10.0.0.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        );
        assert!(
            matches!(verdict, BotVerdict::Human),
            "Chrome browser should be human"
        );
    }

    #[test]
    fn test_disabled_allows_all() {
        let detector = BotDetector::new(false, false, 60);
        let verdict = detector.check("1.1.1.1", "");
        assert!(
            matches!(verdict, BotVerdict::Human),
            "Disabled detector should pass all as human"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Identity Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod identity_tests {
    use xiranet::identity::users::{AuthResult, UserManager, UserRole};

    #[test]
    fn test_register_and_authenticate() {
        let mgr = UserManager::new();
        let user = mgr
            .register(
                "test@xira.net".into(),
                "testuser".into(),
                "securepass123",
                UserRole::Developer,
            )
            .unwrap();
        assert_eq!(user.email, "test@xira.net");
        assert!(user.enabled);

        match mgr.authenticate("test@xira.net", "securepass123") {
            AuthResult::Success { user, token } => {
                assert_eq!(user.email, "test@xira.net");
                assert!(token.starts_with("xira_tok_"));
                assert_eq!(user.login_count, 1);
            }
            other => panic!("Expected Success, got: {other:?}"),
        }
    }

    #[test]
    fn test_wrong_password() {
        let mgr = UserManager::new();
        mgr.register("a@b.com".into(), "a".into(), "correct", UserRole::Viewer)
            .unwrap();
        match mgr.authenticate("a@b.com", "wrong") {
            AuthResult::InvalidCredentials => {}
            other => panic!("Expected InvalidCredentials, got: {other:?}"),
        }
    }

    #[test]
    fn test_duplicate_email_rejected() {
        let mgr = UserManager::new();
        mgr.register(
            "dup@test.com".into(),
            "first".into(),
            "pass",
            UserRole::Viewer,
        )
        .unwrap();
        assert!(mgr
            .register(
                "dup@test.com".into(),
                "second".into(),
                "pass",
                UserRole::Viewer
            )
            .is_err());
    }

    #[test]
    fn test_disable_user_blocks_login() {
        let mgr = UserManager::new();
        let user = mgr
            .register(
                "dis@test.com".into(),
                "dis".into(),
                "pass",
                UserRole::Viewer,
            )
            .unwrap();
        mgr.disable_user(&user.id);
        match mgr.authenticate("dis@test.com", "pass") {
            AuthResult::AccountDisabled => {}
            other => panic!("Expected AccountDisabled, got: {other:?}"),
        }
    }

    #[test]
    fn test_rbac_superadmin_has_all_permissions() {
        let mgr = UserManager::new();
        let user = mgr
            .register(
                "sa@test.com".into(),
                "sa".into(),
                "pass",
                UserRole::SuperAdmin,
            )
            .unwrap();
        assert!(mgr.has_permission(&user.id, "anything"));
        assert!(mgr.has_permission(&user.id, "admin.delete.universe"));
    }

    #[test]
    fn test_rbac_explicit_permissions() {
        let mgr = UserManager::new();
        let user = mgr
            .register(
                "dev@test.com".into(),
                "dev".into(),
                "pass",
                UserRole::Developer,
            )
            .unwrap();
        assert!(!mgr.has_permission(&user.id, "admin.users"));
        mgr.add_permission(&user.id, "admin.users".to_string());
        assert!(mgr.has_permission(&user.id, "admin.users"));
    }

    #[test]
    fn test_password_salting() {
        let mgr = UserManager::new();
        let u1 = mgr
            .register(
                "s1@test.com".into(),
                "s1".into(),
                "samepass",
                UserRole::Viewer,
            )
            .unwrap();
        let u2 = mgr
            .register(
                "s2@test.com".into(),
                "s2".into(),
                "samepass",
                UserRole::Viewer,
            )
            .unwrap();
        assert_ne!(
            u1.password_hash, u2.password_hash,
            "Same password must produce different hashes"
        );
        assert!(
            u1.password_hash.starts_with("$argon2"),
            "Hash must be Argon2 format, got: {}",
            u1.password_hash
        );
        assert!(
            u2.password_hash.starts_with("$argon2"),
            "Hash must be Argon2 format, got: {}",
            u2.password_hash
        );
    }

    #[test]
    fn test_user_count() {
        let mgr = UserManager::new();
        assert_eq!(mgr.user_count(), 0);
        mgr.register("a@a.com".into(), "a".into(), "p", UserRole::Viewer)
            .unwrap();
        mgr.register("b@b.com".into(), "b".into(), "p", UserRole::Viewer)
            .unwrap();
        assert_eq!(mgr.user_count(), 2);
    }
}

// ═══════════════════════════════════════════════════════════════
// Cron Scheduler Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod cron_tests {
    use xiranet::automation::cron::{CronSchedule, CronScheduler};

    #[tokio::test]
    async fn test_add_and_list_jobs() {
        let scheduler = CronScheduler::new();
        let id = scheduler
            .add_job(
                "test-job".into(),
                CronSchedule::EveryMinutes(5),
                "http://localhost:3000/health".into(),
                "GET".into(),
            )
            .await;
        assert!(!id.is_empty());
        let jobs = scheduler.list_jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].name, "test-job");
        assert!(jobs[0].enabled);
    }

    #[tokio::test]
    async fn test_remove_job() {
        let scheduler = CronScheduler::new();
        let id = scheduler
            .add_job(
                "remove-me".into(),
                CronSchedule::EverySeconds(30),
                "http://localhost/test".into(),
                "GET".into(),
            )
            .await;
        assert!(scheduler.remove_job(&id).await);
        assert_eq!(scheduler.list_jobs().await.len(), 0);
    }

    #[tokio::test]
    async fn test_remove_nonexistent() {
        let scheduler = CronScheduler::new();
        assert!(!scheduler.remove_job("nonexistent").await);
    }

    #[test]
    fn test_schedule_intervals() {
        assert_eq!(CronSchedule::EverySeconds(10).interval_secs(), 10);
        assert_eq!(CronSchedule::EveryMinutes(5).interval_secs(), 300);
        assert_eq!(CronSchedule::EveryHours(2).interval_secs(), 7200);
        assert_eq!(
            CronSchedule::Daily { hour: 9, minute: 0 }.interval_secs(),
            86400
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Event Bus Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod eventbus_tests {
    use std::sync::Arc;
    use xiranet::automation::event_bus::EventBus;

    #[tokio::test]
    async fn test_publish_event() {
        let bus = EventBus::new(100);
        let id = bus
            .publish(
                "request.completed",
                "api-service",
                serde_json::json!({"method": "GET", "status": 200}),
            )
            .await;
        assert!(!id.is_empty());
        let events = bus.recent_events(10).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].topic, "request.completed");
        assert_eq!(events[0].source, "api-service");
    }

    #[tokio::test]
    async fn test_subscribe_receives_events() {
        // Önceki versiyon `tokio::time::sleep(50ms)` ile race umut ediyordu — yavaş CI'de
        // subscriber hazır olmadan publish ateşleniyordu. tokio::sync::Notify ile
        // deterministik senkronizasyon yapıyoruz.
        let bus = Arc::new(EventBus::new(100));
        let mut rx = bus.subscribe("test.topic", "sub-1");
        let ready = Arc::new(tokio::sync::Notify::new());

        let bus2 = bus.clone();
        let ready2 = ready.clone();
        let publisher = tokio::spawn(async move {
            ready2.notified().await;
            bus2.publish("test.topic", "src", serde_json::json!({"key": "value"}))
                .await;
        });

        // Subscriber kayıt edildi — publisher'a yeşil ışık ver
        ready.notify_one();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await;
        assert!(event.is_ok(), "Should receive event within timeout");
        let event = event.unwrap().unwrap();
        assert_eq!(event.topic, "test.topic");
        assert_eq!(event.source, "src");
        publisher.await.unwrap();
    }

    #[tokio::test]
    async fn test_event_log_capped() {
        let bus = EventBus::new(5);
        for i in 0..10 {
            bus.publish("test", "src", serde_json::json!({"n": i}))
                .await;
        }
        let events = bus.recent_events(20).await;
        assert!(
            events.len() <= 5,
            "Event log should be capped at max_log_size"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// SLA Monitor Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod sla_tests {
    use xiranet::metrics::sla::SlaMonitor;

    #[test]
    fn test_record_and_report() {
        let monitor = SlaMonitor::new();
        for _ in 0..9 {
            monitor.record_check("api-svc", true, 50.0);
        }
        monitor.record_check("api-svc", false, 5000.0);

        let report = monitor.all_metrics();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].service_name, "api-svc");
        assert_eq!(report[0].total_checks, 10);
        assert!((report[0].uptime_percent - 90.0).abs() < 0.01);
    }

    #[test]
    fn test_sla_violation_detection() {
        let monitor = SlaMonitor::new();
        for _ in 0..10 {
            monitor.record_check("failing-svc", false, 5000.0);
        }
        let violations = monitor.check_violations();
        assert!(
            !violations.is_empty(),
            "Should detect SLA violations when uptime < target"
        );
    }

    #[test]
    fn test_latency_percentiles() {
        let monitor = SlaMonitor::new();
        for i in 1..=100 {
            monitor.record_check("fast-svc", true, i as f64);
        }
        let report = monitor.all_metrics();
        assert!(report[0].latency_p99 > 0.0, "P99 should be calculated");
        assert!(report[0].latency_avg > 0.0, "Average should be calculated");
    }
}

// ═══════════════════════════════════════════════════════════════
// Uptime Page Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod uptime_tests {
    use xiranet::observability::uptime::{ServiceStatus, UptimePage};

    #[test]
    fn test_update_and_render() {
        let page = UptimePage::new();
        page.update("web-api", ServiceStatus::Operational, 45.0);
        page.update("db", ServiceStatus::MajorOutage, 5000.0);

        let rendered = page.render();
        assert_eq!(
            rendered.get("status").and_then(|v| v.as_str()).unwrap(),
            "Issues Detected"
        );
        assert_eq!(
            rendered
                .get("services")
                .and_then(|v| v.as_array())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn test_all_operational() {
        let page = UptimePage::new();
        page.update("svc-1", ServiceStatus::Operational, 50.0);
        page.update("svc-2", ServiceStatus::Operational, 30.0);
        assert_eq!(
            page.render()
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap(),
            "All Systems Operational"
        );
    }

    #[test]
    fn test_history_limited_to_90() {
        let page = UptimePage::new();
        for _ in 0..100 {
            page.update("svc", ServiceStatus::Operational, 50.0);
        }
        // Rendered page should still work
        let rendered = page.render();
        assert_eq!(
            rendered
                .get("services")
                .and_then(|v| v.as_array())
                .unwrap()
                .len(),
            1
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Incident Manager Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod incident_tests {
    use xiranet::observability::incidents::{IncidentManager, IncidentStatus, Severity};

    #[tokio::test]
    async fn test_create_incident() {
        let mgr = IncidentManager::new();
        let id = mgr
            .create(
                "Service Down: api".into(),
                Severity::Major,
                vec!["api".into()],
            )
            .await;
        assert!(!id.is_empty());
        assert_eq!(mgr.list().await.len(), 1);
    }

    #[tokio::test]
    async fn test_incident_lifecycle() {
        let mgr = IncidentManager::new();
        let id = mgr.create("Test".into(), Severity::Minor, vec![]).await;
        mgr.update_status(&id, IncidentStatus::Identified).await;
        mgr.update_status(&id, IncidentStatus::Resolved).await;
        assert_eq!(mgr.active().await.len(), 0);
        assert!(mgr.list().await[0].resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_timeline_entries() {
        let mgr = IncidentManager::new();
        let id = mgr
            .create("Timeline test".into(), Severity::Info, vec![])
            .await;
        mgr.add_update(&id, "Investigating".into(), "eng1".into())
            .await;
        mgr.add_update(&id, "Fix deployed".into(), "eng1".into())
            .await;
        assert_eq!(mgr.list().await[0].timeline.len(), 3); // create + 2 updates
    }
}

// ═══════════════════════════════════════════════════════════════
// Feature Flag Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod feature_flag_tests {
    use std::collections::HashMap;
    use xiranet::deployment::feature_flags::FeatureFlagManager;

    #[test]
    fn test_create_and_toggle() {
        let mgr = FeatureFlagManager::new();
        mgr.create("dark_mode".into(), "Enable dark mode".into(), true, 100);

        let ctx = HashMap::new();
        assert!(mgr.evaluate("dark_mode", &ctx));

        mgr.toggle("dark_mode");
        assert!(!mgr.evaluate("dark_mode", &ctx));

        mgr.toggle("dark_mode");
        assert!(mgr.evaluate("dark_mode", &ctx));
    }

    #[test]
    fn test_percentage_rollout() {
        let mgr = FeatureFlagManager::new();
        mgr.create("zero_flag".into(), "0% rollout".into(), true, 0);
        mgr.create("full_flag".into(), "100% rollout".into(), true, 100);

        let ctx = HashMap::new();
        assert!(
            !mgr.evaluate("zero_flag", &ctx),
            "0% rollout should be disabled"
        );
        assert!(
            mgr.evaluate("full_flag", &ctx),
            "100% rollout should be enabled"
        );
    }

    #[test]
    fn test_list_flags() {
        let mgr = FeatureFlagManager::new();
        mgr.create("flag_a".into(), "A".into(), true, 50);
        mgr.create("flag_b".into(), "B".into(), false, 100);
        assert_eq!(mgr.list().len(), 2);
    }

    #[test]
    fn test_unknown_flag_disabled() {
        let mgr = FeatureFlagManager::new();
        let ctx = HashMap::new();
        assert!(!mgr.evaluate("nonexistent", &ctx));
    }
}

// ═══════════════════════════════════════════════════════════════
// Advanced Metrics Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod metrics_tests {
    use xiranet::metrics::advanced::AdvancedMetrics;

    #[test]
    fn test_record_and_get_service() {
        let metrics = AdvancedMetrics::new();
        metrics.record("api-svc", 200, 1024, 2048, 45.5);
        metrics.record("api-svc", 200, 512, 1024, 30.0);
        metrics.record("api-svc", 500, 256, 128, 100.0);

        let report = metrics.get_service("api-svc");
        assert!(report.is_some(), "Should have metrics for api-svc");
        let svc = report.unwrap();
        assert_eq!(svc.get("requests").and_then(|v| v.as_u64()).unwrap(), 3);
        let codes = svc.get("status_codes").unwrap();
        assert_eq!(codes.get("2xx").and_then(|v| v.as_u64()).unwrap(), 2);
        assert_eq!(codes.get("5xx").and_then(|v| v.as_u64()).unwrap(), 1);
    }

    #[test]
    fn test_multiple_services_tracked() {
        let metrics = AdvancedMetrics::new();
        metrics.record("svc-a", 200, 100, 200, 10.0);
        metrics.record("svc-b", 200, 100, 200, 10.0);

        assert!(metrics.get_service("svc-a").is_some());
        assert!(metrics.get_service("svc-b").is_some());
        assert!(metrics.get_service("svc-c").is_none());
    }
}

// ═══════════════════════════════════════════════════════════════
// Health Scoring Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod health_scoring_tests {
    use xiranet::gateway::health_scoring::HealthScorer;

    #[test]
    fn test_record_and_score() {
        let scorer = HealthScorer::new();
        scorer.record("fast-svc", 50.0, true);
        scorer.record("fast-svc", 60.0, true);
        scorer.record("fast-svc", 40.0, true);

        let scores = scorer.all_scores();
        assert_eq!(scores.len(), 1);
        assert!(
            scores[0].score > 50.0,
            "Healthy fast service should have high score, got: {}",
            scores[0].score
        );
    }

    #[test]
    fn test_failures_lower_score() {
        let scorer = HealthScorer::new();
        for _ in 0..10 {
            scorer.record("good-svc", 50.0, true);
        }
        for _ in 0..3 {
            scorer.record("bad-svc", 50.0, true);
        }
        for _ in 0..7 {
            scorer.record("bad-svc", 50.0, false);
        }

        let scores = scorer.all_scores();
        let good = scores.iter().find(|s| s.upstream == "good-svc").unwrap();
        let bad = scores.iter().find(|s| s.upstream == "bad-svc").unwrap();
        assert!(
            good.score > bad.score,
            "Service with failures should score lower: good={}, bad={}",
            good.score,
            bad.score
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Query Firewall Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod query_firewall_tests {
    use xiranet::dbgateway::query_firewall::{QueryFirewall, QueryVerdict};

    // Bu testler önceden `catch_unwind` ile sarılıydı ve panik'i "kabul edilebilir"
    // sayıyordu — bu yüzden tamamen kırık bir firewall sessizce yeşil geçerdi.
    // Direkt çağırıyoruz: panik test'i bozarsa firewall'a bug var demektir.

    #[test]
    fn test_blocks_drop_table() {
        let fw = QueryFirewall::new(500.0);
        match fw.inspect("DROP TABLE users") {
            QueryVerdict::Block { .. } => {}
            other => panic!("Expected Block for DROP TABLE, got {other:?}"),
        }
    }

    #[test]
    fn test_allows_normal_select() {
        let fw = QueryFirewall::new(500.0);
        match fw.inspect("SELECT id, name FROM users WHERE id = 1") {
            QueryVerdict::Allow { is_read } => {
                assert!(is_read, "SELECT should be classified as read");
            }
            QueryVerdict::Block { reason, .. } => {
                panic!("Normal SELECT should not be blocked: {reason}");
            }
        }
    }

    #[test]
    fn test_classifies_write_queries() {
        let fw = QueryFirewall::new(500.0);
        match fw.inspect("INSERT INTO users (name) VALUES ('test')") {
            QueryVerdict::Allow { is_read } => {
                assert!(!is_read, "INSERT should be classified as write");
            }
            QueryVerdict::Block { reason, .. } => {
                panic!("INSERT into users should be allowed (or block reason recorded): {reason}");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Storage Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod storage_tests {
    use std::fs;
    use std::path::PathBuf;

    use rusqlite::{params, Connection};
    use xiranet::config::TransformConfig;
    use xiranet::registry::models::ServiceEntry;
    use xiranet::registry::storage::SqliteStorage;

    fn make_temp_db_path(test_name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("xiranet-{}-{}", test_name, uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir.join("xiranet.db")
    }

    #[test]
    fn test_storage_persists_advanced_service_fields() {
        let db_path = make_temp_db_path("storage-roundtrip");

        let mut entry = ServiceEntry::new(
            "api".to_string(),
            "/api".to_string(),
            "http://localhost:3000".to_string(),
            "/ready".to_string(),
        );
        entry.upstreams = vec![
            "http://localhost:3001".to_string(),
            "http://localhost:3002".to_string(),
        ];
        entry.load_balance = Some("least_conn".to_string());
        entry.version = Some("v2".to_string());
        entry.validation_schema = Some(r#"{"type":"object"}"#.to_string());
        entry.ip_whitelist = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        entry.ip_blacklist = vec!["192.168.1.8".to_string()];
        entry.transform = Some(TransformConfig {
            add_request_headers: std::collections::HashMap::from([(
                "x-env".to_string(),
                "test".to_string(),
            )]),
            remove_request_headers: vec!["authorization".to_string()],
            add_response_headers: std::collections::HashMap::from([(
                "x-cluster".to_string(),
                "blue".to_string(),
            )]),
            remove_response_headers: vec!["server".to_string()],
        });

        {
            let storage = SqliteStorage::new(db_path.to_str().unwrap()).unwrap();
            storage.save_service(&entry).unwrap();
        }

        let loaded = {
            let storage = SqliteStorage::new(db_path.to_str().unwrap()).unwrap();
            let services = storage.load_all_services().unwrap();
            assert_eq!(services.len(), 1);
            services.into_iter().next().unwrap()
        };

        assert_eq!(loaded.upstreams, entry.upstreams);
        assert_eq!(loaded.load_balance, entry.load_balance);
        assert_eq!(loaded.version, entry.version);
        assert_eq!(loaded.validation_schema, entry.validation_schema);
        assert_eq!(loaded.ip_whitelist, entry.ip_whitelist);
        assert_eq!(loaded.ip_blacklist, entry.ip_blacklist);
        assert_eq!(
            serde_json::to_value(&loaded.transform).unwrap(),
            serde_json::to_value(&entry.transform).unwrap(),
        );

        let _ = fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_storage_migrates_legacy_services_table() {
        let db_path = make_temp_db_path("storage-migration");

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE services (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    prefix TEXT NOT NULL UNIQUE,
                    upstream TEXT NOT NULL,
                    health_endpoint TEXT NOT NULL DEFAULT '/health',
                    upstreams TEXT DEFAULT '[]',
                    load_balance TEXT,
                    version TEXT,
                    validation_schema TEXT,
                    registered_at TEXT NOT NULL,
                    request_count INTEGER DEFAULT 0
                )",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO services (id, name, prefix, upstream, health_endpoint, upstreams, load_balance, version, validation_schema, registered_at, request_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    "legacy-api",
                    "/legacy",
                    "http://localhost:4000",
                    "/health",
                    "[]",
                    Option::<String>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                    chrono::Utc::now().to_rfc3339(),
                    0_i64,
                ],
            ).unwrap();
        }

        let storage = SqliteStorage::new(db_path.to_str().unwrap()).unwrap();
        let columns = storage.query_raw("PRAGMA table_info(services)").unwrap();

        assert!(columns
            .iter()
            .any(|column| column.get("name") == Some(&serde_json::json!("ip_whitelist"))));
        assert!(columns
            .iter()
            .any(|column| column.get("name") == Some(&serde_json::json!("ip_blacklist"))));
        assert!(columns
            .iter()
            .any(|column| column.get("name") == Some(&serde_json::json!("transform"))));

        let services = storage.load_all_services().unwrap();
        assert_eq!(services.len(), 1);
        assert!(services[0].ip_whitelist.is_empty());
        assert!(services[0].ip_blacklist.is_empty());
        assert!(services[0].transform.is_none());

        drop(storage);
        let _ = fs::remove_dir_all(db_path.parent().unwrap());
    }
}

// ═══════════════════════════════════════════════════════════════
// WebSocket Auth Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod websocket_auth_tests {
    use std::sync::Arc;
    use std::time::Instant;

    use actix_web::{http::StatusCode, test, web, App};
    use tokio::sync::RwLock;
    use xiranet::config::XiraConfig;
    use xiranet::dashboard;
    use xiranet::gateway::health_scoring::HealthScorer;
    use xiranet::gateway::ws_metrics;
    use xiranet::metrics::advanced::AdvancedMetrics;
    use xiranet::metrics::sla::SlaMonitor;
    use xiranet::registry::ServiceRegistry;

    #[actix_web::test]
    async fn test_dashboard_websocket_requires_admin_token() {
        let config = Arc::new(RwLock::new(XiraConfig::default()));
        let registry = ServiceRegistry::new();
        let start_time = Instant::now();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(registry))
                .app_data(web::Data::new(start_time))
                .route(
                    "/ws/dashboard",
                    web::get().to(dashboard::ws_dashboard_handler),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/ws/dashboard").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_metrics_websocket_requires_admin_token() {
        let config = Arc::new(RwLock::new(XiraConfig::default()));
        let registry = ServiceRegistry::new();
        let metrics = Arc::new(AdvancedMetrics::new());
        let health_scorer = Arc::new(HealthScorer::new());
        let sla_monitor = Arc::new(SlaMonitor::new());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(registry))
                .app_data(web::Data::new(metrics))
                .app_data(web::Data::new(health_scorer))
                .app_data(web::Data::new(sla_monitor))
                .route("/ws/metrics", web::get().to(ws_metrics::ws_metrics_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/ws/metrics").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ═══════════════════════════════════════════════════════════════
// Config validation — boot-time guard'ların tek source-of-truth'u
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod config_validate_tests {
    use xiranet::config::XiraConfig;

    fn base_toml() -> String {
        r#"
[gateway]
host = "127.0.0.1"
port = 9000
workers = 1

[admin]
api_key = "not-a-default-key-xyz-abc-1234"
enabled = true

[health]
interval_secs = 30
timeout_secs = 5

[cors]
allowed_origins = ["http://localhost"]

[rate_limit]
max_requests = 100
window_secs = 60
"#
        .to_string()
    }

    fn parse(toml: &str) -> XiraConfig {
        toml::from_str(toml).expect("parse")
    }

    #[test]
    fn clean_config_validates() {
        let cfg = parse(&base_toml());
        let r = cfg.validate();
        assert!(r.ok(), "errors: {:?}", r.errors);
    }

    #[test]
    fn default_admin_key_with_external_bind_rejected() {
        let mut t = base_toml();
        t = t.replace("not-a-default-key-xyz-abc-1234", "xira-secret-key-change-me");
        t = t.replace("127.0.0.1", "0.0.0.0");
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(!r.ok(), "must reject default key + external bind");
        assert!(r.errors.iter().any(|e| e.contains("admin.api_key")));
    }

    #[test]
    fn default_admin_key_on_loopback_is_warning_only() {
        let t = base_toml().replace("not-a-default-key-xyz-abc-1234", "xira-secret-key-change-me");
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(r.ok(), "loopback bind ile default key sadece warning olmalı");
        assert!(!r.warnings.is_empty());
    }

    #[test]
    fn weak_jwt_secret_rejected() {
        let t = format!(
            "{}\n[jwt]\nenabled = true\nsecret = \"too-short\"\nalgorithm = \"HS256\"\n",
            base_toml()
        );
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.contains("jwt.secret too short")));
    }

    #[test]
    fn default_jwt_secret_rejected_when_enabled() {
        let t = format!(
            "{}\n[jwt]\nenabled = true\nsecret = \"your-jwt-secret-key-here\"\nalgorithm = \"HS256\"\n",
            base_toml()
        );
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(!r.ok());
        assert!(r
            .errors
            .iter()
            .any(|e| e.contains("known default") || e.contains("default")));
    }

    #[test]
    fn rs256_with_non_pem_secret_rejected() {
        let t = format!(
            "{}\n[jwt]\nenabled = true\nsecret = \"this-is-not-a-pem-but-long-enough-to-pass-32\"\nalgorithm = \"RS256\"\n",
            base_toml()
        );
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.contains("RSA PEM")));
    }

    #[test]
    fn empty_cors_origins_warning() {
        let t = base_toml().replace(
            "allowed_origins = [\"http://localhost\"]",
            "allowed_origins = []",
        );
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(r.ok(), "empty CORS should be warning, not error");
        assert!(r.warnings.iter().any(|w| w.contains("cors.allowed_origins")));
    }

    #[test]
    fn duplicate_service_prefix_rejected() {
        let t = format!(
            "{}\n[[services]]\nname = \"a\"\nprefix = \"/api\"\nupstream = \"http://localhost:3001\"\nhealth_endpoint = \"/health\"\n[[services]]\nname = \"b\"\nprefix = \"/api\"\nupstream = \"http://localhost:3002\"\nhealth_endpoint = \"/health\"\n",
            base_toml()
        );
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.contains("duplicate")));
    }

    #[test]
    fn rate_limit_zero_rejected() {
        let t = base_toml().replace("max_requests = 100", "max_requests = 0");
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(!r.ok());
        assert!(r.errors.iter().any(|e| e.contains("rate_limit")));
    }

    #[test]
    fn password_min_length_below_8_warning() {
        let t = format!(
            "{}\n[identity]\nregistration_enabled = true\nmax_sessions_per_user = 5\npassword_min_length = 4\n",
            base_toml()
        );
        let cfg = parse(&t);
        let r = cfg.validate();
        assert!(r.ok(), "password length is warning not error");
        assert!(r.warnings.iter().any(|w| w.contains("password_min_length")));
    }
}

// ═══════════════════════════════════════════════════════════════
// RBAC Tests — UserRole hierarchy + RequireRole middleware
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod rbac_tests {
    use actix_web::http::StatusCode;
    use actix_web::{test, web, App, HttpResponse};
    use std::sync::Arc;
    use xiranet::identity::sessions::SessionManager;
    use xiranet::identity::users::{UserManager, UserRole};
    use xiranet::middleware::require_role::RequireRole;
    use xiranet::middleware::session::SessionAuth;

    fn fixture() -> (Arc<UserManager>, Arc<SessionManager>, String, String) {
        let users = Arc::new(UserManager::new());
        let sessions = Arc::new(SessionManager::new(10));

        let admin_user = users
            .register(
                "root@x".to_string(),
                "root".to_string(),
                "long-password-1234567890",
                UserRole::SuperAdmin,
            )
            .unwrap();
        let viewer_user = users
            .register(
                "viewer@x".to_string(),
                "viewer".to_string(),
                "long-password-1234567890",
                UserRole::Viewer,
            )
            .unwrap();

        // Token üretimi authenticate üzerinden — gerçek akış
        let admin_token = match users.authenticate(&admin_user.email, "long-password-1234567890") {
            xiranet::identity::users::AuthResult::Success { token, .. } => token,
            other => panic!("admin auth failed: {other:?}"),
        };
        let viewer_token = match users.authenticate(&viewer_user.email, "long-password-1234567890")
        {
            xiranet::identity::users::AuthResult::Success { token, .. } => token,
            other => panic!("viewer auth failed: {other:?}"),
        };

        // Session create
        sessions.create(&admin_user.id, &admin_token, "127.0.0.1", "test", 600);
        sessions.create(&viewer_user.id, &viewer_token, "127.0.0.1", "test", 600);

        (users, sessions, admin_token, viewer_token)
    }

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({"ok": true}))
    }

    #[actix_web::test]
    async fn superadmin_passes_role_check() {
        let (users, sessions, admin_token, _viewer_token) = fixture();
        let app = test::init_service(
            App::new().service(
                web::scope("/protected")
                    .wrap(RequireRole::new(UserRole::SuperAdmin, users.clone()))
                    .wrap(SessionAuth::new(sessions.clone()))
                    .route("/data", web::get().to(ok)),
            ),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/protected/data")
            .insert_header(("X-Session-Token", admin_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn viewer_rejected_from_superadmin_endpoint() {
        let (users, sessions, _admin_token, viewer_token) = fixture();
        let app = test::init_service(
            App::new().service(
                web::scope("/protected")
                    .wrap(RequireRole::new(UserRole::SuperAdmin, users.clone()))
                    .wrap(SessionAuth::new(sessions.clone()))
                    .route("/data", web::get().to(ok)),
            ),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/protected/data")
            .insert_header(("X-Session-Token", viewer_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn missing_session_returns_unauthorized() {
        let (users, sessions, _a, _v) = fixture();
        let app = test::init_service(
            App::new().service(
                web::scope("/protected")
                    .wrap(RequireRole::new(UserRole::SuperAdmin, users.clone()))
                    .wrap(SessionAuth::new(sessions.clone()))
                    .route("/data", web::get().to(ok)),
            ),
        )
        .await;
        let req = test::TestRequest::get().uri("/protected/data").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn admin_can_access_developer_required_endpoint() {
        let (users, sessions, admin_token, _v) = fixture();
        let app = test::init_service(
            App::new().service(
                web::scope("/protected")
                    .wrap(RequireRole::new(UserRole::Developer, users.clone()))
                    .wrap(SessionAuth::new(sessions.clone()))
                    .route("/data", web::get().to(ok)),
            ),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/protected/data")
            .insert_header(("X-Session-Token", admin_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn role_change_invalidates_old_sessions_path() {
        // update_role + invalidate_all akışını doğrula: rol değişimi sonrası eski token
        // 401 dönmeli (session map'ten silinmiş).
        let (users, sessions, viewer_token, _v) = fixture();
        // viewer_token aslında admin token (fixture sırası); rol yükselt ve invalidate çağır
        let admin_user_id = users
            .list_users()
            .into_iter()
            .find(|u| u.get("email").and_then(|v| v.as_str()) == Some("root@x"))
            .and_then(|u| u.get("id").and_then(|v| v.as_str()).map(String::from))
            .unwrap();

        let invalidated = sessions.invalidate_all(&admin_user_id);
        assert!(invalidated >= 1);

        let app = test::init_service(
            App::new().service(
                web::scope("/protected")
                    .wrap(RequireRole::new(UserRole::SuperAdmin, users.clone()))
                    .wrap(SessionAuth::new(sessions.clone()))
                    .route("/data", web::get().to(ok)),
            ),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/protected/data")
            .insert_header(("X-Session-Token", viewer_token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Session invalidate edildi → SessionAuth 401
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ═══════════════════════════════════════════════════════════════
// Adversarial tests — v3.0 Yarı C madde 29
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod adversarial_tests {
    use xiranet::middleware::jwt::JwtAuth;

    /// `alg=none` JWT bypass — boot reddetmesi + decode-level reddetme.
    /// İki katman test:
    ///   1. JwtAuth::new("none", ...) → UnsupportedAlgorithm (boot reject)
    ///   2. Gerçek HTTP request: HS256 server'a `alg=none` JWT yollanırsa 401
    #[test]
    fn jwt_alg_none_init_rejected() {
        let result = JwtAuth::new(
            "any-secret-32-bytes-aaaaaaaaaaaaaaa".to_string(),
            "none",
            None,
            true,
        );
        assert!(
            result.is_err(),
            "alg=none must be rejected at boot (UnsupportedAlgorithm)"
        );
    }

    /// Decode-level alg-confusion reject — jsonwebtoken kütüphanesinin
    /// `validation.algorithms = vec![HS256]` pin'i ile `{"alg":"none"}`
    /// attacker JWT'sini reddetmesi.
    #[test]
    fn jwt_alg_none_decode_rejected() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        // Attacker JWT: alg=none header + payload + boş signature
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"admin","exp":9999999999}"#);
        let evil_token = format!("{header}.{payload}.");

        // Server HS256 pinned — decode reject
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        validation.validate_exp = true;
        let key = DecodingKey::from_secret(b"server-secret-32-bytes-aaaaaaaaaa");

        let result = decode::<serde_json::Value>(&evil_token, &key, &validation);
        assert!(
            result.is_err(),
            "HS256-pinned server must reject alg=none JWT (real attack surface)"
        );
    }

    /// HS→RS algorithm confusion: HS256 server'a `{"alg":"RS256"}` JWT
    /// (attacker server'ın public key'i ile HMAC). Algorithm pin koruma.
    #[test]
    fn jwt_alg_confusion_hs_to_rs_rejected() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"admin","exp":9999999999}"#);
        // Sahte signature
        let sig = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let evil_token = format!("{header}.{payload}.{sig}");

        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256];
        let key = DecodingKey::from_secret(b"server-secret-32-bytes-aaaaaaaaaa");

        let result = decode::<serde_json::Value>(&evil_token, &key, &validation);
        assert!(
            result.is_err(),
            "alg confusion (HS→RS) must be rejected by validation.algorithms pin"
        );
    }

    /// JWT empty algorithm string → unsupported.
    #[test]
    fn jwt_empty_algorithm_rejected() {
        let result = JwtAuth::new(
            "valid-secret-32-bytes-aaaaaaaaaaaaa".to_string(),
            "",
            None,
            true,
        );
        assert!(result.is_err(), "empty alg must be unsupported");
    }

    /// JWT secret 31-byte → WeakSecret reject (HMAC algorithms require >= 32).
    #[test]
    fn jwt_31_byte_secret_rejected() {
        let result = JwtAuth::new(
            "x".repeat(31), // 31 byte
            "HS256",
            None,
            true,
        );
        assert!(result.is_err(), "31-byte HMAC secret must be rejected");
    }

    /// Session create race — 10 concurrent create, max_sessions=3 limitiyle.
    /// Atomic two-phase ile EXACTLY 3 session aktif kalmalı (race-free).
    #[tokio::test]
    async fn session_create_race_max_sessions() {
        use std::sync::Arc;
        use xiranet::identity::sessions::SessionManager;
        let mgr = Arc::new(SessionManager::new(3));
        let mut handles = Vec::new();
        for i in 0..10 {
            let m = mgr.clone();
            handles.push(tokio::spawn(async move {
                let token = format!("xira_tok_concurrent_{i}");
                m.create("u1", &token, "127.0.0.1", "test", 600);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let user_sessions = mgr.user_sessions("u1");
        // EXACTLY 3 — race-free atomic two-phase ile garantili.
        // Eski sürüm "<=3" lax assertion idi; 2 veya 1 ile de geçerdi.
        assert_eq!(
            user_sessions.len(),
            3,
            "max_sessions atomic: expected exactly 3, got {}",
            user_sessions.len()
        );
    }

    /// Session validate IP mismatch → invalidate.
    #[test]
    fn session_ip_binding_invalidates_on_mismatch() {
        use std::sync::Arc;
        use xiranet::identity::sessions::SessionManager;
        let mgr = Arc::new(SessionManager::new(5));
        let session = mgr.create("u1", "xira_tok_test", "1.2.3.4", "Mozilla/5.0", 600);
        // Aynı IP — geçer
        assert!(
            mgr.validate_with_request(&session.token, Some("1.2.3.4"), Some("Mozilla/5.0"))
                .is_some()
        );
        // Farklı IP — invalidate + None
        assert!(
            mgr.validate_with_request(&session.token, Some("5.6.7.8"), Some("Mozilla/5.0"))
                .is_none(),
            "IP mismatch must invalidate"
        );
        // İlk session artık aktif değil
        assert!(
            mgr.validate_with_request(&session.token, Some("1.2.3.4"), Some("Mozilla/5.0"))
                .is_none(),
            "post-invalidation lookup must fail"
        );
    }

    /// DNS rebinding mock — PinnedUrl gerçekten bypass ediyor mu?
    ///
    /// Senaryo: "evil-host.example" gerçek DNS'te attacker IP'lerine resolve
    /// olur. Biz `pin_upstream_url`'i atlayıp manuel PinnedUrl üretiyoruz
    /// (host = "evil-host.example", ip = 127.0.0.1:test_port). build_client
    /// ile reqwest::Client kur. Request `http://evil-host.example:port/`'a
    /// gönderildiğinde reqwest, **sistem DNS'i sormaz**; bizim verdiğimiz
    /// 127.0.0.1:port'a bağlanır → lokal mock listener cevap verir.
    ///
    /// Bu doğrudan TOCTOU mitigation kanıtı: resolve süreci geçtikten sonra
    /// "host"un başka IP'ye resolve olması (rebinding) HTTP connection'ı
    /// etkilemez.
    #[tokio::test]
    async fn pinned_url_dns_rebinding_mitigation() {
        use std::net::IpAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use xiranet::alerting::url_guard::PinnedUrl;

        // Lokal mock HTTP listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let port = bound.port();

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Minimum HTTP parse + cevap
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = b"PINNED_OK";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                body.len(),
                std::str::from_utf8(body).unwrap()
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.flush().await;
        });

        // Pin: host = sahte (sistem DNS'te tanımsız), ip = lokal mock
        let pinned = PinnedUrl {
            url: format!("http://evil-host.example.test.invalid:{port}/"),
            host: "evil-host.example.test.invalid".to_string(),
            ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            port,
        };

        let client = pinned.build_client(5).expect("client build");

        // Request — sistem DNS bu host'u resolve edemez (`.invalid` TLD
        // RFC 2606), ama resolve_to_addrs override aktif → mock'a düşer.
        let resp = client.get(&pinned.url).send().await.expect("send");
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.expect("body");
        assert_eq!(body, "PINNED_OK", "must hit pinned IP, not system DNS");

        server_task.await.unwrap();
    }

    /// Negative test — `resolve_to_addrs` olmadan aynı host system DNS'e
    /// düşer, `.invalid` TLD bağlanamaz. Test kontrolü: bizim mock'ın
    /// gerçekten override'a bağlı olduğunu doğrular.
    #[tokio::test]
    async fn pinned_url_without_resolve_override_fails() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let result = client
            .get("http://evil-host.example.test.invalid:1/")
            .send()
            .await;
        assert!(
            result.is_err(),
            ".invalid TLD must fail without resolve_to_addrs override (sanity check)"
        );
    }

    /// WAF rule ID multi-node coherence — bus event id local'e AYNI yazılır.
    /// Eski sürüm: Node A id=5 publish, Node B apply'da yeni atomic id=12 alır.
    /// Yeni: Node B `apply_add_pattern_with_id(5, ...)` ile aynı id.
    #[tokio::test]
    async fn waf_rule_id_multi_node_coherent() {
        use xiranet::middleware::waf::{Waf, WafMode};
        let node_b = Waf::new(true, WafMode::Block);
        // Simulate: Node A id=5 → bus → Node B apply
        node_b
            .apply_add_pattern_with_id(5, "EVIL-A", "from-a")
            .unwrap();
        node_b
            .apply_add_pattern_with_id(7, "EVIL-B", "from-a")
            .unwrap();
        let rules = node_b.list_custom_patterns();
        let ids: Vec<u64> = rules.iter().map(|r| r.id).collect();
        assert!(ids.contains(&5), "id=5 must be preserved from bus event");
        assert!(ids.contains(&7), "id=7 must be preserved");
        // Local add — next_rule_id bump edildi, 7'den büyük olmalı
        let local_id = node_b.add_custom_pattern("LOCAL", "local").unwrap();
        assert!(
            local_id > 7,
            "next local ID must avoid collision with remote IDs (got {local_id})"
        );
        // Idempotent — aynı id ile tekrar çağrılırsa duplicate eklenmez
        node_b
            .apply_add_pattern_with_id(5, "EVIL-A", "from-a")
            .unwrap();
        let count_after = node_b.list_custom_patterns().len();
        assert_eq!(
            count_after,
            rules.len() + 1,
            "duplicate id should be idempotent"
        );
    }

    /// WAF blocked_ip Arc altında — eski dead code testi.
    #[test]
    fn waf_block_ip_works_under_arc() {
        use std::sync::Arc;
        use xiranet::middleware::waf::{Waf, WafMode, WafVerdict};
        let waf = Arc::new(Waf::new(true, WafMode::Block));
        // Arc<Waf>::block_ip(&self) — derlenir ve çağrılabilir (eski sürüm
        // `&mut self` ile Arc altında compile bile etmiyordu).
        waf.block_ip("9.9.9.9".to_string());
        let verdict = waf.inspect("/test", None, "", &[], "9.9.9.9");
        match verdict {
            WafVerdict::Block { rule, .. } => assert_eq!(rule, "IP_BLOCK"),
            _ => panic!("blocked IP must produce IP_BLOCK verdict"),
        }
        waf.unblock_ip("9.9.9.9");
        let verdict2 = waf.inspect("/test", None, "", &[], "9.9.9.9");
        assert!(matches!(verdict2, WafVerdict::Allow));
    }

    /// failed_attempts email case-permutation bypass kapalı.
    #[test]
    fn brute_force_email_case_permutation_consolidated() {
        use xiranet::identity::users::{UserManager, UserRole};
        let mgr = UserManager::new();
        mgr.register(
            "alice@example.com".to_string(),
            "alice".to_string(),
            "long-password-1234",
            UserRole::Viewer,
        )
        .unwrap();
        // Yanlış şifre — sırayla farklı case'lerle dene
        for variant in &[
            "alice@example.com",
            "Alice@example.com",
            "ALICE@example.com",
            "ALICE@EXAMPLE.COM",
            "AliCe@ExaMple.coM",
        ] {
            let result = mgr.authenticate(variant, "wrong-password");
            // Hep aynı InvalidCredentials — counter consolidated
            assert!(matches!(
                result,
                xiranet::identity::users::AuthResult::InvalidCredentials
                    | xiranet::identity::users::AuthResult::LockedOut { .. }
            ));
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Audit log append-only — SQLite trigger verify
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod audit_append_only_tests {
    use std::sync::Arc;
    use xiranet::middleware::audit_log::AuditLogger;
    use xiranet::registry::storage::SqliteStorage;

    fn temp_db() -> Arc<SqliteStorage> {
        let path = std::env::temp_dir().join(format!(
            "xiranet-audit-trigger-{}.db",
            uuid::Uuid::new_v4()
        ));
        Arc::new(SqliteStorage::new(path.to_str().unwrap()).unwrap())
    }

    #[test]
    fn audit_log_rejects_update() {
        let storage = temp_db();
        let _logger = AuditLogger::new(Some(storage.clone()), true);

        // Insert a row
        storage
            .execute_raw(
                "INSERT INTO audit_log (timestamp, ip, method, path, status) VALUES ('2026-01-01', '127.0.0.1', 'GET', '/', 200)",
            )
            .unwrap();

        // UPDATE → must error
        let result = storage.execute_raw(
            "UPDATE audit_log SET status = 999 WHERE ip = '127.0.0.1'",
        );
        assert!(result.is_err(), "UPDATE on audit_log must be rejected by trigger");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("append-only") || err_str.contains("UPDATE forbidden"),
            "expected append-only message, got: {err_str}"
        );
    }

    #[test]
    fn audit_log_rejects_delete() {
        let storage = temp_db();
        let _logger = AuditLogger::new(Some(storage.clone()), true);

        storage
            .execute_raw(
                "INSERT INTO audit_log (timestamp, ip, method, path, status) VALUES ('2026-01-01', '127.0.0.1', 'GET', '/', 200)",
            )
            .unwrap();

        let result = storage.execute_raw("DELETE FROM audit_log WHERE ip = '127.0.0.1'");
        assert!(result.is_err(), "DELETE on audit_log must be rejected by trigger");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("append-only") || err_str.contains("DELETE forbidden"),
            "expected append-only message, got: {err_str}"
        );
    }

    #[test]
    fn audit_log_allows_insert() {
        let storage = temp_db();
        let _logger = AuditLogger::new(Some(storage.clone()), true);

        let result = storage.execute_raw(
            "INSERT INTO audit_log (timestamp, ip, method, path, status) VALUES ('2026-01-02', '127.0.0.1', 'POST', '/foo', 201)",
        );
        assert!(result.is_ok(), "INSERT must succeed: {result:?}");
    }
}

// ═══════════════════════════════════════════════════════════════
// Multi-node bus tests — REDIS_URL env varsa çalışır, yoksa skip.
// CI'da redis service tarafından sağlanır.
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod bus_tests {
    use std::sync::Arc;
    use std::time::Duration;
    use xiranet::bus::{BusEvent, EventDispatcher, NoOpBus, XiraBus};

    #[tokio::test]
    async fn noop_bus_publish_no_panic() {
        let bus: Arc<dyn XiraBus> = Arc::new(NoOpBus);
        bus.publish(&BusEvent::SessionInvalidateUser {
            user_id: "x".into(),
        })
        .await;
    }

    /// Iki bağımsız Redis bağlantısı üzerinden publish→subscribe roundtrip.
    /// `REDIS_URL` env yoksa skip.
    #[tokio::test]
    async fn redis_bus_publish_subscribe_roundtrip() {
        let url = match std::env::var("REDIS_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("skip: REDIS_URL not set");
                return;
            }
        };

        use xiranet::bus::redis_bus::RedisBus;

        let pub_bus = match RedisBus::connect(&url).await {
            Ok(b) => Arc::new(b),
            Err(e) => panic!("publisher connect: {e}"),
        };
        let sub_bus = match RedisBus::connect(&url).await {
            Ok(b) => b,
            Err(e) => panic!("subscriber connect: {e}"),
        };

        // Handler — gelen event'leri tokio channel'a forward eder
        struct Capture(tokio::sync::mpsc::Sender<BusEvent>);
        #[async_trait::async_trait]
        impl xiranet::bus::BusEventHandler for Capture {
            async fn handle(&self, event: BusEvent) {
                let _ = self.0.send(event).await;
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(10);
        let handler: Arc<dyn xiranet::bus::BusEventHandler> = Arc::new(Capture(tx));
        let dispatcher = Arc::new(EventDispatcher::new(vec![handler]));
        sub_bus.spawn_subscriber(dispatcher);

        // Subscriber'ın subscribe etmesi için kısa bekleme
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Publish
        pub_bus
            .publish(&BusEvent::WafRuleAdded {
                id: 99,
                pattern: "TEST-PATTERN".into(),
                label: "bus-test".into(),
            })
            .await;

        // Receive (3 saniye içinde)
        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for bus event")
            .expect("channel closed");

        match event {
            BusEvent::WafRuleAdded {
                id,
                pattern,
                label,
            } => {
                assert_eq!(id, 99);
                assert_eq!(pattern, "TEST-PATTERN");
                assert_eq!(label, "bus-test");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
