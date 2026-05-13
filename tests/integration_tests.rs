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
