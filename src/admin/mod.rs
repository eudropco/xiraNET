pub mod handlers;
pub mod config_api;
pub mod openapi;
pub mod v2_handlers;

use actix_web::web;

/// Admin API route'larını yapılandır
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/xira")
            // ═══ Core (v1.0) ═══
            .route("/services", web::get().to(handlers::list_services))
            .route("/services", web::post().to(handlers::register_service))
            .route("/services/{id}", web::delete().to(handlers::unregister_service))
            .route("/services/{id}/health", web::get().to(handlers::check_service_health))
            .route("/stats", web::get().to(handlers::get_stats))
            .route("/health", web::get().to(handlers::gateway_health))
            .route("/events", web::get().to(handlers::get_events))
            .route("/logs", web::get().to(handlers::get_logs))
            .route("/cache/clear", web::post().to(handlers::clear_cache))
            .route("/circuit-breakers", web::get().to(handlers::get_circuit_breakers))
            .route("/plugins", web::get().to(handlers::get_plugins))
            .route("/versions", web::get().to(crate::versioning::list_versions))
            .route("/log-stats", web::get().to(handlers::get_log_stats))
            .route("/config", web::get().to(config_api::get_config))
            .route("/config", web::put().to(config_api::update_config))
            .route("/docs", web::get().to(openapi::swagger_ui_handler))
            .route("/docs/spec", web::get().to(openapi::openapi_handler))

            // ═══ Identity Admin (v2.0) ═══
            .route("/identity/users", web::get().to(v2_handlers::list_users))
            .route("/identity/users", web::post().to(v2_handlers::create_user))
            .route("/identity/sessions", web::get().to(v2_handlers::list_sessions))
            .route("/identity/sessions/flush", web::post().to(v2_handlers::flush_sessions))

            // ═══ Automation (v2.0) ═══
            .route("/automation/cron", web::get().to(v2_handlers::list_cron_jobs))
            .route("/automation/cron", web::post().to(v2_handlers::create_cron_job))
            .route("/automation/cron/{id}", web::delete().to(v2_handlers::delete_cron_job))
            .route("/automation/workflows", web::get().to(v2_handlers::list_workflows))
            .route("/automation/events", web::get().to(v2_handlers::list_events))
            .route("/automation/events/publish", web::post().to(v2_handlers::publish_event))

            // ═══ Observability (v2.0) ═══
            .route("/observability/logs", web::get().to(v2_handlers::search_logs))
            .route("/observability/uptime", web::get().to(v2_handlers::get_uptime))
            .route("/observability/incidents", web::get().to(v2_handlers::list_incidents))
            .route("/observability/incidents", web::post().to(v2_handlers::create_incident))
            .route("/observability/incidents/{id}/update", web::post().to(v2_handlers::update_incident))

            // ═══ DB Gateway (v2.0) ═══
            .route("/db/connections", web::get().to(v2_handlers::list_db_connections))
            .route("/db/slow-queries", web::get().to(v2_handlers::get_slow_queries))
            .route("/db/firewall/stats", web::get().to(v2_handlers::get_firewall_stats))

            // ═══ Deployment (v2.0) ═══
            .route("/deployment/flags", web::get().to(v2_handlers::list_flags))
            .route("/deployment/flags", web::post().to(v2_handlers::create_flag))
            .route("/deployment/flags/{name}/toggle", web::post().to(v2_handlers::toggle_flag))
            .route("/deployment/releases", web::get().to(v2_handlers::list_releases))
            .route("/deployment/releases", web::post().to(v2_handlers::create_release))
            .route("/deployment/releases/{id}/switch", web::post().to(v2_handlers::switch_release))

            // ═══ Data Pipeline (v2.0) ═══
            .route("/pipeline/watchers", web::get().to(v2_handlers::list_watchers))
            .route("/pipeline/watchers", web::post().to(v2_handlers::create_watcher))
            .route("/pipeline/analytics", web::get().to(v2_handlers::get_analytics))

            // ═══ Security (v2.0) ═══
            .route("/security/waf", web::get().to(v2_handlers::get_waf_stats))
            .route("/security/bots", web::get().to(v2_handlers::get_bot_stats))
            .route("/security/audit", web::get().to(v2_handlers::get_audit_log))

            // ═══ Advanced Metrics (v2.0) ═══
            .route("/advanced-metrics", web::get().to(v2_handlers::get_advanced_metrics))
            .route("/health-scoring", web::get().to(v2_handlers::get_health_scores))
            .route("/sla", web::get().to(v2_handlers::get_sla_report))
    );
}
