pub mod handlers;

use actix_web::web;

/// Admin API route'larını yapılandır
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/xira")
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
    );
}
