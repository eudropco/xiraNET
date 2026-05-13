use crate::config::CorsConfig;
use actix_cors::Cors;
use actix_web::http;

/// CORS yapılandırması — config-driven explicit origin listesi.
///
/// Wildcard (`allow_any_origin`) artık desteklenmiyor; CORS preflight için
/// her origin'in `[cors].allowed_origins` listesinde olması gerekir. Boş liste
/// → reddet. `allow_credentials = true` ise wildcard yine de mümkün değil
/// (browser zaten reddederdi).
pub fn configure_cors(cfg: &CorsConfig) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec![
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
        ])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
            http::header::HeaderName::from_static("x-api-key"),
            http::header::HeaderName::from_static("x-session-token"),
        ])
        .expose_headers(vec![
            http::header::HeaderName::from_static("x-proxied-by"),
            http::header::HeaderName::from_static("x-trace-id"),
        ])
        .max_age(cfg.max_age);

    for origin in &cfg.allowed_origins {
        cors = cors.allowed_origin(origin);
    }

    if cfg.allow_credentials {
        cors = cors.supports_credentials();
    }

    cors
}
