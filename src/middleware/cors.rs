use actix_cors::Cors;
use actix_web::http;

/// CORS yapılandırması oluştur
pub fn configure_cors() -> Cors {
    Cors::default()
        .allow_any_origin()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
            http::header::HeaderName::from_static("x-api-key"),
        ])
        .expose_headers(vec![
            http::header::HeaderName::from_static("x-proxied-by"),
        ])
        .max_age(3600)
}
