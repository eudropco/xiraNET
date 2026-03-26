use actix_web::{web, HttpRequest, HttpResponse};
use crate::registry::ServiceRegistry;

/// JSON Schema validation middleware (endpoint handler olarak)
pub async fn validate_request_body(
    req: &HttpRequest,
    body: &web::Bytes,
    registry: &ServiceRegistry,
) -> Option<HttpResponse> {
    let path = req.path();

    // Servis bul
    let service = match registry.lookup(path) {
        Some(svc) => svc,
        None => return None,
    };

    // Validation schema tanımlı mı?
    let schema_str = match &service.validation_schema {
        Some(s) if !s.is_empty() => s,
        _ => return None,
    };

    // Sadece POST/PUT/PATCH isteklerinde body doğrula
    let method = req.method().as_str();
    if !["POST", "PUT", "PATCH"].contains(&method) {
        return None;
    }

    if body.is_empty() {
        return None;
    }

    // JSON body parse
    let body_json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Some(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid JSON body",
                "detail": e.to_string()
            })));
        }
    };

    // Schema parse
    let schema_value: serde_json::Value = match serde_json::from_str(schema_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Invalid validation schema for service '{}': {}", service.name, e);
            return None;
        }
    };

    // Validate
    let validator = match jsonschema::validator_for(&schema_value) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Failed to compile schema for '{}': {}", service.name, e);
            return None;
        }
    };

    let error_messages: Vec<String> = validator
        .iter_errors(&body_json)
        .map(|e| format!("{}: {}", e.instance_path, e))
        .collect();

    if !error_messages.is_empty() {
        return Some(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Request validation failed",
            "validation_errors": error_messages,
        })));
    }

    None
}
