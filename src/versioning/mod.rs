use actix_web::{web, HttpRequest, HttpResponse};
use crate::registry::ServiceRegistry;

/// API versioning handler
/// /v1/api/... → /api/... (servisin v1 versiyonu)
/// /v2/api/... → /api/... (servisin v2 versiyonu)
pub async fn versioned_gateway_handler(
    req: HttpRequest,
    body: web::Bytes,
    registry: web::Data<ServiceRegistry>,
) -> HttpResponse {
    let path = req.path().to_string();

    // /v{N}/... formatını kontrol et
    let (version, actual_path) = extract_version(&path);

    if version.is_none() {
        // Versiyonsuz istek — normal gateway'e yönlendir
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "No version specified",
            "hint": "Use /v1/..., /v2/... etc.",
            "path": path
        }));
    }

    let version_str = version.unwrap();

    // Version'a uygun servis bul
    let services = registry.list_all();
    let matching_service = services.iter().find(|svc| {
        // Prefix + version eşleştirmesi
        if let Some(ref svc_version) = svc.version {
            actual_path.starts_with(&svc.prefix) && svc_version == &version_str
        } else {
            actual_path.starts_with(&svc.prefix)
        }
    });

    match matching_service {
        Some(service) => {
            let downstream_path = actual_path.strip_prefix(&service.prefix).unwrap_or("/");
            let downstream_path = if downstream_path.is_empty() { "/" } else { downstream_path };
            let downstream_url = format!("{}{}", service.upstream, downstream_path);

            tracing::info!(
                "Versioned proxy: {} {} (v{}) → {}",
                req.method(), path, version_str, downstream_url
            );

            registry.increment_request_count(&service.id);
            crate::gateway::proxy::forward_request(&req, body, &downstream_url).await
        }
        None => {
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "No service found for this version and path",
                "version": version_str,
                "path": actual_path
            }))
        }
    }
}

/// /v{N}/... → (version, remaining_path) parse
fn extract_version(path: &str) -> (Option<String>, String) {
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    // parts = ["", "v1", "api/..."]

    if parts.len() >= 2 {
        let segment = parts[1];
        if segment.starts_with('v') {
            if let Ok(_num) = segment[1..].parse::<u32>() {
                let remaining = if parts.len() >= 3 {
                    format!("/{}", parts[2])
                } else {
                    "/".to_string()
                };
                return (Some(segment[1..].to_string()), remaining);
            }
        }
    }

    (None, path.to_string())
}

/// Versiyon bilgisi endpoint'i
pub async fn list_versions(registry: web::Data<ServiceRegistry>) -> HttpResponse {
    let services = registry.list_all();
    let versions: Vec<serde_json::Value> = services
        .iter()
        .filter(|s| s.version.is_some())
        .map(|s| serde_json::json!({
            "service": s.name,
            "prefix": s.prefix,
            "version": s.version,
            "upstream": s.upstream,
        }))
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "versions": versions,
        "total": versions.len()
    }))
}
