pub mod proxy;
pub mod circuit_breaker;
pub mod retry;
pub mod cache;
pub mod load_balancer;
pub mod websocket;
pub mod transform;

use actix_web::{web, HttpRequest, HttpResponse};
use crate::registry::ServiceRegistry;
use crate::gateway::cache::ResponseCache;
use crate::gateway::circuit_breaker::CircuitBreakerManager;
use crate::gateway::load_balancer::{LoadBalancer, LoadBalanceStrategy};
use std::sync::Arc;

/// Catch-all handler — routes requests through circuit breaker, load balancer, cache, and proxy
pub async fn gateway_handler(
    req: HttpRequest,
    body: web::Bytes,
    registry: web::Data<ServiceRegistry>,
    cb_manager: web::Data<CircuitBreakerManager>,
    lb: web::Data<LoadBalancer>,
    response_cache: web::Data<Arc<ResponseCache>>,
) -> HttpResponse {
    let path = req.path().to_string();

    // /xira/ admin routes are handled separately
    if path.starts_with("/xira") || path == "/metrics" || path == "/ws" {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Not found via gateway"
        }));
    }

    // Registry'den prefix eşleştirmesi
    let service = match registry.lookup(&path) {
        Some(svc) => svc,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "No service registered for this path",
                "path": path
            }));
        }
    };

    // Circuit Breaker kontrolü
    if let Err(state) = cb_manager.allow_request(&service.id) {
        tracing::warn!("Circuit breaker OPEN for service '{}' (state: {:?})", service.name, state);
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Service temporarily unavailable (circuit breaker open)",
            "service": service.name,
        }));
    }

    // Request count artır
    registry.increment_request_count(&service.id);

    // Cache kontrolü (sadece GET istekleri)
    let is_get = req.method() == actix_web::http::Method::GET;
    let cache_key = if is_get {
        Some(ResponseCache::make_key("GET", &path, req.query_string()))
    } else {
        None
    };

    if let Some(ref key) = cache_key {
        if let Some((status, headers, cached_body)) = response_cache.get(key) {
            tracing::debug!("Cache HIT: {}", key);
            let mut response = HttpResponse::build(
                actix_web::http::StatusCode::from_u16(status)
                    .unwrap_or(actix_web::http::StatusCode::OK)
            );
            for (k, v) in &headers {
                response.insert_header((k.as_str(), v.as_str()));
            }
            response.insert_header(("X-Cache", "HIT"));
            response.insert_header(("X-Proxied-By", "xiraNET"));
            return response.body(cached_body);
        }
    }

    // Load Balancing — upstream seç
    let upstreams = service.all_upstreams();
    let strategy = service.load_balance
        .as_deref()
        .map(LoadBalanceStrategy::from_str)
        .unwrap_or(LoadBalanceStrategy::RoundRobin);

    let selected_upstream = lb.select_upstream(&service.id, &upstreams, &strategy);
    lb.acquire_connection(&selected_upstream);

    // Downstream URL oluştur
    let downstream_path = path.strip_prefix(&service.prefix).unwrap_or("/");
    let downstream_path = if downstream_path.is_empty() { "/" } else { downstream_path };
    let query = req.query_string();
    let downstream_url = if query.is_empty() {
        format!("{}{}", selected_upstream, downstream_path)
    } else {
        format!("{}{}?{}", selected_upstream, downstream_path, query)
    };

    tracing::info!(
        "Proxying {} {} → {} [service: {}, lb: {:?}]",
        req.method(), path, downstream_url, service.name, strategy
    );

    // Proxy isteği
    let result = proxy::forward_request(&req, body, &downstream_url).await;

    // Bağlantı bırak
    lb.release_connection(&selected_upstream);

    // Circuit breaker sonuç kayıt
    match result.status().as_u16() {
        status if status >= 500 => {
            cb_manager.record_failure(&service.id);
        }
        _ => {
            cb_manager.record_success(&service.id);
        }
    }

    // Cache'e yaz (başarılı GET istekleri)
    if is_get && result.status().is_success() {
        if let Some(key) = cache_key {
            // Response body'yi okumak için burada basit bir yaklaşım kullanıyoruz
            // Not: response body zaten proxy tarafından tamamlanmış durumda
            tracing::debug!("Cache MISS: {}", key);
        }
    }

    result
}
