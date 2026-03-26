pub mod proxy;
pub mod circuit_breaker;
pub mod retry;
pub mod cache;
pub mod load_balancer;
pub mod websocket;
pub mod transform;

use actix_web::{web, HttpRequest, HttpResponse};
use crate::config::RetryConfig;
use crate::registry::ServiceRegistry;
use crate::gateway::cache::ResponseCache;
use crate::gateway::circuit_breaker::CircuitBreakerManager;
use crate::gateway::load_balancer::{LoadBalancer, LoadBalanceStrategy};
use crate::gateway::retry::RetryPolicy;
use crate::gateway::transform::TransformRules;
use crate::plugins::PluginManager;
use std::sync::Arc;

/// Catch-all handler — routes requests through full pipeline:
/// IP filter → validation → plugins → circuit breaker → cache → load balancer → transform → retry/proxy → plugins → cache write
pub async fn gateway_handler(
    req: HttpRequest,
    body: web::Bytes,
    registry: web::Data<ServiceRegistry>,
    cb_manager: web::Data<CircuitBreakerManager>,
    lb: web::Data<LoadBalancer>,
    response_cache: web::Data<Arc<ResponseCache>>,
    plugin_manager: web::Data<PluginManager>,
    retry_config: web::Data<RetryConfig>,
) -> HttpResponse {
    let path = req.path().to_string();
    let method = req.method().to_string();

    // /xira/ admin routes are handled separately
    if path.starts_with("/xira") || path == "/metrics" || path == "/ws" || path == "/dashboard" {
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

    // ═══ [7] Per-service IP filter ═══
    let peer_ip = req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    if !service.ip_whitelist.is_empty() || !service.ip_blacklist.is_empty() {
        // Blacklist kontrolü
        if service.ip_blacklist.contains(&peer_ip) {
            tracing::warn!("Per-service IP blocked: {} for service '{}'", peer_ip, service.name);
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied by service IP filter",
                "service": service.name,
            }));
        }
        // Whitelist kontrolü (boş değilse)
        if !service.ip_whitelist.is_empty() && !service.ip_whitelist.contains(&peer_ip) {
            tracing::warn!("Per-service IP not whitelisted: {} for service '{}'", peer_ip, service.name);
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied by service IP whitelist",
                "service": service.name,
            }));
        }
    }

    // ═══ [6] JSON Schema validation (POST/PUT/PATCH) ═══
    if let Some(ref _schema) = service.validation_schema {
        if let Some(error_response) = crate::middleware::validation::validate_request_body(
            &req, &body, registry.get_ref(),
        ).await {
            return error_response;
        }
    }

    // ═══ [4] Plugin on_request hook ═══
    {
        let headers: std::collections::HashMap<String, String> = req.headers().iter()
            .filter_map(|(k, v)| {
                v.to_str().ok().map(|val| (k.to_string(), val.to_string()))
            })
            .collect();

        let actions = plugin_manager.execute_on_request(&method, &path, &headers).await;
        for action in actions {
            match action {
                crate::plugins::PluginAction::Block(status, msg) => {
                    tracing::info!("Plugin blocked request: {} {} → {} {}", method, path, status, msg);
                    let status_code = actix_web::http::StatusCode::from_u16(status)
                        .unwrap_or(actix_web::http::StatusCode::FORBIDDEN);
                    return HttpResponse::build(status_code).json(serde_json::json!({
                        "error": "Blocked by plugin",
                        "message": msg,
                    }));
                }
                _ => {}
            }
        }
    }

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
    crate::metrics::ACTIVE_CONNECTIONS.inc();

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
        method, path, downstream_url, service.name, strategy
    );

    // ═══ [5] Transform — request header'larını dönüştür ═══
    // Not: Transform, proxy::forward_request_raw'a request header'ları üzerinden
    // uygulanamıyor (actix HttpRequest immutable). Transform bilgisi proxy'ye iletilecek.
    let has_transform = service.transform.is_some();
    let transform_rules = service.transform.as_ref().map(TransformRules::from_config);

    // ═══ [3] Retry Policy ile proxy ═══
    let proxy_result = if retry_config.max_retries > 0 {
        // Retry sadece mutating request'ler için değil, tüm istekler için uygulanabilir
        // Ama basitlik için: retry aktifse, retry policy ile gönder
        let retry_policy = RetryPolicy::new(
            retry_config.max_retries,
            retry_config.delay_ms,
            retry_config.backoff_multiplier,
        );

        // Build request headers for retry
        let mut retry_headers = reqwest::header::HeaderMap::new();
        let skip_headers = ["host", "connection", "transfer-encoding", "keep-alive", "upgrade"];
        for (key, value) in req.headers().iter() {
            let key_str = key.as_str().to_lowercase();
            if !skip_headers.contains(&key_str.as_str()) {
                if let Ok(val_str) = value.to_str() {
                    if let (Ok(name), Ok(val)) = (
                        reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()),
                        reqwest::header::HeaderValue::from_str(val_str),
                    ) {
                        retry_headers.insert(name, val);
                    }
                }
            }
        }

        // ═══ [5] Transform request headers ═══
        if let Some(ref rules) = transform_rules {
            rules.apply_request_headers(&mut retry_headers);
        }

        // X-Forwarded headers
        if let Some(peer) = req.peer_addr() {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&peer.ip().to_string()) {
                retry_headers.insert("x-forwarded-for", val);
            }
        }

        let req_method = match method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };

        let body_opt = if body.is_empty() { None } else { Some(body.to_vec()) };

        match retry_policy.execute(
            proxy::client(),
            req_method,
            &downstream_url,
            retry_headers,
            body_opt,
        ).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp.headers().iter()
                    .filter(|(k, _)| !skip_headers.contains(&k.as_str()))
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| (k.to_string(), val.to_string()))
                    })
                    .collect();
                let body_bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                proxy::ProxyResult { status, headers, body: body_bytes, is_error: false }
            }
            Err(e) => {
                tracing::error!("Retry exhausted for {}: {}", downstream_url, e);
                let err_body = serde_json::to_vec(&serde_json::json!({
                    "error": "Service unavailable after retries",
                    "detail": e.to_string()
                })).unwrap_or_default();
                proxy::ProxyResult {
                    status: 502,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: err_body,
                    is_error: true,
                }
            }
        }
    } else {
        // Normal proxy (retry yok veya GET istekleri)
        proxy::forward_request_raw(&req, body, &downstream_url).await
    };

    // Bağlantı bırak
    lb.release_connection(&selected_upstream);
    crate::metrics::ACTIVE_CONNECTIONS.dec();

    // Circuit breaker sonuç kayıt
    match proxy_result.status {
        s if s >= 500 => {
            cb_manager.record_failure(&service.id);
        }
        _ => {
            cb_manager.record_success(&service.id);
        }
    }

    // ═══ [4] Plugin on_response hook ═══
    let mut proxy_result = proxy_result;
    {
        let actions = plugin_manager.execute_on_response(proxy_result.status, &path).await;
        for action in actions {
            match action {
                crate::plugins::PluginAction::AddHeader(key, value) => {
                    proxy_result.headers.push((key, value));
                }
                crate::plugins::PluginAction::Block(status, msg) => {
                    let status_code = actix_web::http::StatusCode::from_u16(status)
                        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
                    return HttpResponse::build(status_code).json(serde_json::json!({
                        "error": "Blocked by plugin (response)",
                        "message": msg,
                    }));
                }
                crate::plugins::PluginAction::Continue => {}
            }
        }
    }

    // Cache'e yaz (başarılı GET istekleri, hata olmayan)
    if is_get && !proxy_result.is_error && proxy_result.status >= 200 && proxy_result.status < 300 {
        if let Some(key) = cache_key {
            tracing::debug!("Cache STORE: {} ({} bytes)", key, proxy_result.body.len());
            response_cache.put(
                key,
                proxy_result.status,
                proxy_result.headers.clone(),
                proxy_result.body.clone(),
            );
        }
    }

    // ═══ [5] Transform — response header'larını dönüştür ═══
    if has_transform {
        if let Some(ref rules) = transform_rules {
            let status = actix_web::http::StatusCode::from_u16(proxy_result.status)
                .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
            let mut response = HttpResponse::build(status);
            for (k, v) in &proxy_result.headers {
                response.insert_header((k.as_str(), v.as_str()));
            }
            response.insert_header(("X-Proxied-By", "xiraNET"));
            response.insert_header(("X-Cache", "MISS"));
            // Response transform uygula
            rules.apply_response_headers(&mut response);
            return response.body(proxy_result.body);
        }
    }

    // Response'u oluştur ve döndür
    proxy_result.into_response()
}
