pub mod body_transform;
pub mod cache;
pub mod canary;
pub mod circuit_breaker;
pub mod connection_pool;
pub mod edge_cache;
pub mod graphql;
pub mod health_scoring;
pub mod interceptors;
pub mod load_balancer;
pub mod proxy;
pub mod request_queue;
pub mod request_replay;
pub mod retry;
pub mod transform;
pub mod websocket;
pub mod ws_metrics;

use crate::gateway::cache::ResponseCache;
use crate::gateway::circuit_breaker::CircuitBreakerManager;
use crate::gateway::load_balancer::{LoadBalanceStrategy, LoadBalancer};
use crate::gateway::retry::RetryPolicy;
use crate::gateway::transform::TransformRules;
use crate::plugins::PluginManager;
use crate::registry::ServiceRegistry;
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

fn cache_control_disables_storage(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("no-store")
        || normalized.contains("private")
        || normalized.contains("no-cache")
}

fn request_is_cacheable(req: &HttpRequest) -> bool {
    for (name, value) in req.headers().iter() {
        let header_name = name.as_str().to_ascii_lowercase();
        if matches!(
            header_name.as_str(),
            "authorization" | "cookie" | "proxy-authorization" | "x-api-key" | "upgrade" | "range"
        ) {
            return false;
        }

        if header_name == "cache-control"
            && value
                .to_str()
                .ok()
                .is_some_and(cache_control_disables_storage)
        {
            return false;
        }
    }

    true
}

fn response_is_cacheable(headers: &[(String, String)]) -> bool {
    for (name, value) in headers {
        let header_name = name.to_ascii_lowercase();
        if header_name == "set-cookie" {
            return false;
        }

        if header_name == "cache-control" && cache_control_disables_storage(value) {
            return false;
        }

        if header_name == "vary" && value.trim() == "*" {
            return false;
        }
    }

    true
}

/// Catch-all handler — routes requests through full pipeline:
/// WAF → Bot detect → IP filter → validation → plugins → circuit breaker → cache → load balancer → transform → retry/proxy → audit → metrics
#[allow(clippy::too_many_arguments)]
pub async fn gateway_handler(
    req: HttpRequest,
    body: web::Bytes,
    registry: web::Data<ServiceRegistry>,
    cb_manager: web::Data<CircuitBreakerManager>,
    lb: web::Data<LoadBalancer>,
    response_cache: web::Data<Arc<ResponseCache>>,
    plugin_manager: web::Data<PluginManager>,
    shared_config: web::Data<Arc<tokio::sync::RwLock<crate::config::XiraConfig>>>,
    // v2.0.0 integrations
    waf: web::Data<Arc<crate::middleware::waf::Waf>>,
    bot_detector: web::Data<Arc<crate::middleware::bot_detect::BotDetector>>,
    audit_logger: web::Data<Arc<crate::middleware::audit_log::AuditLogger>>,
    adv_metrics: web::Data<Arc<crate::metrics::advanced::AdvancedMetrics>>,
    health_scorer: web::Data<Arc<crate::gateway::health_scoring::HealthScorer>>,
    event_bus: web::Data<Arc<crate::automation::event_bus::EventBus>>,
) -> HttpResponse {
    let request_start = std::time::Instant::now();
    let path = req.path().to_string();
    let method = req.method().to_string();
    let peer_ip_log = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "-".to_string());
    let body_size = body.len();

    // ═══ Request ID — her isteğe benzersiz UUID ═══
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // /xira/ admin routes are handled separately
    if path.starts_with("/xira") || path == "/metrics" || path == "/ws" || path == "/dashboard" {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Not found via gateway"
        }));
    }

    // ═══ [WAF] Web Application Firewall ═══
    {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
            .collect();
        // Non-UTF-8 byte'lar replacement char ile lossy çevrilir; WAF inceler ama
        // raw byte payload'larını yutmaz. Aksi halde \xff prefix'i ile WAF bypass mümkün.
        let body_cow = String::from_utf8_lossy(&body);
        let body_str: &str = &body_cow;
        let query_string = req.query_string();
        if let crate::middleware::waf::WafVerdict::Block { reason, rule } =
            waf.inspect(&path, Some(query_string), body_str, &headers, &peer_ip_log)
        {
            tracing::warn!(
                "WAF BLOCKED: {} — rule: {} from {}",
                reason,
                rule,
                peer_ip_log
            );
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Blocked by WAF", "rule": rule, "request_id": request_id,
            }));
        }
    }

    // ═══ [BOT] Bot Detection ═══
    {
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        match bot_detector.check(&peer_ip_log, ua) {
            crate::middleware::bot_detect::BotVerdict::Blocked => {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Bot blocked", "request_id": request_id,
                }));
            }
            crate::middleware::bot_detect::BotVerdict::RateLimited => {
                return HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error": "Bot rate limited", "request_id": request_id,
                }));
            }
            _ => {} // Human or allowed bot
        }
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
    let service_name_for_metrics = service.name.clone();
    let (retry_config, cache_enabled) = {
        let config = shared_config.read().await;
        (config.retry.clone(), config.cache.enabled)
    };

    // ═══ [7] Per-service IP filter ═══
    let peer_ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    if !service.ip_whitelist.is_empty() || !service.ip_blacklist.is_empty() {
        // Blacklist kontrolü
        if service.ip_blacklist.contains(&peer_ip) {
            tracing::warn!(
                "Per-service IP blocked: {} for service '{}'",
                peer_ip,
                service.name
            );
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied by service IP filter",
                "service": service.name,
            }));
        }
        // Whitelist kontrolü (boş değilse)
        if !service.ip_whitelist.is_empty() && !service.ip_whitelist.contains(&peer_ip) {
            tracing::warn!(
                "Per-service IP not whitelisted: {} for service '{}'",
                peer_ip,
                service.name
            );
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied by service IP whitelist",
                "service": service.name,
            }));
        }
    }

    // ═══ [6] JSON Schema validation (POST/PUT/PATCH) ═══
    if let Some(ref _schema) = service.validation_schema {
        if let Some(error_response) =
            crate::middleware::validation::validate_request_body(&req, &body, registry.get_ref())
                .await
        {
            return error_response;
        }
    }

    // ═══ [4] Plugin on_request hook ═══
    {
        let headers: std::collections::HashMap<String, String> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
            .collect();

        let actions = plugin_manager
            .execute_on_request(&method, &path, &headers)
            .await;
        for action in actions {
            if let crate::plugins::PluginAction::Block(status, msg) = action {
                tracing::info!(
                    "Plugin blocked request: {} {} → {} {}",
                    method,
                    path,
                    status,
                    msg
                );
                let status_code = actix_web::http::StatusCode::from_u16(status)
                    .unwrap_or(actix_web::http::StatusCode::FORBIDDEN);
                return HttpResponse::build(status_code).json(serde_json::json!({
                    "error": "Blocked by plugin",
                    "message": msg,
                }));
            }
        }
    }

    // Circuit Breaker kontrolü
    if let Err(state) = cb_manager.allow_request(&service.id) {
        tracing::warn!(
            "Circuit breaker OPEN for service '{}' (state: {:?})",
            service.name,
            state
        );
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Service temporarily unavailable (circuit breaker open)",
            "service": service.name,
        }));
    }

    // Request count artır
    registry.increment_request_count(&service.id);

    // Cache kontrolü (sadece güvenli anonim GET istekleri)
    let is_get = req.method() == actix_web::http::Method::GET;
    let cache_key = if is_get && cache_enabled && request_is_cacheable(&req) {
        Some(ResponseCache::make_key("GET", &path, req.query_string()))
    } else {
        None
    };

    if let Some(ref key) = cache_key {
        // Vary-aware lookup için isteğin header'larını forward et
        let req_headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
            .collect();
        if let Some((status, headers, cached_body)) = response_cache.get(key, &req_headers) {
            tracing::debug!("Cache HIT: {}", key);
            let mut response = HttpResponse::build(
                actix_web::http::StatusCode::from_u16(status)
                    .unwrap_or(actix_web::http::StatusCode::OK),
            );
            for (k, v) in &headers {
                response.insert_header((k.as_str(), v.as_str()));
            }
            response.insert_header(("X-Cache", "HIT"));
            response.insert_header(("X-Proxied-By", "XIRA"));
            return response.body(cached_body);
        }
    }

    // Load Balancing — upstream seç
    let upstreams = service.all_upstreams();
    let strategy = service
        .load_balance
        .as_deref()
        .map(LoadBalanceStrategy::from_str)
        .unwrap_or(LoadBalanceStrategy::RoundRobin);

    let selected_upstream = lb.select_upstream(&service.id, &upstreams, &strategy);
    lb.acquire_connection(&selected_upstream);
    crate::metrics::ACTIVE_CONNECTIONS.inc();

    // Downstream URL oluştur
    let downstream_path = path.strip_prefix(&service.prefix).unwrap_or("/");
    let downstream_path = if downstream_path.is_empty() {
        "/"
    } else {
        downstream_path
    };
    let query = req.query_string();
    let downstream_url = if query.is_empty() {
        format!("{selected_upstream}{downstream_path}")
    } else {
        format!("{selected_upstream}{downstream_path}?{query}")
    };

    tracing::info!(
        "Proxying {} {} → {} [service: {}, lb: {:?}]",
        method,
        path,
        downstream_url,
        service.name,
        strategy
    );

    // ═══ [5] Transform — request header'larını dönüştür ═══
    let has_transform = service.transform.is_some();
    let transform_rules = service.transform.as_ref().map(TransformRules::from_config);
    let mut forwarded_headers = proxy::build_forward_headers(&req);
    if let Some(ref rules) = transform_rules {
        rules.apply_request_headers(&mut forwarded_headers);
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
    let should_retry =
        retry_config.max_retries > 0 && RetryPolicy::method_is_retryable(&req_method);

    // ═══ [3] Retry Policy ile proxy ═══
    let proxy_result = if should_retry {
        let retry_policy = RetryPolicy::new(
            retry_config.max_retries,
            retry_config.delay_ms,
            retry_config.backoff_multiplier,
        );

        let skip_headers = [
            "host",
            "connection",
            "transfer-encoding",
            "keep-alive",
            "upgrade",
        ];
        let body_opt = if body.is_empty() {
            None
        } else {
            Some(body.to_vec())
        };

        match retry_policy
            .execute(
                proxy::client(),
                req_method.clone(),
                &downstream_url,
                forwarded_headers,
                body_opt,
            )
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .filter(|(k, _)| !skip_headers.contains(&k.as_str()))
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| (k.to_string(), val.to_string()))
                    })
                    .collect();
                let body_bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                proxy::ProxyResult {
                    status,
                    headers,
                    body: body_bytes,
                    is_error: false,
                }
            }
            Err(e) => {
                tracing::error!("Retry exhausted for {}: {}", downstream_url, e);
                let err_body = serde_json::to_vec(&serde_json::json!({
                    "error": "Service unavailable after retries",
                    "detail": e.to_string()
                }))
                .unwrap_or_default();
                proxy::ProxyResult {
                    status: 502,
                    headers: vec![("content-type".to_string(), "application/json".to_string())],
                    body: err_body,
                    is_error: true,
                }
            }
        }
    } else {
        proxy::forward_request_raw_with_headers(&req, body, &downstream_url, forwarded_headers)
            .await
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
        let actions = plugin_manager
            .execute_on_response(proxy_result.status, &path)
            .await;
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

    // Cache'e yaz (başarılı anonim GET istekleri, cache-control ile uyumlu cevaplar)
    if is_get
        && !proxy_result.is_error
        && proxy_result.status >= 200
        && proxy_result.status < 300
        && response_is_cacheable(&proxy_result.headers)
    {
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
            response.insert_header(("X-Proxied-By", "XIRA"));
            response.insert_header(("X-Cache", "MISS"));
            // Response transform uygula
            rules.apply_response_headers(&mut response);
            return response.body(proxy_result.body);
        }
    }

    // Response'u oluştur ve döndür
    let mut final_response = proxy_result.into_response();

    // ═══ Request-ID + Latency headers ═══
    let duration_ms = request_start.elapsed().as_secs_f64() * 1000.0;
    final_response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-request-id"),
        actix_web::http::header::HeaderValue::from_str(&request_id)
            .unwrap_or_else(|_| actix_web::http::header::HeaderValue::from_static("-")),
    );
    final_response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("x-response-time"),
        actix_web::http::header::HeaderValue::from_str(&format!("{duration_ms:.2}ms"))
            .unwrap_or_else(|_| actix_web::http::header::HeaderValue::from_static("-")),
    );

    // ═══ [ADVANCED METRICS] Per-service bandwidth + status tracking ═══
    let status_code = final_response.status().as_u16();
    let response_size = final_response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    adv_metrics.record(
        &service_name_for_metrics,
        status_code,
        body_size as u64,
        response_size,
        duration_ms,
    );

    // ═══ [HEALTH SCORING] Feed upstream latency for scoring ═══
    health_scorer.record(&service_name_for_metrics, duration_ms, status_code < 500);

    // ═══ [AUDIT LOG] Write request to audit trail ═══
    {
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let key_preview = req
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(|k| {
                if k.len() > 8 {
                    format!("{}...", &k[..8])
                } else {
                    k.to_string()
                }
            });
        audit_logger.log(&crate::middleware::audit_log::AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            ip: peer_ip_log.clone(),
            method: method.clone(),
            path: path.clone(),
            status: status_code,
            user_agent: ua,
            api_key_preview: key_preview,
            request_id: request_id.clone(),
            duration_ms,
            body_size,
            response_size,
        });
    }

    // ═══ [EVENT BUS] Publish request.completed event ═══
    {
        let bus = event_bus.clone();
        let ev_method = method.clone();
        let ev_path = path.clone();
        let ev_service = service_name_for_metrics.clone();
        let ev_status = status_code;
        let ev_latency = duration_ms;
        tokio::spawn(async move {
            bus.publish(
                "request.completed",
                &ev_service,
                serde_json::json!({
                    "method": ev_method, "path": ev_path,
                    "status": ev_status, "latency_ms": ev_latency,
                }),
            )
            .await;
        });
    }

    // ═══ Access Log (nginx combined format) ═══
    tracing::info!(
        "{} {} {} {} {:.2}ms [{}]",
        peer_ip_log,
        method,
        path,
        status_code,
        duration_ms,
        request_id
    );

    final_response
}

#[cfg(test)]
mod tests {
    use super::{request_is_cacheable, response_is_cacheable};
    use actix_web::test::TestRequest;

    #[test]
    fn test_authenticated_requests_bypass_cache() {
        let req = TestRequest::get()
            .insert_header(("Authorization", "Bearer secret"))
            .to_http_request();
        assert!(!request_is_cacheable(&req));
    }

    #[test]
    fn test_cookie_requests_bypass_cache() {
        let req = TestRequest::get()
            .insert_header(("Cookie", "session=secret"))
            .to_http_request();
        assert!(!request_is_cacheable(&req));
    }

    #[test]
    fn test_plain_get_requests_can_be_cached() {
        let req = TestRequest::get().to_http_request();
        assert!(request_is_cacheable(&req));
    }

    #[test]
    fn test_set_cookie_responses_are_not_cacheable() {
        let headers = vec![("set-cookie".to_string(), "session=secret".to_string())];
        assert!(!response_is_cacheable(&headers));
    }

    #[test]
    fn test_private_cache_control_responses_are_not_cacheable() {
        let headers = vec![(
            "cache-control".to_string(),
            "private, max-age=60".to_string(),
        )];
        assert!(!response_is_cacheable(&headers));
    }
}
