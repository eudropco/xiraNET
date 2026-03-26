use actix_web::{HttpRequest, HttpResponse};
use reqwest::Client;
use std::time::Duration;

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: Client = Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to create HTTP client");
}

pub fn client() -> &'static Client {
    &HTTP_CLIENT
}

/// Proxy sonucu — raw bileşenler (cache için)
pub struct ProxyResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub is_error: bool,
}

impl ProxyResult {
    /// ProxyResult'dan HttpResponse oluştur
    pub fn into_response(self) -> HttpResponse {
        let status = actix_web::http::StatusCode::from_u16(self.status)
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = HttpResponse::build(status);
        for (k, v) in &self.headers {
            response.insert_header((k.as_str(), v.as_str()));
        }
        response.insert_header(("X-Proxied-By", "xiraNET"));
        response.insert_header(("X-Cache", "MISS"));
        response.body(self.body)
    }
}

const SKIP_HEADERS: [&str; 5] = ["host", "connection", "transfer-encoding", "keep-alive", "upgrade"];

/// İsteği downstream servise ilet — raw bileşenler döndür
pub async fn forward_request_raw(
    original_req: &HttpRequest,
    body: actix_web::web::Bytes,
    downstream_url: &str,
) -> ProxyResult {
    let method = match original_req.method().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => {
            let err_body = serde_json::to_vec(&serde_json::json!({"error": "Method not supported"})).unwrap_or_default();
            return ProxyResult {
                status: 405,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: err_body,
                is_error: true,
            };
        }
    };

    let mut forwarded = HTTP_CLIENT.request(method, downstream_url);

    // Header'ları ilet
    for (key, value) in original_req.headers().iter() {
        let key_str = key.as_str().to_lowercase();
        if !SKIP_HEADERS.contains(&key_str.as_str()) {
            if let Ok(val_str) = value.to_str() {
                forwarded = forwarded.header(key.as_str(), val_str);
            }
        }
    }

    // X-Forwarded header'ları
    if let Some(peer) = original_req.peer_addr() {
        forwarded = forwarded.header("X-Forwarded-For", peer.ip().to_string());
    }
    forwarded = forwarded.header("X-Forwarded-Proto", "http");
    if let Some(host) = original_req.headers().get("host") {
        if let Ok(host_str) = host.to_str() {
            forwarded = forwarded.header("X-Forwarded-Host", host_str);
        }
    }

    // Body
    if !body.is_empty() {
        forwarded = forwarded.body(body.to_vec());
    }

    match forwarded.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();

            let headers: Vec<(String, String)> = resp.headers().iter()
                .filter(|(k, _)| !SKIP_HEADERS.contains(&k.as_str()))
                .filter_map(|(k, v)| {
                    v.to_str().ok().map(|val| (k.to_string(), val.to_string()))
                })
                .collect();

            match resp.bytes().await {
                Ok(bytes) => ProxyResult {
                    status,
                    headers,
                    body: bytes.to_vec(),
                    is_error: false,
                },
                Err(e) => {
                    tracing::error!("Failed to read response body: {}", e);
                    let err_body = serde_json::to_vec(&serde_json::json!({
                        "error": "Failed to read upstream response",
                        "detail": e.to_string()
                    })).unwrap_or_default();
                    ProxyResult {
                        status: 502,
                        headers: vec![("content-type".to_string(), "application/json".to_string())],
                        body: err_body,
                        is_error: true,
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Proxy error to {}: {}", downstream_url, e);
            let err_body = serde_json::to_vec(&serde_json::json!({
                "error": "Service unavailable",
                "detail": e.to_string()
            })).unwrap_or_default();
            ProxyResult {
                status: 502,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: err_body,
                is_error: true,
            }
        }
    }
}

/// İsteği downstream servise ilet (eski uyumlu interface)
pub async fn forward_request(
    original_req: &HttpRequest,
    body: actix_web::web::Bytes,
    downstream_url: &str,
) -> HttpResponse {
    forward_request_raw(original_req, body, downstream_url).await.into_response()
}

