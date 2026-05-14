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
        response.insert_header(("X-Proxied-By", "XIRA"));
        response.insert_header(("X-Cache", "MISS"));
        response.body(self.body)
    }
}

/// RFC 7230 §6.1 hop-by-hop header'lar — proxy boyunca forward edilmez.
/// Eksik liste request smuggling ve auth bypass amplifier'ı oluşturur;
/// `te`/`proxy-authorization`/`proxy-connection` v3.0 audit'inde tespit edildi.
const SKIP_HEADERS: [&str; 8] = [
    "host",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "upgrade",
    "te",
    "proxy-authorization",
    "proxy-connection",
];

pub fn build_forward_headers(original_req: &HttpRequest) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();

    for (key, value) in original_req.headers().iter() {
        let key_str = key.as_str().to_lowercase();
        if !SKIP_HEADERS.contains(&key_str.as_str()) {
            if let Ok(val_str) = value.to_str() {
                if let (Ok(name), Ok(val)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()),
                    reqwest::header::HeaderValue::from_str(val_str),
                ) {
                    headers.insert(name, val);
                }
            }
        }
    }

    if let Some(peer) = original_req.peer_addr() {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&peer.ip().to_string()) {
            headers.insert("x-forwarded-for", val);
        }
    }
    // X-Forwarded-Proto'yu connection scheme'den türet — TLS-terminated trafiği "http"
    // diye markalama yanlış cookie/redirect davranışına yol açar.
    let scheme = original_req.connection_info().scheme().to_string();
    let scheme_static = if scheme == "https" { "https" } else { "http" };
    headers.insert(
        "x-forwarded-proto",
        reqwest::header::HeaderValue::from_static(scheme_static),
    );
    if let Some(host) = original_req.headers().get("host") {
        if let Ok(host_str) = host.to_str() {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(host_str) {
                headers.insert("x-forwarded-host", val);
            }
        }
    }

    headers
}

/// İsteği downstream servise ilet — raw bileşenler döndür
pub async fn forward_request_raw(
    original_req: &HttpRequest,
    body: actix_web::web::Bytes,
    downstream_url: &str,
) -> ProxyResult {
    forward_request_raw_with_headers(
        original_req,
        body,
        downstream_url,
        build_forward_headers(original_req),
    )
    .await
}

/// İsteği downstream servise ilet — hazır header map ile
pub async fn forward_request_raw_with_headers(
    original_req: &HttpRequest,
    body: actix_web::web::Bytes,
    downstream_url: &str,
    forwarded_headers: reqwest::header::HeaderMap,
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
            let err_body =
                serde_json::to_vec(&serde_json::json!({"error": "Method not supported"}))
                    .unwrap_or_default();
            return ProxyResult {
                status: 405,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: err_body,
                is_error: true,
            };
        }
    };

    let mut forwarded = HTTP_CLIENT.request(method, downstream_url);

    for (key, value) in forwarded_headers.iter() {
        forwarded = forwarded.header(key, value);
    }

    // Body
    if !body.is_empty() {
        forwarded = forwarded.body(body.to_vec());
    }

    match forwarded.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();

            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .filter(|(k, _)| !SKIP_HEADERS.contains(&k.as_str()))
                .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
                .collect();

            match resp.bytes().await {
                Ok(bytes) => ProxyResult {
                    status,
                    headers,
                    body: bytes.to_vec(),
                    is_error: false,
                },
                Err(e) => {
                    // Detay sadece server log'a; client'a sızdırma — eski sürüm
                    // upstream hostname / DNS / port'u recon helper olarak veriyordu.
                    tracing::error!(error = %e, "Failed to read upstream response body");
                    let err_body = serde_json::to_vec(&serde_json::json!({
                        "error": "Failed to read upstream response",
                    }))
                    .unwrap_or_default();
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
            // Detay (downstream URL, DNS hata mesajı, port info) sadece server
            // log'a. Client generic 502 görür — internal topology leak yok.
            tracing::error!(downstream = %downstream_url, error = %e, "Proxy error");
            let err_body = serde_json::to_vec(&serde_json::json!({
                "error": "Service unavailable",
            }))
            .unwrap_or_default();
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
    forward_request_raw(original_req, body, downstream_url)
        .await
        .into_response()
}
