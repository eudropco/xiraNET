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

/// İsteği downstream servise ilet
pub async fn forward_request(
    original_req: &HttpRequest,
    body: actix_web::web::Bytes,
    downstream_url: &str,
) -> HttpResponse {
    let method = match original_req.method().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => {
            return HttpResponse::MethodNotAllowed().json(serde_json::json!({
                "error": "Method not supported"
            }));
        }
    };

    let mut forwarded = HTTP_CLIENT.request(method, downstream_url);

    // Header'ları ilet
    let skip_headers = ["host", "connection", "transfer-encoding", "keep-alive", "upgrade"];
    for (key, value) in original_req.headers().iter() {
        let key_str = key.as_str().to_lowercase();
        if !skip_headers.contains(&key_str.as_str()) {
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
            let status = actix_web::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

            let mut response = HttpResponse::build(status);

            for (key, value) in resp.headers().iter() {
                let key_str = key.as_str().to_lowercase();
                if !skip_headers.contains(&key_str.as_str()) {
                    if let Ok(val_str) = value.to_str() {
                        response.insert_header((key.as_str(), val_str));
                    }
                }
            }

            response.insert_header(("X-Proxied-By", "xiraNET"));
            response.insert_header(("X-Cache", "MISS"));

            match resp.bytes().await {
                Ok(bytes) => response.body(bytes.to_vec()),
                Err(e) => {
                    tracing::error!("Failed to read response body: {}", e);
                    HttpResponse::BadGateway().json(serde_json::json!({
                        "error": "Failed to read upstream response",
                        "detail": e.to_string()
                    }))
                }
            }
        }
        Err(e) => {
            tracing::error!("Proxy error to {}: {}", downstream_url, e);
            HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Service unavailable",
                "detail": e.to_string()
            }))
        }
    }
}
