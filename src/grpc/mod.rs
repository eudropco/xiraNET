use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::registry::ServiceRegistry;

/// gRPC için paylaşılan client. http2_prior_knowledge + connection pool.
/// Her isteğe `Client::new()` yapmak HTTP/2'siz default'a düşürdüğü için
/// gRPC kırılır ve socket exhaustion'a yol açar.
fn grpc_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .http2_prior_knowledge()
            .pool_max_idle_per_host(20)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("gRPC client init must succeed")
    })
}

/// HTTP/1 hop-by-hop header'ları (RFC 7230). Bunlar end-to-end değildir
/// ve forward edilirse request smuggling / TE-CL desync'e yol açabilir.
fn is_hop_by_hop(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host" // Host'u upstream URL'den biz set ederiz
            | "content-length" // reqwest yeniden hesaplar
    )
}

/// gRPC transparent proxy server
pub async fn start_grpc_proxy(registry: Arc<ServiceRegistry>, host: String, port: u16) {
    let addr = format!("{host}:{port}");

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind gRPC proxy on {}: {}", addr, e);
            return;
        }
    };

    tracing::info!("gRPC proxy listening on {}", addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("gRPC accept error: {}", e);
                continue;
            }
        };

        let registry = registry.clone();
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                let registry = registry.clone();
                async move { handle_grpc_request(req, &registry, &peer.to_string()).await }
            });

            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .http2_only()
                    .serve_connection(io, service)
                    .await
            {
                tracing::debug!("gRPC connection ended: {}", e);
            }
        });
    }
}

async fn handle_grpc_request(
    req: hyper::Request<Incoming>,
    registry: &ServiceRegistry,
    _peer: &str,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    // gRPC path format: /package.ServiceName/MethodName
    let service = registry.lookup(&path);

    match service {
        Some(svc) => {
            let downstream_path = path.strip_prefix(&svc.prefix).unwrap_or(&path);
            let downstream_url = format!("{}{}", svc.upstream, downstream_path);

            tracing::info!("gRPC proxy: {} → {}", path, downstream_url);

            let client = grpc_client();

            // gRPC her zaman POST'tur
            let mut forwarded = client.request(reqwest::Method::POST, &downstream_url);

            // Header'ları forward et — hop-by-hop'ları filtrele
            for (key, value) in req.headers().iter() {
                if is_hop_by_hop(key.as_str()) {
                    continue;
                }
                if let Ok(val_str) = value.to_str() {
                    forwarded = forwarded.header(key.as_str(), val_str);
                }
            }

            // Body
            let body_bytes = match http_body_util::BodyExt::collect(req.into_body()).await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => bytes::Bytes::new(),
            };

            forwarded = forwarded.body(body_bytes.to_vec());

            match forwarded.send().await {
                Ok(resp) => {
                    let status = hyper::StatusCode::from_u16(resp.status().as_u16())
                        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);

                    let mut response = hyper::Response::builder().status(status);

                    for (key, value) in resp.headers().iter() {
                        if is_hop_by_hop(key.as_str()) {
                            continue;
                        }
                        if let Ok(val_str) = value.to_str() {
                            response = response.header(key.as_str(), val_str);
                        }
                    }

                    match resp.bytes().await {
                        Ok(resp_body) => Ok(response
                            .body(http_body_util::Full::new(resp_body))
                            .unwrap_or_else(|_| internal_grpc_error())),
                        Err(e) => {
                            tracing::warn!("gRPC body read error: {}", e);
                            Ok(internal_grpc_error())
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("gRPC proxy error: {}", e);
                    let response = hyper::Response::builder()
                        .status(hyper::StatusCode::BAD_GATEWAY)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "14") // UNAVAILABLE
                        .header("grpc-message", "upstream unavailable")
                        .body(http_body_util::Full::new(bytes::Bytes::new()))
                        .unwrap();
                    Ok(response)
                }
            }
        }
        None => {
            let response = hyper::Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .header("content-type", "application/grpc")
                .header("grpc-status", "12") // UNIMPLEMENTED
                .header("grpc-message", "no service registered for path")
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap();
            Ok(response)
        }
    }
}

fn internal_grpc_error() -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/grpc")
        .header("grpc-status", "13") // INTERNAL
        .header("grpc-message", "proxy internal error")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap()
}
