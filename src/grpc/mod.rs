use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::registry::ServiceRegistry;

/// gRPC transparent proxy server
pub async fn start_grpc_proxy(
    registry: Arc<ServiceRegistry>,
    host: String,
    port: u16,
) {
    let addr = format!("{}:{}", host, port);

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
                async move {
                    handle_grpc_request(req, &registry, &peer.to_string()).await
                }
            });

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new()
            )
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
    // İlk segment'i service prefix olarak kullan
    let service = registry.lookup(&path);

    match service {
        Some(svc) => {
            let downstream_path = path.strip_prefix(&svc.prefix).unwrap_or(&path);
            let downstream_url = format!("{}{}", svc.upstream, downstream_path);

            tracing::info!("gRPC proxy: {} → {}", path, downstream_url);

            // Forward gRPC request via reqwest (HTTP/2)
            let client = reqwest::Client::builder()
                .http2_prior_knowledge()
                .build()
                .unwrap_or_default();

            let method = match req.method().as_str() {
                "POST" => reqwest::Method::POST,
                _ => reqwest::Method::POST, // gRPC is always POST
            };

            let mut forwarded = client.request(method, &downstream_url);

            // Forward headers
            for (key, value) in req.headers().iter() {
                if let Ok(val_str) = value.to_str() {
                    forwarded = forwarded.header(key.as_str(), val_str);
                }
            }

            // Forward body
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
                        if let Ok(val_str) = value.to_str() {
                            response = response.header(key.as_str(), val_str);
                        }
                    }

                    let resp_body = resp.bytes().await.unwrap_or_default();
                    Ok(response.body(http_body_util::Full::new(resp_body)).unwrap())
                }
                Err(e) => {
                    tracing::error!("gRPC proxy error: {}", e);
                    let response = hyper::Response::builder()
                        .status(hyper::StatusCode::BAD_GATEWAY)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "14") // UNAVAILABLE
                        .header("grpc-message", format!("upstream error: {}", e))
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
                .header("grpc-message", format!("no service for path: {}", path))
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap();
            Ok(response)
        }
    }
}
