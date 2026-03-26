use actix_web::{HttpRequest, HttpResponse, web};
use actix_ws::Message;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

/// WebSocket bidirectional proxy handler
pub async fn websocket_proxy(
    req: HttpRequest,
    body: web::Payload,
    registry: web::Data<crate::registry::ServiceRegistry>,
) -> Result<HttpResponse, actix_web::Error> {
    let path = req.path().to_string();

    let service = match registry.lookup(&path) {
        Some(svc) => svc,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "No WebSocket service for this path"
            })));
        }
    };

    let downstream_path = path.strip_prefix(&service.prefix).unwrap_or("/");
    let downstream_path = if downstream_path.is_empty() { "/" } else { downstream_path };

    // http:// → ws://, https:// → wss://
    let ws_upstream = service.upstream
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let ws_url = format!("{}{}", ws_upstream, downstream_path);

    tracing::info!("WebSocket proxy: {} → {}", path, ws_url);

    // Actix WebSocket başlat (client tarafı)
    let (response, client_session, mut client_stream) = actix_ws::handle(&req, body)?;

    // Downstream WebSocket bağlantısı kur
    let ws_connect_result = tokio_tungstenite::connect_async(&ws_url).await;

    let (upstream_ws, _) = match ws_connect_result {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Failed to connect to upstream WebSocket {}: {}", ws_url, e);
            let _ = client_session.close(Some(actix_ws::CloseReason {
                code: actix_ws::CloseCode::Away,
                description: Some(format!("Upstream connection failed: {}", e)),
            })).await;
            return Ok(response);
        }
    };

    let (upstream_sink, mut upstream_stream) = upstream_ws.split();

    tracing::info!("WebSocket proxy connected: {} ↔ {}", path, ws_url);

    // Upstream sink'i Mutex ile paylaş (actix_rt::spawn Send gerektirmediği için uygun)
    let upstream_sink = std::sync::Arc::new(tokio::sync::Mutex::new(upstream_sink));
    let upstream_sink_clone = upstream_sink.clone();

    // Client session'ı upstream→client task için klonla
    let mut client_session_clone = client_session.clone();

    let ws_url_log = ws_url.clone();

    // actix_rt::spawn: !Send future'ları destekler
    actix_rt::spawn(async move {
        // Upstream → Client (ayrı task)
        let upstream_handle = actix_rt::spawn(async move {
            while let Some(Ok(msg)) = upstream_stream.next().await {
                let result = match msg {
                    tungstenite::Message::Text(text) => {
                        tracing::debug!("WS upstream→client: {} bytes", text.len());
                        client_session_clone.text(text).await
                    }
                    tungstenite::Message::Binary(bin) => {
                        tracing::debug!("WS upstream→client: {} bytes (binary)", bin.len());
                        client_session_clone.binary(bin).await
                    }
                    tungstenite::Message::Ping(data) => {
                        client_session_clone.ping(&data).await
                    }
                    tungstenite::Message::Pong(data) => {
                        client_session_clone.pong(&data).await
                    }
                    tungstenite::Message::Close(frame) => {
                        let reason = frame.map(|f| actix_ws::CloseReason {
                            code: actix_ws::CloseCode::from(u16::from(f.code)),
                            description: Some(f.reason.to_string()),
                        });
                        let _ = client_session_clone.close(reason).await;
                        break;
                    }
                    _ => continue,
                };

                if result.is_err() {
                    break;
                }
            }
        });

        // Client → Upstream (ana task)
        while let Some(Ok(msg)) = client_stream.next().await {
            let tungstenite_msg = match msg {
                Message::Text(text) => {
                    tracing::debug!("WS client→upstream: {} bytes", text.len());
                    tungstenite::Message::Text(text.to_string())
                }
                Message::Binary(bin) => {
                    tracing::debug!("WS client→upstream: {} bytes (binary)", bin.len());
                    tungstenite::Message::Binary(bin.to_vec())
                }
                Message::Ping(data) => {
                    tungstenite::Message::Ping(data.to_vec())
                }
                Message::Pong(data) => {
                    tungstenite::Message::Pong(data.to_vec())
                }
                Message::Close(reason) => {
                    let close_frame = reason.map(|r| {
                        let code_u16: u16 = r.code.into();
                        tungstenite::protocol::CloseFrame {
                            code: tungstenite::protocol::frame::coding::CloseCode::from(code_u16),
                            reason: r.description.unwrap_or_default().into(),
                        }
                    });
                    let mut sink = upstream_sink_clone.lock().await;
                    let _ = sink.send(tungstenite::Message::Close(close_frame)).await;
                    break;
                }
                _ => continue,
            };

            let mut sink = upstream_sink_clone.lock().await;
            if sink.send(tungstenite_msg).await.is_err() {
                break;
            }
        }

        // Client tarafı kapandı, upstream task'ı da durdur
        upstream_handle.abort();
        tracing::info!("WebSocket proxy closed: {}", ws_url_log);
    });

    Ok(response)
}
