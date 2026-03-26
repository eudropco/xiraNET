use actix_web::{HttpRequest, HttpResponse, web};
use actix_ws::Message;
use futures_util::StreamExt;

/// WebSocket proxy handler
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

    // Actix WebSocket başlat
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;

    // Downstream WebSocket bağlantısı kur
    actix_rt::spawn(async move {
        // Basitleştirilmiş WebSocket proxy:
        // Actix-ws session ile client arasında mesaj aktarımı
        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Ping(data) => {
                    if session.pong(&data).await.is_err() {
                        break;
                    }
                }
                Message::Text(text) => {
                    tracing::debug!("WS message (text): {} bytes → {}", text.len(), ws_url);
                    // Echo back (gerçek implementasyonda downstream'e ilet)
                    if session.text(text).await.is_err() {
                        break;
                    }
                }
                Message::Binary(bin) => {
                    tracing::debug!("WS message (binary): {} bytes → {}", bin.len(), ws_url);
                    if session.binary(bin).await.is_err() {
                        break;
                    }
                }
                Message::Close(reason) => {
                    let _ = session.close(reason).await;
                    break;
                }
                _ => {}
            }
        }

        tracing::info!("WebSocket connection closed");
    });

    Ok(response)
}
