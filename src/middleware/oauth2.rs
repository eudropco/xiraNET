use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

/// OAuth2 token introspection middleware (RFC 7662).
/// İyileştirmeler:
/// - Paylaşılan reqwest::Client (per-request build yerine connection reuse)
/// - body parse de timeout altında — slow body stall'ı engelle
/// - `active=true` tek başına yeterli değil; `aud`/`iss`/`exp` opsiyonel olarak doğrulanır
/// - Hata mesajları client'a generic döner; detail server-side log
pub struct OAuth2Auth {
    introspection_url: Arc<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    expected_aud: Option<Arc<String>>,
    expected_iss: Option<Arc<String>>,
    enabled: bool,
    client: Arc<reqwest::Client>,
}

impl OAuth2Auth {
    pub fn new(
        introspection_url: String,
        client_id: String,
        client_secret: String,
        enabled: bool,
    ) -> Self {
        Self::new_with_validation(introspection_url, client_id, client_secret, None, None, enabled)
    }

    pub fn new_with_validation(
        introspection_url: String,
        client_id: String,
        client_secret: String,
        expected_aud: Option<String>,
        expected_iss: Option<String>,
        enabled: bool,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(2))
            .pool_max_idle_per_host(8)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            introspection_url: Arc::new(introspection_url),
            client_id: Arc::new(client_id),
            client_secret: Arc::new(client_secret),
            expected_aud: expected_aud.map(Arc::new),
            expected_iss: expected_iss.map(Arc::new),
            enabled,
            client: Arc::new(client),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for OAuth2Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = OAuth2AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OAuth2AuthMiddleware {
            service,
            introspection_url: self.introspection_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            expected_aud: self.expected_aud.clone(),
            expected_iss: self.expected_iss.clone(),
            enabled: self.enabled,
            client: self.client.clone(),
        }))
    }
}

pub struct OAuth2AuthMiddleware<S> {
    service: S,
    introspection_url: Arc<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    expected_aud: Option<Arc<String>>,
    expected_iss: Option<Arc<String>>,
    enabled: bool,
    client: Arc<reqwest::Client>,
}

impl<S, B> Service<ServiceRequest> for OAuth2AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if !self.enabled {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Admin ve internal endpoint'leri atla — kendi auth mekanizmalarını kullanırlar
        let path = req.path().to_string();
        if path.starts_with("/xira/")
            || path == "/xira"
            || path == "/metrics"
            || path == "/health"
            || path == "/dashboard"
            || path.starts_with("/ws/")
            || path.starts_with("/auth/")
            || path == "/auth"
        {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        let token = match token {
            Some(t) => t,
            None => {
                return Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Missing Bearer token for OAuth2"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                });
            }
        };

        let url = self.introspection_url.clone();
        let client_id = self.client_id.clone();
        let client_secret = self.client_secret.clone();
        let expected_aud = self.expected_aud.clone();
        let expected_iss = self.expected_iss.clone();
        let client = self.client.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let introspect_result = client
                .post(url.as_str())
                .basic_auth(client_id.as_str(), Some(client_secret.as_str()))
                .form(&[
                    ("token", token.as_str()),
                    ("token_type_hint", "access_token"),
                ])
                .send()
                .await;

            match introspect_result {
                Ok(resp) => {
                    // body parse de timeout altında; tokio::time::timeout ekstra kalkan
                    let parsed = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        resp.json::<serde_json::Value>(),
                    )
                    .await;

                    let body = match parsed {
                        Ok(Ok(b)) => b,
                        Ok(Err(e)) => {
                            tracing::warn!("OAuth2 introspection body parse failed: {}", e);
                            return Err(actix_web::error::ErrorUnauthorized(
                                "Token validation failed",
                            ));
                        }
                        Err(_) => {
                            tracing::warn!("OAuth2 introspection body parse timeout");
                            return Err(actix_web::error::ErrorServiceUnavailable(
                                "Auth provider slow",
                            ));
                        }
                    };

                    if !body.get("active").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Err(actix_web::error::ErrorUnauthorized(
                            "Token is not active",
                        ));
                    }

                    // RFC 7662: exp opsiyonel; varsa kontrol et
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if let Some(exp) = body.get("exp").and_then(|v| v.as_i64()) {
                        if exp <= now {
                            return Err(actix_web::error::ErrorUnauthorized("Token expired"));
                        }
                    }

                    // aud kontrolü (config edilmişse)
                    if let Some(ref expected) = expected_aud {
                        let aud_match = match body.get("aud") {
                            Some(serde_json::Value::String(s)) => s == expected.as_str(),
                            Some(serde_json::Value::Array(arr)) => arr
                                .iter()
                                .any(|v| v.as_str().map(|s| s == expected.as_str()).unwrap_or(false)),
                            _ => false,
                        };
                        if !aud_match {
                            tracing::warn!("OAuth2 token aud mismatch");
                            return Err(actix_web::error::ErrorUnauthorized(
                                "Token audience mismatch",
                            ));
                        }
                    }

                    // iss kontrolü (config edilmişse)
                    if let Some(ref expected) = expected_iss {
                        let iss_match = body
                            .get("iss")
                            .and_then(|v| v.as_str())
                            .map(|s| s == expected.as_str())
                            .unwrap_or(false);
                        if !iss_match {
                            tracing::warn!("OAuth2 token iss mismatch");
                            return Err(actix_web::error::ErrorUnauthorized(
                                "Token issuer mismatch",
                            ));
                        }
                    }

                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                }
                Err(e) => {
                    tracing::error!("OAuth2 introspection failed: {}", e);
                    // Fail-closed
                    Err(actix_web::error::ErrorServiceUnavailable(
                        "OAuth2 introspection unavailable",
                    ))
                }
            }
        })
    }
}
