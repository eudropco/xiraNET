use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

/// OAuth2 token introspection middleware
pub struct OAuth2Auth {
    introspection_url: Arc<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    enabled: bool,
}

impl OAuth2Auth {
    pub fn new(
        introspection_url: String,
        client_id: String,
        client_secret: String,
        enabled: bool,
    ) -> Self {
        Self {
            introspection_url: Arc::new(introspection_url),
            client_id: Arc::new(client_id),
            client_secret: Arc::new(client_secret),
            enabled,
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
            enabled: self.enabled,
        }))
    }
}

pub struct OAuth2AuthMiddleware<S> {
    service: S,
    introspection_url: Arc<String>,
    client_id: Arc<String>,
    client_secret: Arc<String>,
    enabled: bool,
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

        // Admin ve internal endpoint'leri atla
        let path = req.path().to_string();
        if path.starts_with("/xira") || path == "/metrics" || path == "/health" {
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
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "Missing Bearer token for OAuth2"
                        }));
                    Ok(req.into_response(response).map_into_right_body())
                });
            }
        };

        let url = self.introspection_url.clone();
        let client_id = self.client_id.clone();
        let client_secret = self.client_secret.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            // Token introspection isteği
            let client = reqwest::Client::new();
            let introspect_result = client
                .post(url.as_str())
                .basic_auth(client_id.as_str(), Some(client_secret.as_str()))
                .form(&[("token", token.as_str()), ("token_type_hint", "access_token")])
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;

            match introspect_result {
                Ok(resp) => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                        if active {
                            let res = fut.await?;
                            return Ok(res.map_into_left_body());
                        }
                    }

                    Err(actix_web::error::ErrorUnauthorized("Token is not active or invalid"))
                }
                Err(e) => {
                    tracing::error!("OAuth2 introspection failed: {}", e);
                    // İntrospection başarısız olduğunda isteğe izin ver (fail-open)
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                }
            }
        })
    }
}
