use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: Option<String>,
    pub exp: Option<usize>,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub roles: Option<Vec<String>>,
}

/// JWT Authentication middleware
pub struct JwtAuth {
    secret: Arc<String>,
    algorithm: Algorithm,
    issuer: Option<String>,
    enabled: bool,
}

impl JwtAuth {
    pub fn new(secret: String, algorithm_str: &str, issuer: Option<String>, enabled: bool) -> Self {
        let algorithm = match algorithm_str.to_uppercase().as_str() {
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            _ => Algorithm::HS256,
        };

        Self {
            secret: Arc::new(secret),
            algorithm,
            issuer,
            enabled,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware {
            service,
            secret: self.secret.clone(),
            algorithm: self.algorithm,
            issuer: self.issuer.clone(),
            enabled: self.enabled,
        }))
    }
}

pub struct JwtAuthMiddleware<S> {
    service: S,
    secret: Arc<String>,
    algorithm: Algorithm,
    issuer: Option<String>,
    enabled: bool,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
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

        // Admin ve health endpoint'lerini atla
        let path = req.path().to_string();
        if path.starts_with("/xira") || path == "/metrics" || path == "/health" {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Authorization header'dan token al
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
                            "error": "Missing or invalid Authorization header",
                            "hint": "Use: Authorization: Bearer <token>"
                        }));
                    Ok(req.into_response(response).map_into_right_body())
                });
            }
        };

        // Token doğrula
        let mut validation = Validation::new(self.algorithm);
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }

        let key = DecodingKey::from_secret(self.secret.as_bytes());

        match decode::<JwtClaims>(&token, &key, &validation) {
            Ok(_token_data) => {
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                })
            }
            Err(e) => {
                tracing::warn!("JWT validation failed: {}", e);
                Box::pin(async move {
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "Invalid or expired token",
                            "detail": e.to_string()
                        }));
                    Ok(req.into_response(response).map_into_right_body())
                })
            }
        }
    }
}
