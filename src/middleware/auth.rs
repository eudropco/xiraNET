use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Constant-time string comparison — eşit uzunluklu olsalar bile timing leak'i engeller.
/// Farklı uzunlukta da timing-safe: önce uzunluk eşitse byte-bazlı CT compare yapar,
/// değilse sahte CT compare çalıştırıp false döndürür.
#[inline]
fn ct_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        // Yine de bir CT karşılaştırma çalıştır ki erken-return timing leak'i olmasın.
        let _ = a.as_bytes().ct_eq(a.as_bytes());
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// API Key tabanlı authentication middleware
pub struct ApiKeyAuth {
    api_key: Arc<String>,
}

impl ApiKeyAuth {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key: Arc::new(api_key),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for ApiKeyAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = ApiKeyAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ApiKeyAuthMiddleware {
            service,
            api_key: self.api_key.clone(),
        }))
    }
}

pub struct ApiKeyAuthMiddleware<S> {
    service: S,
    api_key: Arc<String>,
}

impl<S, B> Service<ServiceRequest> for ApiKeyAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Sadece /xira/ admin route'larını koru
        let path = req.path().to_string();
        if !path.starts_with("/xira") {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // API key kontrolü
        let provided_key = req
            .headers()
            .get("X-Api-Key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let expected_key = self.api_key.clone();

        match provided_key {
            Some(key) if ct_eq_str(&key, expected_key.as_str()) => {
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                })
            }
            Some(_) => {
                crate::metrics::AUTH_REJECTS.with_label_values(&["wrong_key"]).inc();
                tracing::warn!("Unauthorized access attempt to admin API: {}", path);
                Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Unauthorized",
                        "message": "Valid X-Api-Key header required"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                })
            }
            None => {
                crate::metrics::AUTH_REJECTS.with_label_values(&["missing_key"]).inc();
                tracing::warn!("Unauthorized access attempt to admin API: {}", path);
                Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Unauthorized",
                        "message": "Valid X-Api-Key header required"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                })
            }
        }
    }
}
