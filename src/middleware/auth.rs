use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

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
            Some(key) if key == *expected_key => {
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                })
            }
            _ => {
                tracing::warn!("Unauthorized access attempt to admin API: {}", path);
                Box::pin(async move {
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "Unauthorized",
                            "message": "Valid X-Api-Key header required"
                        }));
                    Ok(req.into_response(response).map_into_right_body())
                })
            }
        }
    }
}
