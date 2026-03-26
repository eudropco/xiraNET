use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use crate::registry::ServiceRegistry;
use crate::registry::storage::SqliteStorage;

/// Request/Response loglama middleware (Prometheus metrics + SQLite entegrasyonu)
pub struct RequestLogger {
    storage: Option<Arc<SqliteStorage>>,
}

impl RequestLogger {
    pub fn new() -> Self {
        Self { storage: None }
    }

    pub fn with_storage(storage: Arc<SqliteStorage>) -> Self {
        Self { storage: Some(storage) }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerMiddleware {
            service,
            storage: self.storage.clone(),
        }))
    }
}

pub struct RequestLoggerMiddleware<S> {
    service: S,
    storage: Option<Arc<SqliteStorage>>,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().to_string();
        let path = req.path().to_string();
        let peer = req
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "-".to_string());
        let start = Instant::now();

        // Registry'den service_id bul (opsiyonel)
        let service_id = req.app_data::<actix_web::web::Data<ServiceRegistry>>()
            .and_then(|reg| reg.lookup(&path))
            .map(|svc| svc.id.to_string());

        let storage = self.storage.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let duration = start.elapsed();
            let status = res.status().as_u16();
            let duration_ms = duration.as_millis() as u64;
            let duration_secs = duration.as_secs_f64();

            // Tracing log
            tracing::info!(
                method = %method,
                path = %path,
                status = %status,
                duration_ms = %duration_ms,
                peer = %peer,
                "Request completed"
            );

            // Prometheus metrics
            crate::metrics::record_request(&method, &path, status, duration_secs);

            // SQLite request log (admin/metrics/dashboard hariç)
            if !path.starts_with("/xira") && path != "/metrics" && path != "/dashboard" {
                if let Some(ref storage) = storage {
                    let _ = storage.log_request(
                        service_id.as_deref(),
                        &method,
                        &path,
                        status,
                        duration_ms,
                        &peer,
                    );
                }
            }

            Ok(res)
        })
    }
}
