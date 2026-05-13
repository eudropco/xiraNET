/// Session token doğrulama middleware'i.
///
/// `Authorization: Bearer <session-token>` header'ı veya `X-Session-Token` header'ı
/// üzerinden gelen plaintext session token'ını `SessionManager::validate` ile
/// doğrular. Geçerli ise request extension'larına `SessionInfo` koyar; değilse
/// 401 döner.
///
/// JWT middleware'inden ayrıdır — JWT (stateless) ve Session (stateful) farklı
/// auth yolları. `/auth/login` session üretir; bu middleware downstream'de
/// session-protected endpoint'lere uygulanır (logout, me, sessions list).
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

use crate::identity::sessions::SessionManager;

/// Doğrulanmış session bilgisi — handler'lar `req.extensions().get::<SessionInfo>()`
/// ile erişebilir.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub user_id: String,
    /// Plaintext token — invalidate için handler'lar kullanır.
    pub token: String,
}

pub struct SessionAuth {
    sessions: Arc<SessionManager>,
}

impl SessionAuth {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        Self { sessions }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SessionAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = SessionAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SessionAuthMiddleware {
            service,
            sessions: self.sessions.clone(),
        }))
    }
}

pub struct SessionAuthMiddleware<S> {
    service: S,
    sessions: Arc<SessionManager>,
}

impl<S, B> Service<ServiceRequest> for SessionAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Token: önce X-Session-Token, yoksa Authorization: Bearer
        let token = req
            .headers()
            .get("X-Session-Token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.headers()
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.strip_prefix("Bearer "))
                    .map(|s| s.to_string())
            });

        let sessions = self.sessions.clone();
        match token {
            Some(t) => match sessions.validate(&t) {
                Some(session) => {
                    req.extensions_mut().insert(SessionInfo {
                        user_id: session.user_id,
                        token: t,
                    });
                    let fut = self.service.call(req);
                    Box::pin(async move {
                        let res = fut.await?;
                        Ok(res.map_into_left_body())
                    })
                }
                None => Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "invalid or expired session"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                }),
            },
            None => Box::pin(async move {
                let response = HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "missing session token",
                    "hint": "Use: Authorization: Bearer <token> or X-Session-Token: <token>"
                }));
                Ok(req.into_response(response).map_into_right_body())
            }),
        }
    }
}
