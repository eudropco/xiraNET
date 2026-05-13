/// Role-based access control middleware.
///
/// `SessionAuth` middleware'inden sonra zincirlenir: session token doğrulanmış
/// kullanıcının rolünü `UserManager` üzerinden çeker ve `min_role`'ün hierarchy
/// seviyesinden eşit/üst olduğunu kontrol eder.
///
/// Kullanım:
/// ```ignore
/// web::scope("/admin/users")
///     .wrap(RequireRole::new(min_role = UserRole::Admin, users = mgr.clone()))
///     .wrap(SessionAuth::new(sessions.clone()))
///     .route(...)
/// ```
///
/// `wrap` ters sırada uygulanır → önce SessionAuth çalışır, `SessionInfo` insert
/// eder, sonra RequireRole role check yapar.
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

use crate::identity::users::{UserManager, UserRole};
use crate::middleware::session::SessionInfo;

pub struct RequireRole {
    min_role: UserRole,
    users: Arc<UserManager>,
}

impl RequireRole {
    pub fn new(min_role: UserRole, users: Arc<UserManager>) -> Self {
        Self { min_role, users }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireRole
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = RequireRoleMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireRoleMiddleware {
            service,
            min_role: self.min_role.clone(),
            users: self.users.clone(),
        }))
    }
}

pub struct RequireRoleMiddleware<S> {
    service: S,
    min_role: UserRole,
    users: Arc<UserManager>,
}

impl<S, B> Service<ServiceRequest> for RequireRoleMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // SessionAuth çıktısı — SessionInfo extension
        let session_info = req.extensions().get::<SessionInfo>().cloned();
        let session_info = match session_info {
            Some(s) => s,
            None => {
                // SessionAuth wire edilmemiş — fail-closed
                return Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "session required (RequireRole expects SessionAuth upstream)"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                });
            }
        };

        let role = self.users.user_role(&session_info.user_id);
        let role = match role {
            Some(r) => r,
            None => {
                return Box::pin(async move {
                    let response = HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "user not found"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                });
            }
        };

        if !role.satisfies(&self.min_role) {
            let required = self.min_role.as_str().to_string();
            let actual = role.as_str().to_string();
            return Box::pin(async move {
                let response = HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "insufficient role",
                    "required": required,
                    "actual": actual,
                }));
                Ok(req.into_response(response).map_into_right_body())
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superadmin_satisfies_everything() {
        assert!(UserRole::SuperAdmin.satisfies(&UserRole::Admin));
        assert!(UserRole::SuperAdmin.satisfies(&UserRole::Developer));
        assert!(UserRole::SuperAdmin.satisfies(&UserRole::Viewer));
        assert!(UserRole::SuperAdmin.satisfies(&UserRole::SuperAdmin));
    }

    #[test]
    fn viewer_does_not_satisfy_admin() {
        assert!(!UserRole::Viewer.satisfies(&UserRole::Admin));
        assert!(!UserRole::Viewer.satisfies(&UserRole::Developer));
        assert!(UserRole::Viewer.satisfies(&UserRole::Viewer));
    }

    #[test]
    fn custom_role_does_not_climb_hierarchy() {
        let custom = UserRole::Custom("billing".into());
        assert!(!custom.satisfies(&UserRole::Admin));
        assert!(custom.satisfies(&UserRole::Custom("billing".into())));
        // Built-in roles do not satisfy a Custom requirement either
        assert!(!UserRole::Admin.satisfies(&UserRole::Custom("billing".into())));
    }

    #[test]
    fn admin_satisfies_developer_and_below() {
        assert!(UserRole::Admin.satisfies(&UserRole::Developer));
        assert!(UserRole::Admin.satisfies(&UserRole::Viewer));
        assert!(!UserRole::Admin.satisfies(&UserRole::SuperAdmin));
    }
}
