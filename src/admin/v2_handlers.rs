/// v2.1.0 Admin API Handlers — all domain endpoints
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════
// IDENTITY — Typed Request DTOs
// ═══════════════════════════════════════════════════════════════

use crate::config::XiraConfig;
use crate::identity::sessions::SessionManager;
use crate::identity::users::UserManager;

#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}
fn default_role() -> String {
    "Viewer".to_string()
}

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn list_users(mgr: web::Data<Arc<UserManager>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "users": mgr.list_users(),
        "total": mgr.user_count(),
    }))
}

pub async fn create_user(
    mgr: web::Data<Arc<UserManager>>,
    config: web::Data<Arc<tokio::sync::RwLock<XiraConfig>>>,
    body: web::Json<CreateUserRequest>,
) -> HttpResponse {
    let cfg = config.read().await;

    // Enforce registration_enabled config
    if !cfg.identity.registration_enabled {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "Registration is disabled"}));
    }

    // Enforce password_min_length
    if body.password.len() < cfg.identity.password_min_length {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Password must be at least {} characters", cfg.identity.password_min_length)
        }));
    }

    // Validate required fields
    if body.email.is_empty() || body.username.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "email and username are required"}));
    }

    let role = match body.role.as_str() {
        "SuperAdmin" => crate::identity::users::UserRole::SuperAdmin,
        "Admin" => crate::identity::users::UserRole::Admin,
        "Developer" => crate::identity::users::UserRole::Developer,
        "Service" => crate::identity::users::UserRole::Service,
        "Viewer" => crate::identity::users::UserRole::Viewer,
        other => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Unknown role: {}", other),
                "valid_roles": ["SuperAdmin", "Admin", "Developer", "Service", "Viewer"],
            }));
        }
    };

    let elevated = matches!(
        role,
        crate::identity::users::UserRole::SuperAdmin | crate::identity::users::UserRole::Admin
    );

    match mgr.register(
        body.email.clone(),
        body.username.clone(),
        &body.password,
        role.clone(),
    ) {
        Ok(user) => {
            if elevated {
                tracing::warn!(
                    audit = "elevated_user_created",
                    user_id = %user.id,
                    email = %user.email,
                    role = ?role,
                    "Admin endpoint created user with elevated role"
                );
            }
            HttpResponse::Created().json(serde_json::json!({
                "id": user.id, "email": user.email, "username": user.username,
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

pub async fn login_user(
    authenticator: web::Data<Arc<crate::identity::authenticator::Authenticator>>,
    req: HttpRequest,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    if body.email.is_empty() || body.password.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "email and password are required"}));
    }

    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    use crate::identity::authenticator::AuthOutcome;
    match authenticator.login(&body.email, &body.password, &ip, &ua) {
        AuthOutcome::Success { user_id, session, .. } => HttpResponse::Ok().json(serde_json::json!({
            "token": session.token, "user_id": user_id,
            "expires_at": session.expires_at,
        })),
        AuthOutcome::MfaRequired { user_id } => {
            HttpResponse::Ok().json(serde_json::json!({"mfa_required": true, "user_id": user_id}))
        }
        AuthOutcome::AccountDisabled => {
            HttpResponse::Forbidden().json(serde_json::json!({"error": "Account disabled"}))
        }
        AuthOutcome::LockedOut { retry_after_secs } => HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", retry_after_secs.to_string()))
            .json(serde_json::json!({
                "error": "Too many failed attempts",
                "retry_after_secs": retry_after_secs,
            })),
        AuthOutcome::InvalidCredentials => {
            HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}))
        }
    }
}

pub async fn list_sessions(sessions: web::Data<Arc<SessionManager>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "active": sessions.active_count(),
        "total": sessions.total_count(),
    }))
}

pub async fn flush_sessions(sessions: web::Data<Arc<SessionManager>>) -> HttpResponse {
    let cleaned = sessions.cleanup_expired();
    HttpResponse::Ok().json(serde_json::json!({"cleaned": cleaned}))
}

/// GET /auth/me — geçerli session'ın user bilgisini döndür.
/// SessionAuth middleware tarafından doğrulanmış olmalı.
pub async fn me(
    req: HttpRequest,
    users: web::Data<Arc<UserManager>>,
) -> HttpResponse {
    let session_info = match req.extensions().get::<crate::middleware::session::SessionInfo>() {
        Some(s) => s.clone(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "no session"}));
        }
    };
    match users.get_user(&session_info.user_id) {
        Some(u) => HttpResponse::Ok().json(serde_json::json!({
            "id": u.id,
            "email": u.email,
            "username": u.username,
            "role": u.role,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
    }
}

/// POST /auth/logout — geçerli session'ı invalidate et.
pub async fn logout(
    req: HttpRequest,
    sessions: web::Data<Arc<SessionManager>>,
) -> HttpResponse {
    let token = match req.extensions().get::<crate::middleware::session::SessionInfo>() {
        Some(s) => s.token.clone(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "no session"}));
        }
    };
    let removed = sessions.invalidate(&token);
    HttpResponse::Ok().json(serde_json::json!({"logged_out": removed}))
}

/// GET /auth/sessions — geçerli kullanıcının aktif session'larını listele.
pub async fn my_sessions(
    req: HttpRequest,
    sessions: web::Data<Arc<SessionManager>>,
) -> HttpResponse {
    let user_id = match req.extensions().get::<crate::middleware::session::SessionInfo>() {
        Some(s) => s.user_id.clone(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "no session"}));
        }
    };
    let active = sessions.user_sessions(&user_id);
    // Plaintext token'ı dışa sızdırma — sadece metadata.
    let safe: Vec<serde_json::Value> = active
        .iter()
        .map(|s| {
            serde_json::json!({
                "device": s.device_name,
                "ip": s.ip,
                "user_agent": s.user_agent,
                "created_at": s.created_at,
                "expires_at": s.expires_at,
                "last_activity": s.last_activity,
            })
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({"sessions": safe, "count": safe.len()}))
}

// ═══════════════════════════════════════════════════════════════
// Role-protected user administration (SuperAdmin)
// ═══════════════════════════════════════════════════════════════

/// GET /auth/admin/users — tüm kullanıcıları listele (RBAC: SuperAdmin)
pub async fn admin_list_users(
    users: web::Data<Arc<UserManager>>,
) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "users": users.list_users(),
        "count": users.user_count(),
    }))
}

#[derive(serde::Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

/// PUT /auth/admin/users/{id}/role — kullanıcı rolünü değiştir (RBAC: SuperAdmin)
pub async fn admin_update_role(
    users: web::Data<Arc<UserManager>>,
    sessions: web::Data<Arc<SessionManager>>,
    path: web::Path<String>,
    body: web::Json<UpdateRoleRequest>,
) -> HttpResponse {
    let target_id = path.into_inner();
    let role = match body.role.as_str() {
        "SuperAdmin" => crate::identity::users::UserRole::SuperAdmin,
        "Admin" => crate::identity::users::UserRole::Admin,
        "Developer" => crate::identity::users::UserRole::Developer,
        "Service" => crate::identity::users::UserRole::Service,
        "Viewer" => crate::identity::users::UserRole::Viewer,
        other => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Unknown role: {other}"),
            }));
        }
    };
    if !users.update_role(&target_id, role.clone()) {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}));
    }
    // Privilege change → tüm session'larını kapat (force re-auth with new role)
    let invalidated = sessions.invalidate_all(&target_id);
    tracing::warn!(
        audit = "role_change",
        user_id = %target_id,
        new_role = %role.as_str(),
        sessions_invalidated = invalidated,
        "User role changed via admin endpoint"
    );
    HttpResponse::Ok().json(serde_json::json!({
        "updated": true,
        "sessions_invalidated": invalidated,
    }))
}

/// POST /auth/admin/users/{id}/disable — kullanıcıyı devre dışı bırak (RBAC: SuperAdmin)
pub async fn admin_disable_user(
    users: web::Data<Arc<UserManager>>,
    sessions: web::Data<Arc<SessionManager>>,
    path: web::Path<String>,
) -> HttpResponse {
    let target_id = path.into_inner();
    if !users.disable_user(&target_id) {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}));
    }
    let invalidated = sessions.invalidate_all(&target_id);
    tracing::warn!(
        audit = "user_disabled",
        user_id = %target_id,
        sessions_invalidated = invalidated,
    );
    HttpResponse::Ok().json(serde_json::json!({
        "disabled": true,
        "sessions_invalidated": invalidated,
    }))
}

/// POST /auth/admin/users/{id}/mfa/disable — kullanıcının MFA'sını kapat (recovery, RBAC: SuperAdmin)
pub async fn admin_disable_mfa(
    users: web::Data<Arc<UserManager>>,
    path: web::Path<String>,
) -> HttpResponse {
    let target_id = path.into_inner();
    if !users.disable_mfa(&target_id) {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}));
    }
    tracing::warn!(
        audit = "mfa_disabled_by_admin",
        user_id = %target_id,
    );
    HttpResponse::Ok().json(serde_json::json!({"mfa_disabled": true}))
}

/// POST /auth/admin/users/{id}/logout-all — başka kullanıcıyı force logout (RBAC: SuperAdmin)
pub async fn admin_logout_all(
    sessions: web::Data<Arc<SessionManager>>,
    path: web::Path<String>,
) -> HttpResponse {
    let target_id = path.into_inner();
    let count = sessions.invalidate_all(&target_id);
    tracing::warn!(
        audit = "force_logout",
        user_id = %target_id,
        sessions = count,
    );
    HttpResponse::Ok().json(serde_json::json!({"invalidated": count}))
}

/// POST /auth/logout-all — geçerli kullanıcının TÜM session'larını kapat.
pub async fn logout_all(
    req: HttpRequest,
    sessions: web::Data<Arc<SessionManager>>,
) -> HttpResponse {
    let user_id = match req.extensions().get::<crate::middleware::session::SessionInfo>() {
        Some(s) => s.user_id.clone(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "no session"}));
        }
    };
    let count = sessions.invalidate_all(&user_id);
    HttpResponse::Ok().json(serde_json::json!({"invalidated": count}))
}

/// POST /auth/mfa/enroll — geçerli kullanıcı için MFA seed üret + QR URL döndür.
pub async fn mfa_enroll(
    req: HttpRequest,
    users: web::Data<Arc<UserManager>>,
) -> HttpResponse {
    let user_id = match req.extensions().get::<crate::middleware::session::SessionInfo>() {
        Some(s) => s.user_id.clone(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "no session"}));
        }
    };
    match users.start_mfa_enrollment(&user_id) {
        Ok((secret, qr)) => HttpResponse::Ok().json(serde_json::json!({
            "secret": secret,
            "qr_url": qr,
            "next": "POST /auth/mfa/verify with the 6-digit code from your authenticator"
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

#[derive(serde::Deserialize)]
pub struct MfaCodeRequest {
    pub code: String,
}

/// POST /auth/mfa/verify — enrollment'ı doğrula, mfa_enabled = true yap.
pub async fn mfa_verify(
    req: HttpRequest,
    users: web::Data<Arc<UserManager>>,
    body: web::Json<MfaCodeRequest>,
) -> HttpResponse {
    let user_id = match req.extensions().get::<crate::middleware::session::SessionInfo>() {
        Some(s) => s.user_id.clone(),
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "no session"}));
        }
    };
    if users.verify_mfa_setup(&user_id, &body.code) {
        HttpResponse::Ok().json(serde_json::json!({"mfa_enabled": true}))
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid code"}))
    }
}

#[derive(serde::Deserialize)]
pub struct MfaLoginRequest {
    pub user_id: String,
    pub code: String,
}

/// POST /auth/mfa/login — login yanıtında MfaRequired alındığında 2. adım.
pub async fn mfa_login(
    authenticator: web::Data<Arc<crate::identity::authenticator::Authenticator>>,
    req: HttpRequest,
    body: web::Json<MfaLoginRequest>,
) -> HttpResponse {
    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    use crate::identity::authenticator::AuthOutcome;
    match authenticator.complete_mfa(&body.user_id, &body.code, &ip, &ua) {
        AuthOutcome::Success { user_id, session, .. } => HttpResponse::Ok().json(serde_json::json!({
            "token": session.token,
            "user_id": user_id,
            "expires_at": session.expires_at,
        })),
        AuthOutcome::AccountDisabled => {
            HttpResponse::Forbidden().json(serde_json::json!({"error": "Account disabled"}))
        }
        _ => HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid code"})),
    }
}

// ═══════════════════════════════════════════════════════════════
// AUTOMATION
// ═══════════════════════════════════════════════════════════════

use crate::automation::cron::CronScheduler;
use crate::automation::event_bus::EventBus;

pub async fn list_cron_jobs(scheduler: web::Data<Arc<CronScheduler>>) -> HttpResponse {
    let jobs = scheduler.list_jobs().await;
    HttpResponse::Ok().json(serde_json::json!({"jobs": jobs, "total": jobs.len()}))
}

#[derive(serde::Deserialize)]
pub struct CreateCronJobRequest {
    #[serde(default = "default_unnamed")]
    pub name: String,
    pub url: String,
    #[serde(default = "default_get")]
    pub method: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}
fn default_unnamed() -> String {
    "unnamed".to_string()
}
fn default_get() -> String {
    "GET".to_string()
}
fn default_interval() -> u64 {
    60
}

pub async fn create_cron_job(
    scheduler: web::Data<Arc<CronScheduler>>,
    body: web::Json<CreateCronJobRequest>,
) -> HttpResponse {
    // SSRF guard — cron internal servislere de çağrı yapabilir; metadata her durumda block.
    if let Err(e) = crate::alerting::url_guard::validate_upstream_url(&body.url).await {
        let err_str = e.to_string();
        crate::metrics::SSRF_REJECTS
            .with_label_values(&[crate::metrics::ssrf_category(&err_str)])
            .inc();
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": format!("URL rejected: {err_str}")}));
    }
    let schedule = crate::automation::cron::CronSchedule::EverySeconds(body.interval_secs);
    let id = scheduler
        .add_job(
            body.name.clone(),
            schedule,
            body.url.clone(),
            body.method.clone(),
        )
        .await;
    HttpResponse::Created().json(serde_json::json!({"id": id}))
}

pub async fn delete_cron_job(
    scheduler: web::Data<Arc<CronScheduler>>,
    path: web::Path<String>,
) -> HttpResponse {
    if scheduler.remove_job(&path.into_inner()).await {
        HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "Job not found"}))
    }
}

pub async fn list_workflows(
    engine: web::Data<Arc<crate::automation::workflows::WorkflowEngine>>,
) -> HttpResponse {
    let wfs = engine.list().await;
    HttpResponse::Ok().json(serde_json::json!({"workflows": wfs, "total": wfs.len()}))
}

pub async fn list_events(bus: web::Data<Arc<EventBus>>) -> HttpResponse {
    let events = bus.recent_events(100).await;
    let stats = bus.stats().await;
    HttpResponse::Ok().json(serde_json::json!({"events": events, "stats": stats}))
}

#[derive(serde::Deserialize)]
pub struct PublishEventRequest {
    #[serde(default = "default_topic")]
    pub topic: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub data: serde_json::Value,
}
fn default_topic() -> String {
    "default".to_string()
}
fn default_source() -> String {
    "api".to_string()
}

pub async fn publish_event(
    bus: web::Data<Arc<EventBus>>,
    body: web::Json<PublishEventRequest>,
) -> HttpResponse {
    let id = bus
        .publish(&body.topic, &body.source, body.data.clone())
        .await;
    HttpResponse::Created().json(serde_json::json!({"event_id": id}))
}

// ═══════════════════════════════════════════════════════════════
// OBSERVABILITY
// ═══════════════════════════════════════════════════════════════

use crate::observability::incidents::IncidentManager;
use crate::observability::log_aggregator::LogAggregator;
use crate::observability::uptime::UptimePage;

pub async fn search_logs(
    agg: web::Data<Arc<LogAggregator>>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let limit = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    let logs = if let Some(q) = query.get("q") {
        agg.search(q, limit).await
    } else if let Some(level) = query.get("level") {
        let lv = match level.as_str() {
            "Error" => crate::observability::log_aggregator::LogLevel::Error,
            "Warn" => crate::observability::log_aggregator::LogLevel::Warn,
            "Info" => crate::observability::log_aggregator::LogLevel::Info,
            "Debug" => crate::observability::log_aggregator::LogLevel::Debug,
            _ => crate::observability::log_aggregator::LogLevel::Info,
        };
        agg.by_level(&lv, limit).await
    } else {
        agg.recent(limit).await
    };

    let stats = agg.stats().await;
    HttpResponse::Ok().json(serde_json::json!({"logs": logs, "stats": stats}))
}

pub async fn get_uptime(page: web::Data<Arc<tokio::sync::RwLock<UptimePage>>>) -> HttpResponse {
    let p = page.read().await;
    HttpResponse::Ok().json(p.render())
}

pub async fn list_incidents(mgr: web::Data<Arc<IncidentManager>>) -> HttpResponse {
    let active = mgr.active().await;
    let all = mgr.list().await;
    HttpResponse::Ok().json(serde_json::json!({
        "active": active, "active_count": active.len(),
        "all": all, "total": all.len(),
    }))
}

#[derive(serde::Deserialize)]
pub struct CreateIncidentRequest {
    #[serde(default = "default_untitled")]
    pub title: String,
    #[serde(default = "default_minor")]
    pub severity: String,
    #[serde(default)]
    pub services: Vec<String>,
}
fn default_untitled() -> String {
    "Untitled".to_string()
}
fn default_minor() -> String {
    "Minor".to_string()
}

pub async fn create_incident(
    mgr: web::Data<Arc<IncidentManager>>,
    body: web::Json<CreateIncidentRequest>,
) -> HttpResponse {
    let severity = match body.severity.as_str() {
        "Critical" => crate::observability::incidents::Severity::Critical,
        "Major" => crate::observability::incidents::Severity::Major,
        "Info" => crate::observability::incidents::Severity::Info,
        _ => crate::observability::incidents::Severity::Minor,
    };

    let id = mgr
        .create(body.title.clone(), severity, body.services.clone())
        .await;
    HttpResponse::Created().json(serde_json::json!({"incident_id": id}))
}

#[derive(serde::Deserialize)]
pub struct UpdateIncidentRequest {
    #[serde(default)]
    pub message: String,
    #[serde(default = "default_admin")]
    pub author: String,
    pub status: Option<String>,
}
fn default_admin() -> String {
    "admin".to_string()
}

pub async fn update_incident(
    mgr: web::Data<Arc<IncidentManager>>,
    path: web::Path<String>,
    body: web::Json<UpdateIncidentRequest>,
) -> HttpResponse {
    let id = path.into_inner();

    if let Some(ref status) = body.status {
        let s = match status.as_str() {
            "Identified" => crate::observability::incidents::IncidentStatus::Identified,
            "Monitoring" => crate::observability::incidents::IncidentStatus::Monitoring,
            "Resolved" => crate::observability::incidents::IncidentStatus::Resolved,
            _ => crate::observability::incidents::IncidentStatus::Investigating,
        };
        mgr.update_status(&id, s).await;
    }

    if !body.message.is_empty() {
        mgr.add_update(&id, body.message.clone(), body.author.clone())
            .await;
    }

    HttpResponse::Ok().json(serde_json::json!({"updated": true}))
}

// ═══════════════════════════════════════════════════════════════
// DB GATEWAY
// ═══════════════════════════════════════════════════════════════

use crate::dbgateway::proxy::DbProxy;
use crate::dbgateway::query_firewall::QueryFirewall;

pub async fn list_db_connections(proxy: web::Data<Arc<DbProxy>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "connections": proxy.list(), "total": proxy.count(),
    }))
}

pub async fn get_slow_queries(fw: web::Data<Arc<QueryFirewall>>) -> HttpResponse {
    let slow = fw.get_slow_queries(50).await;
    let stats = fw.stats().await;
    HttpResponse::Ok().json(serde_json::json!({"slow_queries": slow, "stats": stats}))
}

pub async fn get_firewall_stats(fw: web::Data<Arc<QueryFirewall>>) -> HttpResponse {
    let stats = fw.stats().await;
    HttpResponse::Ok().json(serde_json::json!({"query_firewall": stats}))
}

// ═══════════════════════════════════════════════════════════════
// DEPLOYMENT
// ═══════════════════════════════════════════════════════════════

use crate::deployment::feature_flags::FeatureFlagManager;
use crate::deployment::releases::ReleaseManager;

pub async fn list_flags(mgr: web::Data<Arc<FeatureFlagManager>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"flags": mgr.list()}))
}

#[derive(serde::Deserialize)]
pub struct CreateFlagRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_percentage")]
    pub percentage: u32,
}
fn default_percentage() -> u32 {
    100
}

pub async fn create_flag(
    mgr: web::Data<Arc<FeatureFlagManager>>,
    body: web::Json<CreateFlagRequest>,
) -> HttpResponse {
    mgr.create(
        body.name.clone(),
        body.description.clone(),
        body.enabled,
        body.percentage,
    );
    HttpResponse::Created().json(serde_json::json!({"created": body.name}))
}

pub async fn toggle_flag(
    mgr: web::Data<Arc<FeatureFlagManager>>,
    path: web::Path<String>,
) -> HttpResponse {
    let name = path.into_inner();
    match mgr.toggle(&name) {
        Some(state) => HttpResponse::Ok().json(serde_json::json!({"flag": name, "enabled": state})),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Flag not found"})),
    }
}

pub async fn list_releases(mgr: web::Data<Arc<ReleaseManager>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"releases": mgr.list()}))
}

#[derive(serde::Deserialize)]
pub struct CreateReleaseRequest {
    pub service: String,
    pub blue: String,
    pub green: String,
    #[serde(default = "default_threshold")]
    pub error_threshold: f64,
}
fn default_threshold() -> f64 {
    0.1
}

pub async fn create_release(
    mgr: web::Data<Arc<ReleaseManager>>,
    body: web::Json<CreateReleaseRequest>,
) -> HttpResponse {
    let strategy = crate::deployment::releases::ReleaseStrategy::BlueGreen;
    let id = mgr.create(
        body.service.clone(),
        body.blue.clone(),
        body.green.clone(),
        strategy,
        body.error_threshold,
    );
    HttpResponse::Created().json(serde_json::json!({"release_id": id}))
}

pub async fn switch_release(
    mgr: web::Data<Arc<ReleaseManager>>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    match mgr.switch(&id) {
        Some(color) => HttpResponse::Ok().json(serde_json::json!({"active": color})),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Release not found"})),
    }
}

// ═══════════════════════════════════════════════════════════════
// DATA PIPELINE
// ═══════════════════════════════════════════════════════════════

use crate::datapipeline::pipeline::DataPipeline;

pub async fn list_watchers(pipeline: web::Data<Arc<DataPipeline>>) -> HttpResponse {
    let watchers = pipeline.list_watchers().await;
    HttpResponse::Ok().json(serde_json::json!({"watchers": watchers}))
}

#[derive(serde::Deserialize)]
pub struct CreateWatcherRequest {
    pub endpoint: String,
    pub webhook_url: String,
}

pub async fn create_watcher(
    pipeline: web::Data<Arc<DataPipeline>>,
    body: web::Json<CreateWatcherRequest>,
) -> HttpResponse {
    let id = pipeline
        .add_watcher(body.endpoint.clone(), body.webhook_url.clone())
        .await;
    HttpResponse::Created().json(serde_json::json!({"watcher_id": id}))
}

pub async fn get_analytics(pipeline: web::Data<Arc<DataPipeline>>) -> HttpResponse {
    let events = pipeline.export().await;
    HttpResponse::Ok().json(serde_json::json!({"events": events, "total": events.len()}))
}

// ═══════════════════════════════════════════════════════════════
// SECURITY (WAF, Bots, Audit)
// ═══════════════════════════════════════════════════════════════

use crate::middleware::audit_log::AuditLogger;
use crate::middleware::bot_detect::BotDetector;
use crate::middleware::waf::Waf;

/// GET /xira/security/waf/rules — runtime custom rule listesi
pub async fn list_waf_rules(waf: web::Data<Arc<Waf>>) -> HttpResponse {
    let rules = waf.list_custom_patterns();
    HttpResponse::Ok().json(serde_json::json!({
        "rules": rules,
        "count": rules.len(),
    }))
}

#[derive(serde::Deserialize)]
pub struct AddWafRuleRequest {
    pub pattern: String,
    #[serde(default)]
    pub label: String,
}

/// POST /xira/security/waf/rules — yeni custom rule ekle (regex doğrulanır)
pub async fn add_waf_rule(
    waf: web::Data<Arc<Waf>>,
    body: web::Json<AddWafRuleRequest>,
) -> HttpResponse {
    match waf.add_custom_pattern(&body.pattern, &body.label) {
        Ok(id) => {
            tracing::warn!(audit = "waf_rule_added", id, label = %body.label, "WAF custom rule added");
            HttpResponse::Created().json(serde_json::json!({"id": id, "label": body.label}))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// DELETE /xira/security/waf/rules/{id} — custom rule sil
pub async fn delete_waf_rule(
    waf: web::Data<Arc<Waf>>,
    path: web::Path<u64>,
) -> HttpResponse {
    let id = path.into_inner();
    if waf.remove_custom_pattern(id) {
        tracing::warn!(audit = "waf_rule_removed", id, "WAF custom rule removed");
        HttpResponse::Ok().json(serde_json::json!({"removed": id}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "rule not found"}))
    }
}

pub async fn get_waf_stats(waf: web::Data<Arc<Waf>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "waf": { "enabled": waf.is_enabled(), "mode": format!("{:?}", waf.mode()) },
    }))
}

pub async fn get_bot_stats(detector: web::Data<Arc<BotDetector>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "bots": detector.stats(),
    }))
}

pub async fn get_audit_log(
    logger: web::Data<Arc<AuditLogger>>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let limit = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let entries = logger.recent(limit);
    let stats = logger.stats();
    HttpResponse::Ok().json(serde_json::json!({"audit_log": entries, "stats": stats}))
}

// ═══════════════════════════════════════════════════════════════
// ADVANCED METRICS + HEALTH SCORING + SLA
// ═══════════════════════════════════════════════════════════════

use crate::gateway::health_scoring::HealthScorer;
use crate::metrics::advanced::AdvancedMetrics;
use crate::metrics::sla::SlaMonitor;

pub async fn get_advanced_metrics(m: web::Data<Arc<AdvancedMetrics>>) -> HttpResponse {
    HttpResponse::Ok().json(m.all_services())
}

pub async fn get_health_scores(scoring: web::Data<Arc<HealthScorer>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"scores": scoring.all_scores()}))
}

// ═══════════════════════════════════════════════════════════════
// OAUTH2 GATEWAY
// ═══════════════════════════════════════════════════════════════

use crate::middleware::oauth2_gateway::{OAuth2Gateway, TokenValidation};

pub async fn oauth2_status(
    gateway: web::Data<Arc<OAuth2Gateway>>,
) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "enabled": gateway.is_enabled(),
        "issuer_url": gateway.issuer_url(),
        "jwks_url": gateway.jwks_url(),
        "cache_size": gateway.cache_size(),
    }))
}

pub async fn oauth2_clear_cache(
    gateway: web::Data<Arc<OAuth2Gateway>>,
) -> HttpResponse {
    gateway.clear_cache();
    HttpResponse::Ok().json(serde_json::json!({"cleared": true}))
}

#[derive(serde::Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

/// POST /xira/oauth2/introspect — token'ı doğrula. Cache'li.
pub async fn oauth2_introspect(
    gateway: web::Data<Arc<OAuth2Gateway>>,
    body: web::Json<IntrospectRequest>,
) -> HttpResponse {
    match gateway.validate_token(&body.token).await {
        TokenValidation::Valid { sub, claims } => HttpResponse::Ok().json(serde_json::json!({
            "active": true,
            "sub": sub,
            "claims": claims,
        })),
        TokenValidation::Invalid { reason } => {
            HttpResponse::Ok().json(serde_json::json!({"active": false, "reason": reason}))
        }
        TokenValidation::Error { reason } => HttpResponse::BadGateway()
            .json(serde_json::json!({"error": "introspection failed", "reason": reason})),
    }
}

// ═══════════════════════════════════════════════════════════════
// SERVICE MESH
// ═══════════════════════════════════════════════════════════════

use crate::discovery::mesh::ServiceMesh;

pub async fn mesh_list(
    mesh: web::Data<Arc<ServiceMesh>>,
) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "enabled": mesh.is_enabled(),
        "services": mesh.list_services(),
        "count": mesh.service_count(),
    }))
}

#[derive(serde::Deserialize)]
pub struct MeshRegisterRequest {
    pub name: String,
    pub sidecar_port: u16,
    #[serde(default)]
    pub mtls: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub async fn mesh_register(
    mesh: web::Data<Arc<ServiceMesh>>,
    body: web::Json<MeshRegisterRequest>,
) -> HttpResponse {
    mesh.register_service(body.name.clone(), body.sidecar_port, body.mtls, body.tags.clone());
    HttpResponse::Created().json(serde_json::json!({"registered": body.name}))
}

pub async fn get_sla_report(sla: web::Data<Arc<SlaMonitor>>) -> HttpResponse {
    let metrics = sla.all_metrics();
    let violations = sla.check_violations();
    HttpResponse::Ok().json(serde_json::json!({"sla": metrics, "violations": violations}))
}
