/// v2.1.0 Admin API Handlers — all domain endpoints
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════
// IDENTITY — Typed Request DTOs
// ═══════════════════════════════════════════════════════════════

use crate::identity::users::UserManager;
use crate::identity::sessions::SessionManager;
use crate::config::XiraConfig;

#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}
fn default_role() -> String { "Viewer".to_string() }

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
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Registration is disabled"}));
    }

    // Enforce password_min_length
    if body.password.len() < cfg.identity.password_min_length {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Password must be at least {} characters", cfg.identity.password_min_length)
        }));
    }

    // Validate required fields
    if body.email.is_empty() || body.username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "email and username are required"}));
    }

    let role = match body.role.as_str() {
        "SuperAdmin" => crate::identity::users::UserRole::SuperAdmin,
        "Admin" => crate::identity::users::UserRole::Admin,
        "Developer" => crate::identity::users::UserRole::Developer,
        "Service" => crate::identity::users::UserRole::Service,
        _ => crate::identity::users::UserRole::Viewer,
    };

    match mgr.register(body.email.clone(), body.username.clone(), &body.password, role) {
        Ok(user) => HttpResponse::Created().json(serde_json::json!({
            "id": user.id, "email": user.email, "username": user.username,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

pub async fn login_user(
    mgr: web::Data<Arc<UserManager>>,
    sessions: web::Data<Arc<SessionManager>>,
    req: HttpRequest,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    if body.email.is_empty() || body.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "email and password are required"}));
    }

    let ip = req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let ua = req.headers().get("user-agent")
        .and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();

    match mgr.authenticate(&body.email, &body.password) {
        crate::identity::users::AuthResult::Success { user, token } => {
            let session = sessions.create(&user.id, &token, &ip, &ua, 86400);
            HttpResponse::Ok().json(serde_json::json!({
                "token": session.token, "user_id": user.id,
                "expires_at": session.expires_at,
            }))
        }
        crate::identity::users::AuthResult::MfaRequired { user_id } => {
            HttpResponse::Ok().json(serde_json::json!({"mfa_required": true, "user_id": user_id}))
        }
        crate::identity::users::AuthResult::AccountDisabled => {
            HttpResponse::Forbidden().json(serde_json::json!({"error": "Account disabled"}))
        }
        _ => HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"})),
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

// ═══════════════════════════════════════════════════════════════
// AUTOMATION
// ═══════════════════════════════════════════════════════════════

use crate::automation::cron::CronScheduler;
use crate::automation::event_bus::EventBus;

pub async fn list_cron_jobs(scheduler: web::Data<Arc<CronScheduler>>) -> HttpResponse {
    let jobs = scheduler.list_jobs().await;
    HttpResponse::Ok().json(serde_json::json!({"jobs": jobs, "total": jobs.len()}))
}

pub async fn create_cron_job(
    scheduler: web::Data<Arc<CronScheduler>>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string();
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
    let interval = body.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(60);

    let schedule = crate::automation::cron::CronSchedule::EverySeconds(interval);
    let id = scheduler.add_job(name, schedule, url, method).await;
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

pub async fn list_workflows(engine: web::Data<Arc<crate::automation::workflows::WorkflowEngine>>) -> HttpResponse {
    let wfs = engine.list().await;
    HttpResponse::Ok().json(serde_json::json!({"workflows": wfs, "total": wfs.len()}))
}

pub async fn list_events(bus: web::Data<Arc<EventBus>>) -> HttpResponse {
    let events = bus.recent_events(100).await;
    let stats = bus.stats().await;
    HttpResponse::Ok().json(serde_json::json!({"events": events, "stats": stats}))
}

pub async fn publish_event(
    bus: web::Data<Arc<EventBus>>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let topic = body.get("topic").and_then(|v| v.as_str()).unwrap_or("default").to_string();
    let source = body.get("source").and_then(|v| v.as_str()).unwrap_or("api").to_string();
    let data = body.get("data").cloned().unwrap_or(serde_json::json!({}));

    let id = bus.publish(&topic, &source, data).await;
    HttpResponse::Created().json(serde_json::json!({"event_id": id}))
}

// ═══════════════════════════════════════════════════════════════
// OBSERVABILITY
// ═══════════════════════════════════════════════════════════════

use crate::observability::log_aggregator::LogAggregator;
use crate::observability::uptime::UptimePage;
use crate::observability::incidents::IncidentManager;

pub async fn search_logs(
    agg: web::Data<Arc<LogAggregator>>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let limit = query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(50);

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

pub async fn create_incident(
    mgr: web::Data<Arc<IncidentManager>>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled").to_string();
    let severity = match body.get("severity").and_then(|v| v.as_str()).unwrap_or("Minor") {
        "Critical" => crate::observability::incidents::Severity::Critical,
        "Major" => crate::observability::incidents::Severity::Major,
        "Info" => crate::observability::incidents::Severity::Info,
        _ => crate::observability::incidents::Severity::Minor,
    };
    let services: Vec<String> = body.get("services")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let id = mgr.create(title, severity, services).await;
    HttpResponse::Created().json(serde_json::json!({"incident_id": id}))
}

pub async fn update_incident(
    mgr: web::Data<Arc<IncidentManager>>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let id = path.into_inner();
    let message = body.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let author = body.get("author").and_then(|v| v.as_str()).unwrap_or("admin").to_string();

    if let Some(status) = body.get("status").and_then(|v| v.as_str()) {
        let s = match status {
            "Identified" => crate::observability::incidents::IncidentStatus::Identified,
            "Monitoring" => crate::observability::incidents::IncidentStatus::Monitoring,
            "Resolved" => crate::observability::incidents::IncidentStatus::Resolved,
            _ => crate::observability::incidents::IncidentStatus::Investigating,
        };
        mgr.update_status(&id, s).await;
    }

    if !message.is_empty() {
        mgr.add_update(&id, message, author).await;
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

pub async fn create_flag(
    mgr: web::Data<Arc<FeatureFlagManager>>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let desc = body.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let pct = body.get("percentage").and_then(|v| v.as_u64()).unwrap_or(100) as u32;

    mgr.create(name.clone(), desc, enabled, pct);
    HttpResponse::Created().json(serde_json::json!({"created": name}))
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

pub async fn create_release(
    mgr: web::Data<Arc<ReleaseManager>>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let service = body.get("service").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let blue = body.get("blue").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let green = body.get("green").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let threshold = body.get("error_threshold").and_then(|v| v.as_f64()).unwrap_or(0.1);

    let strategy = crate::deployment::releases::ReleaseStrategy::BlueGreen;
    let id = mgr.create(service, blue, green, strategy, threshold);
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

pub async fn create_watcher(
    pipeline: web::Data<Arc<DataPipeline>>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let endpoint = body.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let webhook = body.get("webhook_url").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let id = pipeline.add_watcher(endpoint, webhook).await;
    HttpResponse::Created().json(serde_json::json!({"watcher_id": id}))
}

pub async fn get_analytics(pipeline: web::Data<Arc<DataPipeline>>) -> HttpResponse {
    let events = pipeline.export().await;
    HttpResponse::Ok().json(serde_json::json!({"events": events, "total": events.len()}))
}

// ═══════════════════════════════════════════════════════════════
// SECURITY (WAF, Bots, Audit)
// ═══════════════════════════════════════════════════════════════

use crate::middleware::waf::Waf;
use crate::middleware::bot_detect::BotDetector;
use crate::middleware::audit_log::AuditLogger;

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
    let limit = query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100);
    let entries = logger.recent(limit);
    let stats = logger.stats();
    HttpResponse::Ok().json(serde_json::json!({"audit_log": entries, "stats": stats}))
}

// ═══════════════════════════════════════════════════════════════
// ADVANCED METRICS + HEALTH SCORING + SLA
// ═══════════════════════════════════════════════════════════════

use crate::metrics::advanced::AdvancedMetrics;
use crate::gateway::health_scoring::HealthScorer;
use crate::metrics::sla::SlaMonitor;

pub async fn get_advanced_metrics(m: web::Data<Arc<AdvancedMetrics>>) -> HttpResponse {
    HttpResponse::Ok().json(m.all_services())
}

pub async fn get_health_scores(scoring: web::Data<Arc<HealthScorer>>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"scores": scoring.all_scores()}))
}

pub async fn get_sla_report(sla: web::Data<Arc<SlaMonitor>>) -> HttpResponse {
    let metrics = sla.all_metrics();
    let violations = sla.check_violations();
    HttpResponse::Ok().json(serde_json::json!({"sla": metrics, "violations": violations}))
}
