/// WebSocket Live Metrics — push real-time metrics to connected clients
use actix_web::{HttpRequest, HttpResponse, web};
use std::sync::Arc;
use crate::metrics::advanced::AdvancedMetrics;
use crate::gateway::health_scoring::HealthScorer;
use crate::metrics::sla::SlaMonitor;
use crate::registry::ServiceRegistry;

/// WebSocket metrics endpoint handler
/// GET /ws/metrics → real-time metrics push every 2 seconds
pub async fn ws_metrics_handler(
    req: HttpRequest,
    stream: web::Payload,
    registry: web::Data<Arc<ServiceRegistry>>,
    metrics: web::Data<Arc<AdvancedMetrics>>,
    health_scorer: web::Data<Arc<HealthScorer>>,
    sla_monitor: web::Data<Arc<SlaMonitor>>,
) -> Result<HttpResponse, actix_web::Error> {
    let (response, mut session, _msg_stream) = actix_ws::handle(&req, stream)?;

    let registry = registry.get_ref().clone();
    let metrics = metrics.get_ref().clone();
    let health_scorer = health_scorer.get_ref().clone();
    let sla_monitor = sla_monitor.get_ref().clone();

    actix_rt::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

        loop {
            interval.tick().await;

            let services = registry.list_all();
            let all_metrics = metrics.all_services();
            let health_scores = health_scorer.all_scores();
            let sla_report = sla_monitor.all_metrics();

            let payload = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "services_count": services.len(),
                "metrics": all_metrics,
                "health_scores": health_scores.iter().map(|s| serde_json::json!({
                    "upstream": s.upstream,
                    "score": s.score,
                    "avg_latency_ms": s.avg_latency_ms,
                    "error_rate": s.error_rate,
                })).collect::<Vec<_>>(),
                "sla": sla_report.iter().map(|m| serde_json::json!({
                    "service": m.service_name,
                    "uptime": m.uptime_percent,
                    "total_checks": m.total_checks,
                })).collect::<Vec<_>>(),
            });

            if session.text(payload.to_string()).await.is_err() {
                break; // Client disconnected
            }
        }
    });

    Ok(response)
}
