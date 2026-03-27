use crate::registry::{models::ServiceStatus, ServiceRegistry};
use crate::alerting::AlertManager;
use crate::observability::uptime::{UptimePage, ServiceStatus as UptimeStatus};
use crate::observability::incidents::{IncidentManager, Severity};
use crate::metrics::sla::SlaMonitor;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Periyodik health check worker (alerting + uptime + incidents + SLA entegrasyonu)
pub async fn start_health_checker(
    registry: ServiceRegistry,
    alert_manager: AlertManager,
    interval_secs: u64,
    timeout_secs: u64,
    // v2.0 cross-domain feeds
    uptime_page: Arc<tokio::sync::RwLock<UptimePage>>,
    incident_manager: Arc<IncidentManager>,
    sla_monitor: Arc<SlaMonitor>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .expect("Failed to create health-check HTTP client");

    let mut interval = time::interval(Duration::from_secs(interval_secs));

    tracing::info!(
        "Health checker started (interval: {}s, timeout: {}s)",
        interval_secs, timeout_secs
    );

    loop {
        interval.tick().await;

        let services = registry.list_all();
        if services.is_empty() {
            continue;
        }

        // Prometheus gauge güncelle
        let up_count = registry.count_by_status(&ServiceStatus::Up);
        let down_count = registry.count_by_status(&ServiceStatus::Down);
        crate::metrics::update_service_gauges(services.len(), up_count, down_count);

        for service in &services {
            let health_url = format!("{}{}", service.upstream, service.health_endpoint);

            // Health check with retry (3 attempts)
            let max_retries = 3u8;
            let mut last_status = ServiceStatus::Down;
            let mut last_msg = String::new();
            let check_start = std::time::Instant::now();

            for attempt in 1..=max_retries {
                let result = client.get(&health_url).send().await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        last_status = ServiceStatus::Up;
                        last_msg = format!("{}: UP", service.name);
                        break;
                    }
                    Ok(resp) => {
                        last_status = ServiceStatus::Down;
                        last_msg = format!("{}: DOWN (HTTP {})", service.name, resp.status());
                    }
                    Err(e) => {
                        last_status = ServiceStatus::Down;
                        last_msg = format!("{}: DOWN (error sending request for url ({}))", service.name, health_url);
                        let _ = e;
                    }
                }

                if attempt < max_retries {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }

            let check_latency_ms = check_start.elapsed().as_secs_f64() * 1000.0;
            let (new_status, log_msg) = (last_status, last_msg);
            let is_up = new_status == ServiceStatus::Up;

            // ═══ [UPTIME PAGE] Feed health result ═══
            {
                let uptime_status = if is_up { UptimeStatus::Operational } else { UptimeStatus::MajorOutage };
                let page = uptime_page.read().await;
                page.update(&service.name, uptime_status, check_latency_ms);
            }

            // ═══ [SLA MONITOR] Record health check ═══
            sla_monitor.record_check(&service.name, is_up, check_latency_ms);

            // Durum değiştiyse log + alert + incident
            if service.status != new_status {
                match new_status {
                    ServiceStatus::Up => {
                        tracing::info!("🟢 {}", log_msg);
                        alert_manager.alert_service_up(&service.name, &service.id.to_string()).await;
                    }
                    ServiceStatus::Down => {
                        tracing::warn!("🔴 {}", log_msg);
                        alert_manager.alert_service_down(
                            &service.name,
                            &service.id.to_string(),
                            &log_msg,
                        ).await;

                        // ═══ [INCIDENT] Auto-create incident on service down ═══
                        incident_manager.create(
                            format!("Service Down: {}", service.name),
                            Severity::Major,
                            vec![service.name.clone()],
                        ).await;
                    }
                    ServiceStatus::Unknown => {
                        tracing::debug!("⚪ {}", log_msg);
                    }
                }

                // Event kaydet (SQLite)
                if let Some(storage) = registry.storage() {
                    let _ = storage.log_event(
                        &format!("health_{}", new_status.to_string().to_lowercase()),
                        Some(&service.id.to_string()),
                        Some(&service.name),
                        &log_msg,
                    );
                }
            }

            registry.update_status(&service.id, new_status);
        }
    }
}
