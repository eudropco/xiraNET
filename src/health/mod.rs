use crate::registry::{models::ServiceStatus, ServiceRegistry};
use crate::alerting::AlertManager;
use std::time::Duration;
use tokio::time;

/// Periyodik health check worker (alerting entegrasyonu ile)
pub async fn start_health_checker(
    registry: ServiceRegistry,
    alert_manager: AlertManager,
    interval_secs: u64,
    timeout_secs: u64,
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

            for attempt in 1..=max_retries {
                let result = client.get(&health_url).send().await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        last_status = ServiceStatus::Up;
                        last_msg = format!("{}: UP", service.name);
                        break; // Başarılı, retry gerekmez
                    }
                    Ok(resp) => {
                        last_status = ServiceStatus::Down;
                        last_msg = format!("{}: DOWN (HTTP {})", service.name, resp.status());
                    }
                    Err(e) => {
                        last_status = ServiceStatus::Down;
                        last_msg = format!("{}: DOWN (error sending request for url ({}))", service.name, health_url);
                        let _ = e; // suppress unused
                    }
                }

                if attempt < max_retries {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }

            let (new_status, log_msg) = (last_status, last_msg);

            // Durum değiştiyse log + alert
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
