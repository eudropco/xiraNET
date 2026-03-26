use crate::registry::ServiceRegistry;
use crate::registry::models::ServiceEntry;
use std::sync::Arc;
use std::time::Duration;

/// Service discovery backend tipi
#[derive(Debug, Clone)]
pub enum DiscoveryBackend {
    /// Consul HTTP API polling
    Consul { url: String, datacenter: Option<String> },
    /// DNS SRV record çözümleme
    Dns { domain: String },
    /// Static (config-only, discovery yok)
    Static,
}

/// Consul service response
#[derive(serde::Deserialize)]
struct ConsulService {
    #[serde(rename = "ServiceName")]
    service_name: String,
    #[serde(rename = "ServiceAddress")]
    service_address: String,
    #[serde(rename = "ServicePort")]
    service_port: u16,
    #[serde(rename = "ServiceTags")]
    service_tags: Vec<String>,
}

/// Service discovery daemon
pub async fn start_discovery(
    registry: Arc<ServiceRegistry>,
    backend: DiscoveryBackend,
    interval_secs: u64,
) {
    let interval = Duration::from_secs(interval_secs);
    let client = reqwest::Client::new();

    tracing::info!("Service discovery started: {:?} (interval: {}s)", backend, interval_secs);

    loop {
        match &backend {
            DiscoveryBackend::Consul { url, datacenter } => {
                discover_consul(&client, &registry, url, datacenter.as_deref()).await;
            }
            DiscoveryBackend::Dns { domain } => {
                discover_dns(&registry, domain).await;
            }
            DiscoveryBackend::Static => {
                // Static backend — no discovery
            }
        }

        tokio::time::sleep(interval).await;
    }
}

/// Consul'dan servisleri keşfet
async fn discover_consul(
    client: &reqwest::Client,
    registry: &ServiceRegistry,
    consul_url: &str,
    datacenter: Option<&str>,
) {
    let url = if let Some(dc) = datacenter {
        format!("{}/v1/catalog/services?dc={}", consul_url, dc)
    } else {
        format!("{}/v1/catalog/services", consul_url)
    };

    let services_map = match client.get(&url).send().await {
        Ok(resp) => match resp.json::<std::collections::HashMap<String, Vec<String>>>().await {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!("Consul parse error: {}", e);
                return;
            }
        },
        Err(e) => {
            tracing::warn!("Consul connection failed: {}", e);
            return;
        }
    };

    for (service_name, tags) in &services_map {
        if service_name == "consul" {
            continue; // Skip consul itself
        }

        // Servis detaylarını al
        let detail_url = format!("{}/v1/catalog/service/{}", consul_url, service_name);
        if let Ok(resp) = client.get(&detail_url).send().await {
            if let Ok(instances) = resp.json::<Vec<ConsulService>>().await {
                if let Some(instance) = instances.first() {
                    let prefix = format!("/{}", service_name);
                    let upstream = format!("http://{}:{}", instance.service_address, instance.service_port);

                    // Zaten kayıtlı mı?
                    if registry.find_by_prefix(&prefix).is_none() {
                        let _entry = ServiceEntry::new(
                            service_name.clone(),
                            prefix.clone(),
                            upstream.clone(),
                            "/health".to_string(),
                        );

                        tracing::info!(
                            "Discovered service via Consul: {} → {} (tags: {:?})",
                            service_name, upstream, tags
                        );

                        // Register with multiple instances as upstreams
                        let upstreams: Vec<String> = instances.iter()
                            .map(|i| format!("http://{}:{}", i.service_address, i.service_port))
                            .collect();

                        registry.register(
                            service_name.clone(),
                            prefix,
                            upstream,
                            "/health".to_string(),
                        );

                        // Additional upstreams ekle
                        if upstreams.len() > 1 {
                            if let Some(mut svc) = registry.find_by_prefix(&format!("/{}", service_name)) {
                                svc.upstreams = upstreams[1..].to_vec();
                            }
                        }
                    }
                }
            }
        }
    }
}

/// DNS SRV record'dan servisleri keşfet
async fn discover_dns(registry: &ServiceRegistry, domain: &str) {
    // DNS SRV lookup — tokio'nun resolver'ını kullan
    tracing::debug!("DNS discovery for domain: {}", domain);

    // DNS SRV resolution would typically use trust-dns or hickory-dns
    // For now, log that DNS discovery is configured
    tracing::info!("DNS SRV discovery configured for: {} (requires trust-dns for full implementation)", domain);
}
