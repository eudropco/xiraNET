pub mod mesh;

use crate::registry::models::ServiceEntry;
use crate::registry::ServiceRegistry;
use std::sync::Arc;
use std::time::Duration;

/// Service discovery backend tipi
#[derive(Debug, Clone)]
pub enum DiscoveryBackend {
    /// Consul HTTP API polling
    Consul {
        url: String,
        datacenter: Option<String>,
    },
    /// DNS SRV record çözümleme
    Dns { domain: String },
    /// Static (config-only, discovery yok)
    Static,
}

/// Consul service response — sadece kullandığımız alanları deserialize ediyoruz.
/// Extra JSON field'ları serde tarafından sessizce ignore edilir.
#[derive(serde::Deserialize)]
struct ConsulService {
    #[serde(rename = "ServiceAddress")]
    service_address: String,
    #[serde(rename = "ServicePort")]
    service_port: u16,
}

/// Service discovery daemon
pub async fn start_discovery(
    registry: Arc<ServiceRegistry>,
    backend: DiscoveryBackend,
    interval_secs: u64,
) {
    let interval = Duration::from_secs(interval_secs);
    let client = reqwest::Client::new();

    tracing::info!(
        "Service discovery started: {:?} (interval: {}s)",
        backend,
        interval_secs
    );

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
        format!("{consul_url}/v1/catalog/services?dc={dc}")
    } else {
        format!("{consul_url}/v1/catalog/services")
    };

    let services_map = match client.get(&url).send().await {
        Ok(resp) => match resp
            .json::<std::collections::HashMap<String, Vec<String>>>()
            .await
        {
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
        let detail_url = format!("{consul_url}/v1/catalog/service/{service_name}");
        if let Ok(resp) = client.get(&detail_url).send().await {
            if let Ok(instances) = resp.json::<Vec<ConsulService>>().await {
                if let Some(instance) = instances.first() {
                    let prefix = format!("/{service_name}");
                    let upstream = format!(
                        "http://{}:{}",
                        instance.service_address, instance.service_port
                    );

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
                            service_name,
                            upstream,
                            tags
                        );

                        // Register with multiple instances as upstreams
                        let upstreams: Vec<String> = instances
                            .iter()
                            .map(|i| format!("http://{}:{}", i.service_address, i.service_port))
                            .collect();

                        let registered = registry.register(
                            service_name.clone(),
                            prefix.clone(),
                            upstream,
                            "/health".to_string(),
                        );

                        // Additional upstreams: register sonrası registry'deki ID
                        // üzerinden gerçek mutation yap. Eski kod `find_by_prefix`'ten
                        // dönen owned ServiceEntry'yi mutate ediyordu — sessizce kayboluyordu.
                        if upstreams.len() > 1 {
                            registry.set_upstreams(&registered.id, upstreams[1..].to_vec());
                        }
                    }
                }
            }
        }
    }
}

/// DNS SRV record'dan servisleri keşfet — hickory-resolver kullanır.
///
/// Format: `_<service>._tcp.<domain>` SRV kaydı taranır. Her hedef için
/// ayrı bir prefix (`/<service>`) altında upstream'ler register edilir.
async fn discover_dns(registry: &ServiceRegistry, domain: &str) {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // domain örneği: "services.example.com" — bu durumda biz alt servisleri keşfetmek için
    // _<service>._tcp.<domain> SRV kaydını tarayamayız çünkü servis isimlerini bilmiyoruz.
    // Pragmatik yaklaşım: domain bizzat tek servis olarak kabul edilir; "service.tcp.domain"
    // formatı kullanıcıya bırakılır. Kullanıcı her servis için ayrı discovery girişi açar.
    //
    // İleri sürüm: TXT kaydından servis listesi okuyup _<svc>._tcp.<domain> taraması.
    let lookup = match resolver.srv_lookup(domain).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, domain = %domain, "DNS SRV lookup failed");
            return;
        }
    };

    let mut targets: Vec<(String, u16)> = Vec::new();
    for rec in lookup.iter() {
        let target = rec.target().to_string();
        let port = rec.port();
        targets.push((target.trim_end_matches('.').to_string(), port));
    }

    if targets.is_empty() {
        tracing::debug!(domain = %domain, "DNS SRV: no records");
        return;
    }

    // Servis ismi: domain'in ilk segmenti (ör. "_api._tcp.example.com" → "api").
    let service_name = domain
        .trim_start_matches('_')
        .split('.')
        .next()
        .unwrap_or("dns-svc")
        .to_string();
    let prefix = format!("/{service_name}");

    let upstreams: Vec<String> = targets
        .iter()
        .map(|(host, port)| format!("http://{host}:{port}"))
        .collect();

    if registry.find_by_prefix(&prefix).is_none() {
        let primary = upstreams.first().cloned().unwrap_or_default();
        let entry = registry.register(
            service_name.clone(),
            prefix.clone(),
            primary,
            "/health".to_string(),
        );
        if upstreams.len() > 1 {
            registry.set_upstreams(&entry.id, upstreams[1..].to_vec());
        }
        tracing::info!(
            "Discovered service via DNS SRV: {} → {} target(s)",
            service_name,
            upstreams.len()
        );
    }
}
