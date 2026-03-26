/// Service Mesh Mode — sidecar pattern stubs + service-to-service mTLS registry
use dashmap::DashMap;

pub struct ServiceMesh {
    enabled: bool,
    mesh_services: DashMap<String, MeshService>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MeshService {
    pub name: String,
    pub sidecar_port: u16,
    pub mtls_enabled: bool,
    pub retry_policy: RetryPolicy,
    pub circuit_breaker: bool,
    pub load_balance: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub per_try_timeout_ms: u64,
    pub retry_on: Vec<String>, // "5xx", "reset", "connect-failure"
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            per_try_timeout_ms: 5000,
            retry_on: vec!["5xx".to_string(), "connect-failure".to_string()],
        }
    }
}

impl ServiceMesh {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            mesh_services: DashMap::new(),
        }
    }

    /// Servis mesh'e kaydet
    pub fn register_service(&self, name: String, sidecar_port: u16, mtls: bool, tags: Vec<String>) {
        let service = MeshService {
            name: name.clone(),
            sidecar_port,
            mtls_enabled: mtls,
            retry_policy: RetryPolicy::default(),
            circuit_breaker: true,
            load_balance: "round-robin".to_string(),
            tags,
        };
        self.mesh_services.insert(name, service);
    }

    /// Servis mesh'ten lookup
    pub fn resolve(&self, name: &str) -> Option<MeshService> {
        self.mesh_services.get(name).map(|e| e.value().clone())
    }

    /// Tüm mesh servisleri
    pub fn list_services(&self) -> Vec<MeshService> {
        self.mesh_services.iter().map(|e| e.value().clone()).collect()
    }

    /// Mesh'ten kaldır
    pub fn deregister(&self, name: &str) -> bool {
        self.mesh_services.remove(name).is_some()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn service_count(&self) -> usize {
        self.mesh_services.len()
    }
}

/// Docker container label'larından servis keşfi
pub struct DockerDiscovery {
    pub docker_socket: String,
    pub label_prefix: String,
}

impl DockerDiscovery {
    pub fn new(socket: String) -> Self {
        Self {
            docker_socket: socket,
            label_prefix: "xiranet.".to_string(),
        }
    }

    /// Docker API'den container listesi al ve label'ları parse et
    pub async fn discover(&self) -> Vec<DiscoveredService> {
        let url = format!("{}/containers/json?filters={{\"status\":[\"running\"]}}", self.docker_socket);

        let client = reqwest::Client::new();
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(containers) = resp.json::<Vec<serde_json::Value>>().await {
                    return containers.iter().filter_map(|c| {
                        let labels = c.get("Labels")?.as_object()?;
                        let name = labels.get("xiranet.service.name")?.as_str()?;
                        let prefix = labels.get("xiranet.service.prefix")?.as_str()?;
                        let port = labels.get("xiranet.service.port")?.as_str()?.parse::<u16>().ok()?;

                        // Container IP'sini al
                        let networks = c.get("NetworkSettings")?.get("Networks")?.as_object()?;
                        let ip = networks.values().next()?
                            .get("IPAddress")?.as_str()?;

                        Some(DiscoveredService {
                            name: name.to_string(),
                            prefix: prefix.to_string(),
                            upstream: format!("http://{}:{}", ip, port),
                            health_endpoint: labels.get("xiranet.service.health")
                                .and_then(|h| h.as_str())
                                .unwrap_or("/health")
                                .to_string(),
                        })
                    }).collect();
                }
                vec![]
            }
            Err(e) => {
                tracing::warn!("Docker discovery failed: {}", e);
                vec![]
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub name: String,
    pub prefix: String,
    pub upstream: String,
    pub health_endpoint: String,
}
