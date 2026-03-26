/// CORS per-Service — servis bazlı CORS policies
use dashmap::DashMap;

pub struct CorsManager {
    policies: DashMap<String, CorsPolicy>,
    default_policy: CorsPolicy,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CorsPolicy {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: u64,
    pub allow_credentials: bool,
}

impl Default for CorsPolicy {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".into(), "POST".into(), "PUT".into(), "DELETE".into(), "OPTIONS".into()],
            allowed_headers: vec!["Content-Type".into(), "Authorization".into(), "X-Api-Key".into()],
            expose_headers: vec!["X-Request-Id".into(), "X-Response-Time".into()],
            max_age: 86400,
            allow_credentials: false,
        }
    }
}

impl CorsManager {
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
            default_policy: CorsPolicy::default(),
        }
    }

    /// Servis bazlı CORS policy ayarla
    pub fn set_policy(&self, service_prefix: &str, policy: CorsPolicy) {
        self.policies.insert(service_prefix.to_string(), policy);
    }

    /// Servis prefix'ine göre policy getir
    pub fn get_policy(&self, path: &str) -> CorsPolicy {
        for entry in self.policies.iter() {
            if path.starts_with(entry.key().as_str()) {
                return entry.value().clone();
            }
        }
        self.default_policy.clone()
    }

    /// CORS header'larını oluştur
    pub fn build_headers(&self, path: &str, origin: Option<&str>) -> Vec<(String, String)> {
        let policy = self.get_policy(path);
        let mut headers = Vec::new();

        // Origin check
        let origin = origin.unwrap_or("*");
        let allow_origin = if policy.allowed_origins.contains(&"*".to_string()) {
            "*".to_string()
        } else if policy.allowed_origins.iter().any(|o| o == origin) {
            origin.to_string()
        } else {
            return headers; // Origin izin verilmedi
        };

        headers.push(("Access-Control-Allow-Origin".into(), allow_origin));
        headers.push(("Access-Control-Allow-Methods".into(), policy.allowed_methods.join(", ")));
        headers.push(("Access-Control-Allow-Headers".into(), policy.allowed_headers.join(", ")));
        headers.push(("Access-Control-Expose-Headers".into(), policy.expose_headers.join(", ")));
        headers.push(("Access-Control-Max-Age".into(), policy.max_age.to_string()));

        if policy.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }

        headers
    }

    pub fn list_policies(&self) -> Vec<(String, CorsPolicy)> {
        self.policies.iter().map(|e| (e.key().clone(), e.value().clone())).collect()
    }
}
