use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
pub struct XiraConfig {
    pub gateway: GatewayConfig,
    pub admin: AdminConfig,
    pub health: HealthConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub alerting: AlertingConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub oauth2: OAuth2Config,
    #[serde(default)]
    pub ip_filter: IpFilterConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub retry: RetryConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
    #[serde(default)]
    pub grpc: GrpcConfig,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    // v2.1.0 domain configs
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub bot_detection: BotDetectionConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub bus: BusConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BusConfig {
    /// Multi-node coordination bus. "noop" (default, single-node) veya "redis".
    #[serde(default = "default_bus_backend")]
    pub backend: String,
    /// `redis://host:port[/db]` URL'i. backend="redis" iken zorunlu.
    #[serde(default)]
    pub redis_url: String,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            backend: default_bus_backend(),
            redis_url: String::new(),
        }
    }
}

fn default_bus_backend() -> String {
    "noop".to_string()
}

#[derive(Debug, Clone, Deserialize, Default, Serialize)]
pub struct AuditConfig {
    /// JSON Lines append-only sink. Boş bırakılırsa file sink devre dışı.
    #[serde(default)]
    pub file_path: Option<String>,
    /// HTTP webhook sink — uzak SIEM/log aggregator. Boş ise devre dışı.
    /// SSRF guard her durumda uygulanır.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Webhook isteklerinde ek header'lar (örn. Bearer auth).
    #[serde(default)]
    pub webhook_headers: std::collections::HashMap<String, String>,
    /// Sink buffer kapasitesi. Doluysa eski entry'ler DROP edilir.
    #[serde(default = "default_audit_buffer")]
    pub buffer_size: usize,
}

fn default_audit_buffer() -> usize {
    10_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsConfig {
    /// Açıkça izin verilen origin listesi. Boş bırakılırsa origin matching devre dışı —
    /// kayıp güvenliği için varsayılan localhost dev origin'leri.
    #[serde(default = "default_cors_origins")]
    pub allowed_origins: Vec<String>,
    /// Cookie/credentials taşıma — sadece explicit origin listesiyle birlikte.
    #[serde(default)]
    pub allow_credentials: bool,
    /// Cache süresi (saniye).
    #[serde(default = "default_cors_max_age")]
    pub max_age: usize,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_cors_origins(),
            allow_credentials: false,
            max_age: default_cors_max_age(),
        }
    }
}

fn default_cors_origins() -> Vec<String> {
    vec![
        "http://localhost".to_string(),
        "http://127.0.0.1".to_string(),
    ]
}
fn default_cors_max_age() -> usize {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_workers")]
    pub workers: usize,
}

fn default_workers() -> usize {
    4
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub api_key: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    pub interval_secs: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub mtls_enabled: bool,
    #[serde(default)]
    pub client_ca_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_true() -> bool {
    true
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LoggingConfig {
    #[serde(default)]
    pub file_enabled: bool,
    #[serde(default = "default_log_path")]
    pub file_path: String,
    #[serde(default = "default_log_rotation")]
    pub rotation: String,
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_path() -> String {
    "logs/xiranet.log".to_string()
}
fn default_log_rotation() -> String {
    "daily".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AlertingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub on_service_down: bool,
    #[serde(default)]
    pub on_service_up: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit")]
    pub max_requests: u32,
    #[serde(default = "default_rate_window")]
    pub window_secs: u64,
    /// Per-route overrides: path prefix → max requests per window
    #[serde(default)]
    pub routes: std::collections::HashMap<String, u32>,
    /// Reverse proxy/LB arkasındaysa X-Forwarded-For ilk hop'unu client IP
    /// say. Doğrudan public exposure'da AÇILMAZ — XFF spoof'lanabilir.
    #[serde(default)]
    pub trust_xff: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 60,
            routes: std::collections::HashMap::new(),
            trust_xff: false,
        }
    }
}

fn default_rate_limit() -> u32 {
    100
}
fn default_rate_window() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,
    #[serde(default = "default_cache_capacity")]
    pub max_entries: usize,
}

fn default_cache_ttl() -> u64 {
    300
}
fn default_cache_capacity() -> usize {
    1000
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct JwtConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_jwt_algo")]
    pub algorithm: String,
    #[serde(default)]
    pub issuer: Option<String>,
}

fn default_jwt_algo() -> String {
    "HS256".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OAuth2Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer_url: String,
    #[serde(default)]
    pub introspection_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct IpFilterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_cb_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_cb_timeout")]
    pub reset_timeout_secs: u64,
    #[serde(default = "default_cb_half_open")]
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout_secs: 30,
            half_open_max_requests: 3,
        }
    }
}

fn default_cb_threshold() -> u32 {
    5
}
fn default_cb_timeout() -> u64 {
    30
}
fn default_cb_half_open() -> u32 {
    3
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_retry_max")]
    pub max_retries: u32,
    #[serde(default = "default_retry_delay")]
    pub delay_ms: u64,
    #[serde(default = "default_retry_multiplier")]
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            delay_ms: 100,
            backoff_multiplier: 2.0,
        }
    }
}

fn default_retry_max() -> u32 {
    3
}
fn default_retry_delay() -> u64 {
    100
}
fn default_retry_multiplier() -> f64 {
    2.0
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PluginConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_plugin_dir")]
    pub directory: String,
}

fn default_plugin_dir() -> String {
    "plugins".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GrpcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_grpc_port")]
    pub port: u16,
}

fn default_grpc_port() -> u16 {
    9001
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DiscoveryConfig {
    #[serde(default)]
    pub enabled: bool,
    /// "consul", "dns", "static"
    #[serde(default = "default_discovery_backend")]
    pub backend: String,
    #[serde(default)]
    pub consul_url: Option<String>,
    #[serde(default)]
    pub consul_datacenter: Option<String>,
    #[serde(default)]
    pub dns_domain: Option<String>,
    #[serde(default = "default_discovery_interval")]
    pub interval_secs: u64,
    /// Service mesh sidecar koordinasyonu (deneysel)
    #[serde(default)]
    pub mesh_enabled: bool,
    /// Docker label-based discovery
    #[serde(default)]
    pub docker_enabled: bool,
    #[serde(default = "default_docker_socket")]
    pub docker_socket: String,
}

fn default_docker_socket() -> String {
    "http://localhost:2375".to_string()
}

fn default_discovery_backend() -> String {
    "static".to_string()
}
fn default_discovery_interval() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RedisConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otel_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

fn default_otel_endpoint() -> String {
    "http://localhost:4317".to_string()
}
fn default_service_name() -> String {
    "xiranet".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// "block" or "detect_only"
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    #[serde(default)]
    pub custom_block_patterns: Vec<String>,
}
impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "block".into(),
            custom_block_patterns: vec![],
        }
    }
}
fn default_waf_mode() -> String {
    "block".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct BotDetectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub block_bots: bool,
    #[serde(default = "default_crawl_rate")]
    pub crawl_rate_limit: u32,
}
impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_bots: false,
            crawl_rate_limit: 60,
        }
    }
}
fn default_crawl_rate() -> u32 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    #[serde(default = "default_max_sessions")]
    pub max_sessions_per_user: usize,
    #[serde(default = "default_password_min")]
    pub password_min_length: usize,
    #[serde(default = "default_true")]
    pub registration_enabled: bool,
}
impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            max_sessions_per_user: 5,
            password_min_length: 8,
            registration_enabled: true,
        }
    }
}
fn default_max_sessions() -> usize {
    5
}
fn default_password_min() -> usize {
    8
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_log_max_entries")]
    pub log_max_entries: usize,
    #[serde(default = "default_uptime_history")]
    pub uptime_history_days: u32,
    #[serde(default = "default_sla_target")]
    pub sla_target_uptime: f64,
    #[serde(default = "default_sla_latency")]
    pub sla_target_latency_ms: f64,
}
impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_max_entries: 50000,
            uptime_history_days: 90,
            sla_target_uptime: 99.9,
            sla_target_latency_ms: 500.0,
        }
    }
}
fn default_log_max_entries() -> usize {
    50000
}
fn default_uptime_history() -> u32 {
    90
}
fn default_sla_target() -> f64 {
    99.9
}
fn default_sla_latency() -> f64 {
    500.0
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub prefix: String,
    pub upstream: String,
    #[serde(default = "default_health_endpoint")]
    pub health_endpoint: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub load_balance: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub transform: Option<TransformConfig>,
    #[serde(default)]
    pub validation_schema: Option<String>,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TransformConfig {
    #[serde(default)]
    pub add_request_headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub remove_request_headers: Vec<String>,
    #[serde(default)]
    pub add_response_headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub remove_response_headers: Vec<String>,
}

fn default_health_endpoint() -> String {
    "/health".to_string()
}

/// Thread-safe config holder for hot-reload
pub type SharedConfig = Arc<RwLock<XiraConfig>>;

/// Config semantic doğrulama sonucu — error'lar `Err`, soft warning'ler `Ok(warnings)`.
#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Default/example admin key'lerini tanı.
pub fn is_default_admin_key(api_key: &str) -> bool {
    matches!(
        api_key,
        "" | "xira-default-key"
            | "xira-secret-key-change-me"
            | "change-me"
            | "changeme"
            | "secret"
    )
}

/// Default/example JWT secret'larını tanı.
pub fn is_default_jwt_secret(s: &str) -> bool {
    matches!(
        s,
        ""
            | "your-jwt-secret-key-here"
            | "change-me"
            | "changeme"
            | "secret"
            | "jwt-secret"
            | "xira-secret-key-change-me"
    )
}

pub fn binds_externally(host: &str) -> bool {
    !matches!(host, "127.0.0.1" | "localhost" | "::1")
}

impl XiraConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: XiraConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Config'in semantic doğrulamasını yap. Boot-time guard'ların tek source-of-truth'u.
    /// CLI `xira system validate` ve `main.rs::Serve` aynı kontrolü kullanır.
    pub fn validate(&self) -> ValidationReport {
        let mut r = ValidationReport::default();

        // 1) Default admin key + dış bind = boot reddi
        if is_default_admin_key(&self.admin.api_key) {
            if binds_externally(&self.gateway.host) {
                r.errors.push(format!(
                    "admin.api_key is a known default and gateway.host = {} binds externally — refuse to start",
                    self.gateway.host
                ));
            } else {
                r.warnings.push(
                    "admin.api_key is a known default; change before deploying externally".into(),
                );
            }
        }

        // 2) JWT enabled → secret kalitesi
        if self.jwt.enabled {
            if is_default_jwt_secret(&self.jwt.secret) {
                r.errors.push(
                    "jwt.secret is a known default/example value — refuse to start with jwt.enabled=true"
                        .into(),
                );
            }
            let algo_up = self.jwt.algorithm.to_uppercase();
            match algo_up.as_str() {
                "HS256" | "HS384" | "HS512" => {
                    if self.jwt.secret.len() < 32 {
                        r.errors.push(format!(
                            "jwt.secret too short ({} bytes), HMAC algorithms require >= 32 bytes",
                            self.jwt.secret.len()
                        ));
                    }
                }
                "RS256" => {
                    use jsonwebtoken::DecodingKey;
                    if DecodingKey::from_rsa_pem(self.jwt.secret.as_bytes()).is_err() {
                        r.errors.push(
                            "jwt.algorithm = RS256 but jwt.secret is not a valid RSA PEM".into(),
                        );
                    }
                }
                other => {
                    r.errors
                        .push(format!("jwt.algorithm = {other} unsupported (HS256/HS384/HS512/RS256)"));
                }
            }
        }

        // 3) CORS: explicit origin listesi boş → tüm browser çağrıları başarısız olur (warning)
        if self.cors.allowed_origins.is_empty() {
            r.warnings.push(
                "cors.allowed_origins is empty — browser requests will be rejected by CORS".into(),
            );
        }

        // 4) Duplicate service prefix
        let mut seen = std::collections::HashSet::new();
        for svc in &self.services {
            if !seen.insert(svc.prefix.clone()) {
                r.errors.push(format!(
                    "duplicate [[services]] prefix: {} (each prefix must be unique)",
                    svc.prefix
                ));
            }
        }

        // 5) TLS dosya varlığı
        if let Some(ref tls) = self.tls {
            if tls.enabled {
                if !std::path::Path::new(&tls.cert_path).exists() {
                    r.errors
                        .push(format!("tls.cert_path not found: {}", tls.cert_path));
                }
                if !std::path::Path::new(&tls.key_path).exists() {
                    r.errors
                        .push(format!("tls.key_path not found: {}", tls.key_path));
                }
                if tls.mtls_enabled {
                    if let Some(ref ca) = tls.client_ca_path {
                        if !std::path::Path::new(ca).exists() {
                            r.errors
                                .push(format!("tls.client_ca_path not found: {ca}"));
                        }
                    } else {
                        r.errors
                            .push("tls.mtls_enabled = true requires client_ca_path".into());
                    }
                }
            }
        }

        // 6) Identity password_min_length sanity
        if self.identity.password_min_length < 8 {
            r.warnings.push(format!(
                "identity.password_min_length = {} is below recommended 8",
                self.identity.password_min_length
            ));
        }

        // 7) Plugin directory uyarı
        if self.plugins.enabled && !std::path::Path::new(&self.plugins.directory).exists() {
            r.warnings.push(format!(
                "plugins.enabled = true but directory not found: {}",
                self.plugins.directory
            ));
        }

        // 8) Rate limit sanity
        if self.rate_limit.max_requests == 0 {
            r.errors
                .push("rate_limit.max_requests = 0 blocks all traffic".into());
        }

        // 9) Cache sanity
        if self.cache.enabled && self.cache.max_entries == 0 {
            r.warnings
                .push("cache.enabled = true but cache.max_entries = 0 (cache effectively off)".into());
        }

        // 10) Bus config sanity
        match self.bus.backend.as_str() {
            "noop" => {}
            "redis" => {
                if self.bus.redis_url.is_empty() {
                    r.errors
                        .push("bus.backend = \"redis\" requires bus.redis_url".into());
                } else if !self.bus.redis_url.starts_with("redis://")
                    && !self.bus.redis_url.starts_with("rediss://")
                {
                    r.errors.push(format!(
                        "bus.redis_url must start with redis:// or rediss://, got: {}",
                        self.bus.redis_url
                    ));
                }
            }
            other => {
                r.errors
                    .push(format!("bus.backend = {other} unsupported (noop|redis)"));
            }
        }

        r
    }

    pub fn load_or_default() -> Self {
        let paths = vec![
            "xiranet.toml",
            "config/xiranet.toml",
            "/etc/xiranet/xiranet.toml",
        ];
        for path in paths {
            if Path::new(path).exists() {
                match Self::load(path) {
                    Ok(config) => {
                        tracing::info!("Config loaded from: {}", path);
                        return config;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load config from {}: {}", path, e);
                    }
                }
            }
        }

        tracing::warn!("No config file found, using defaults");
        Self::default()
    }
}

impl Default for XiraConfig {
    fn default() -> Self {
        XiraConfig {
            gateway: GatewayConfig {
                host: "0.0.0.0".to_string(),
                port: 9000,
                workers: 4,
            },
            admin: AdminConfig {
                api_key: "xira-default-key".to_string(),
                enabled: true,
            },
            health: HealthConfig {
                interval_secs: 30,
                timeout_secs: 5,
            },
            tls: None,
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            alerting: AlertingConfig::default(),
            rate_limit: RateLimitConfig::default(),
            cache: CacheConfig::default(),
            jwt: JwtConfig::default(),
            oauth2: OAuth2Config::default(),
            ip_filter: IpFilterConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            retry: RetryConfig::default(),
            plugins: PluginConfig::default(),
            grpc: GrpcConfig::default(),
            services: vec![],
            discovery: DiscoveryConfig::default(),
            redis: RedisConfig::default(),
            telemetry: TelemetryConfig::default(),
            waf: WafConfig::default(),
            bot_detection: BotDetectionConfig::default(),
            identity: IdentityConfig::default(),
            observability: ObservabilityConfig::default(),
            cors: CorsConfig::default(),
            audit: AuditConfig::default(),
            bus: BusConfig::default(),
        }
    }
}

/// Config hot-reload: watches xiranet.toml and reloads on change
pub fn start_config_watcher(config_path: String, shared: SharedConfig) {
    use notify::{Event, EventKind, RecursiveMode, Watcher};

    let rt = tokio::runtime::Handle::current();

    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel::<()>();

        let mut watcher =
            match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let _ = tx.send(());
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Cannot create file watcher: {e} - hot-reload disabled");
                    return;
                }
            };

        if let Err(e) = watcher.watch(Path::new(&config_path), RecursiveMode::NonRecursive) {
            eprintln!(
                "Cannot watch config file {config_path}: {e} - hot-reload disabled"
            );
            return;
        }

        println!("Config hot-reload enabled for: {config_path}");

        while rx.recv().is_ok() {
            // Debounce
            std::thread::sleep(std::time::Duration::from_millis(500));
            // Drain extra events
            while rx.try_recv().is_ok() {}

            match XiraConfig::load(&config_path) {
                Ok(new_config) => {
                    let shared_clone = shared.clone();
                    rt.spawn(async move {
                        let mut cfg = shared_clone.write().await;
                        *cfg = new_config;
                        tracing::info!("🔄 Config reloaded");
                    });
                }
                Err(e) => {
                    eprintln!("Failed to reload config: {e}");
                }
            }
        }
    });
}
