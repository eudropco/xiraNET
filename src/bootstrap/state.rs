//! AppState — tüm domain Arc'larını tek struct'ta topla. main.rs'in init
//! bloğunu (~270 satır) buraya taşı.
//!
//! Tüm field'lar Clone-able: Arc<T> veya internal-Arc'lı struct (RateLimiter,
//! CircuitBreakerManager, LoadBalancer, AlertManager, PluginManager,
//! ServiceRegistry hepsi `#[derive(Clone)]`).
//!
//! HttpServer::new closure'ı `state.clone()` ile state'i alır, sonra her
//! field'ı web::Data ile sarmalar (actix gereksinimi).

use std::sync::Arc;

use crate::alerting::AlertManager;
use crate::automation::cron::CronScheduler;
use crate::automation::event_bus::EventBus;
use crate::automation::workflows::WorkflowEngine;
use crate::bus::XiraBus;
use crate::config::{SharedConfig, XiraConfig};
use crate::datapipeline::pipeline::DataPipeline;
use crate::dbgateway::proxy::DbProxy;
use crate::dbgateway::query_firewall::QueryFirewall;
use crate::deployment::feature_flags::FeatureFlagManager;
use crate::deployment::releases::ReleaseManager;
use crate::discovery::mesh::ServiceMesh;
use crate::gateway::cache::ResponseCache;
use crate::gateway::circuit_breaker::CircuitBreakerManager;
use crate::gateway::health_scoring::HealthScorer;
use crate::gateway::load_balancer::LoadBalancer;
use crate::identity::authenticator::Authenticator;
use crate::identity::sessions::SessionManager;
use crate::identity::users::UserManager;
use crate::metrics::advanced::AdvancedMetrics;
use crate::metrics::sla::SlaMonitor;
use crate::middleware::audit_log::AuditLogger;
use crate::middleware::bot_detect::BotDetector;
use crate::middleware::oauth2_gateway::OAuth2Gateway;
use crate::middleware::rate_limit::RateLimiter;
use crate::middleware::waf::{Waf, WafMode};
use crate::observability::incidents::IncidentManager;
use crate::observability::log_aggregator::LogAggregator;
use crate::observability::uptime::UptimePage;
use crate::plugins::{LoggingPlugin, PluginManager, SecurityHeadersPlugin};
use crate::registry::storage::SqliteStorage;
use crate::registry::ServiceRegistry;

#[derive(Clone)]
pub struct AppState {
    // Config + ortak storage
    pub xira_config: XiraConfig,
    pub config_path: String,
    pub storage: Arc<SqliteStorage>,
    pub shared_config: SharedConfig,

    // Gateway domain
    pub registry: ServiceRegistry,
    pub cb_manager: CircuitBreakerManager,
    pub load_balancer: LoadBalancer,
    pub response_cache: Arc<ResponseCache>,
    pub rate_limiter: RateLimiter,
    pub waf: Arc<Waf>,
    pub bot_detector: Arc<BotDetector>,

    // Identity domain
    pub user_manager: Arc<UserManager>,
    pub session_manager: Arc<SessionManager>,
    pub authenticator: Arc<Authenticator>,

    // Automation
    pub cron_scheduler: Arc<CronScheduler>,
    pub event_bus: Arc<EventBus>,
    pub workflow_engine: Arc<WorkflowEngine>,

    // Observability
    pub log_aggregator: Arc<LogAggregator>,
    pub uptime_page: Arc<tokio::sync::RwLock<UptimePage>>,
    pub incident_manager: Arc<IncidentManager>,
    pub audit_logger: Arc<AuditLogger>,
    pub advanced_metrics: Arc<AdvancedMetrics>,
    pub health_scorer: Arc<HealthScorer>,
    pub sla_monitor: Arc<SlaMonitor>,

    // Deployment
    pub feature_flags: Arc<FeatureFlagManager>,
    pub release_manager: Arc<ReleaseManager>,

    // Data pipeline + DB gateway
    pub db_proxy: Arc<DbProxy>,
    pub query_firewall: Arc<QueryFirewall>,
    pub data_pipeline: Arc<DataPipeline>,

    // OAuth2 + Mesh + Plugins
    pub oauth2_gateway: Arc<OAuth2Gateway>,
    pub service_mesh: Arc<ServiceMesh>,
    pub plugin_manager: PluginManager,

    // Cross-cutting
    pub alert_manager: AlertManager,
    pub bus: Arc<dyn XiraBus>,
}

impl AppState {
    /// Tüm Arc state'i kurar + side-effect spawn'ları (bus subscriber, config
    /// watcher, runtime config sync, docker discovery, cron daemon, health
    /// checker). main.rs sadece `App::new()` route mount'unu yapar.
    pub async fn init(
        xira_config: XiraConfig,
        config_path: String,
    ) -> std::io::Result<Self> {
        // ─── Storage ───────────────────────────────────────────────
        let db_path =
            std::env::var("XIRA_DB_PATH").unwrap_or_else(|_| "data/xiranet.db".to_string());
        let storage = Arc::new(
            SqliteStorage::new(&db_path)
                .map_err(|e| std::io::Error::other(format!("SQLite init: {e}")))?,
        );
        let storage_arc = storage.clone();

        // ─── Registry ──────────────────────────────────────────────
        let registry = ServiceRegistry::with_storage(storage.clone());
        registry.load_from_config(&xira_config.services);
        let service_count = registry.count();
        tracing::info!("Loaded {} service(s)", service_count);

        // ─── Gateway internals ─────────────────────────────────────
        let cb_manager = CircuitBreakerManager::new(
            xira_config.circuit_breaker.failure_threshold,
            xira_config.circuit_breaker.reset_timeout_secs,
            xira_config.circuit_breaker.half_open_max_requests,
        );
        let load_balancer = LoadBalancer::new();
        let response_cache = Arc::new(ResponseCache::new(
            xira_config.cache.max_entries,
            xira_config.cache.ttl_secs,
            xira_config.cache.enabled,
        ));
        let alert_manager = AlertManager::new(
            xira_config.alerting.webhook_url.clone(),
            xira_config.alerting.enabled,
            xira_config.alerting.on_service_down,
            xira_config.alerting.on_service_up,
        );
        let rate_limiter = RateLimiter::with_options(
            xira_config.rate_limit.max_requests,
            xira_config.rate_limit.window_secs,
            xira_config.rate_limit.trust_xff,
        );

        // ─── Plugins ───────────────────────────────────────────────
        let plugin_manager = PluginManager::new(xira_config.plugins.enabled);
        if xira_config.plugins.enabled {
            plugin_manager.register(Arc::new(LoggingPlugin)).await;
            plugin_manager
                .register(Arc::new(SecurityHeadersPlugin))
                .await;
            plugin_manager
                .scan_directory(&xira_config.plugins.directory)
                .await;
        }

        // ─── Config hot-reload ─────────────────────────────────────
        let shared_config = Arc::new(tokio::sync::RwLock::new(xira_config.clone()));
        crate::config::start_config_watcher(config_path.clone(), shared_config.clone());

        // ─── Multi-node bus ────────────────────────────────────────
        let bus: Arc<dyn XiraBus> = match xira_config.bus.backend.as_str() {
            "redis" => match crate::bus::redis_bus::RedisBus::connect(&xira_config.bus.redis_url)
                .await
            {
                Ok(b) => {
                    tracing::info!(
                        "Multi-node bus: Redis connected ({})",
                        xira_config.bus.redis_url
                    );
                    Arc::new(b)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Redis bus connect failed — fallback NoOp");
                    Arc::new(crate::bus::NoOpBus)
                }
            },
            _ => Arc::new(crate::bus::NoOpBus),
        };

        // ─── WAF + runtime config sync ─────────────────────────────
        let waf_mode = if xira_config.waf.mode == "detect_only" {
            WafMode::DetectOnly
        } else {
            WafMode::Block
        };
        let waf = Arc::new(Waf::new(xira_config.waf.enabled, waf_mode));
        waf.load_custom_patterns_from_strings(&xira_config.waf.custom_block_patterns);
        waf.set_bus(bus.clone());

        spawn_config_sync(
            shared_config.clone(),
            rate_limiter.clone(),
            response_cache.clone(),
            cb_manager.clone(),
            alert_manager.clone(),
            waf.clone(),
        );

        let bot_detector = Arc::new(BotDetector::new(
            xira_config.bot_detection.enabled,
            xira_config.bot_detection.block_bots,
            xira_config.bot_detection.crawl_rate_limit,
        ));

        // ─── Audit sink ────────────────────────────────────────────
        let mut sinks: Vec<Arc<dyn crate::middleware::audit_sink::AuditSink>> = Vec::new();
        if let Some(ref p) = xira_config.audit.file_path {
            sinks.push(Arc::new(crate::middleware::audit_sink::FileSink::new(
                std::path::PathBuf::from(p),
            )));
            tracing::info!("Audit file sink active: {p}");
        }
        if let Some(ref u) = xira_config.audit.webhook_url {
            let headers: Vec<(String, String)> = xira_config
                .audit
                .webhook_headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            sinks.push(Arc::new(crate::middleware::audit_sink::HttpSink::new(
                u.clone(),
                headers,
            )));
            tracing::info!("Audit HTTP sink active: {u}");
        }
        let audit_dispatcher = if sinks.is_empty() {
            None
        } else {
            Some(Arc::new(crate::middleware::audit_sink::AuditDispatcher::new(
                sinks,
                xira_config.audit.buffer_size,
            )))
        };
        let audit_logger = Arc::new(AuditLogger::new_with_dispatcher(
            Some(storage_arc.clone()),
            true,
            audit_dispatcher,
        ));

        // ─── Identity domain ───────────────────────────────────────
        let secret_box = match crate::identity::secret_box::SecretBox::from_env() {
            Ok(sb) => {
                tracing::info!("Identity: at-rest encryption enabled (XIRA_SECRETS_KEY)");
                Some(sb)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Identity: at-rest encryption DISABLED — set XIRA_SECRETS_KEY (>= 32 bytes)"
                );
                None
            }
        };
        let user_manager = Arc::new(UserManager::with_storage_and_secrets(
            storage_arc.clone(),
            secret_box.clone(),
        ));
        let mut session_mgr =
            SessionManager::with_storage(xira_config.identity.max_sessions_per_user, storage_arc.clone());
        session_mgr.set_bus(bus.clone());
        let session_manager = Arc::new(session_mgr);
        let authenticator = Arc::new(Authenticator::new(
            user_manager.clone(),
            session_manager.clone(),
        ));

        // Bus subscriber — trait method üzerinden, ek instance gerek yok.
        let dispatcher = Arc::new(crate::bus::EventDispatcher::new(vec![
            session_manager.clone() as Arc<dyn crate::bus::BusEventHandler>,
            waf.clone() as Arc<dyn crate::bus::BusEventHandler>,
        ]));
        bus.spawn_subscriber(dispatcher);
        tracing::info!("Bus subscriber registered (kind: {})", bus.kind());

        // ─── Rest of v2.1 domains ──────────────────────────────────
        let cron_scheduler = Arc::new(CronScheduler::with_storage(storage_arc.clone()));
        let event_bus = Arc::new(EventBus::new(10000));
        let workflow_engine = Arc::new(WorkflowEngine::new());
        let log_aggregator = Arc::new(LogAggregator::new(xira_config.observability.log_max_entries));
        let uptime_page = Arc::new(tokio::sync::RwLock::new(UptimePage::new()));
        let incident_manager = Arc::new(IncidentManager::new());
        let feature_flags = Arc::new(FeatureFlagManager::new());
        let release_manager = Arc::new(ReleaseManager::new());
        let db_proxy = Arc::new(DbProxy::new());
        let query_firewall = Arc::new(QueryFirewall::new(500.0));
        let data_pipeline = Arc::new(DataPipeline::new(1000, None));
        let advanced_metrics = Arc::new(AdvancedMetrics::new());
        let health_scorer = Arc::new(HealthScorer::new());
        let sla_monitor = Arc::new(SlaMonitor::new());

        let oauth2_gateway = Arc::new(OAuth2Gateway::new(
            xira_config.oauth2.enabled,
            xira_config.oauth2.issuer_url.clone(),
            xira_config.oauth2.introspection_url.clone(),
            xira_config.oauth2.client_id.clone().unwrap_or_default(),
            xira_config.oauth2.client_secret.clone().unwrap_or_default(),
        ));

        let service_mesh = Arc::new(ServiceMesh::new(xira_config.discovery.mesh_enabled));
        if xira_config.discovery.docker_enabled {
            spawn_docker_discovery(
                xira_config.discovery.docker_socket.clone(),
                xira_config.discovery.interval_secs,
                registry.clone(),
            );
        }

        // ─── Background tasks ──────────────────────────────────────
        cron_scheduler.clone().start();
        spawn_health_checker(
            registry.clone(),
            alert_manager.clone(),
            xira_config.health.interval_secs,
            xira_config.health.timeout_secs,
            uptime_page.clone(),
            incident_manager.clone(),
            sla_monitor.clone(),
        );

        // ─── Startup self-test ─────────────────────────────────────
        run_startup_self_test(&registry).await;

        tracing::info!("v3.0 AppState initialized");

        Ok(Self {
            xira_config,
            config_path,
            storage,
            shared_config,
            registry,
            cb_manager,
            load_balancer,
            response_cache,
            rate_limiter,
            waf,
            bot_detector,
            user_manager,
            session_manager,
            authenticator,
            cron_scheduler,
            event_bus,
            workflow_engine,
            log_aggregator,
            uptime_page,
            incident_manager,
            audit_logger,
            advanced_metrics,
            health_scorer,
            sla_monitor,
            feature_flags,
            release_manager,
            db_proxy,
            query_firewall,
            data_pipeline,
            oauth2_gateway,
            service_mesh,
            plugin_manager,
            alert_manager,
            bus,
        })
    }
}

fn spawn_config_sync(
    shared_config: SharedConfig,
    rate_limiter: RateLimiter,
    response_cache: Arc<ResponseCache>,
    cb_manager: CircuitBreakerManager,
    alert_manager: AlertManager,
    waf: Arc<Waf>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut last_waf_patterns_hash: u64 = 0;
        loop {
            interval.tick().await;
            let config = shared_config.read().await;
            rate_limiter.set_limits(config.rate_limit.max_requests, config.rate_limit.window_secs);
            rate_limiter.set_trust_xff(config.rate_limit.trust_xff);
            response_cache.set_enabled(config.cache.enabled);
            response_cache.set_ttl_secs(config.cache.ttl_secs);
            cb_manager.update_config(
                config.circuit_breaker.failure_threshold,
                config.circuit_breaker.reset_timeout_secs,
                config.circuit_breaker.half_open_max_requests,
            );
            alert_manager.update_config(
                config.alerting.webhook_url.clone(),
                config.alerting.enabled,
                config.alerting.on_service_down,
                config.alerting.on_service_up,
            );
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for p in &config.waf.custom_block_patterns {
                p.hash(&mut h);
            }
            let new_hash = h.finish();
            if new_hash != last_waf_patterns_hash {
                last_waf_patterns_hash = new_hash;
                waf.load_custom_patterns_from_strings(&config.waf.custom_block_patterns);
                tracing::info!(
                    "WAF custom patterns hot-reloaded ({} rule(s))",
                    config.waf.custom_block_patterns.len()
                );
            }
        }
    });
}

fn spawn_docker_discovery(socket: String, interval_secs: u64, registry: ServiceRegistry) {
    tokio::spawn(async move {
        let docker = crate::discovery::mesh::DockerDiscovery::new(socket);
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(10)));
        loop {
            interval.tick().await;
            let svcs = docker.discover().await;
            for svc in svcs {
                if registry.find_by_prefix(&svc.prefix).is_none() {
                    let _ = registry.register(
                        svc.name.clone(),
                        svc.prefix,
                        svc.upstream,
                        svc.health_endpoint,
                    );
                    tracing::info!("Docker discovery registered: {}", svc.name);
                }
            }
        }
    });
}

fn spawn_health_checker(
    registry: ServiceRegistry,
    alerts: AlertManager,
    interval_secs: u64,
    timeout_secs: u64,
    uptime: Arc<tokio::sync::RwLock<UptimePage>>,
    incidents: Arc<IncidentManager>,
    sla: Arc<SlaMonitor>,
) {
    tokio::spawn(async move {
        crate::health::start_health_checker(
            registry,
            alerts,
            interval_secs,
            timeout_secs,
            uptime,
            incidents,
            sla,
        )
        .await;
    });
}

async fn run_startup_self_test(registry: &ServiceRegistry) {
    let svc_list = registry.list_all();
    if svc_list.is_empty() {
        return;
    }
    tracing::info!(
        "Running startup self-test for {} service(s)...",
        svc_list.len()
    );
    let test_client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    for svc in &svc_list {
        let health_url = format!("{}{}", svc.upstream, svc.health_endpoint);
        match test_client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("  ✔ {} ({}) — UP", svc.name, svc.upstream);
            }
            Ok(resp) => {
                tracing::warn!("  ✘ {} ({}) — HTTP {}", svc.name, svc.upstream, resp.status());
            }
            Err(_) => {
                tracing::warn!("  ✘ {} ({}) — UNREACHABLE", svc.name, svc.upstream);
            }
        }
    }
}
