use actix_web::{middleware::DefaultHeaders, web, App, HttpServer};
use std::sync::Arc;
use std::time::Instant;

// ═══ XIRA Platform v3.0 imports ═══
//
// Architecture: domain crates compile independently (cargo test --workspace)
// but hub still uses its own copies for runtime type compatibility.
// Future: hub will re-export crate types via trait-based abstraction.
//
use xiranet::automation::cron::CronScheduler;
use xiranet::automation::event_bus::EventBus;
use xiranet::automation::workflows::WorkflowEngine;
use xiranet::datapipeline::pipeline::DataPipeline;
use xiranet::dbgateway::proxy::DbProxy;
use xiranet::dbgateway::query_firewall::QueryFirewall;
use xiranet::deployment::feature_flags::FeatureFlagManager;
use xiranet::deployment::releases::ReleaseManager;
use xiranet::gateway::health_scoring::HealthScorer;
use xiranet::identity::sessions::SessionManager;
use xiranet::identity::users::UserManager;
use xiranet::metrics::advanced::AdvancedMetrics;
use xiranet::metrics::sla::SlaMonitor;
use xiranet::middleware::audit_log::AuditLogger;
use xiranet::middleware::bot_detect::BotDetector;
use xiranet::middleware::waf::{Waf, WafMode};
use xiranet::observability::incidents::IncidentManager;
use xiranet::observability::log_aggregator::LogAggregator;
use xiranet::observability::uptime::UptimePage;

use xiranet::alerting::AlertManager;
use xiranet::cli::{Cli, Commands};
use xiranet::config::XiraConfig;
use xiranet::dashboard;
use xiranet::gateway;
use xiranet::gateway::cache::ResponseCache;
use xiranet::gateway::circuit_breaker::CircuitBreakerManager;
use xiranet::gateway::load_balancer::LoadBalancer;
use xiranet::health;
use xiranet::metrics;
use xiranet::middleware::{
    auth::ApiKeyAuth, cors, ip_filter::IpFilter, jwt::JwtAuth, logger::RequestLogger,
    rate_limit::RateLimiter,
};
use xiranet::plugins::{LoggingPlugin, PluginManager, SecurityHeadersPlugin};
use xiranet::registry::storage::SqliteStorage;
use xiranet::registry::ServiceRegistry;

fn print_banner(host: &str, port: u16, features: &[&str]) {
    println!(
        r#"
    ██╗  ██╗██╗██████╗  █████╗ 
    ╚██╗██╔╝██║██╔══██╗██╔══██╗
     ╚███╔╝ ██║██████╔╝███████║
     ██╔██╗ ██║██╔══██╗██╔══██║
    ██╔╝ ██╗██║██║  ██║██║  ██║
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
    
    ⚡ XIRA Platform v{}
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🌐 Gateway:    http://{}:{}
    🔧 Admin API:  http://{}:{}/xira/services
    📊 Dashboard:  http://{}:{}/dashboard
    📈 Metrics:    http://{}:{}/metrics
    🏥 Health:     http://{}:{}/xira/health
    
    📦 Crates: common | security | auth | ops | flow | gateway
    🔌 Features: {}
"#,
        env!("CARGO_PKG_VERSION"),
        host,
        port,
        host,
        port,
        host,
        port,
        host,
        port,
        host,
        port,
        features.join(" | ")
    );
}

fn is_default_admin_key(api_key: &str) -> bool {
    api_key == "xira-default-key" || api_key == "xira-secret-key-change-me"
}

fn binds_externally(host: &str) -> bool {
    !matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn start_runtime_config_sync(
    shared_config: Arc<tokio::sync::RwLock<XiraConfig>>,
    rate_limiter: RateLimiter,
    response_cache: Arc<ResponseCache>,
    cb_manager: CircuitBreakerManager,
    alert_manager: AlertManager,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            interval.tick().await;

            let config = shared_config.read().await;
            rate_limiter.set_limits(
                config.rate_limit.max_requests,
                config.rate_limit.window_secs,
            );
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
        }
    });
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse_args();

    match &cli.command {
        Commands::Serve { config, port } => {
            // Konfigürasyonu yükle
            let mut xira_config = if std::path::Path::new(config).exists() {
                XiraConfig::load(config).unwrap_or_else(|e| {
                    eprintln!("Config load error: {e}");
                    XiraConfig::load_or_default()
                })
            } else {
                XiraConfig::load_or_default()
            };

            if let Some(p) = port {
                xira_config.gateway.port = *p;
            }

            // Tracing başlat (file + console)
            xiranet::tracing_ext::init_tracing(
                &xira_config.logging.level,
                xira_config.logging.file_enabled,
                &xira_config.logging.file_path,
                &xira_config.logging.rotation,
            );

            let host = xira_config.gateway.host.clone();
            let port = xira_config.gateway.port;
            let workers = xira_config.gateway.workers;
            let api_key = xira_config.admin.api_key.clone();

            // ⚠️ Default key guard — warn loudly in production
            if is_default_admin_key(&api_key) {
                tracing::warn!("═══════════════════════════════════════════════════════════");
                tracing::warn!("⚠️  SECURITY WARNING: Using default admin API key!");
                tracing::warn!("⚠️  Change [admin].api_key in your config before deploying.");
                tracing::warn!("═══════════════════════════════════════════════════════════");
                if binds_externally(&host) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "Refusing to bind {host}:{port} with the default admin API key"
                        ),
                    ));
                }
            }

            // SQLite Storage (path from config or default)
            let db_path =
                std::env::var("XIRA_DB_PATH").unwrap_or_else(|_| "data/xiranet.db".to_string());
            let storage = Arc::new(SqliteStorage::new(&db_path).expect("Failed to init SQLite"));

            // Service Registry (SQLite entegrasyonlu)
            let storage_arc = storage.clone();
            let registry = ServiceRegistry::with_storage(storage);
            registry.load_from_config(&xira_config.services);
            let service_count = registry.count();
            tracing::info!("Loaded {} service(s)", service_count);

            // Circuit Breaker Manager
            let cb_manager = CircuitBreakerManager::new(
                xira_config.circuit_breaker.failure_threshold,
                xira_config.circuit_breaker.reset_timeout_secs,
                xira_config.circuit_breaker.half_open_max_requests,
            );

            // Load Balancer
            let load_balancer = LoadBalancer::new();

            // Response Cache
            let response_cache = Arc::new(ResponseCache::new(
                xira_config.cache.max_entries,
                xira_config.cache.ttl_secs,
                xira_config.cache.enabled,
            ));

            // Alert Manager
            let alert_manager = AlertManager::new(
                xira_config.alerting.webhook_url.clone(),
                xira_config.alerting.enabled,
                xira_config.alerting.on_service_down,
                xira_config.alerting.on_service_up,
            );
            let rate_limiter = RateLimiter::new(
                xira_config.rate_limit.max_requests,
                xira_config.rate_limit.window_secs,
            );

            // Plugin Manager
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

            // Config Hot-Reload
            let shared_config = Arc::new(tokio::sync::RwLock::new(xira_config.clone()));
            let config_path = config.clone();
            xiranet::config::start_config_watcher(config_path, shared_config.clone());
            start_runtime_config_sync(
                shared_config.clone(),
                rate_limiter.clone(),
                response_cache.clone(),
                cb_manager.clone(),
                alert_manager.clone(),
            );

            // ═══ v2.1.0 — Domain State (config-driven) ═══
            let waf_mode = if xira_config.waf.mode == "detect_only" {
                WafMode::DetectOnly
            } else {
                WafMode::Block
            };
            let waf = Arc::new(Waf::new(xira_config.waf.enabled, waf_mode));
            let bot_detector = Arc::new(BotDetector::new(
                xira_config.bot_detection.enabled,
                xira_config.bot_detection.block_bots,
                xira_config.bot_detection.crawl_rate_limit,
            ));
            let audit_logger = Arc::new(AuditLogger::new(Some(storage_arc.clone()), true));
            let advanced_metrics = Arc::new(AdvancedMetrics::new());
            let health_scorer = Arc::new(HealthScorer::new());
            let sla_monitor = Arc::new(SlaMonitor::new());
            // At-rest secret kasası: XIRA_SECRETS_KEY varsa MFA seed'leri şifreli saklanır.
            let secret_box = match xiranet::identity::secret_box::SecretBox::from_env() {
                Ok(sb) => {
                    tracing::info!("Identity: at-rest encryption enabled (XIRA_SECRETS_KEY)");
                    Some(sb)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Identity: at-rest encryption DISABLED — set XIRA_SECRETS_KEY (>= 32 bytes) to encrypt MFA seeds"
                    );
                    None
                }
            };
            let user_manager = Arc::new(UserManager::with_storage_and_secrets(
                storage_arc.clone(),
                secret_box.clone(),
            ));
            let session_manager = Arc::new(SessionManager::with_storage(
                xira_config.identity.max_sessions_per_user,
                storage_arc.clone(),
            ));
            let cron_scheduler = Arc::new(CronScheduler::with_storage(storage_arc.clone()));
            let event_bus = Arc::new(EventBus::new(10000));
            let workflow_engine = Arc::new(WorkflowEngine::new());
            let log_aggregator = Arc::new(LogAggregator::new(
                xira_config.observability.log_max_entries,
            ));
            let uptime_page = Arc::new(tokio::sync::RwLock::new(UptimePage::new()));
            let incident_manager = Arc::new(IncidentManager::new());
            let feature_flags = Arc::new(FeatureFlagManager::new());
            let release_manager = Arc::new(ReleaseManager::new());
            let db_proxy = Arc::new(DbProxy::new());
            let query_firewall = Arc::new(QueryFirewall::new(500.0));
            let data_pipeline = Arc::new(DataPipeline::new(1000, None));

            // OAuth2/OIDC Gateway — introspection-tabanlı token doğrulama.
            // Disabled iken bile struct yaratılır (admin endpoint 200 + enabled=false döner).
            let oauth2_gateway = Arc::new(xiranet::middleware::oauth2_gateway::OAuth2Gateway::new(
                xira_config.oauth2.enabled,
                xira_config.oauth2.issuer_url.clone(),
                xira_config.oauth2.introspection_url.clone(),
                xira_config.oauth2.client_id.clone().unwrap_or_default(),
                xira_config.oauth2.client_secret.clone().unwrap_or_default(),
            ));

            // Service Mesh + DockerDiscovery — config-driven, default off.
            let service_mesh = Arc::new(xiranet::discovery::mesh::ServiceMesh::new(
                xira_config.discovery.mesh_enabled,
            ));
            if xira_config.discovery.docker_enabled {
                let docker = xiranet::discovery::mesh::DockerDiscovery::new(
                    xira_config.discovery.docker_socket.clone(),
                );
                let registry_for_docker = registry.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                        xira_config.discovery.interval_secs.max(10),
                    ));
                    loop {
                        interval.tick().await;
                        let svcs = docker.discover().await;
                        for svc in svcs {
                            if registry_for_docker.find_by_prefix(&svc.prefix).is_none() {
                                let _ = registry_for_docker.register(
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

            // Start Cron Daemon
            cron_scheduler.clone().start();

            tracing::info!("v2.1.0 domains initialized: Identity, Automation, Observability, DB Gateway, Deployment, Pipeline");

            // Health Checker (with v2.0 cross-domain feeds)
            let health_registry = registry.clone();
            let health_alerts = alert_manager.clone();
            let health_interval = xira_config.health.interval_secs;
            let health_timeout = xira_config.health.timeout_secs;
            let health_uptime = uptime_page.clone();
            let health_incidents = incident_manager.clone();
            let health_sla = sla_monitor.clone();
            tokio::spawn(async move {
                health::start_health_checker(
                    health_registry,
                    health_alerts,
                    health_interval,
                    health_timeout,
                    health_uptime,
                    health_incidents,
                    health_sla,
                )
                .await;
            });

            // ═══ Startup Self-Test ═══
            {
                let svc_list = registry.list_all();
                if !svc_list.is_empty() {
                    tracing::info!(
                        "Running startup self-test for {} service(s)...",
                        svc_list.len()
                    );
                    let test_client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(3))
                        .build()
                        .unwrap();
                    for svc in &svc_list {
                        let health_url = format!("{}{}", svc.upstream, svc.health_endpoint);
                        match test_client.get(&health_url).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                tracing::info!("  ✔ {} ({}) — UP", svc.name, svc.upstream);
                            }
                            Ok(resp) => {
                                tracing::warn!(
                                    "  ✘ {} ({}) — HTTP {}",
                                    svc.name,
                                    svc.upstream,
                                    resp.status()
                                );
                            }
                            Err(_) => {
                                tracing::warn!("  ✘ {} ({}) — UNREACHABLE", svc.name, svc.upstream);
                            }
                        }
                    }
                }
            }

            let start_time = Instant::now();

            // Aktif özellikleri belirle
            let mut features = vec![
                "Gateway",
                "Admin API",
                "Dashboard",
                "Prometheus",
                "SQLite",
                "Compression",
            ];
            features.push("WAF");
            features.push("Identity");
            features.push("Automation");
            features.push("Observability");
            if xira_config.jwt.enabled {
                features.push("JWT");
            }
            if xira_config.ip_filter.enabled {
                features.push("IP Filter");
            }
            if xira_config.cache.enabled {
                features.push("Cache");
            }
            if xira_config.alerting.enabled {
                features.push("Alerting");
            }
            if xira_config.plugins.enabled {
                features.push("Plugins");
            }
            if xira_config.tls.is_some() {
                features.push("TLS");
            }
            if xira_config.grpc.enabled {
                features.push("gRPC");
            }
            if xira_config.discovery.enabled {
                features.push("Discovery");
            }
            if xira_config.redis.enabled {
                features.push("Redis");
            }
            if xira_config.telemetry.enabled {
                features.push("OpenTelemetry");
            }

            print_banner(&host, port, &features);

            // gRPC Proxy
            if xira_config.grpc.enabled {
                let grpc_registry = Arc::new(registry.clone());
                let grpc_host = host.clone();
                let grpc_port = xira_config.grpc.port;
                tokio::spawn(async move {
                    xiranet::grpc::start_grpc_proxy(grpc_registry, grpc_host, grpc_port).await;
                });
                tracing::info!("gRPC proxy enabled on port {}", xira_config.grpc.port);
            }

            // Service Discovery
            if xira_config.discovery.enabled {
                let disc_registry = Arc::new(registry.clone());
                let disc_backend = match xira_config.discovery.backend.as_str() {
                    "consul" => xiranet::discovery::DiscoveryBackend::Consul {
                        url: xira_config
                            .discovery
                            .consul_url
                            .clone()
                            .unwrap_or_else(|| "http://localhost:8500".to_string()),
                        datacenter: xira_config.discovery.consul_datacenter.clone(),
                    },
                    "dns" => xiranet::discovery::DiscoveryBackend::Dns {
                        domain: xira_config.discovery.dns_domain.clone().unwrap_or_default(),
                    },
                    _ => xiranet::discovery::DiscoveryBackend::Static,
                };
                let disc_interval = xira_config.discovery.interval_secs;
                tokio::spawn(async move {
                    xiranet::discovery::start_discovery(disc_registry, disc_backend, disc_interval)
                        .await;
                });
            }

            // OpenTelemetry
            let _otel_guard = if xira_config.telemetry.enabled {
                match xiranet::telemetry::init_opentelemetry(
                    &xira_config.telemetry.otlp_endpoint,
                    &xira_config.telemetry.service_name,
                ) {
                    Ok(guard) => Some(guard),
                    Err(e) => {
                        tracing::warn!(
                            "OpenTelemetry init failed: {} — running without tracing export",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            };

            // Shared state — Core
            let registry_data = web::Data::new(registry);
            let cb_data = web::Data::new(cb_manager);
            let lb_data = web::Data::new(load_balancer);
            let cache_data = web::Data::new(response_cache);
            let start_data = web::Data::new(start_time);
            let plugin_data = web::Data::new(plugin_manager);
            let rate_limiter_data = web::Data::new(rate_limiter.clone());
            let storage_data = web::Data::new(storage_arc.clone());
            let shared_config_data = web::Data::new(shared_config.clone());
            let alert_manager_data = web::Data::new(alert_manager.clone());

            // Shared state — v2.1.0 Domains
            let waf_data = web::Data::new(waf.clone());
            let bot_data = web::Data::new(bot_detector.clone());
            let audit_data = web::Data::new(audit_logger.clone());
            let adv_metrics_data = web::Data::new(advanced_metrics.clone());
            let health_score_data = web::Data::new(health_scorer.clone());
            let sla_data = web::Data::new(sla_monitor.clone());
            let user_data = web::Data::new(user_manager.clone());
            let session_data = web::Data::new(session_manager.clone());
            let cron_data = web::Data::new(cron_scheduler.clone());
            let event_data = web::Data::new(event_bus.clone());
            let workflow_data = web::Data::new(workflow_engine.clone());
            let log_agg_data = web::Data::new(log_aggregator.clone());
            let uptime_data = web::Data::new(uptime_page.clone());
            let incident_data = web::Data::new(incident_manager.clone());
            let flag_data = web::Data::new(feature_flags.clone());
            let release_data = web::Data::new(release_manager.clone());
            let db_proxy_data = web::Data::new(db_proxy.clone());
            let qf_data = web::Data::new(query_firewall.clone());
            let pipeline_data = web::Data::new(data_pipeline.clone());
            let oauth2_data = web::Data::new(oauth2_gateway.clone());
            let mesh_data = web::Data::new(service_mesh.clone());

            // JWT config — boot-time'da bir kez kur, zayıf/default secret'ı reddet.
            let jwt_enabled = xira_config.jwt.enabled;
            let jwt = match JwtAuth::new(
                xira_config.jwt.secret.clone(),
                &xira_config.jwt.algorithm,
                xira_config.jwt.issuer.clone(),
                jwt_enabled,
            ) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(error = %e, "JWT initialization failed — refuse to start");
                    eprintln!("\n[XIRA] JWT init error: {e}\n");
                    std::process::exit(1);
                }
            };

            // IP filter config
            let ip_enabled = xira_config.ip_filter.enabled;
            let ip_whitelist = xira_config.ip_filter.whitelist.clone();
            let ip_blacklist = xira_config.ip_filter.blacklist.clone();

            let storage_for_logger = storage_arc.clone();

            let server = HttpServer::new(move || {
                let mut app = App::new()
                    // Shared state — Core
                    .app_data(registry_data.clone())
                    .app_data(cb_data.clone())
                    .app_data(lb_data.clone())
                    .app_data(cache_data.clone())
                    .app_data(start_data.clone())
                    .app_data(plugin_data.clone())
                    .app_data(rate_limiter_data.clone())
                    .app_data(storage_data.clone())
                    .app_data(shared_config_data.clone())
                    .app_data(alert_manager_data.clone())
                    // Shared state — v2.1.0 Domains
                    .app_data(waf_data.clone())
                    .app_data(bot_data.clone())
                    .app_data(audit_data.clone())
                    .app_data(adv_metrics_data.clone())
                    .app_data(health_score_data.clone())
                    .app_data(sla_data.clone())
                    .app_data(user_data.clone())
                    .app_data(session_data.clone())
                    .app_data(cron_data.clone())
                    .app_data(event_data.clone())
                    .app_data(workflow_data.clone())
                    .app_data(log_agg_data.clone())
                    .app_data(uptime_data.clone())
                    .app_data(incident_data.clone())
                    .app_data(flag_data.clone())
                    .app_data(release_data.clone())
                    .app_data(db_proxy_data.clone())
                    .app_data(qf_data.clone())
                    .app_data(pipeline_data.clone())
                    .app_data(oauth2_data.clone())
                    .app_data(mesh_data.clone())
                    // Middleware (ters sırada uygulanır)
                    .wrap(actix_web::middleware::Compress::default())
                    .wrap(cors::configure_cors(&xira_config.cors))
                    .wrap(RequestLogger::with_storage(storage_for_logger.clone()))
                    .wrap(rate_limiter.clone())
                    .wrap(jwt.clone())
                    .wrap(IpFilter::new(
                        ip_whitelist.clone(),
                        ip_blacklist.clone(),
                        ip_enabled,
                    ))
                    .wrap(ApiKeyAuth::new(api_key.clone()))
                    .wrap(
                        DefaultHeaders::new()
                            .add(("X-Content-Type-Options", "nosniff"))
                            .add(("X-Frame-Options", "DENY"))
                            .add(("X-XSS-Protection", "1; mode=block")),
                    )
                    // Dashboard
                    .route("/dashboard", web::get().to(dashboard::dashboard_handler))
                    // Public health endpoint (no auth required — for Docker/LB/smoke tests)
                    .route(
                        "/health",
                        web::get().to(xiranet::admin::handlers::gateway_health),
                    )
                    // Auth endpoints — login + MFA-login public, geri kalan SessionAuth ile protected.
                    .service(
                        web::scope("/auth")
                            .route(
                                "/login",
                                web::post().to(xiranet::admin::v2_handlers::login_user),
                            )
                            .route(
                                "/mfa/login",
                                web::post().to(xiranet::admin::v2_handlers::mfa_login),
                            )
                            .service(
                                web::scope("")
                                    .wrap(xiranet::middleware::session::SessionAuth::new(
                                        session_manager.clone(),
                                    ))
                                    .route("/me", web::get().to(xiranet::admin::v2_handlers::me))
                                    .route(
                                        "/logout",
                                        web::post().to(xiranet::admin::v2_handlers::logout),
                                    )
                                    .route(
                                        "/logout-all",
                                        web::post().to(xiranet::admin::v2_handlers::logout_all),
                                    )
                                    .route(
                                        "/sessions",
                                        web::get().to(xiranet::admin::v2_handlers::my_sessions),
                                    )
                                    .route(
                                        "/mfa/enroll",
                                        web::post().to(xiranet::admin::v2_handlers::mfa_enroll),
                                    )
                                    .route(
                                        "/mfa/verify",
                                        web::post().to(xiranet::admin::v2_handlers::mfa_verify),
                                    ),
                            )
                            // Role-protected user administration (SuperAdmin)
                            .service(
                                web::scope("/admin")
                                    .wrap(xiranet::middleware::require_role::RequireRole::new(
                                        xiranet::identity::users::UserRole::SuperAdmin,
                                        user_manager.clone(),
                                    ))
                                    .wrap(xiranet::middleware::session::SessionAuth::new(
                                        session_manager.clone(),
                                    ))
                                    .route(
                                        "/users",
                                        web::get()
                                            .to(xiranet::admin::v2_handlers::admin_list_users),
                                    )
                                    .route(
                                        "/users/{id}/role",
                                        web::put()
                                            .to(xiranet::admin::v2_handlers::admin_update_role),
                                    )
                                    .route(
                                        "/users/{id}/disable",
                                        web::post()
                                            .to(xiranet::admin::v2_handlers::admin_disable_user),
                                    )
                                    .route(
                                        "/users/{id}/mfa/disable",
                                        web::post()
                                            .to(xiranet::admin::v2_handlers::admin_disable_mfa),
                                    )
                                    .route(
                                        "/users/{id}/logout-all",
                                        web::post()
                                            .to(xiranet::admin::v2_handlers::admin_logout_all),
                                    ),
                            ),
                    )
                    // WebSocket (dashboard = authenticated, others = proxy)
                    .route(
                        "/ws/metrics",
                        web::get().to(gateway::ws_metrics::ws_metrics_handler),
                    )
                    .route(
                        "/ws/dashboard",
                        web::get().to(dashboard::ws_dashboard_handler),
                    )
                    .route(
                        "/ws/{tail:.*}",
                        web::get().to(gateway::websocket::websocket_proxy),
                    )
                    // Versioned routes
                    .route(
                        "/v{version}/{tail:.*}",
                        web::route().to(xiranet::versioning::versioned_gateway_handler),
                    );

                // Prometheus metrics — config-driven
                if xira_config.metrics.enabled {
                    app = app.route(
                        &xira_config.metrics.path,
                        web::get().to(metrics::metrics_handler),
                    );
                }

                // Admin API — config-driven
                if xira_config.admin.enabled {
                    app = app.configure(xiranet::admin::configure);
                }

                // Gateway catch-all (must be last)
                app.default_service(web::route().to(gateway::gateway_handler))
            })
            .workers(workers)
            .bind(format!("{host}:{port}"))?;

            // TLS desteği
            if let Some(ref tls_config) = xira_config.tls {
                if tls_config.enabled {
                    match xiranet::tls::create_tls_config(
                        &tls_config.cert_path,
                        &tls_config.key_path,
                        tls_config.mtls_enabled,
                        tls_config.client_ca_path.as_deref(),
                    ) {
                        Ok(rustls_config) => {
                            tracing::info!("🔒 TLS enabled (mTLS: {})", tls_config.mtls_enabled);
                            return server
                                .bind_rustls_0_23(format!("{}:{}", host, port + 1), rustls_config)?
                                .run()
                                .await;
                        }
                        Err(e) => {
                            tracing::error!("TLS config failed: {} - running without TLS", e);
                        }
                    }
                }
            }

            // Graceful shutdown handler — SIGINT (Ctrl+C) ve SIGTERM (Docker stop, k8s)
            let server_handle = server.run();
            let srv = server_handle.handle();

            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sigterm = match signal(SignalKind::terminate()) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("Failed to install SIGTERM handler: {}", e);
                            // Fallback: yalnızca SIGINT bekle
                            let _ = tokio::signal::ctrl_c().await;
                            tracing::info!(
                                "⚓ Graceful shutdown (SIGINT) — waiting for active connections..."
                            );
                            srv.stop(true).await;
                            return;
                        }
                    };
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            tracing::info!(
                                "⚓ Graceful shutdown (SIGINT) — waiting for active connections..."
                            );
                        }
                        _ = sigterm.recv() => {
                            tracing::info!(
                                "⚓ Graceful shutdown (SIGTERM) — waiting for active connections..."
                            );
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!(
                        "⚓ Graceful shutdown (Ctrl+C) — waiting for active connections..."
                    );
                }
                srv.stop(true).await;
                tracing::info!("✔ Shutdown complete");
            });

            server_handle.await
        }

        Commands::GenerateCerts => {
            xiranet::tls::print_cert_generation_help();
            Ok(())
        }

        cmd => {
            if let Err(e) = xiranet::cli::run_cli_command(cmd).await {
                eprintln!("❌ Error: {e}");
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
