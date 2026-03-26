use actix_web::{web, App, HttpServer, middleware::DefaultHeaders};
use std::sync::Arc;
use std::time::Instant;

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
    auth::ApiKeyAuth,
    cors,
    ip_filter::IpFilter,
    jwt::JwtAuth,
    logger::RequestLogger,
    rate_limit::RateLimiter,
};
use xiranet::plugins::{LoggingPlugin, PluginManager, SecurityHeadersPlugin};
use xiranet::registry::storage::SqliteStorage;
use xiranet::registry::ServiceRegistry;

fn print_banner(host: &str, port: u16, features: &[&str]) {
    println!(
        r#"
    ██╗  ██╗██╗██████╗  █████╗ ███╗   ██╗███████╗████████╗
    ╚██╗██╔╝██║██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
     ╚███╔╝ ██║██████╔╝███████║██╔██╗ ██║█████╗     ██║   
     ██╔██╗ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══╝     ██║   
    ██╔╝ ██╗██║██║  ██║██║  ██║██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
    
    ⚡ Central Infrastructure Hub v{}
    🌐 Gateway:    http://{}:{}
    🔧 Admin API:  http://{}:{}/xira/services
    📊 Dashboard:  http://{}:{}/dashboard
    📈 Metrics:    http://{}:{}/metrics
    🏥 Health:     http://{}:{}/xira/health
    
    Features: {}
"#,
        env!("CARGO_PKG_VERSION"),
        host, port, host, port, host, port, host, port, host, port,
        features.join(" | ")
    );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse_args();

    match &cli.command {
        Commands::Serve { config, port } => {
            // Konfigürasyonu yükle
            let mut xira_config = if std::path::Path::new(config).exists() {
                XiraConfig::load(config).unwrap_or_else(|e| {
                    eprintln!("Config load error: {}", e);
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

            // SQLite Storage
            let storage = Arc::new(
                SqliteStorage::new("data/xiranet.db").expect("Failed to init SQLite")
            );

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

            // Plugin Manager
            let plugin_manager = PluginManager::new(xira_config.plugins.enabled);
            if xira_config.plugins.enabled {
                plugin_manager.register(Arc::new(LoggingPlugin)).await;
                plugin_manager.register(Arc::new(SecurityHeadersPlugin)).await;
                plugin_manager.scan_directory(&xira_config.plugins.directory);
            }

            // Config Hot-Reload
            let shared_config = Arc::new(tokio::sync::RwLock::new(xira_config.clone()));
            let config_path = config.clone();
            xiranet::config::start_config_watcher(config_path, shared_config.clone());

            // Health Checker
            let health_registry = registry.clone();
            let health_alerts = alert_manager.clone();
            let health_interval = xira_config.health.interval_secs;
            let health_timeout = xira_config.health.timeout_secs;
            tokio::spawn(async move {
                health::start_health_checker(health_registry, health_alerts, health_interval, health_timeout).await;
            });

            let start_time = Instant::now();

            // Aktif özellikleri belirle
            let mut features = vec!["Gateway", "Admin API", "Dashboard", "Prometheus", "SQLite"];
            if xira_config.jwt.enabled { features.push("JWT"); }
            if xira_config.ip_filter.enabled { features.push("IP Filter"); }
            if xira_config.cache.enabled { features.push("Cache"); }
            if xira_config.alerting.enabled { features.push("Alerting"); }
            if xira_config.plugins.enabled { features.push("Plugins"); }
            if xira_config.tls.is_some() { features.push("TLS"); }

            print_banner(&host, port, &features);

            // Retry config
            let retry_config = xira_config.retry.clone();

            // Shared state
            let registry_data = web::Data::new(registry);
            let cb_data = web::Data::new(cb_manager);
            let lb_data = web::Data::new(load_balancer);
            let cache_data = web::Data::new(response_cache);
            let start_data = web::Data::new(start_time);
            let plugin_data = web::Data::new(plugin_manager);
            let retry_data = web::Data::new(retry_config);
            let storage_data = web::Data::new(storage_arc.clone());

            // JWT config
            let jwt_enabled = xira_config.jwt.enabled;
            let jwt_secret = xira_config.jwt.secret.clone();
            let jwt_algo = xira_config.jwt.algorithm.clone();
            let jwt_issuer = xira_config.jwt.issuer.clone();

            // IP filter config
            let ip_enabled = xira_config.ip_filter.enabled;
            let ip_whitelist = xira_config.ip_filter.whitelist.clone();
            let ip_blacklist = xira_config.ip_filter.blacklist.clone();

            // Rate limit config
            let rl_max = xira_config.rate_limit.max_requests;
            let rl_window = xira_config.rate_limit.window_secs;

            let storage_for_logger = storage_arc.clone();

            let server = HttpServer::new(move || {
                App::new()
                    // Shared state
                    .app_data(registry_data.clone())
                    .app_data(cb_data.clone())
                    .app_data(lb_data.clone())
                    .app_data(cache_data.clone())
                    .app_data(start_data.clone())
                    .app_data(plugin_data.clone())
                    .app_data(retry_data.clone())
                    .app_data(storage_data.clone())
                    // Middleware (ters sırada uygulanır)
                    .wrap(cors::configure_cors())
                    .wrap(RequestLogger::with_storage(storage_for_logger.clone()))
                    .wrap(RateLimiter::new(rl_max, rl_window))
                    .wrap(JwtAuth::new(jwt_secret.clone(), &jwt_algo, jwt_issuer.clone(), jwt_enabled))
                    .wrap(IpFilter::new(ip_whitelist.clone(), ip_blacklist.clone(), ip_enabled))
                    .wrap(ApiKeyAuth::new(api_key.clone()))
                    .wrap(DefaultHeaders::new()
                        .add(("X-Powered-By", "xiraNET"))
                        .add(("X-Version", env!("CARGO_PKG_VERSION")))
                        .add(("X-Content-Type-Options", "nosniff"))
                        .add(("X-Frame-Options", "DENY"))
                        .add(("X-XSS-Protection", "1; mode=block"))
                    )
                    // Dashboard
                    .route("/dashboard", web::get().to(dashboard::dashboard_handler))
                    // Prometheus metrics
                    .route("/metrics", web::get().to(metrics::metrics_handler))
                    // WebSocket
                    .route("/ws/{tail:.*}", web::get().to(gateway::websocket::websocket_proxy))
                    // Versioned routes
                    .route("/v{version}/{tail:.*}", web::route().to(xiranet::versioning::versioned_gateway_handler))
                    // Admin API
                    .configure(xiranet::admin::configure)
                    // Gateway catch-all
                    .default_service(web::route().to(gateway::gateway_handler))
            })
            .workers(workers)
            .bind(format!("{}:{}", host, port))?;

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
                            return server.bind_rustls_0_23(
                                format!("{}:{}", host, port + 1),
                                rustls_config,
                            )?.run().await;
                        }
                        Err(e) => {
                            tracing::error!("TLS config failed: {} - running without TLS", e);
                        }
                    }
                }
            }

            server.run().await
        }

        Commands::GenerateCerts => {
            xiranet::tls::print_cert_generation_help();
            Ok(())
        }

        cmd => {
            if let Err(e) = xiranet::cli::run_cli_command(cmd).await {
                eprintln!("❌ Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
