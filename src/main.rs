use actix_web::{middleware::DefaultHeaders, web, App, HttpServer};
use std::sync::Arc;
use std::time::Instant;

// v3 audit Yarı C #26: domain bootstrap bootstrap::AppState::init'e taşındı.
// main.rs şu an sadece CLI dispatch + HttpServer route mount.
use xiranet::cli::{Cli, Commands};
use xiranet::config::XiraConfig;
use xiranet::dashboard;
use xiranet::gateway;
use xiranet::metrics;
use xiranet::middleware::{
    auth::ApiKeyAuth, cors, ip_filter::IpFilter, jwt::JwtAuth, logger::RequestLogger,
};

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

// Boot-time default-key + bind check now lives in xiranet::config::{is_default_admin_key,
// binds_externally} so CLI `xira system validate` and the `Serve` boot path use the
// same source of truth.

// `start_runtime_config_sync` bootstrap::state::spawn_config_sync'a taşındı
// (v3 audit Yarı C madde 26 — main.rs domain split).

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

            // Single-source config validation — boot reddi + warning loop
            let report = xira_config.validate();
            for w in &report.warnings {
                tracing::warn!(target: "xira::config", "{w}");
            }
            if !report.ok() {
                for e in &report.errors {
                    tracing::error!(target: "xira::config", "{e}");
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "config validation failed with {} blocking error(s); run `xira system validate --config {}` for details",
                        report.errors.len(),
                        config
                    ),
                ));
            }

            // ═══ AppState — tüm Arc init burada (v3 audit Yarı C #26) ═══
            // Eski sürüm 770 satırlık tanrı fonksiyonu idi; bootstrap::state'e
            // taşındı. main.rs şu an sadece CLI dispatch + HttpServer wire.
            let state =
                match xiranet::bootstrap::AppState::init(xira_config.clone(), config.clone())
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "AppState init failed");
                        return Err(e);
                    }
                };
            let storage_arc = state.storage.clone();
            let registry = state.registry.clone();
            let service_count = registry.count();
            tracing::info!("Loaded {} service(s)", service_count);

            // Tüm aşağıdaki Arc init bootstrap::AppState::init içinde yapıldı.
            // Kalan: state field'larını lokal değişkenlere clone'la (closure'da
            // hareket için).
            let cb_manager = state.cb_manager.clone();
            let load_balancer = state.load_balancer.clone();
            let response_cache = state.response_cache.clone();
            let alert_manager = state.alert_manager.clone();
            let rate_limiter = state.rate_limiter.clone();
            let plugin_manager = state.plugin_manager.clone();
            let shared_config = state.shared_config.clone();
            let bus = state.bus.clone();
            let waf = state.waf.clone();
            let bot_detector = state.bot_detector.clone();
            let audit_logger = state.audit_logger.clone();
            let advanced_metrics = state.advanced_metrics.clone();
            let health_scorer = state.health_scorer.clone();
            let sla_monitor = state.sla_monitor.clone();
            let user_manager = state.user_manager.clone();
            let session_manager = state.session_manager.clone();
            let authenticator = state.authenticator.clone();
            let cron_scheduler = state.cron_scheduler.clone();
            let event_bus = state.event_bus.clone();
            let workflow_engine = state.workflow_engine.clone();
            let log_aggregator = state.log_aggregator.clone();
            let uptime_page = state.uptime_page.clone();
            let incident_manager = state.incident_manager.clone();
            let feature_flags = state.feature_flags.clone();
            let release_manager = state.release_manager.clone();
            let db_proxy = state.db_proxy.clone();
            let query_firewall = state.query_firewall.clone();
            let data_pipeline = state.data_pipeline.clone();
            let oauth2_gateway = state.oauth2_gateway.clone();
            let service_mesh = state.service_mesh.clone();
            // `bus` ve diğerleri yalnız warning silinmesi için referans alındı.
            let _ = (bus, audit_logger.clone(), event_bus.clone(), workflow_engine.clone(),
                     log_aggregator.clone(), uptime_page.clone(), incident_manager.clone(),
                     feature_flags.clone(), release_manager.clone(), db_proxy.clone(),
                     query_firewall.clone(), data_pipeline.clone(), oauth2_gateway.clone(),
                     service_mesh.clone(), cron_scheduler.clone());

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
            let authenticator_data = web::Data::new(authenticator.clone());
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
                    .app_data(authenticator_data.clone())
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
                    // Route sırası: spesifik prefix'ler (/admin/, /mfa/*) önce, sonra session'lı genel.
                    .service(
                        web::scope("/auth")
                            // Role-protected user administration — SessionAuth + RequireRole(SuperAdmin)
                            // ÖNCE deklare edilir, aksi halde session-only sub-scope path'i yutar.
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
                            )
                            .route(
                                "/login",
                                web::post().to(xiranet::admin::v2_handlers::login_user),
                            )
                            .route(
                                "/mfa/login",
                                web::post().to(xiranet::admin::v2_handlers::mfa_login),
                            )
                            // Session-protected (kullanıcının kendi context'i)
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
