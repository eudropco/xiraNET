use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xira",
    about = "⚡ XIRA Platform — Modular Infrastructure Hub v3.0",
    version,
    author = "valverde"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the XIRA gateway server
    Serve {
        #[arg(short, long, default_value = "xiranet.toml")]
        config: String,
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Show platform status
    Status {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Service management
    #[command(subcommand)]
    Service(ServiceCommands),
    /// Security & compliance
    #[command(subcommand)]
    Security(SecurityCommands),
    /// Observability & monitoring
    #[command(subcommand)]
    Ops(OpsCommands),
    /// System utilities
    #[command(subcommand)]
    System(SystemCommands),
    /// User administration via /auth/admin/* (RBAC: SuperAdmin session token)
    #[command(subcommand)]
    Admin(AdminCommands),
    /// Servis ekle
    #[command(hide = true)]
    Add {
        name: String,
        prefix: String,
        upstream: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
        #[arg(long)]
        upstreams: Vec<String>,
        #[arg(long)]
        load_balance: Option<String>,
        #[arg(long)]
        version: Option<String>,
    },
    #[command(hide = true)]
    Remove {
        id: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    List {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    Health {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    Stats {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    CircuitBreakers {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    CacheClear {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    GenerateCerts,
    #[command(hide = true)]
    Validate {
        #[arg(short, long, default_value = "xiranet.toml")]
        config: String,
    },
    #[command(hide = true)]
    Logs {
        #[arg(short = 'n', long, default_value = "20")]
        tail: usize,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    Bench {
        url: String,
        #[arg(short = 'n', long, default_value = "100")]
        requests: usize,
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
    },
    #[command(hide = true)]
    Init,
    #[command(hide = true)]
    Doctor {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
    },
    #[command(hide = true)]
    Export {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
        #[arg(short, long, default_value = "xiranet-export.json")]
        output: String,
    },
    #[command(hide = true)]
    Import {
        file: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    #[command(hide = true)]
    ProxyTest {
        path: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum ServiceCommands {
    /// List all registered services
    List {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Add a new service
    Add {
        name: String,
        prefix: String,
        upstream: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
        #[arg(long)]
        upstreams: Vec<String>,
        #[arg(long)]
        load_balance: Option<String>,
        #[arg(long)]
        version: Option<String>,
    },
    /// Remove a service by ID
    Remove {
        id: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Test proxy to a path
    Test {
        path: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum SecurityCommands {
    /// View audit log entries
    Audit {
        #[arg(short = 'n', long, default_value = "20")]
        tail: usize,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Show WAF status
    Waf {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum OpsCommands {
    /// Show gateway statistics
    Stats {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Show circuit breaker states
    Breakers {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// View recent request logs
    Logs {
        #[arg(short = 'n', long, default_value = "20")]
        tail: usize,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Run a load test
    Bench {
        url: String,
        #[arg(short = 'n', long, default_value = "100")]
        requests: usize,
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
    },
    /// Clear response cache
    CacheClear {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum AdminCommands {
    /// List all users (SuperAdmin token required)
    Users {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        /// Session token (xira_tok_...) — SuperAdmin role gerekir
        #[arg(short, long, env = "XIRA_SESSION_TOKEN", hide_env_values = true)]
        token: String,
    },
    /// Set user role
    SetRole {
        user_id: String,
        /// New role: SuperAdmin / Admin / Developer / Service / Viewer
        role: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_SESSION_TOKEN", hide_env_values = true)]
        token: String,
    },
    /// Disable a user
    Disable {
        user_id: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_SESSION_TOKEN", hide_env_values = true)]
        token: String,
    },
    /// Force logout all sessions of a user
    Logout {
        user_id: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_SESSION_TOKEN", hide_env_values = true)]
        token: String,
    },
    /// MFA recovery — disable MFA for a user
    MfaReset {
        user_id: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_SESSION_TOKEN", hide_env_values = true)]
        token: String,
    },
    /// Login (email + password) and print session token
    Login {
        email: String,
        password: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
    },
}

#[derive(Subcommand)]
pub enum SystemCommands {
    /// Initialize a new config
    Init,
    /// Validate config file
    Validate {
        #[arg(short, long, default_value = "xiranet.toml")]
        config: String,
    },
    /// Run diagnostics
    Doctor {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
    },
    /// Export to JSON
    Export {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
        #[arg(short, long, default_value = "xira-export.json")]
        output: String,
    },
    /// Import from JSON
    Import {
        file: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, env = "XIRA_API_KEY", hide_env_values = true, default_value = "")]
        key: String,
    },
    /// Generate TLS certificates
    GenerateCerts,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

/// Komut'tan key extract et — Subcommand'larda key ortak alan olmadığı için manuel.
fn command_key(cmd: &Commands) -> Option<&str> {
    match cmd {
        Commands::Status { key, .. }
        | Commands::Add { key, .. }
        | Commands::Remove { key, .. }
        | Commands::List { key, .. }
        | Commands::Health { key, .. }
        | Commands::Stats { key, .. }
        | Commands::CircuitBreakers { key, .. }
        | Commands::CacheClear { key, .. }
        | Commands::Logs { key, .. }
        | Commands::Export { key, .. }
        | Commands::Import { key, .. }
        | Commands::ProxyTest { key, .. } => Some(key.as_str()),
        Commands::Service(sc) => service_key(sc),
        Commands::Security(sc) => security_key(sc),
        Commands::Ops(sc) => ops_key(sc),
        Commands::System(sc) => system_key(sc),
        _ => None,
    }
}

fn service_key(s: &ServiceCommands) -> Option<&str> {
    match s {
        ServiceCommands::Add { key, .. }
        | ServiceCommands::Remove { key, .. }
        | ServiceCommands::List { key, .. }
        | ServiceCommands::Test { key, .. } => Some(key.as_str()),
    }
}

fn security_key(s: &SecurityCommands) -> Option<&str> {
    match s {
        SecurityCommands::Waf { key, .. } | SecurityCommands::Audit { key, .. } => {
            Some(key.as_str())
        }
    }
}

fn ops_key(s: &OpsCommands) -> Option<&str> {
    match s {
        OpsCommands::Stats { key, .. }
        | OpsCommands::Breakers { key, .. }
        | OpsCommands::Logs { key, .. }
        | OpsCommands::CacheClear { key, .. } => Some(key.as_str()),
        OpsCommands::Bench { .. } => None,
    }
}

fn system_key(s: &SystemCommands) -> Option<&str> {
    match s {
        SystemCommands::Export { key, .. } | SystemCommands::Import { key, .. } => {
            Some(key.as_str())
        }
        _ => None,
    }
}

pub async fn run_cli_command(cmd: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    // Erken kontrol: gerekli key var mı?
    if let Some(k) = command_key(cmd) {
        if k.is_empty() {
            return Err(
                "API key not provided. Set XIRA_API_KEY env variable, or pass --key <KEY>"
                    .into(),
            );
        }
    }

    let client = reqwest::Client::new();

    match cmd {
        Commands::Add {
            name,
            prefix,
            upstream,
            gateway,
            key,
            upstreams,
            load_balance,
            version,
        } => {
            let url = format!("{gateway}/xira/services");
            let resp = client
                .post(&url)
                .header("X-Api-Key", key.as_str())
                .json(&serde_json::json!({
                    "name": name, "prefix": prefix, "upstream": upstream,
                    "health_endpoint": "/health",
                    "upstreams": upstreams,
                    "load_balance": load_balance,
                    "version": version,
                }))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("✅ {}", serde_json::to_string_pretty(&body)?);
        }
        Commands::Remove { id, gateway, key } => {
            let resp = client
                .delete(format!("{gateway}/xira/services/{id}"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::List { gateway, key } => {
            let resp = client
                .get(format!("{gateway}/xira/services"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(data) = body.get("data") {
                if let Some(services) = data.get("services").and_then(|s| s.as_array()) {
                    if services.is_empty() {
                        println!("📭 No services registered");
                    } else {
                        println!("📋 Registered Services ({}):\n", services.len());
                        for svc in services {
                            let icon = match svc.get("status").and_then(|s| s.as_str()) {
                                Some("Up") => "🟢",
                                Some("Down") => "🔴",
                                _ => "⚪",
                            };
                            println!(
                                "  {} {} → {} [{}]",
                                icon,
                                svc.get("prefix").and_then(|p| p.as_str()).unwrap_or("?"),
                                svc.get("upstream").and_then(|u| u.as_str()).unwrap_or("?"),
                                svc.get("name").and_then(|n| n.as_str()).unwrap_or("?"),
                            );
                            if let Some(lb) = svc.get("load_balance").and_then(|l| l.as_str()) {
                                println!("    Load Balance: {lb}");
                            }
                            if let Some(ver) = svc.get("version").and_then(|v| v.as_str()) {
                                println!("    Version: v{ver}");
                            }
                            println!(
                                "    ID: {} | Requests: {}",
                                svc.get("id").and_then(|i| i.as_str()).unwrap_or("?"),
                                svc.get("request_count")
                                    .and_then(|r| r.as_u64())
                                    .unwrap_or(0),
                            );
                        }
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }
        Commands::Health { gateway, key } => {
            let resp = client
                .get(format!("{gateway}/xira/health"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!(
                "🏥 Gateway Health:\n{}",
                serde_json::to_string_pretty(&body)?
            );
        }
        Commands::Stats { gateway, key } => {
            let resp = client
                .get(format!("{gateway}/xira/stats"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(data) = body.get("data") {
                println!("📊 XIRA Stats:");
                println!(
                    "  Total Services:  {}",
                    data.get("total_services")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  🟢 UP:           {}",
                    data.get("services_up")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  🔴 DOWN:         {}",
                    data.get("services_down")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Total Requests:  {}",
                    data.get("total_requests")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Uptime:          {}s",
                    data.get("uptime_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }
        Commands::CircuitBreakers { gateway, key } => {
            let resp = client
                .get(format!("{gateway}/xira/circuit-breakers"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!(
                "⚡ Circuit Breakers:\n{}",
                serde_json::to_string_pretty(&body)?
            );
        }
        Commands::CacheClear { gateway, key } => {
            let resp = client
                .post(format!("{gateway}/xira/cache/clear"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("🗑️  {}", serde_json::to_string_pretty(&body)?);
        }

        // ═══ v3.0 — Deep config validation (semantic, security-aware) ═══
        Commands::Validate { config } => {
            println!("🔍 Validating config: {config}\n");
            if !std::path::Path::new(config).exists() {
                eprintln!("❌ Config file not found: {config}");
                std::process::exit(1);
            }
            let cfg = match crate::config::XiraConfig::load(config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("❌ Parse error: {e}");
                    std::process::exit(1);
                }
            };

            let report = cfg.validate();

            // Özet
            println!("  Gateway:     {}:{}", cfg.gateway.host, cfg.gateway.port);
            println!("  Workers:     {}", cfg.gateway.workers);
            println!("  Services:    {}", cfg.services.len());
            println!(
                "  JWT:         {} ({})",
                if cfg.jwt.enabled { "enabled" } else { "disabled" },
                cfg.jwt.algorithm,
            );
            println!(
                "  Cache:       {} ({} entries)",
                if cfg.cache.enabled { "enabled" } else { "disabled" },
                cfg.cache.max_entries
            );
            println!("  CORS origins: {}", cfg.cors.allowed_origins.len());
            println!(
                "  TLS:         {}",
                if cfg.tls.is_some() { "configured" } else { "disabled" }
            );
            println!(
                "  Rate Limit:  {}/{}s",
                cfg.rate_limit.max_requests, cfg.rate_limit.window_secs
            );

            // Errors
            if !report.errors.is_empty() {
                println!("\n❌ Errors ({}):", report.errors.len());
                for e in &report.errors {
                    println!("  • {e}");
                }
            }

            // Warnings
            if !report.warnings.is_empty() {
                println!("\n⚠️  Warnings ({}):", report.warnings.len());
                for w in &report.warnings {
                    println!("  • {w}");
                }
            }

            if report.ok() {
                if report.warnings.is_empty() {
                    println!("\n✅ Config is valid — no issues found.");
                } else {
                    println!("\n✅ Config is valid (with {} warning(s) above).", report.warnings.len());
                }
            } else {
                println!(
                    "\n❌ Config has {} blocking error(s) — server would refuse to start.",
                    report.errors.len()
                );
                std::process::exit(1);
            }
        }

        Commands::Status { gateway, key } => {
            println!("📡 XIRA Status ({gateway})\n");

            // Health
            let health = client
                .get(format!("{gateway}/xira/health"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await;
            match health {
                Ok(resp) => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    let status = body
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                    println!(
                        "  Gateway:     {} (v{})",
                        if status == "healthy" {
                            "🟢 HEALTHY"
                        } else {
                            "🔴 UNHEALTHY"
                        },
                        version
                    );
                    if let Some(uptime) = body.get("uptime_seconds").and_then(|u| u.as_u64()) {
                        let h = uptime / 3600;
                        let m = (uptime % 3600) / 60;
                        println!("  Uptime:      {h}h {m}m");
                    }
                }
                Err(e) => {
                    println!("  Gateway:     🔴 UNREACHABLE ({e})");
                    return Ok(());
                }
            }

            // Stats
            if let Ok(resp) = client
                .get(format!("{gateway}/xira/stats"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(data) = body.get("data") {
                        println!(
                            "  Services:    {} total ({} up, {} down)",
                            data.get("total_services")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            data.get("services_up")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            data.get("services_down")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                        );
                        println!(
                            "  Requests:    {}",
                            data.get("total_requests")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                    }
                }
            }

            // Services
            if let Ok(resp) = client
                .get(format!("{gateway}/xira/services"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(services) = body
                        .get("data")
                        .and_then(|d| d.get("services"))
                        .and_then(|s| s.as_array())
                    {
                        println!("\n  Services:");
                        for svc in services {
                            let icon = match svc.get("status").and_then(|s| s.as_str()) {
                                Some("Up") => "🟢",
                                Some("Down") => "🔴",
                                _ => "⚪",
                            };
                            println!(
                                "    {} {} → {} ({} reqs)",
                                icon,
                                svc.get("prefix").and_then(|p| p.as_str()).unwrap_or("?"),
                                svc.get("upstream").and_then(|u| u.as_str()).unwrap_or("?"),
                                svc.get("request_count")
                                    .and_then(|r| r.as_u64())
                                    .unwrap_or(0),
                            );
                        }
                    }
                }
            }
        }

        Commands::Logs { tail, gateway, key } => {
            let resp = client
                .get(format!("{gateway}/xira/log-stats"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;

            if let Some(logs) = body
                .get("data")
                .and_then(|d| d.get("recent_logs"))
                .and_then(|l| l.as_array())
            {
                let show = std::cmp::min(*tail, logs.len());
                println!("📋 Last {show} request logs:\n");
                for log in logs.iter().take(show) {
                    let method = log.get("method").and_then(|m| m.as_str()).unwrap_or("?");
                    let path = log.get("path").and_then(|p| p.as_str()).unwrap_or("?");
                    let status = log.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
                    let duration = log
                        .get("duration_ms")
                        .and_then(|d| d.as_f64())
                        .unwrap_or(0.0);
                    let ip = log.get("ip").and_then(|i| i.as_str()).unwrap_or("-");
                    let time = log.get("timestamp").and_then(|t| t.as_str()).unwrap_or("-");

                    let status_icon = if status >= 500 {
                        "🔴"
                    } else if status >= 400 {
                        "🟡"
                    } else {
                        "🟢"
                    };
                    println!(
                        "  {time} {status_icon} {method} {path} → {status} ({duration:.1}ms) [{ip}]"
                    );
                }
            } else {
                println!("📋 No logs available (log-stats endpoint may not return recent_logs)");
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }

        Commands::Bench {
            url,
            requests,
            concurrency,
        } => {
            println!(
                "🚀 Benchmarking {url} ({requests} requests, {concurrency} concurrent)\n"
            );

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?;

            let start = std::time::Instant::now();
            let mut durations: Vec<f64> = Vec::with_capacity(*requests);
            let mut success = 0u32;
            let mut errors = 0u32;
            let mut status_codes: std::collections::HashMap<u16, u32> =
                std::collections::HashMap::new();

            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(*concurrency));

            let mut handles = Vec::new();
            for _ in 0..*requests {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let client = client.clone();
                let url = url.clone();
                handles.push(tokio::spawn(async move {
                    let req_start = std::time::Instant::now();
                    let result = client.get(&url).send().await;
                    let duration = req_start.elapsed().as_secs_f64() * 1000.0;
                    drop(permit);
                    match result {
                        Ok(resp) => (true, resp.status().as_u16(), duration),
                        Err(_) => (false, 0, duration),
                    }
                }));
            }

            for handle in handles {
                if let Ok((ok, status, duration)) = handle.await {
                    durations.push(duration);
                    if ok {
                        success += 1;
                        *status_codes.entry(status).or_insert(0) += 1;
                    } else {
                        errors += 1;
                    }
                }
            }

            let total_time = start.elapsed().as_secs_f64();
            durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

            let avg = durations.iter().sum::<f64>() / durations.len() as f64;
            let p50 = durations[durations.len() / 2];
            let p95 = durations[(durations.len() as f64 * 0.95) as usize];
            let p99 = durations[(durations.len() as f64 * 0.99) as usize];
            let min = durations.first().copied().unwrap_or(0.0);
            let max = durations.last().copied().unwrap_or(0.0);

            println!("  Total Time:    {total_time:.2}s");
            println!("  Requests/sec:  {:.1}", *requests as f64 / total_time);
            println!(
                "  Success:       {} ({:.1}%)",
                success,
                success as f64 / *requests as f64 * 100.0
            );
            println!("  Errors:        {errors}");
            println!();
            println!("  Latency:");
            println!("    Min:    {min:.2}ms");
            println!("    Avg:    {avg:.2}ms");
            println!("    P50:    {p50:.2}ms");
            println!("    P95:    {p95:.2}ms");
            println!("    P99:    {p99:.2}ms");
            println!("    Max:    {max:.2}ms");
            println!();
            println!("  Status Codes:");
            let mut codes: Vec<_> = status_codes.iter().collect();
            codes.sort_by_key(|(k, _)| *k);
            for (code, count) in codes {
                println!("    {code}: {count}");
            }
        }

        Commands::Serve { .. } | Commands::GenerateCerts => {}

        // ═══ Nested subcommand dispatch ═══
        Commands::Service(sub) => match sub {
            ServiceCommands::List { gateway, key } => {
                return Box::pin(run_cli_command(&Commands::List {
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            ServiceCommands::Add {
                name,
                prefix,
                upstream,
                gateway,
                key,
                upstreams,
                load_balance,
                version,
            } => {
                return Box::pin(run_cli_command(&Commands::Add {
                    name: name.clone(),
                    prefix: prefix.clone(),
                    upstream: upstream.clone(),
                    gateway: gateway.clone(),
                    key: key.clone(),
                    upstreams: upstreams.clone(),
                    load_balance: load_balance.clone(),
                    version: version.clone(),
                }))
                .await;
            }
            ServiceCommands::Remove { id, gateway, key } => {
                return Box::pin(run_cli_command(&Commands::Remove {
                    id: id.clone(),
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            ServiceCommands::Test {
                path,
                method,
                gateway,
                key,
            } => {
                return Box::pin(run_cli_command(&Commands::ProxyTest {
                    path: path.clone(),
                    method: method.clone(),
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
        },

        Commands::Security(sub) => match sub {
            SecurityCommands::Audit { tail, gateway, key } => {
                return Box::pin(run_cli_command(&Commands::Logs {
                    tail: *tail,
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            SecurityCommands::Waf { gateway, key } => {
                let resp = client
                    .get(format!("{gateway}/xira/security/waf"))
                    .header("X-Api-Key", key.as_str())
                    .send()
                    .await?;
                let body: serde_json::Value = resp.json().await?;
                println!("🛡️  WAF Status:\n{}", serde_json::to_string_pretty(&body)?);
            }
        },

        Commands::Ops(sub) => match sub {
            OpsCommands::Stats { gateway, key } => {
                return Box::pin(run_cli_command(&Commands::Stats {
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            OpsCommands::Breakers { gateway, key } => {
                return Box::pin(run_cli_command(&Commands::CircuitBreakers {
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            OpsCommands::Logs { tail, gateway, key } => {
                return Box::pin(run_cli_command(&Commands::Logs {
                    tail: *tail,
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            OpsCommands::Bench {
                url,
                requests,
                concurrency,
            } => {
                return Box::pin(run_cli_command(&Commands::Bench {
                    url: url.clone(),
                    requests: *requests,
                    concurrency: *concurrency,
                }))
                .await;
            }
            OpsCommands::CacheClear { gateway, key } => {
                return Box::pin(run_cli_command(&Commands::CacheClear {
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
        },

        Commands::Admin(sub) => {
            let bearer = |t: &str| format!("Bearer {t}");
            match sub {
                AdminCommands::Users { gateway, token } => {
                    let resp = client
                        .get(format!("{gateway}/auth/admin/users"))
                        .header("Authorization", bearer(token))
                        .send()
                        .await?;
                    let status = resp.status();
                    let body: serde_json::Value = resp.json().await?;
                    if !status.is_success() {
                        println!("❌ {status}: {body}");
                        return Ok(());
                    }
                    if let Some(users) = body.get("users").and_then(|u| u.as_array()) {
                        println!("👤 Users ({}):", users.len());
                        for u in users {
                            let id = u.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                            let email = u.get("email").and_then(|v| v.as_str()).unwrap_or("?");
                            let role = u.get("role").and_then(|v| v.as_str()).unwrap_or("?");
                            let mfa = u
                                .get("mfa_enabled")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let enabled = u
                                .get("enabled")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true);
                            let status_icon = if !enabled { "🚫" } else { "🟢" };
                            let mfa_icon = if mfa { " 🔐" } else { "" };
                            println!("  {status_icon} {email}  [{role}]{mfa_icon}");
                            println!("     id: {id}");
                        }
                    }
                }
                AdminCommands::SetRole {
                    user_id,
                    role,
                    gateway,
                    token,
                } => {
                    let resp = client
                        .put(format!("{gateway}/auth/admin/users/{user_id}/role"))
                        .header("Authorization", bearer(token))
                        .json(&serde_json::json!({"role": role}))
                        .send()
                        .await?;
                    let status = resp.status();
                    let body: serde_json::Value = resp.json().await?;
                    if status.is_success() {
                        println!("✅ role updated to {role}");
                        println!("   sessions invalidated: {}",
                            body.get("sessions_invalidated").and_then(|v| v.as_u64()).unwrap_or(0));
                    } else {
                        println!("❌ {status}: {body}");
                    }
                }
                AdminCommands::Disable { user_id, gateway, token } => {
                    let resp = client
                        .post(format!("{gateway}/auth/admin/users/{user_id}/disable"))
                        .header("Authorization", bearer(token))
                        .send()
                        .await?;
                    let status = resp.status();
                    let body: serde_json::Value = resp.json().await?;
                    if status.is_success() {
                        println!("🚫 user disabled");
                        println!("   sessions invalidated: {}",
                            body.get("sessions_invalidated").and_then(|v| v.as_u64()).unwrap_or(0));
                    } else {
                        println!("❌ {status}: {body}");
                    }
                }
                AdminCommands::Logout { user_id, gateway, token } => {
                    let resp = client
                        .post(format!("{gateway}/auth/admin/users/{user_id}/logout-all"))
                        .header("Authorization", bearer(token))
                        .send()
                        .await?;
                    let status = resp.status();
                    let body: serde_json::Value = resp.json().await?;
                    if status.is_success() {
                        let n = body.get("invalidated").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("✅ {n} session(s) invalidated");
                    } else {
                        println!("❌ {status}: {body}");
                    }
                }
                AdminCommands::MfaReset { user_id, gateway, token } => {
                    let resp = client
                        .post(format!("{gateway}/auth/admin/users/{user_id}/mfa/disable"))
                        .header("Authorization", bearer(token))
                        .send()
                        .await?;
                    let status = resp.status();
                    let body: serde_json::Value = resp.json().await?;
                    if status.is_success() {
                        println!("🔓 MFA disabled (user must re-enroll)");
                    } else {
                        println!("❌ {status}: {body}");
                    }
                }
                AdminCommands::Login { email, password, gateway } => {
                    let resp = client
                        .post(format!("{gateway}/auth/login"))
                        .json(&serde_json::json!({
                            "email": email, "password": password,
                        }))
                        .send()
                        .await?;
                    let status = resp.status();
                    let body: serde_json::Value = resp.json().await?;
                    if !status.is_success() {
                        println!("❌ {status}: {body}");
                        return Ok(());
                    }
                    if body.get("mfa_required").and_then(|v| v.as_bool()) == Some(true) {
                        let uid = body
                            .get("user_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        println!("🔐 MFA required");
                        println!("   user_id: {uid}");
                        println!("   POST /auth/mfa/login → {{user_id, code}} ile devam et.");
                    } else if let Some(token) = body.get("token").and_then(|v| v.as_str()) {
                        let exp = body
                            .get("expires_at")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        println!("✅ logged in as {email}");
                        println!("   token: {token}");
                        println!("   export XIRA_SESSION_TOKEN={token}");
                        println!("   expires_at: {exp}");
                    } else {
                        println!("? unexpected response: {body}");
                    }
                }
            }
        }

        Commands::System(sub) => match sub {
            SystemCommands::Init => {
                return Box::pin(run_cli_command(&Commands::Init)).await;
            }
            SystemCommands::Validate { config } => {
                return Box::pin(run_cli_command(&Commands::Validate {
                    config: config.clone(),
                }))
                .await;
            }
            SystemCommands::Doctor { gateway } => {
                return Box::pin(run_cli_command(&Commands::Doctor {
                    gateway: gateway.clone(),
                }))
                .await;
            }
            SystemCommands::Export {
                gateway,
                key,
                output,
            } => {
                return Box::pin(run_cli_command(&Commands::Export {
                    gateway: gateway.clone(),
                    key: key.clone(),
                    output: output.clone(),
                }))
                .await;
            }
            SystemCommands::Import { file, gateway, key } => {
                return Box::pin(run_cli_command(&Commands::Import {
                    file: file.clone(),
                    gateway: gateway.clone(),
                    key: key.clone(),
                }))
                .await;
            }
            SystemCommands::GenerateCerts => {}
        },

        // ═══ v1.0.3 — New CLI Commands ═══
        Commands::Init => {
            let template = r#"# XIRA Platform Configuration
[gateway]
host = "0.0.0.0"
port = 9000
workers = 4

[rate_limit]
max_requests = 100
window_secs = 60

[health]
interval_secs = 30
timeout_secs = 5

[cache]
enabled = true
ttl_secs = 300
max_entries = 1000

[jwt]
enabled = false
secret = "change-me"

[auth]
api_key = "xira-secret-key-change-me"

[alerting]
enabled = false

[plugins]
enabled = true
directory = "plugins"

[grpc]
enabled = false
port = 9001

[[services]]
name = "my-api"
prefix = "/api"
upstream = "http://localhost:3001"
health_endpoint = "/health"
"#;
            if std::path::Path::new("xiranet.toml").exists() {
                println!("⚠️  xiranet.toml already exists! Use --force to overwrite.");
            } else {
                std::fs::write("xiranet.toml", template).expect("Failed to write");
                println!("✅ xiranet.toml created!");
                println!("   Edit the file, then run: xira serve");
            }
        }

        Commands::Doctor { gateway } => {
            println!("🩺 XIRA Doctor\n");

            let mut errors: Vec<String> = Vec::new();
            let mut warnings: Vec<String> = Vec::new();

            // ─── Environment ─────────────────────────────────────────
            println!("Environment:");
            print!("  XIRA_SECRETS_KEY:  ");
            match std::env::var("XIRA_SECRETS_KEY") {
                Ok(v) if v.len() >= 32 => println!("🟢 set ({} bytes)", v.len()),
                Ok(v) => {
                    println!("🔴 too short ({} bytes, need >= 32)", v.len());
                    errors.push("XIRA_SECRETS_KEY is set but too short".into());
                }
                Err(_) => {
                    println!("🟡 not set — MFA seed'leri düz metin saklanır");
                    warnings.push("XIRA_SECRETS_KEY not set (MFA at-rest encryption disabled)".into());
                }
            }
            print!("  XIRA_DB_PATH:      ");
            match std::env::var("XIRA_DB_PATH") {
                Ok(p) => println!("🟢 {p}"),
                Err(_) => println!("⚪ default (data/xiranet.db)"),
            }
            print!("  XIRA_API_KEY:      ");
            match std::env::var("XIRA_API_KEY") {
                Ok(_) => println!("🟢 set"),
                Err(_) => println!("⚪ not set (CLI komutları --key gerektirir)"),
            }

            // ─── Config ──────────────────────────────────────────────
            println!("\nConfig:");
            print!("  xiranet.toml:      ");
            if std::path::Path::new("xiranet.toml").exists() {
                println!("🟢 found");
                match crate::config::XiraConfig::load("xiranet.toml") {
                    Ok(cfg) => {
                        let r = cfg.validate();
                        if r.ok() {
                            if r.warnings.is_empty() {
                                println!("  Validation:        🟢 clean");
                            } else {
                                println!(
                                    "  Validation:        🟡 {} warning(s)",
                                    r.warnings.len()
                                );
                                for w in &r.warnings {
                                    println!("    • {w}");
                                    warnings.push(w.clone());
                                }
                            }
                        } else {
                            println!(
                                "  Validation:        🔴 {} blocking error(s)",
                                r.errors.len()
                            );
                            for e in &r.errors {
                                println!("    • {e}");
                                errors.push(e.clone());
                            }
                        }
                    }
                    Err(e) => {
                        println!("  Validation:        🔴 parse error: {e}");
                        errors.push(format!("config parse: {e}"));
                    }
                }
            } else {
                println!("🔴 not found (run: xira system init)");
                errors.push("xiranet.toml not found".into());
            }

            // ─── Filesystem ──────────────────────────────────────────
            println!("\nFilesystem:");
            let db_path = std::env::var("XIRA_DB_PATH")
                .unwrap_or_else(|_| "data/xiranet.db".to_string());
            print!("  SQLite ({db_path}): ");
            if std::path::Path::new(&db_path).exists() {
                // Write check
                match std::fs::OpenOptions::new().append(true).open(&db_path) {
                    Ok(_) => println!("🟢 writable"),
                    Err(_) => {
                        println!("🔴 exists but not writable");
                        errors.push(format!("{db_path} not writable"));
                    }
                }
            } else {
                let parent = std::path::Path::new(&db_path)
                    .parent()
                    .unwrap_or(std::path::Path::new("."));
                if parent.exists() {
                    println!("⚪ will be created on first run");
                } else {
                    println!("🟡 parent dir missing: {}", parent.display());
                    warnings.push(format!("DB parent dir missing: {}", parent.display()));
                }
            }
            print!("  logs/:             ");
            if std::path::Path::new("logs").exists() {
                println!("🟢 found");
            } else {
                println!("⚪ will be created on first run");
            }

            // ─── Live gateway ────────────────────────────────────────
            println!("\nLive gateway ({gateway}):");
            print!("  Port reachable:    ");
            let port = gateway
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(9000);
            let host = gateway
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| "127.0.0.1".to_string());
            match std::net::TcpStream::connect_timeout(
                &format!("{host}:{port}").parse().unwrap_or_else(|_| {
                    "127.0.0.1:0".parse().unwrap()
                }),
                std::time::Duration::from_secs(2),
            ) {
                Ok(_) => println!("🟢 yes"),
                Err(_) => {
                    println!("🔴 no — gateway not running?");
                    warnings.push(format!("{gateway} not reachable"));
                }
            }

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap();

            print!("  /health:           ");
            match client.get(format!("{gateway}/health")).send().await {
                Ok(resp) if resp.status().is_success() => println!("🟢 200"),
                Ok(resp) => println!("🟡 HTTP {}", resp.status()),
                Err(_) => println!("🔴 unreachable"),
            }

            print!("  /metrics:          ");
            match client.get(format!("{gateway}/metrics")).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.text().await.unwrap_or_default();
                    let has_audit = body.contains("xiranet_auth_rejects_total")
                        && body.contains("xiranet_ssrf_rejects_total")
                        && body.contains("xiranet_session_events_total");
                    if has_audit {
                        println!("🟢 v3.0 audit counters present");
                    } else {
                        println!(
                            "🟡 200 but missing v3.0 counters (stale binary? size={})",
                            body.len()
                        );
                        warnings.push("metrics endpoint lacks v3.0 audit counters".into());
                    }
                }
                Ok(resp) => println!("🟡 HTTP {}", resp.status()),
                Err(_) => println!("🔴 unreachable"),
            }

            print!("  Admin auth:        ");
            // No-key request must 401 (K3 fix verification)
            match client.get(format!("{gateway}/xira/services")).send().await {
                Ok(resp) if resp.status().as_u16() == 401 => {
                    println!("🟢 no-key → 401 (constant-time API key compare active)")
                }
                Ok(resp) => {
                    println!("🔴 no-key → HTTP {} (expected 401)", resp.status());
                    errors.push(format!(
                        "admin endpoint no-key returned {} (security regression)",
                        resp.status()
                    ));
                }
                Err(_) => println!("⚪ gateway not running"),
            }

            // ─── Version ──────────────────────────────────────────────
            println!("\n  xiranet:           v{}", env!("CARGO_PKG_VERSION"));

            // ─── Summary ──────────────────────────────────────────────
            println!();
            if errors.is_empty() && warnings.is_empty() {
                println!("✅ All checks passed.");
            } else {
                if !errors.is_empty() {
                    println!("❌ {} error(s) — gateway will not start or is misbehaving.", errors.len());
                }
                if !warnings.is_empty() {
                    println!("⚠️  {} warning(s) — review before production.", warnings.len());
                }
                if !errors.is_empty() {
                    std::process::exit(1);
                }
            }
        }

        Commands::Export {
            gateway,
            key,
            output,
        } => {
            println!("📦 Exporting from {gateway} ...");

            let mut export = serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "exported_at": chrono::Utc::now().to_rfc3339()});

            if let Ok(resp) = client
                .get(format!("{gateway}/xira/services"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    export["services"] = body;
                }
            }
            if let Ok(resp) = client
                .get(format!("{gateway}/xira/config"))
                .header("X-Api-Key", key.as_str())
                .send()
                .await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    export["config"] = body;
                }
            }

            std::fs::write(output, serde_json::to_string_pretty(&export)?)?;
            println!("✅ Exported to {output}");
        }

        Commands::Import { file, gateway, key } => {
            println!("📥 Importing from {file} ...");
            let content = std::fs::read_to_string(file)?;
            let data: serde_json::Value = serde_json::from_str(&content)?;

            if let Some(services) = data
                .get("services")
                .and_then(|s| s.get("data"))
                .and_then(|d| d.get("services"))
                .and_then(|s| s.as_array())
            {
                let mut imported = 0;
                for svc in services {
                    let name = svc
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    let prefix = svc.get("prefix").and_then(|p| p.as_str()).unwrap_or("/");
                    let upstream = svc.get("upstream").and_then(|u| u.as_str()).unwrap_or("");

                    if upstream.is_empty() {
                        continue;
                    }

                    match client.post(format!("{gateway}/xira/services"))
                        .header("X-Api-Key", key.as_str())
                        .json(&serde_json::json!({"name": name, "prefix": prefix, "upstream": upstream, "health_endpoint": "/health"}))
                        .send().await {
                        Ok(_) => { imported += 1; println!("  ✅ {prefix} → {upstream}"); },
                        Err(e) => println!("  ❌ {name} — {e}"),
                    }
                }
                println!("\n📦 Imported {imported} services");
            } else {
                println!("❌ No services found in import file");
            }
        }

        Commands::ProxyTest {
            path,
            method,
            gateway,
            key,
        } => {
            let url = format!("{gateway}{path}");
            println!("🧪 Testing {method} {url} ...\n");

            let start = std::time::Instant::now();
            let resp = match method.to_uppercase().as_str() {
                "POST" => {
                    client
                        .post(&url)
                        .header("X-Api-Key", key.as_str())
                        .send()
                        .await
                }
                "PUT" => {
                    client
                        .put(&url)
                        .header("X-Api-Key", key.as_str())
                        .send()
                        .await
                }
                "DELETE" => {
                    client
                        .delete(&url)
                        .header("X-Api-Key", key.as_str())
                        .send()
                        .await
                }
                _ => {
                    client
                        .get(&url)
                        .header("X-Api-Key", key.as_str())
                        .send()
                        .await
                }
            };
            let duration = start.elapsed();

            match resp {
                Ok(resp) => {
                    let status = resp.status();
                    let headers: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("-").to_string()))
                        .collect();
                    let body = resp.text().await.unwrap_or_default();

                    let icon = if status.is_success() {
                        "🟢"
                    } else if status.is_client_error() {
                        "🟡"
                    } else {
                        "🔴"
                    };
                    println!("  {icon} Status:   {status}");
                    println!("  ⏱ Duration:  {:.2}ms", duration.as_secs_f64() * 1000.0);
                    println!("  📏 Body:     {} bytes", body.len());

                    // Key response headers
                    for (k, v) in &headers {
                        if k.starts_with("x-") || k == "content-type" {
                            println!("  📎 {k}: {v}");
                        }
                    }

                    if body.len() < 500 {
                        println!("\n  Response:\n  {body}");
                    } else {
                        println!("\n  Response (first 500 chars):\n  {}...", &body[..500]);
                    }
                }
                Err(e) => println!("  🔴 Error: {e}"),
            }
        }
    }
    Ok(())
}
