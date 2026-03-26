use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xiranet", about = "xiraNET — Central Infrastructure Hub", version, author)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// xiraNET gateway sunucusunu başlat
    Serve {
        #[arg(short, long, default_value = "xiranet.toml")]
        config: String,
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Servis ekle
    Add {
        name: String,
        prefix: String,
        upstream: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
        /// Ek upstream'ler (load balancing)
        #[arg(long)]
        upstreams: Vec<String>,
        /// Load balance stratejisi
        #[arg(long)]
        load_balance: Option<String>,
        /// API versiyonu
        #[arg(long)]
        version: Option<String>,
    },
    /// Servis kaldır
    Remove {
        id: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Servisleri listele
    List {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Sağlık durumu
    Health {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// İstatistikler
    Stats {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Circuit breaker durumları
    CircuitBreakers {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Cache temizle
    CacheClear {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// TLS sertifika oluşturma yardımı
    GenerateCerts,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

pub async fn run_cli_command(cmd: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    match cmd {
        Commands::Add { name, prefix, upstream, gateway, key, upstreams, load_balance, version } => {
            let url = format!("{}/xira/services", gateway);
            let resp = client.post(&url)
                .header("X-Api-Key", key.as_str())
                .json(&serde_json::json!({
                    "name": name, "prefix": prefix, "upstream": upstream,
                    "health_endpoint": "/health",
                    "upstreams": upstreams,
                    "load_balance": load_balance,
                    "version": version,
                }))
                .send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("✅ {}", serde_json::to_string_pretty(&body)?);
        }
        Commands::Remove { id, gateway, key } => {
            let resp = client.delete(&format!("{}/xira/services/{}", gateway, id))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::List { gateway, key } => {
            let resp = client.get(&format!("{}/xira/services", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(data) = body.get("data") {
                if let Some(services) = data.get("services").and_then(|s| s.as_array()) {
                    if services.is_empty() {
                        println!("📭 No services registered");
                    } else {
                        println!("📋 Registered Services ({}):\n", services.len());
                        for svc in services {
                            let icon = match svc.get("status").and_then(|s| s.as_str()) {
                                Some("Up") => "🟢", Some("Down") => "🔴", _ => "⚪",
                            };
                            println!("  {} {} → {} [{}]",
                                icon,
                                svc.get("prefix").and_then(|p| p.as_str()).unwrap_or("?"),
                                svc.get("upstream").and_then(|u| u.as_str()).unwrap_or("?"),
                                svc.get("name").and_then(|n| n.as_str()).unwrap_or("?"),
                            );
                            if let Some(lb) = svc.get("load_balance").and_then(|l| l.as_str()) {
                                println!("    Load Balance: {}", lb);
                            }
                            if let Some(ver) = svc.get("version").and_then(|v| v.as_str()) {
                                println!("    Version: v{}", ver);
                            }
                            println!("    ID: {} | Requests: {}",
                                svc.get("id").and_then(|i| i.as_str()).unwrap_or("?"),
                                svc.get("request_count").and_then(|r| r.as_u64()).unwrap_or(0),
                            );
                        }
                    }
                }
            } else { println!("{}", serde_json::to_string_pretty(&body)?); }
        }
        Commands::Health { gateway, key } => {
            let resp = client.get(&format!("{}/xira/health", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("🏥 Gateway Health:\n{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::Stats { gateway, key } => {
            let resp = client.get(&format!("{}/xira/stats", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(data) = body.get("data") {
                println!("📊 xiraNET Stats:");
                println!("  Total Services:  {}", data.get("total_services").and_then(|v| v.as_u64()).unwrap_or(0));
                println!("  🟢 UP:           {}", data.get("services_up").and_then(|v| v.as_u64()).unwrap_or(0));
                println!("  🔴 DOWN:         {}", data.get("services_down").and_then(|v| v.as_u64()).unwrap_or(0));
                println!("  Total Requests:  {}", data.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(0));
                println!("  Uptime:          {}s", data.get("uptime_seconds").and_then(|v| v.as_u64()).unwrap_or(0));
            } else { println!("{}", serde_json::to_string_pretty(&body)?); }
        }
        Commands::CircuitBreakers { gateway, key } => {
            let resp = client.get(&format!("{}/xira/circuit-breakers", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("⚡ Circuit Breakers:\n{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::CacheClear { gateway, key } => {
            let resp = client.post(&format!("{}/xira/cache/clear", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("🗑️  {}", serde_json::to_string_pretty(&body)?);
        }
        Commands::Serve { .. } | Commands::GenerateCerts => {}
    }
    Ok(())
}
