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
        #[arg(long)]
        upstreams: Vec<String>,
        #[arg(long)]
        load_balance: Option<String>,
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
    /// Config dosyasını doğrula
    Validate {
        #[arg(short, long, default_value = "xiranet.toml")]
        config: String,
    },
    /// Gateway durumunu göster (servise bağlanır)
    Status {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Son request loglarını göster
    Logs {
        /// Gösterilecek log sayısı
        #[arg(short = 'n', long, default_value = "20")]
        tail: usize,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Basit load test (benchmark)
    Bench {
        /// Hedef URL
        url: String,
        /// Toplam istek sayısı
        #[arg(short = 'n', long, default_value = "100")]
        requests: usize,
        /// Eşzamanlı istek sayısı
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
    },
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

        // ═══ v1.0.1 — New Commands ═══

        Commands::Validate { config } => {
            println!("🔍 Validating config: {}", config);
            if !std::path::Path::new(config).exists() {
                println!("❌ Config file not found: {}", config);
                return Ok(());
            }
            match crate::config::XiraConfig::load(config) {
                Ok(cfg) => {
                    println!("✅ Config is valid!");
                    println!("  Gateway:     {}:{}", cfg.gateway.host, cfg.gateway.port);
                    println!("  Workers:     {}", cfg.gateway.workers);
                    println!("  Services:    {}", cfg.services.len());
                    println!("  JWT:         {}", if cfg.jwt.enabled { "enabled" } else { "disabled" });
                    println!("  Cache:       {}", if cfg.cache.enabled { "enabled" } else { "disabled" });
                    let grpc_str = if cfg.grpc.enabled { format!("port {}", cfg.grpc.port) } else { "disabled".to_string() };
                    println!("  gRPC:        {}", grpc_str);
                    println!("  TLS:         {}", if cfg.tls.is_some() { "configured" } else { "disabled" });
                    println!("  Rate Limit:  {}/{}s", cfg.rate_limit.max_requests, cfg.rate_limit.window_secs);
                }
                Err(e) => {
                    println!("❌ Config validation failed: {}", e);
                }
            }
        }

        Commands::Status { gateway, key } => {
            println!("📡 xiraNET Status ({})\n", gateway);

            // Health
            let health = client.get(&format!("{}/xira/health", gateway))
                .header("X-Api-Key", key.as_str()).send().await;
            match health {
                Ok(resp) => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    let status = body.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
                    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("  Gateway:     {} (v{})", if status == "healthy" { "🟢 HEALTHY" } else { "🔴 UNHEALTHY" }, version);
                    if let Some(uptime) = body.get("uptime_seconds").and_then(|u| u.as_u64()) {
                        let h = uptime / 3600;
                        let m = (uptime % 3600) / 60;
                        println!("  Uptime:      {}h {}m", h, m);
                    }
                }
                Err(e) => {
                    println!("  Gateway:     🔴 UNREACHABLE ({})", e);
                    return Ok(());
                }
            }

            // Stats
            if let Ok(resp) = client.get(&format!("{}/xira/stats", gateway))
                .header("X-Api-Key", key.as_str()).send().await {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(data) = body.get("data") {
                        println!("  Services:    {} total ({} up, {} down)",
                            data.get("total_services").and_then(|v| v.as_u64()).unwrap_or(0),
                            data.get("services_up").and_then(|v| v.as_u64()).unwrap_or(0),
                            data.get("services_down").and_then(|v| v.as_u64()).unwrap_or(0),
                        );
                        println!("  Requests:    {}", data.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(0));
                    }
                }
            }

            // Services
            if let Ok(resp) = client.get(&format!("{}/xira/services", gateway))
                .header("X-Api-Key", key.as_str()).send().await {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(services) = body.get("data").and_then(|d| d.get("services")).and_then(|s| s.as_array()) {
                        println!("\n  Services:");
                        for svc in services {
                            let icon = match svc.get("status").and_then(|s| s.as_str()) {
                                Some("Up") => "🟢", Some("Down") => "🔴", _ => "⚪",
                            };
                            println!("    {} {} → {} ({} reqs)",
                                icon,
                                svc.get("prefix").and_then(|p| p.as_str()).unwrap_or("?"),
                                svc.get("upstream").and_then(|u| u.as_str()).unwrap_or("?"),
                                svc.get("request_count").and_then(|r| r.as_u64()).unwrap_or(0),
                            );
                        }
                    }
                }
            }
        }

        Commands::Logs { tail, gateway, key } => {
            let resp = client.get(&format!("{}/xira/log-stats", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;

            if let Some(logs) = body.get("data").and_then(|d| d.get("recent_logs")).and_then(|l| l.as_array()) {
                let show = std::cmp::min(*tail, logs.len());
                println!("📋 Last {} request logs:\n", show);
                for log in logs.iter().take(show) {
                    let method = log.get("method").and_then(|m| m.as_str()).unwrap_or("?");
                    let path = log.get("path").and_then(|p| p.as_str()).unwrap_or("?");
                    let status = log.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
                    let duration = log.get("duration_ms").and_then(|d| d.as_f64()).unwrap_or(0.0);
                    let ip = log.get("ip").and_then(|i| i.as_str()).unwrap_or("-");
                    let time = log.get("timestamp").and_then(|t| t.as_str()).unwrap_or("-");

                    let status_icon = if status >= 500 { "🔴" } else if status >= 400 { "🟡" } else { "🟢" };
                    println!("  {} {} {} {} → {} ({:.1}ms) [{}]",
                        time, status_icon, method, path, status, duration, ip);
                }
            } else {
                println!("📋 No logs available (log-stats endpoint may not return recent_logs)");
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }

        Commands::Bench { url, requests, concurrency } => {
            println!("🚀 Benchmarking {} ({} requests, {} concurrent)\n", url, requests, concurrency);

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?;

            let start = std::time::Instant::now();
            let mut durations: Vec<f64> = Vec::with_capacity(*requests);
            let mut success = 0u32;
            let mut errors = 0u32;
            let mut status_codes: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();

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

            println!("  Total Time:    {:.2}s", total_time);
            println!("  Requests/sec:  {:.1}", *requests as f64 / total_time);
            println!("  Success:       {} ({:.1}%)", success, success as f64 / *requests as f64 * 100.0);
            println!("  Errors:        {}", errors);
            println!();
            println!("  Latency:");
            println!("    Min:    {:.2}ms", min);
            println!("    Avg:    {:.2}ms", avg);
            println!("    P50:    {:.2}ms", p50);
            println!("    P95:    {:.2}ms", p95);
            println!("    P99:    {:.2}ms", p99);
            println!("    Max:    {:.2}ms", max);
            println!();
            println!("  Status Codes:");
            let mut codes: Vec<_> = status_codes.iter().collect();
            codes.sort_by_key(|(k, _)| *k);
            for (code, count) in codes {
                println!("    {}: {}", code, count);
            }
        }

        Commands::Serve { .. } | Commands::GenerateCerts => {}
    }
    Ok(())
}
