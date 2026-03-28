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
    /// Yeni proje için xiranet.toml template oluştur
    Init,
    /// Sistem bağımlılıkları kontrol (port, SQLite, network)
    Doctor {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
    },
    /// Tüm config + servisleri JSON'a export et
    Export {
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
        /// Çıktı dosyası
        #[arg(short, long, default_value = "xiranet-export.json")]
        output: String,
    },
    /// JSON'dan servisleri toplu import et
    Import {
        /// JSON dosya yolu
        file: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
    },
    /// Belirli servise test request gönder
    ProxyTest {
        /// Test URL (ör: /api/health)
        path: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long, default_value = "http://localhost:9000")]
        gateway: String,
        #[arg(short, long, default_value = "xira-secret-key-change-me")]
        key: String,
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
            let resp = client.delete(format!("{}/xira/services/{}", gateway, id))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::List { gateway, key } => {
            let resp = client.get(format!("{}/xira/services", gateway))
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
            let resp = client.get(format!("{}/xira/health", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("🏥 Gateway Health:\n{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::Stats { gateway, key } => {
            let resp = client.get(format!("{}/xira/stats", gateway))
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
            let resp = client.get(format!("{}/xira/circuit-breakers", gateway))
                .header("X-Api-Key", key.as_str()).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("⚡ Circuit Breakers:\n{}", serde_json::to_string_pretty(&body)?);
        }
        Commands::CacheClear { gateway, key } => {
            let resp = client.post(format!("{}/xira/cache/clear", gateway))
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
            let health = client.get(format!("{}/xira/health", gateway))
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
            if let Ok(resp) = client.get(format!("{}/xira/stats", gateway))
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
            if let Ok(resp) = client.get(format!("{}/xira/services", gateway))
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
            let resp = client.get(format!("{}/xira/log-stats", gateway))
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

        // ═══ v1.0.3 — New CLI Commands ═══

        Commands::Init => {
            let template = r#"# xiraNET Configuration
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
            println!("🩺 xiraNET Doctor\n");

            // Port check
            print!("  Port 9000:     ");
            match std::net::TcpStream::connect("127.0.0.1:9000") {
                Ok(_) => println!("🟢 IN USE (gateway running)"),
                Err(_) => println!("⚪ AVAILABLE"),
            }

            // Config check
            print!("  Config:        ");
            if std::path::Path::new("xiranet.toml").exists() {
                println!("🟢 Found (xiranet.toml)");
            } else {
                println!("🔴 Not found (run: xira init)");
            }

            // SQLite check
            print!("  SQLite:        ");
            if std::path::Path::new("data/xiranet.db").exists() {
                println!("🟢 Found (data/xiranet.db)");
            } else {
                println!("⚪ Will be created on first run");
            }

            // Gateway connectivity
            print!("  Gateway API:   ");
            match reqwest::Client::new().get(format!("{}/xira/health", gateway)).send().await {
                Ok(resp) if resp.status().is_success() => println!("🟢 Healthy"),
                Ok(resp) => println!("🟡 Responding (HTTP {})", resp.status()),
                Err(_) => println!("🔴 Unreachable ({})", gateway),
            }

            // Logs directory
            print!("  Logs dir:      ");
            if std::path::Path::new("logs").exists() {
                println!("🟢 Found");
            } else {
                println!("⚪ Will be created on first run");
            }

            println!("\n  Version:       v{}", env!("CARGO_PKG_VERSION"));
        }

        Commands::Export { gateway, key, output } => {
            println!("📦 Exporting from {} ...", gateway);

            let mut export = serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "exported_at": chrono::Utc::now().to_rfc3339()});

            if let Ok(resp) = client.get(format!("{}/xira/services", gateway)).header("X-Api-Key", key.as_str()).send().await {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    export["services"] = body;
                }
            }
            if let Ok(resp) = client.get(format!("{}/xira/config", gateway)).header("X-Api-Key", key.as_str()).send().await {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    export["config"] = body;
                }
            }

            std::fs::write(output, serde_json::to_string_pretty(&export)?)?;
            println!("✅ Exported to {}", output);
        }

        Commands::Import { file, gateway, key } => {
            println!("📥 Importing from {} ...", file);
            let content = std::fs::read_to_string(file)?;
            let data: serde_json::Value = serde_json::from_str(&content)?;

            if let Some(services) = data.get("services").and_then(|s| s.get("data")).and_then(|d| d.get("services")).and_then(|s| s.as_array()) {
                let mut imported = 0;
                for svc in services {
                    let name = svc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                    let prefix = svc.get("prefix").and_then(|p| p.as_str()).unwrap_or("/");
                    let upstream = svc.get("upstream").and_then(|u| u.as_str()).unwrap_or("");

                    if upstream.is_empty() { continue; }

                    match client.post(format!("{}/xira/services", gateway))
                        .header("X-Api-Key", key.as_str())
                        .json(&serde_json::json!({"name": name, "prefix": prefix, "upstream": upstream, "health_endpoint": "/health"}))
                        .send().await {
                        Ok(_) => { imported += 1; println!("  ✅ {} → {}", prefix, upstream); },
                        Err(e) => println!("  ❌ {} — {}", name, e),
                    }
                }
                println!("\n📦 Imported {} services", imported);
            } else {
                println!("❌ No services found in import file");
            }
        }

        Commands::ProxyTest { path, method, gateway, key } => {
            let url = format!("{}{}", gateway, path);
            println!("🧪 Testing {} {} ...\n", method, url);

            let start = std::time::Instant::now();
            let resp = match method.to_uppercase().as_str() {
                "POST" => client.post(&url).header("X-Api-Key", key.as_str()).send().await,
                "PUT" => client.put(&url).header("X-Api-Key", key.as_str()).send().await,
                "DELETE" => client.delete(&url).header("X-Api-Key", key.as_str()).send().await,
                _ => client.get(&url).header("X-Api-Key", key.as_str()).send().await,
            };
            let duration = start.elapsed();

            match resp {
                Ok(resp) => {
                    let status = resp.status();
                    let headers: Vec<(String, String)> = resp.headers().iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("-").to_string()))
                        .collect();
                    let body = resp.text().await.unwrap_or_default();

                    let icon = if status.is_success() { "🟢" } else if status.is_client_error() { "🟡" } else { "🔴" };
                    println!("  {} Status:   {}", icon, status);
                    println!("  ⏱ Duration:  {:.2}ms", duration.as_secs_f64() * 1000.0);
                    println!("  📏 Body:     {} bytes", body.len());

                    // Key response headers
                    for (k, v) in &headers {
                        if k.starts_with("x-") || k == "content-type" {
                            println!("  📎 {}: {}", k, v);
                        }
                    }

                    if body.len() < 500 {
                        println!("\n  Response:\n  {}", body);
                    } else {
                        println!("\n  Response (first 500 chars):\n  {}...", &body[..500]);
                    }
                },
                Err(e) => println!("  🔴 Error: {}", e),
            }
        }
    }
    Ok(())
}
