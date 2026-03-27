# xiraNET — Central Infrastructure Hub

```
    ██╗  ██╗██╗██████╗  █████╗ ███╗   ██╗███████╗████████╗
    ╚██╗██╔╝██║██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
     ╚███╔╝ ██║██████╔╝███████║██╔██╗ ██║█████╗     ██║   
     ██╔██╗ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══╝     ██║   
    ██╔╝ ██╗██║██║  ██║██║  ██║██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

**v2.0.0** — Production-grade API Gateway + Identity + Automation + Observability + Deployment + Security

Tüm projelerinizi tek bir merkezden yönetin. Runtime'da servis bağlayın, WAF/Bot koruması, SLA izleme, cron otomasyonu ve olay yönetimi tek yerden.

## Kurulum

```bash
# Rust yüklü olmalı (https://rustup.rs)
cd xiraNET
cargo build --release

# Binary'yi path'e kopyala
cp target/release/xiranet ~/.local/bin/xira
```

## Hızlı Başlangıç

```bash
# Gateway'i başlat
xira serve

# Servis bağla
xira add my-api /api http://localhost:3001
xira add my-frontend /app http://localhost:8080

# Tüm istekler xiraNET üzerinden
curl http://localhost:9000/api/users        # → localhost:3001/users
curl http://localhost:9000/app/index.html   # → localhost:8080/index.html

# Yönetim
xira list     # Servisleri listele
xira stats    # İstatistikler
xira health   # Sağlık durumu
```

## Mimari

```
                    ┌─────────────────────────────────────────────────────┐
                    │                   xiraNET v2.0.0                    │
                    │              Central Infrastructure Hub             │
                    ├─────────────────────────────────────────────────────┤
                    │                                                     │
  Request ──────►   │  WAF ► Bot Detection ► IP Filter ► Validation       │
                    │     ► Circuit Breaker ► Cache ► Load Balancer        │
                    │     ► Transform ► Retry/Proxy ► Metrics             │
                    │     ► Health Scoring ► Audit Log ► EventBus          │
                    │                                                     │
  Response ◄────   │                                                     │
                    ├─────────────┬──────────────┬────────────────────────┤
                    │  Identity   │  Automation   │    Observability       │
                    │  Users/RBAC │  Cron/Events  │    Logs/Uptime/SLA    │
                    ├─────────────┼──────────────┼────────────────────────┤
                    │  DB Gateway │  Deployment   │    Data Pipeline       │
                    │  SQL Firewall│ Feature Flags │    CDC/Analytics      │
                    └─────────────┴──────────────┴────────────────────────┘
```

## Konfigürasyon (xiranet.toml)

```toml
[gateway]
host = "0.0.0.0"
port = 9000

[admin]
api_key = "xira-secret-key-change-me"
enabled = true

[health]
interval_secs = 30
timeout_secs = 5

[cache]
enabled = true
max_entries = 5000
ttl_secs = 300

[jwt]
enabled = false
secret = "change-me"

[alerting]
enabled = true
webhook_url = "https://hooks.slack.com/..."

[[services]]
name = "my-api"
prefix = "/api"
upstream = "http://localhost:3001"
health_endpoint = "/health"
```

## Admin API (49 Endpoint)

Tüm admin endpoint'leri `X-Api-Key` header gerektirir.

### Core

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/services` | Tüm servisleri listele |
| `POST` | `/xira/services` | Yeni servis kaydet |
| `DELETE` | `/xira/services/{id}` | Servis kaldır |
| `GET` | `/xira/services/{id}/health` | Tekil health check |
| `GET` | `/xira/stats` | İstatistikler |
| `GET` | `/xira/health` | Gateway sağlık durumu |
| `GET` | `/xira/events` | Olay geçmişi |
| `GET` | `/xira/circuit-breakers` | Circuit breaker durumları |
| `GET` | `/xira/plugins` | Aktif plugin'ler |
| `GET` | `/xira/log-stats` | Log istatistikleri |
| `GET/PUT` | `/xira/config` | Runtime konfigürasyon |
| `POST` | `/xira/cache/clear` | Cache temizle |
| `GET` | `/xira/docs` | Swagger UI |
| `GET` | `/xira/docs/spec` | OpenAPI JSON |

### Identity & Access

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/identity/users` | Kullanıcıları listele |
| `POST` | `/xira/identity/users` | Yeni kullanıcı oluştur |
| `POST` | `/xira/identity/login` | Email/şifre ile giriş |
| `GET` | `/xira/identity/sessions` | Aktif oturumlar |
| `POST` | `/xira/identity/sessions/flush` | Süresi dolan oturumları temizle |

### Automation

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/automation/cron` | Zamanlanmış işleri listele |
| `POST` | `/xira/automation/cron` | Yeni cron iş ekle |
| `DELETE` | `/xira/automation/cron/{id}` | Cron iş kaldır |
| `GET` | `/xira/automation/workflows` | Workflow'ları listele |
| `GET` | `/xira/automation/events` | Event bus olayları |
| `POST` | `/xira/automation/events/publish` | Event yayınla |

### Observability

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/observability/logs?q=&level=` | Log arama/filtreleme |
| `GET` | `/xira/observability/uptime` | Public status page |
| `GET` | `/xira/observability/incidents` | Incident'ları listele |
| `POST` | `/xira/observability/incidents` | Yeni incident oluştur |
| `POST` | `/xira/observability/incidents/{id}/update` | Incident güncelle |

### DB Gateway

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/db/connections` | DB bağlantıları |
| `GET` | `/xira/db/slow-queries` | Yavaş sorgular |
| `GET` | `/xira/db/firewall/stats` | SQL firewall istatistikleri |

### Deployment

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/deployment/flags` | Feature flag'leri listele |
| `POST` | `/xira/deployment/flags` | Yeni flag oluştur |
| `POST` | `/xira/deployment/flags/{name}/toggle` | Flag aç/kapa |
| `GET` | `/xira/deployment/releases` | Release'leri listele |
| `POST` | `/xira/deployment/releases` | Yeni blue/green release |
| `POST` | `/xira/deployment/releases/{id}/switch` | Aktif renk değiştir |

### Data Pipeline

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/pipeline/watchers` | CDC watcher'ları listele |
| `POST` | `/xira/pipeline/watchers` | Yeni watcher ekle |
| `GET` | `/xira/pipeline/analytics` | Analytics buffer'ı dışa aktar |

### Security & Metrics

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/security/waf` | WAF durumu |
| `GET` | `/xira/security/bots` | Bot detection istatistikleri |
| `GET` | `/xira/security/audit` | Audit log geçmişi |
| `GET` | `/xira/advanced-metrics` | Per-service bandwidth/error rate |
| `GET` | `/xira/health-scoring` | Upstream sağlık skorları |
| `GET` | `/xira/sla` | SLA metrikleri + ihlaller |

## CLI Komutları

| Komut | Açıklama |
|-------|----------|
| `xira serve` | Gateway'i başlat |
| `xira add <name> <prefix> <url>` | Servis ekle |
| `xira remove <id>` | Servis kaldır |
| `xira list` | Servisleri listele |
| `xira health` | Sağlık durumu |
| `xira stats` | İstatistikler |

## Gateway Pipeline

Her proxied request şu aşamalardan geçer:

1. **WAF** — SQL injection, XSS, path traversal tespiti (regex)
2. **Bot Detection** — 25 bot imzası + crawl rate limiting (60/min)
3. **IP Filter** — Per-service blacklist/whitelist
4. **Validation** — JSON schema (POST/PUT/PATCH)
5. **Plugins** — Custom on_request/on_response hooks
6. **Circuit Breaker** — Failure-based otomatik devre kesme
7. **Cache** — TTL-based response caching (GET only)
8. **Load Balancer** — RoundRobin / Random / LeastConn / IPHash
9. **Transform** — Request/response header dönüşümü
10. **Retry** — Exponential backoff ile yeniden deneme
11. **Advanced Metrics** — Per-service bandwidth, status codes, avg latency
12. **Health Scoring** — Upstream latency → 0-100 score
13. **Audit Log** — Her request SQLite'a yazılır
14. **Event Bus** — `request.completed` event yayınlanır (async)

## Özellikler

| Kategori | Özellik |
|----------|---------|
| **Gateway** | Reverse proxy, prefix routing, load balancing, circuit breaker, retry, cache, transform |
| **Security** | WAF (SQLI/XSS/Traversal), bot detection, IP filter, JWT auth, API key auth, audit log |
| **Identity** | User RBAC, session management, salted password hashing, MFA support |
| **Automation** | Cron scheduler (daemon), event bus (pub/sub), workflow engine |
| **Observability** | Log aggregator, uptime status page, incident management, SLA monitoring |
| **Deployment** | Feature flags (percentage rollout), blue/green releases |
| **Data** | CDC change watchers, analytics event buffering, SQL query firewall |
| **Metrics** | Prometheus, advanced per-service metrics, health scoring, SLA P99 tracking |
| **Dashboard** | Embedded web UI, real-time WebSocket updates, dark/light theme |

## Lisans

MIT
