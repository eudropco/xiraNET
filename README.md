# xiraNET — Central Infrastructure Hub

```
    ██╗  ██╗██╗██████╗  █████╗ ███╗   ██╗███████╗████████╗
    ╚██╗██╔╝██║██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
     ╚███╔╝ ██║██████╔╝███████║██╔██╗ ██║█████╗     ██║   
     ██╔██╗ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══╝     ██║   
    ██╔╝ ██╗██║██║  ██║██║  ██║██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

**v3.0.0** — Modular API Gateway + Identity + Automation + Observability + Deployment + Security

Tüm projelerinizi tek bir merkezden yönetin. Runtime'da servis bağlayın, WAF/Bot koruması, SLA izleme, cron otomasyonu, MFA ve olay yönetimi tek yerden.

> ✅ **v3.0.0 dürüstlük notu — Yarı A + B audit fix'leri tamamlandı.**
>
> Daha önceki cenaze raporundaki 27 maddenin **24'ü kapandı**, 2'si
> next phase olarak işaretlendi (main.rs split + ek adversarial test
> coverage). Detaylı durum: [`docs/AUDIT-FINDINGS.md`](docs/AUDIT-FINDINGS.md).
>
> Bu sürümde ne yapıldı (özet):
>
> - **WAF**: 2-pass URL-decode + unicode escape normalize, structured header
>   allow-list (JWT/cookie false-positive yok), atomic rule ID, `block_ip`
>   `&self`+`DashSet` (eski `&mut self`+Arc dead code).
> - **Rate limiter**: shared `Arc<DashMap>` (eski per-worker × bug),
>   `[rate_limit].trust_xff` → X-Forwarded-For ilk hop, 30s'de bir
>   eviction task.
> - **Proxy**: error response body sanitize (upstream URL/DNS/port server
>   log'a), RFC 7230 hop-by-hop tam liste.
> - **SSRF**: `PinnedUrl` + `reqwest::ClientBuilder::resolve_to_addrs` ile
>   DNS TOCTOU bypass (custom resolver semantics). UpstreamOnly port
>   allow-list — Redis 6379, Postgres 5432, MySQL 3306 reddedilir.
> - **Sessions**: IP binding strict + UA binding warn-only, last_activity
>   30s throttled persist, max_sessions atomic two-phase (race fix).
> - **Identity**: `Authenticator` façade (login↔session contract type-system'da),
>   email case-permutation bypass kapalı, `failed_attempts` 10K LRU cap,
>   `update_role` `events` audit row.
> - **Crypto**: Argon2id explicit pin (m=19456, t=2, p=1) hem live hem dummy
>   hash, SecretBox 64-hex raw key veya Argon2id KDF, `hash_token`
>   HMAC-SHA256 (XIRA_SECRETS_KEY varsa).
> - **JWT**: path normalize gerçek `..` strip (eski yorum yalan), RSA
>   `Arc<DecodingKey>` boot-time parse.
> - **Multi-node**: `XiraBus` trait'e `spawn_subscriber` eklendi → tek
>   bus instance, ek Redis connection yok.
> - **CI**: `cargo audit --deny warnings`, `cargo install --locked`
>   (`|| true` kaldırıldı).
>
> Production'a önce: `xira system validate`, `xira system doctor` çalıştır,
> Grafana "xiraNET — Security & Audit" dashboard'ı izle. Multi-node deploy
> için sticky LB + Redis bus.

---

## Kurulum

```bash
# Rust 1.88+ yüklü olmalı (https://rustup.rs) — repo'da rust-toolchain.toml pinned.
cd xiraNET
cargo build --release

# Binary'yi path'e kopyala
cp target/release/xiranet ~/.local/bin/xira
```

### Zorunlu environment

```bash
# MFA seed'leri ve hassas materyallerin at-rest şifrelenmesi için (>= 32 byte).
# Ayarlanmazsa MFA/identity ÇALIŞIR ama seed'ler düz metin saklanır (warn).
#
# **Önerilen — 64 hex char (raw 32-byte key, KDF yok, en yüksek entropy):**
export XIRA_SECRETS_KEY="$(openssl rand -hex 32)"

# Alternatif — passphrase modu (Argon2id KDF, m=19MB t=2 p=1). Bu modda
# XIRA_SECRETS_SALT da set edilmeli; salt değişimi = key rotation.
# export XIRA_SECRETS_KEY="long-passphrase-min-32-chars-..."
# export XIRA_SECRETS_SALT="rotation-handle-min-16-chars"

# DB yolunu özelleştirmek için (opsiyonel)
export XIRA_DB_PATH=/var/lib/xira/xiranet.db
```

### Mevcut deployment'tan upgrade — MFA migration uyarısı

v3.0 patch'lerinde `SecretBox` KDF'i Argon2id'e geçti. Eski sürümlerde aynı
`XIRA_SECRETS_KEY` SHA-256 üzerinden derive edilmiş AES key üretiyordu; yeni
sürümde derivation şu mantığa düştü:

- `XIRA_SECRETS_KEY` 64 ASCII hex char ise: **raw 32-byte key** (KDF yok).
  Önceki SHA-256 davranışından farklı; aynı hex string artık doğrudan key.
- Aksi halde: Argon2id KDF + `XIRA_SECRETS_SALT`.

**Üretimde live bir deployment'ı upgrade ederken**: mevcut MFA seed'leri eski
key ile sealed durumda. Yeni binary açıldığında decrypt başarısız olur ve
sessizce plaintext fallback yapılır (boot warning log'a girer). Güvenli
upgrade sırası:

1. Mevcut kullanıcılara "MFA recovery gerekecek" duyurusu yap.
2. Yeni binary'yi `XIRA_SECRETS_KEY` aynı kalacak şekilde deploy et.
3. Admin endpoint'inden tüm MFA-enabled hesapları `/auth/admin/users/{id}/mfa/disable`
   ile reset et (audit log otomatik yazılır).
4. Kullanıcılar tekrar `/auth/mfa/enroll` çağırır; yeni seed Argon2id-derived
   key ile sealed yazılır.

Tek-shot operasyonel sınır; ileride çoklu key versioning eklenince bu adım
kaldırılacak.

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
                    │                   xiraNET v3.0.0                    │
                    │              Central Infrastructure Hub             │
                    ├─────────────────────────────────────────────────────┤
                    │                                                     │
  Request ──────►   │  WAF ► Bot Detection ► IP Filter ► Validation       │
                    │     ► Circuit Breaker ► Cache ► Load Balancer       │
                    │     ► Transform ► Retry/Proxy ► Metrics             │
                    │     ► Health Scoring ► Audit Log ► EventBus         │
                    │                                                     │
  Response ◄────    │                                                     │
                    ├─────────────┬──────────────┬────────────────────────┤
                    │  Identity   │  Automation  │    Observability       │
                    │ Users/MFA   │ Cron/Events  │   Logs/Uptime/SLA      │
                    │  Sessions   │  Workflows   │     Incidents          │
                    ├─────────────┼──────────────┼────────────────────────┤
                    │  DB Gateway │  Deployment  │    Data Pipeline       │
                    │ SQL Firewall│ Feature Flags│    CDC/Analytics       │
                    ├─────────────┴──────────────┴────────────────────────┤
                    │  OAuth2/OIDC Gateway · Service Mesh · Plugins       │
                    │  Discovery: Consul · DNS SRV · Docker labels        │
                    └─────────────────────────────────────────────────────┘
```

## Konfigürasyon (xiranet.toml)

```toml
[gateway]
host = "127.0.0.1"      # 0.0.0.0 dış bind için; default key ile bind reddedilir
port = 9000

[admin]
api_key = "üretim-için-değiştir"   # default değerler reddedilir
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
secret = ""              # enabled=true ise min 32 byte + default-değer reddi
algorithm = "HS256"      # HS256/HS384/HS512/RS256 (RS256 PEM start-time'da parse)
issuer = ""
audience = ""

[cors]
allowed_origins = ["http://localhost:3000"]  # allow_any_origin ARTIK YOK
allow_credentials = false
max_age = 3600

[oauth2]
enabled = false
issuer_url = "https://auth.example.com"
introspection_url = "https://auth.example.com/oauth2/introspect"
client_id = "..."
client_secret = "..."

[discovery]
enabled = false
backend = "static"       # "consul" | "dns" | "static"
consul_url = "http://localhost:8500"
dns_domain = "_api._tcp.example.com"
docker_enabled = false
docker_socket = "http://localhost:2375"

[alerting]
enabled = true
webhook_url = "https://hooks.slack.com/..."

[[services]]
name = "my-api"
prefix = "/api"
upstream = "http://localhost:3001"
health_endpoint = "/health"
```

## Auth & Identity

### Login Flow

```bash
# 1. Login → session token (MFA yoksa direkt)
curl -X POST http://localhost:9000/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email": "mert@example.com", "password": "..."}'
# → { "token": "xira_tok_...", "expires_at": ... }

# 2. MFA enabled ise:
# → { "mfa_required": true, "user_id": "..." }
# Devamı:
curl -X POST http://localhost:9000/auth/mfa/login \
    -d '{"user_id": "...", "code": "123456"}'

# 3. Session'lı endpoint'ler:
curl http://localhost:9000/auth/me \
    -H 'Authorization: Bearer xira_tok_...'
# veya:
#   -H 'X-Session-Token: xira_tok_...'
```

### Public Auth Endpoints

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `POST` | `/auth/login` | Email + şifre → session token (veya MFA challenge) |
| `POST` | `/auth/mfa/login` | MFA challenge sonrası 6-haneli TOTP kodu |

### Session-Protected Endpoints (`Authorization: Bearer <token>`)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/auth/me` | Geçerli kullanıcı bilgisi |
| `GET` | `/auth/sessions` | Aktif session'larım |
| `POST` | `/auth/logout` | Bu session'ı kapat |
| `POST` | `/auth/logout-all` | TÜM session'larımı kapat (force logout) |
| `POST` | `/auth/mfa/enroll` | TOTP enrollment başlat (QR URL döner) |
| `POST` | `/auth/mfa/verify` | Enrollment'ı 6-haneli kod ile doğrula |

### RBAC Admin Endpoints (`/auth/admin/*`, **SuperAdmin role gerekir**)

`SessionAuth` + `RequireRole(SuperAdmin)` middleware zinciri. API key tier'ından
bağımsız; user-context işlemler için (kullanıcı yönetimi, force logout, MFA recovery).

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/auth/admin/users` | Tüm kullanıcıları listele |
| `PUT` | `/auth/admin/users/{id}/role` | Kullanıcı rolünü değiştir (tüm session'ları invalidate edilir) |
| `POST` | `/auth/admin/users/{id}/disable` | Kullanıcıyı devre dışı bırak + session'larını kapat |
| `POST` | `/auth/admin/users/{id}/mfa/disable` | MFA recovery (kullanıcı erişimini kaybettiğinde) |
| `POST` | `/auth/admin/users/{id}/logout-all` | Başka kullanıcıyı force logout |

**Role hierarchy** (üst alttakileri kapsar):
```
SuperAdmin (100) > Admin (80) > Developer (60) > Service (40) > Viewer (20)
                                                                  Custom (0, explicit)
```

`Custom(name)` rolü hierarchy'e dahil değildir — eşit string-match veya explicit
permission grant gerekir.

## Admin API

Tüm `/xira/*` endpoint'leri `X-Api-Key` header gerektirir. Karşılaştırma `subtle::ConstantTimeEq` ile timing-safe.

### Core

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/services` | Tüm servisleri listele |
| `POST` | `/xira/services` | Yeni servis kaydet (upstream SSRF guard'lı) |
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
| `GET` | `/xira/identity/sessions` | Aktif oturumlar (sayım) |
| `POST` | `/xira/identity/sessions/flush` | Süresi dolan oturumları temizle |

### Automation

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/automation/cron` | Zamanlanmış işleri listele |
| `POST` | `/xira/automation/cron` | Yeni cron iş (URL SSRF guard'lı) |
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

### OAuth2 / OIDC (v3.0)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/oauth2/status` | Issuer/JWKS URL + cache size |
| `POST` | `/xira/oauth2/introspect` | Token introspect (cache'li, SHA-256 key) |
| `POST` | `/xira/oauth2/cache/clear` | Token cache temizle |

### Service Mesh (v3.0)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/mesh/services` | Mesh servisleri |
| `POST` | `/xira/mesh/services` | Sidecar kaydet (mTLS + retry policy) |

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

1. **WAF** — SQL injection (kontekst-aware), XSS, path traversal; lossy UTF-8 body inspection (non-UTF-8 byte bypass kapalı)
2. **Bot Detection** — 25 bot imzası + crawl rate limiting (60/min)
3. **IP Filter** — Per-service blacklist/whitelist
4. **Validation** — JSON schema (POST/PUT/PATCH)
5. **Plugins** — Custom on_request/on_response hooks (built-in + dynamic .so/.dylib/.dll)
6. **Circuit Breaker** — Failure-based otomatik devre kesme
7. **Cache** — TTL-based response caching (GET; Authorization/Cookie/Set-Cookie/Vary:* bypass)
8. **Load Balancer** — RoundRobin / Random / LeastConn / IPHash
9. **Transform** — Request/response header dönüşümü
10. **Retry** — Exponential backoff ile yeniden deneme
11. **Advanced Metrics** — Per-service bandwidth, status codes, avg latency
12. **Health Scoring** — Upstream latency → 0-100 score
13. **Audit Log** — Her request SQLite'a yazılır (best-effort, hata `tracing::warn`)
14. **Event Bus** — `request.completed` event yayınlanır (async)

Proxy forwarded headers: `X-Forwarded-For` (peer IP), `X-Forwarded-Proto` (connection scheme'den türetilir — TLS-terminated trafik doğru işaretlenir), `X-Forwarded-Host`.

## Özellikler

| Kategori | Özellik |
|----------|---------|
| **Gateway** | Reverse proxy, prefix routing, load balancing, circuit breaker, retry, cache, transform |
| **Security** | WAF (SQLI/XSS/Traversal), bot detection, IP filter, JWT, API key (constant-time), audit log, SSRF guards |
| **Identity** | User RBAC, session management (SQLite persistent), Argon2 password hashing, **MFA TOTP** (enroll + verify + login, **AES-256-GCM at-rest**) |
| **Auth** | JWT (default-secret/weak-secret/RS256-PEM guard, algorithm pinning), OAuth2/OIDC introspection (SHA-256 cache key) |
| **Automation** | Cron scheduler (in-flight overlap guard, SQLite persistent), event bus (pub/sub), workflow engine |
| **Observability** | Log aggregator, uptime status page, incident management, SLA monitoring |
| **Deployment** | Feature flags (percentage rollout), blue/green releases |
| **Data** | CDC change watchers (three-phase lock), analytics event buffering, SQL query firewall |
| **Discovery** | Consul (multi-instance), DNS SRV (hickory-resolver), Docker label scanning, service mesh sidecar registry |
| **Plugins** | Built-in (Logging, SecurityHeaders) + dynamic `extern "Rust" fn xira_plugin_create()` + Script DSL hooks |
| **Metrics** | Prometheus, advanced per-service metrics, health scoring, SLA P99 tracking |
| **Dashboard** | Embedded web UI, real-time WebSocket updates, dark/light theme |

## Geliştirme

```bash
# Build (workspace)
cargo build --workspace --release

# Test (in-source unit + integration tests)
cargo test --workspace --all-targets

# Lint (CI ile aynı sıkılık)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Security audit
cargo install --locked cargo-audit
cargo audit

# E2E testler (server gerektirir, varsayılan ignored)
cargo test --test e2e_tests -- --ignored
```

### Plugin yazma

Dynamic plugin (host ile aynı toolchain'de derlenmeli — Rust ABI):

```rust
use xiranet::plugins::{PluginAction, XiraPlugin};
use async_trait::async_trait;

pub struct MyPlugin;

#[async_trait]
impl XiraPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }
    async fn on_init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }
    async fn on_request(&self, m: &str, p: &str, _h: &std::collections::HashMap<String, String>) -> PluginAction {
        if p.starts_with("/admin") { PluginAction::Block(403, "no".into()) } else { PluginAction::Continue }
    }
    async fn on_response(&self, _s: u16, _p: &str) -> PluginAction { PluginAction::Continue }
    async fn on_shutdown(&self) {}
}

#[no_mangle]
pub fn xira_plugin_create() -> Box<dyn XiraPlugin> {
    Box::new(MyPlugin)
}
```

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]
```

Derlenmiş `.so/.dylib/.dll` → `plugins/` dizinine kopyala → `xira serve` başlangıçta yükler.

## Deploy

### Docker

```bash
# Build
docker build -t xiranet:3.0.0 .

# Run (XIRA_SECRETS_KEY zorunlu — MFA at-rest encryption için)
docker run -d \
    -p 9000:9000 \
    -e XIRA_SECRETS_KEY="$(openssl rand -hex 32)" \
    -v $(pwd)/xiranet.toml:/app/xiranet.toml:ro \
    -v xira-data:/app/data \
    xiranet:3.0.0
```

Container `xira` user (uid 10001) altında çalışır; `cap_drop ALL` + `NET_BIND_SERVICE` only.

### docker-compose

```bash
# .env içine XIRA_SECRETS_KEY ve GRAFANA_ADMIN_PASSWORD koy
docker compose --profile monitoring up -d
```

`--profile monitoring` ile Prometheus (`:9090`) ve Grafana (`:3000`) ayağa kalkar.
Grafana auto-provisioning ile iki dashboard hazır gelir:

- **xiraNET — Security & Audit** (`xiranet-security`) — auth rejects, WAF blocks/detects,
  SSRF rejects, JWT rejects, MFA events, session lifecycle, DB persist errors
- **xiraNET — Gateway Operations** (`xiranet-gateway`) — HTTP request rate by status,
  latency P50/P95/P99, services up/down, circuit breaker opens, cache hit rate, proxy errors

Datasource (`prometheus` → `http://prometheus:9090`) ve dashboard provisioning
config'leri `observability/grafana/` altında repo'da.

## Konfigürasyon doğrulama

```bash
# Pre-deploy gate (CI'da çalıştırılabilir)
xira system validate --config xiranet.toml

# Boot edilirse aynı kontrol Serve içinde de çalışır — error varsa process exit 1
# olur, log'da `xira::config` target'lı error/warning satırları görünür.
```

Doğrulama kapsamı: default API key + dış bind (block), JWT default-secret/zayıf
secret/RS256 PEM, CORS empty origins, duplicate service prefix, TLS dosya varlığı,
rate-limit/cache sanity. Detay için `XiraConfig::validate()`.

## CHANGELOG — v3.0.0 audit highlights

Bu sürüm geniş bir security/correctness audit'inden çıktı. Tam liste için commit history'e (`security:`, `feat:`, `ops:`, `chore:` prefix'li commit'ler) bak. Öne çıkanlar:

### Security
- **Session validation wired** — `/auth/login` token'ı artık `SessionAuth` middleware ile downstream'de doğrulanıyor (önceden hiçbir middleware `SessionManager::validate` çağırmıyordu).
- **SSRF guards** — admin'in oluşturduğu cron URL'leri ve service upstream'leri `url_guard` ile inspect edilir. Cloud metadata (IMDS, GCP metadata) her durumda bloke; `Strict` mod RFC1918'i de bloke eder (webhook'lar için), `UpstreamOnly` mod local servisleri allow eder.
- **Constant-time API key compare** — `subtle::ConstantTimeEq` (timing leak fix).
- **JWT hardening** — default/example secret start-time'da reddedilir; HMAC için min 32-byte; RS256 PEM boot'ta parse edilir; `validation.algorithms` tek değere pin (alg confusion engellenir).
- **CORS** — `allow_any_origin` kaldırıldı; `[cors].allowed_origins` explicit listesi zorunlu.
- **MFA at-rest** — TOTP seed'leri AES-256-GCM ile şifrelenir (`XIRA_SECRETS_KEY` env ile). Enrollment + verify + login akışları implemented.
- **WAF false positives** — `;`/`--`/`@` artık standalone değil, SQL keyword bağlamı yakınında match. Non-UTF-8 body lossy convert (bypass engeli).
- **Proxy** — `X-Forwarded-Proto` connection scheme'den (`https` korunur).
- **OAuth2 cache** — token raw değil SHA-256(token) key (heap dump'tan bearer sızdırmaz).

### Reliability / persistence
- **Session SQLite persistence** — restart sonrası aktif session'lar yüklenir.
- **Datapipeline CDC** — three-phase lock disiplini: snapshot → drop → HTTP → reacquire. Bir slow upstream tüm CDC'yi kilitlemiyor.
- **Cron in-flight guard** — aynı job aynı anda iki kez tetiklenmiyor.

### Functional gaps closed
- **DNS SRV discovery** — `hickory-resolver` ile gerçek implementasyon (eski log-only stub).
- **Consul multi-instance fix** — `registry.set_upstreams()` ile gerçek mutation.
- **Docker discovery wired** — `[discovery].docker_enabled` ile container label scan.
- **OAuth2Gateway, ServiceMesh** — `/xira/oauth2/*` ve `/xira/mesh/*` admin endpoint'lerine bağlandı.
- **Plugin libloading** — gerçek dynamic loading (eski "logs `Found plugin library`" stub).

### Hygiene
- `crates/` ağacı workspace dışına alındı (stale fork; src/ tek truth source).
- `[[bin]] xira` duplicate kaldırıldı.
- CI: `--workspace --all-targets`, fmt, audit job'ları eklendi.
- Docker: non-root user (10001), `.dockerignore`, pinned tags, healthcheck'ten hardcoded API key kaldırıldı.
- `rust-toolchain.toml`: 1.88 pin.
- `let _ = storage.*` silent fail → `tracing::warn`.

## Audit log remote sink

SQLite audit_log artık append-only trigger'larla korunmuş olsa da `DROP TABLE`
veya disk tampering hâlâ mümkün. Gerçek tamper-evident için kayıtların DB
dışına paralel yazılması gerek:

```toml
[audit]
# JSON Lines append-only file (logrotate veya WORM volume ile koordine)
file_path = "/var/log/xira/audit.jsonl"

# Uzak SIEM / log aggregator (OTLP-friendly JSON POST)
webhook_url = "https://siem.example.com/ingest/xira"

# Webhook'a ekstra header (auth için)
[audit.webhook_headers]
"Authorization" = "Bearer ${SIEM_TOKEN}"

# Buffer dolarsa eski entry'ler DROP edilir (uygulama'yı yavaşlatmamak için).
# Drop sayısı `xiranet_db_persist_errors_total{table="audit_sink_buffer_full"}`
# counter'ına yansır.
buffer_size = 10000
```

Sink'ler **paralel** çalışır — biri yavaş/down olsa diğeri etkilenmez. SSRF
guard her HTTP sink'e uygulanır; metadata IP'ler reddedilir.

## CLI session persistence

```bash
# Login → token ~/.config/xira/session dosyasına yazılır (mode 0600)
xira admin login admin@example.com hunter2
# ✅ logged in as admin@example.com
#    token saved: /Users/x/.config/xira/session (mode 0600)

# Sonraki komutlar artık --token gerektirmez
xira admin whoami
xira admin users

# Destructive op'lar interactive onay ister; otomasyon için --yes:
xira admin set-role <uid> Viewer --yes

# Çıkış
xira admin logoff
```

Token store öncelik: `--token` flag > `XIRA_SESSION_TOKEN` env > `~/.config/xira/session`.

## Multi-node deployment

Phase 4.4/4.5 ile xiraNET çoklu instance'la çalışabilir — Redis pub/sub
üzerinden session invalidation ve WAF rule sync.

### Konfigürasyon

```toml
[bus]
backend = "redis"                      # "noop" (default, single-node) | "redis"
redis_url = "redis://redis:6379/0"
```

Backend `redis` ise boot'ta connect denenir; başarısız olursa **otomatik
fallback** `noop` (gateway başlar, tracing error log'lar, multi-node sync yok).

### Çalışma mantığı

| Event | Channel | Publish edilen | Local etkisi (subscriber) |
|-------|---------|----------------|---------------------------|
| `invalidate(token)`     | `xira:bus` | `SessionInvalidateToken { hashed_token }`     | `apply_invalidate_token` — bus broadcast etmez (loop önlemi) |
| `invalidate_all(uid)`   | `xira:bus` | `SessionInvalidateUser { user_id }`           | `apply_invalidate_user`                                       |
| `add_custom_pattern`    | `xira:bus` | `WafRuleAdded { id, pattern, label }`         | `apply_add_pattern` — local regex compile + insert            |
| `remove_custom_pattern` | `xira:bus` | `WafRuleRemoved { id }`                       | `apply_remove_pattern`                                        |

Self-published event'ler de dönüyor — `apply_*` fonksiyonları **idempotent**
ve bus'a yeniden yayınlamıyor (loop fix).

### Deploy mimarisi

```
   ┌──────────┐    ┌──────────┐    ┌──────────┐
   │ xira-1   │    │ xira-2   │    │ xira-3   │
   │ :9000    │    │ :9000    │    │ :9000    │
   └────┬─────┘    └────┬─────┘    └────┬─────┘
        │               │               │
        └─────────┬─────┴───────┬───────┘
                  │             │
            ┌─────┴─────┐  ┌────┴────┐
            │ Sticky LB │  │  Redis  │  ← xira:bus channel
            │ (nginx /  │  │  pub/sub│
            │  HAProxy) │  └─────────┘
            └─────┬─────┘
                  │
              clients
```

- **Sticky LB hâlâ önerilir**: bus invalidate eventually-consistent. Round-robin
  LB ile login'den hemen sonra istek başka node'a düşerse o node'un cache'inde
  session yok — `validate()` SQLite'tan okuyabilir (her node'un kendi DB'si var,
  paylaşılmıyor). Solution: shared `XIRA_DB_PATH` (NFS/EBS) veya sticky LB.
- **Audit log** hâlâ node-local; remote sink (`[audit].webhook_url`) ile SIEM'e
  paralel yaz.
- **Cron scheduler** hâlâ node-local; aynı job birden fazla node'da paralel
  tetiklenebilir — Phase 5'te leader election düşünülüyor.

### CI

`.github/workflows/ci.yml` `test` job'ı Redis 7 service ile koşuyor; bus
testleri `REDIS_URL=redis://127.0.0.1:6379/0` env'ini görüp gerçek pub/sub
roundtrip'i doğruluyor. Env yoksa testler skip'lenir (single-developer dev).

### Observability

- `xiranet_sessions_active{instance=...}` — sticky LB doğru çalışıyor mu kontrol
- `xiranet_db_persist_errors_total{table="bus_publish"}` — Redis publish hatası
- Subscriber background task disconnect'lerde exponential backoff retry'a girer;
  log'da görünür.

## Threat model

xiraNET'in nelere koruma sağladığını ve **NEYE SAĞLAMADIĞINI** açıkça yazmak, kullanıcının doğru yere yatırım yapmasını sağlar.

### Yes — bunlar adres alınmıştır

| Tehdit | Karşı önlem |
|--------|-------------|
| Admin API key brute-force | Constant-time compare (`subtle::ConstantTimeEq`), `xiranet_auth_rejects_total{wrong_key}` counter, opsiyonel rate limit |
| Cron / service register SSRF | `url_guard` strict/upstream mode, cloud metadata IP'leri her zaman block |
| Session token theft sonrası replay | Token SHA-256 hashed-at-rest, logout-all force invalidate, `xiranet_session_events_total` |
| JWT default-secret deployments | Boot-time guard (`xira system validate` ve `Serve`), known-default list, min 32-byte HMAC, RS256 PEM parse zorunluluğu |
| MFA seed leak (DB backup) | `SecretBox` AES-256-GCM at-rest, `XIRA_SECRETS_KEY` ile envelope |
| CORS misconfiguration → cross-origin admin | `allow_any_origin` kaldırıldı; explicit `[cors].allowed_origins` zorunlu |
| Algorithm confusion (alg=none, HS→RS) | `validation.algorithms` tek değere pin |
| WAF UTF-8 bypass (\xff prefix) | Lossy UTF-8 inspection |
| SQLi false positives (email/markdown) | Pattern'ler SQL keyword bağlamı yakınında; standalone `;`/`--`/`@` match etmez |
| Audit trail silent loss | `tracing::warn` + `xiranet_db_persist_errors_total{table}` counter |
| Container privilege escalation | Non-root user (uid 10001), `cap_drop ALL` + `NET_BIND_SERVICE` only |
| Healthcheck'te credential leak | Public `/health` endpoint, API key gerektirmiyor |
| Privilege change replay attack | Role değişimi `invalidate_all` tetikler — eski token'lar invalidate |
| Boot ile uygun olmayan config | `XiraConfig::validate()` blocking errors → process exit |

### No — bunlar adres alınmamıştır (dürüstlük)

| Tehdit | Neden / işaret |
|--------|----------------|
| Distributed DDoS | Tek-instance rate limit yetmez; CDN/Cloudflare/AWS Shield seviyesinde absorb gerekir |
| Process memory dump | Loaded SecretBox + session map plaintext bellekte; hardware enclave değiliz |
| Side-channel: cache timing, Spectre vb. | Rust + Tokio kontrol etmiyor; AWS Nitro/SEV seviyesi gerekir |
| DNS rebinding | `url_guard` resolve + check arası kısa pencere açık; tam koruma için custom resolver gerekir |
| Supply chain (crate compromise) | `cargo audit` advisory-only; `cargo-vet` veya `cargo-deny` gibi policy yok |
| Cross-replica session sync | Sessions SQLite-persistent ama tek node; multi-node deploy session-sticky LB gerektirir |
| TOTP secret derive (HOTP counter) | RFC 6238 ±1 step window kullanılır; ±2/±3 yapılabilir ama brute-force window artar |
| Rate-limit bypass (X-Forwarded-For spoof) | Peer IP kullanılır; arkada proxy varsa `X-Forwarded-For`'a güvenilmemeli (ilk-hop) |
| RBAC `Custom(name)` hiyerarşi | Custom rol explicit eşleşme — hierarchy'e dahil değil; permission grants ile kullanılmalı |
| Plugin sandbox | `xira_plugin_create` çağırdığı plugin host process'i ile aynı yetkilere sahip — code review gerekir |
| Browser cookie auth | Session token Authorization header / X-Session-Token ile alınır; cookie + CSRF protect mevcut değil |
| Audit log tampering | SQLite tablo herhangi biri DB'ye yazma erişimi olursa silebilir; append-only log değil |

### Operasyonel öneriler

1. **Pre-deploy**: `xira system validate --config xiranet.toml` CI gate'i.
2. **Boot zamanında**: `xira system doctor` — env vars, file permissions, live gateway health.
3. **Sürekli**: Grafana "xiraNET — Security & Audit" dashboard'ı izle.
4. **`XIRA_SECRETS_KEY` rotation**: yapılmıyor; MFA seed'ler tek key ile sealed, key değişirse mevcut seed'ler kayıp.
5. **`cargo audit`**: CI'da koşar; advisory için PR aç, otomatik update yok.

## Lisans

MIT OR Apache-2.0
