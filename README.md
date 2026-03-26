# xiraNET — Central Infrastructure Hub

```
    ██╗  ██╗██╗██████╗  █████╗ ███╗   ██╗███████╗████████╗
    ╚██╗██╔╝██║██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
     ╚███╔╝ ██║██████╔╝███████║██╔██╗ ██║█████╗     ██║   
     ██╔██╗ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══╝     ██║   
    ██╔╝ ██╗██║██║  ██║██║  ██║██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

Tüm projelerinizi tek bir merkezden yönetin. Endpoint'leri runtime'da bağlayın.

## Kurulum

```bash
# Rust yüklü olmalı (https://rustup.rs)
cd xiraNET
cargo build --release
```

## Hızlı Başlangıç

```bash
# Gateway'i başlat
cargo run -- serve

# Servis bağla
cargo run -- add my-api /api http://localhost:3001
cargo run -- add my-frontend /app http://localhost:8080

# Artık tüm istekler xiraNET üzerinden
curl http://localhost:9000/api/users        # → localhost:3001/users
curl http://localhost:9000/app/index.html   # → localhost:8080/index.html

# Servisleri listele
cargo run -- list

# İstatistikler
cargo run -- stats
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

[[services]]
name = "my-api"
prefix = "/api"
upstream = "http://localhost:3001"
health_endpoint = "/health"
```

## Admin API

Tüm admin endpoint'leri `X-Api-Key` header gerektirir.

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/xira/services` | Tüm servisleri listele |
| `POST` | `/xira/services` | Yeni servis kaydet |
| `DELETE` | `/xira/services/{id}` | Servis kaldır |
| `GET` | `/xira/services/{id}/health` | Tekil health check |
| `GET` | `/xira/stats` | İstatistikler |
| `GET` | `/xira/health` | Gateway sağlık durumu |

## CLI Komutları

| Komut | Açıklama |
|-------|----------|
| `xiranet serve` | Gateway'i başlat |
| `xiranet add <name> <prefix> <url>` | Servis ekle |
| `xiranet remove <id>` | Servis kaldır |
| `xiranet list` | Servisleri listele |
| `xiranet health` | Sağlık durumu |
| `xiranet stats` | İstatistikler |

## Mimari

- **API Gateway** — Reverse proxy, prefix-based routing
- **Service Registry** — DashMap tabanlı concurrent registry
- **Middleware** — Auth (API-Key), Rate Limiting, CORS, Logging
- **Health Monitor** — Periyodik sağlık kontrolü
- **CLI** — Terminal yönetim aracı

## Lisans

MIT
