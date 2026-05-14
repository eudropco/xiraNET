use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use dashmap::DashMap;
use std::future::{ready, Future, Ready};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Instant;

/// IP bazlı rate limiting (sliding-fixed-window token bucket).
///
/// v3.0 audit fix'leri (Yarı A, madde 3–5, 12, 13, 14):
/// - **Shared `Arc<DashMap>`**: Eski sürüm her Actix worker'da ayrı map
///   yaratıyordu → effective rate = config × workers. Şimdi map RateLimiter
///   struct'ında, tüm worker'lar aynı bucket'ı paylaşır.
/// - **X-Forwarded-For (trusted-proxy)**: `trusted_proxies` listesi varsa
///   peer_addr listede olduğunda XFF chain sağdan-sola gezilir, ilk untrusted
///   hop client IP'si kabul edilir. Liste boşsa legacy `trust_xff` flag'i
///   geçerli (XFF spoof'a açık, sadece backward-compat).
/// - **Eviction**: Her create'te bir background task `now - 2 * window` öncesi
///   entry'leri purges; IPv6 /64 rotating attacker OOM riskini kapatır.
///   Limiter Drop edildiğinde `Weak` upgrade-fail → task çıkar.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    max_requests: AtomicU32,
    window_secs: AtomicU64,
    trust_xff: AtomicBool,
    /// Trusted proxy IP/CIDR listesi (parse edilmiş). Boşsa legacy flag yolu.
    trusted_proxies: RwLock<Vec<CidrEntry>>,
    /// Tek paylaşılan map — tüm worker'lar buradan okur/yazar.
    limits: DashMap<String, RateLimitEntry>,
}

struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// IP veya CIDR notation: `10.0.0.1`, `10.0.0.0/8`, `fd00::/8`. Tek IP, /32 veya
/// /128 prefix olarak temsil edilir.
#[derive(Debug, Clone)]
struct CidrEntry {
    network: IpAddr,
    prefix: u8,
}

impl CidrEntry {
    fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some((addr_part, prefix_part)) = trimmed.split_once('/') {
            let network: IpAddr = addr_part.parse().ok()?;
            let prefix: u8 = prefix_part.parse().ok()?;
            let max = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return None;
            }
            Some(Self { network, prefix })
        } else {
            let network: IpAddr = trimmed.parse().ok()?;
            let prefix = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(Self { network, prefix })
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_bits = u32::from(net);
                let addr_bits = u32::from(*addr);
                if self.prefix == 0 {
                    return true;
                }
                let mask: u32 = (!0u32) << (32 - self.prefix);
                (net_bits & mask) == (addr_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_bits = u128::from(net);
                let addr_bits = u128::from(*addr);
                if self.prefix == 0 {
                    return true;
                }
                let mask: u128 = (!0u128) << (128 - self.prefix);
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

fn parse_proxies(list: &[String]) -> Vec<CidrEntry> {
    list.iter()
        .filter_map(|s| {
            let parsed = CidrEntry::parse(s);
            if parsed.is_none() {
                tracing::warn!(entry = %s, "skip invalid trusted_proxies entry");
            }
            parsed
        })
        .collect()
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self::with_options(max_requests, window_secs, false)
    }

    pub fn with_options(max_requests: u32, window_secs: u64, trust_xff: bool) -> Self {
        Self::with_trusted_proxies(max_requests, window_secs, trust_xff, &[])
    }

    pub fn with_trusted_proxies(
        max_requests: u32,
        window_secs: u64,
        trust_xff: bool,
        trusted_proxies: &[String],
    ) -> Self {
        let inner = Arc::new(Inner {
            max_requests: AtomicU32::new(max_requests.max(1)),
            window_secs: AtomicU64::new(window_secs.max(1)),
            trust_xff: AtomicBool::new(trust_xff),
            trusted_proxies: RwLock::new(parse_proxies(trusted_proxies)),
            limits: DashMap::new(),
        });
        spawn_evictor(Arc::downgrade(&inner));
        Self { inner }
    }

    pub fn set_limits(&self, max_requests: u32, window_secs: u64) {
        self.inner
            .max_requests
            .store(max_requests.max(1), Ordering::Relaxed);
        self.inner
            .window_secs
            .store(window_secs.max(1), Ordering::Relaxed);
    }

    pub fn set_trust_xff(&self, value: bool) {
        self.inner.trust_xff.store(value, Ordering::Relaxed);
    }

    /// Hot-reload trusted_proxies list (config watcher'dan çağrılır).
    pub fn set_trusted_proxies(&self, list: &[String]) {
        let parsed = parse_proxies(list);
        if let Ok(mut g) = self.inner.trusted_proxies.write() {
            *g = parsed;
        }
    }

    pub fn snapshot(&self) -> (u32, u64) {
        (
            self.inner.max_requests.load(Ordering::Relaxed),
            self.inner.window_secs.load(Ordering::Relaxed),
        )
    }

    /// Test/observability — şu an map'te kaç bucket var?
    pub fn bucket_count(&self) -> usize {
        self.inner.limits.len()
    }
}

/// Periyodik prune — `2 * window` üzerinden geçmiş entry'leri sil. Weak
/// upgrade fail → tüm RateLimiter clone'ları drop edildi, task çıkar.
fn spawn_evictor(weak: Weak<Inner>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let inner = match weak.upgrade() {
                Some(i) => i,
                None => return, // limiter dropped
            };
            let window = inner.window_secs.load(Ordering::Relaxed).max(1);
            let now = Instant::now();
            let stale = std::time::Duration::from_secs(window * 2);
            inner
                .limits
                .retain(|_, entry| now.duration_since(entry.window_start) < stale);
        }
    });
}

/// Client IP extraction strategy (priority order):
///
/// 1. `trusted_proxies` listesi dolu VE `peer_addr` bu listede ise: XFF chain'i
///    SAĞDAN-SOLA gez, ilk untrusted hop'u client IP'si kabul et. Tüm zincir
///    trusted ise zincirin en solu (orijinal client).
/// 2. `trusted_proxies` boş VE legacy `trust_xff = true` ise: XFF'in ilk
///    (en sol) hop'unu körü körüne kabul et — spoof'a açık, sadece backward-compat.
/// 3. Aksi halde `peer_addr`.
///
/// Doğru yöntem #1. #2 düz tehlikelidir; production deployment'lar
/// `trusted_proxies` ile çalışmalı.
fn client_ip(req: &ServiceRequest, inner: &Inner) -> String {
    let peer = req.peer_addr().map(|a| a.ip());

    let proxies_snapshot = inner
        .trusted_proxies
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();

    // Strategy #1 — trusted_proxies aktif
    if !proxies_snapshot.is_empty() {
        let peer_ip = match peer {
            Some(ip) => ip,
            None => return "unknown".to_string(),
        };
        let peer_is_trusted = proxies_snapshot.iter().any(|c| c.contains(&peer_ip));
        if !peer_is_trusted {
            // peer trusted değil → XFF yok say, peer_addr kullan.
            return peer_ip.to_string();
        }
        // peer trusted — XFF chain'i sağdan-sola gez. Format:
        // "client, proxy1, proxy2" — son hop bize en yakın. Bizim direct
        // peer son hop (zaten kontrol edildi). Header değerlerini de aynı
        // sıraya çevir: zincirin sağındaki ilk untrusted = orijinal client.
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                let hops: Vec<&str> = s.split(',').map(|h| h.trim()).collect();
                // Sağdan sola gez (peer trusted olduğundan, son hop'un peer
                // olduğunu varsayıyoruz; o hop hâlâ trusted listede).
                for hop in hops.iter().rev() {
                    if hop.is_empty() {
                        continue;
                    }
                    let parsed: Option<IpAddr> = hop.parse().ok();
                    match parsed {
                        Some(ip) if proxies_snapshot.iter().any(|c| c.contains(&ip)) => {
                            // hop trusted, devam
                            continue;
                        }
                        Some(ip) => {
                            // İlk untrusted hop — orijinal client.
                            return ip.to_string();
                        }
                        None => {
                            // Parse edilemeyen entry — körü körüne trust etme,
                            // peer'a düş.
                            return peer_ip.to_string();
                        }
                    }
                }
                // Tüm zincir trusted; ilk hop'u (zincirin başı) kullan.
                if let Some(first) = hops.first() {
                    let candidate = first.trim();
                    if !candidate.is_empty() {
                        return candidate.to_string();
                    }
                }
            }
        }
        return peer_ip.to_string();
    }

    // Strategy #2 — legacy trust_xff (spoof-prone, deprecated)
    if inner.trust_xff.load(Ordering::Relaxed) {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                if let Some(first) = s.split(',').next() {
                    let candidate = first.trim();
                    if !candidate.is_empty() {
                        return candidate.to_string();
                    }
                }
            }
        }
    }

    // Strategy #3 — peer_addr fallback
    peer.map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddleware {
            service,
            inner: self.inner.clone(),
        }))
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    inner: Arc<Inner>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = client_ip(&req, &self.inner);

        let now = Instant::now();
        let max_requests = self.inner.max_requests.load(Ordering::Relaxed).max(1);
        let window_duration =
            std::time::Duration::from_secs(self.inner.window_secs.load(Ordering::Relaxed).max(1));

        let mut entry = self.inner.limits.entry(ip.clone()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) > window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count > max_requests {
            let remaining = window_duration
                .checked_sub(now.duration_since(entry.window_start))
                .unwrap_or_default();

            drop(entry);

            crate::metrics::AUTH_REJECTS
                .with_label_values(&["rate_limited"])
                .inc();
            tracing::warn!("Rate limit exceeded for IP: {}", ip);
            return Box::pin(async move {
                let response = HttpResponse::TooManyRequests()
                    .insert_header(("Retry-After", remaining.as_secs().to_string()))
                    .json(serde_json::json!({
                        "error": "Rate limit exceeded",
                        "retry_after_secs": remaining.as_secs()
                    }));
                Ok(req.into_response(response).map_into_right_body())
            });
        }

        drop(entry);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    fn make_inner(trust_xff: bool, proxies: &[&str]) -> Arc<Inner> {
        let owned: Vec<String> = proxies.iter().map(|s| s.to_string()).collect();
        Arc::new(Inner {
            max_requests: AtomicU32::new(100),
            window_secs: AtomicU64::new(60),
            trust_xff: AtomicBool::new(trust_xff),
            trusted_proxies: RwLock::new(parse_proxies(&owned)),
            limits: DashMap::new(),
        })
    }

    #[actix_web::test]
    async fn limits_shared_across_clones() {
        let lim = RateLimiter::new(2, 60);
        lim.inner.limits.insert(
            "1.2.3.4".to_string(),
            RateLimitEntry {
                count: 1,
                window_start: Instant::now(),
            },
        );
        let lim2 = lim.clone();
        assert_eq!(lim2.bucket_count(), 1, "clone must share map");
    }

    /// Legacy mode: `trust_xff=true` + boş trusted_proxies → XFF ilk hop kabul
    /// edilir (spoof-prone, deprecated path).
    #[actix_web::test]
    async fn legacy_trust_xff_first_hop() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.1, 10.0.0.1, 127.0.0.1"))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        let inner = make_inner(true, &[]);
        assert_eq!(client_ip(&req, &inner), "203.0.113.1");
        // trust_xff false → peer_addr
        let inner_off = make_inner(false, &[]);
        assert_eq!(client_ip(&req, &inner_off), "10.0.0.99");
    }

    #[actix_web::test]
    async fn legacy_xff_empty_falls_back_to_peer() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", ""))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        let inner = make_inner(true, &[]);
        assert_eq!(client_ip(&req, &inner), "10.0.0.99");
    }

    /// CIDR parse — IPv4 single, IPv4 /8, IPv6 /64, invalid format.
    #[actix_web::test]
    async fn cidr_parse_variants() {
        assert!(CidrEntry::parse("10.0.0.1").is_some());
        assert!(CidrEntry::parse("10.0.0.0/8").is_some());
        assert!(CidrEntry::parse("fd00::/8").is_some());
        assert!(CidrEntry::parse("::1").is_some());
        assert!(CidrEntry::parse("10.0.0.0/33").is_none()); // prefix > 32
        assert!(CidrEntry::parse("not-an-ip").is_none());
        assert!(CidrEntry::parse("").is_none());
    }

    #[actix_web::test]
    async fn cidr_contains() {
        let c = CidrEntry::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(&"10.0.0.1".parse().unwrap()));
        assert!(c.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!c.contains(&"11.0.0.1".parse().unwrap()));
        // v4 ≠ v6
        assert!(!c.contains(&"::1".parse().unwrap()));

        let single = CidrEntry::parse("192.168.1.5").unwrap();
        assert!(single.contains(&"192.168.1.5".parse().unwrap()));
        assert!(!single.contains(&"192.168.1.6".parse().unwrap()));

        let v6 = CidrEntry::parse("fd00::/8").unwrap();
        assert!(v6.contains(&"fd00::1".parse().unwrap()));
        assert!(!v6.contains(&"fc00::1".parse().unwrap()));
    }

    /// peer_addr trusted_proxies'de değilse XFF görmezden gelinir — spoof bypass.
    #[actix_web::test]
    async fn untrusted_peer_xff_ignored() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "8.8.8.8"))
            .peer_addr("4.4.4.4:1000".parse().unwrap()) // public peer, not in list
            .to_srv_request();
        let inner = make_inner(true, &["10.0.0.0/8"]);
        // Attacker public IP'den geliyor, XFF içine ne yazarsa yazsın peer_addr
        // kullanılır — rate limit kendi gerçek IP'sine yazılır.
        assert_eq!(
            client_ip(&req, &inner),
            "4.4.4.4",
            "untrusted peer must not enable XFF spoofing"
        );
    }

    /// peer_addr trusted + XFF chain'in sağdan-sola ilk untrusted = client.
    #[actix_web::test]
    async fn trusted_peer_xff_walked_right_to_left() {
        // Chain: "client, edge_proxy, internal_proxy"
        // peer = internal_proxy (10.0.0.99)
        // trusted = 10.0.0.0/8
        // Beklenen: edge_proxy public → o "client" sayılır? Hayır — edge_proxy
        // de public IP olabilir. Doğru semantic: sağdan sola gez,
        // ilk untrusted hop = orijinal client.
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.5, 198.51.100.7, 10.0.0.1"))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        let inner = make_inner(false, &["10.0.0.0/8"]);
        // Right-to-left: 10.0.0.1 (trusted, skip), 198.51.100.7 (untrusted, STOP)
        assert_eq!(
            client_ip(&req, &inner),
            "198.51.100.7",
            "first untrusted hop from right = original client"
        );
    }

    /// Tüm zincir trusted → en soldaki hop'u kullan.
    #[actix_web::test]
    async fn trusted_peer_all_chain_trusted_uses_leftmost() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "10.1.0.5, 10.2.0.7"))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        let inner = make_inner(false, &["10.0.0.0/8"]);
        assert_eq!(client_ip(&req, &inner), "10.1.0.5");
    }

    /// XFF içindeki parse edilemeyen entry → peer_addr'a düş (defansif).
    #[actix_web::test]
    async fn malformed_xff_entry_falls_back_to_peer() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "garbage-not-an-ip, 10.0.0.1"))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        let inner = make_inner(false, &["10.0.0.0/8"]);
        // sağdan: 10.0.0.1 trusted, sonraki "garbage" parse fail → peer_addr
        assert_eq!(client_ip(&req, &inner), "10.0.0.99");
    }

    /// IPv6 trusted proxy + IPv6 client.
    #[actix_web::test]
    async fn ipv6_trusted_proxy_chain() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "2001:db8::1, fd00::1"))
            .peer_addr("[fd00::99]:1000".parse().unwrap())
            .to_srv_request();
        let inner = make_inner(false, &["fd00::/8"]);
        assert_eq!(client_ip(&req, &inner), "2001:db8::1");
    }
}
