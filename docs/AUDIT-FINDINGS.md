# xiraNET v3.0 — Audit Findings (açık + kapalı)

Bu dosya, v3.0.0 sürümü için yapılan iç audit ve harici çeyrek-yıllık eleştiri
turunun **tam çıktısıdır**. Önceki README'de yalnızca kapanan maddeler
listelenmişti; bu dosya açık olanları da gizlemeden ortaya koyar.

## Format

Her madde: **[severity] kategori — kısa açıklama → durum**.
Severity: CRITICAL / HIGH / MEDIUM / LOW. Durum: OPEN (henüz fix yok),
PARTIAL (kısmen fix var, kalan iş tanımlı), CLOSED (test edilmiş + dokümante).

---

## CLOSED — Yarı A (production öncesi minimum, hepsi commit edildi)

1. ✅ **WAF `block_ip` `&self`** — `DashSet<String>` ile yeniden yazıldı;
   `Arc<Waf>` altında çağrılabilir. `list_blocked_ips()` eklendi.
2. ✅ **WAF rule ID atomic** — `AtomicU64::fetch_add(1, Relaxed)` ile race-free
   + multi-node node-local unique. `len() + 1` patterni silindi.
3. ✅ **Rate limiter shared map** — `Inner` struct'ında `DashMap`; tüm worker
   thread'leri aynı bucket'ı paylaşır. Effective rate artık config'e eşit,
   workers × config değil.
4. ✅ **Rate limiter XFF** — `[rate_limit].trust_xff` config flag.
   `client_ip(req, trust_xff)` helper, README'de uyarı (sadece reverse proxy
   altında açılmalı).
5. ✅ **Rate limiter eviction** — `spawn_evictor` background task,
   `2 * window_secs` öncesi entry'leri 30s'de bir prune eder. `Weak`
   upgrade-fail → task çıkar (limiter drop edildiğinde).
6. ✅ **Proxy error sanitize** — client artık sadece `{"error": "Service
   unavailable"}` görür; downstream URL/DNS/port server log'a. RFC 7230
   hop-by-hop liste tamamlandı (`te`, `proxy-authorization`,
   `proxy-connection` eklendi).
7. ✅ **JWT path normalize gerçek `..` strip** — segment stack ile resolve;
   `/xira/../api/secret` → `/api/secret`. 6 unit test (collapse/traversal/
   dot/trailing-slash/above-root).
8. ✅ **failed_attempts normalize + cap** — `normalize_email()` lowercase
   + trim; lookup + index + remove tüm yerlerde. `FAILED_ATTEMPTS_MAX_ENTRIES
   = 10_000` cap; aşıldığında time-based prune + en eski LRU evict.
9. ✅ **Authenticator façade** — `src/identity/authenticator.rs`.
   `login(email, pw, ip, ua) -> AuthOutcome`; `AuthOutcome::Success` ham
   token taşımaz, sadece `Session` taşır (= sessions.create() çağrılmış
   demektir). Handler'lar `Arc<Authenticator>` alır; UserManager +
   SessionManager doğrudan inject edilmiyor login path'lerinde.
10. ✅ **crates/ silindi** — repo'dan tamamen kaldırıldı (7K satır
    divergent fork). Önceki "silindi" yalanı dürüst hale geldi.

---

## OPEN — Yarı B (öncelik 1, sertleştirme)

### HIGH
10. **WAF input normalization yok** — URL-decode, unicode escape, JSON
    unescape, comment-obfuscation hiçbiri yok. `id=1+UNION%2520SELECT...`
    bypass'lar. Fix: WAF inspect'ten önce input normalize chain
    (urldecode → unicode → unescape).
11. **WAF structured header'ları skip etmiyor** — `Authorization`, `Cookie`,
    `User-Agent` regex inspection'a girer; JWT/base64 random byte'ları
    `\b(or|and)\b\s+\d+\s*=\s*\d+` desenini tetikler → legitimate login
    block. Fix: header allow-list inspection.
12. **SSRF guard TOCTOU** — `src/alerting/url_guard.rs::validate_outbound_url`
    yorumda kendisi söylüyor: resolve→connect arası IP değişebilir
    (DNS rebinding). Fix: custom resolver, resolve sonrası IP-pin geçir
    (`reqwest::Client::dns_resolver`).
13. **UpstreamOnly mode loopback'e izin → Redis/Postgres CRLF smuggling** —
    `http://127.0.0.1:6379/` upstream kaydı; HTTP request CRLF'leri Redis
    ASCII protokolünde komut olarak parse edilir → gopher-tipi SSRF.
    Fix: port allow-list (80/443/3000-9999 falan) veya protocol negotiation.
14. **Sessions IP/UA binding yok** — `validate()` token kontrol eder, kayıtlı
    `ip`/`user_agent` ile karşılaştırmaz → token theft replay açık. Fix:
    request IP/UA vs stored, mismatch'te invalidate veya warn.
15. **Sessions max_sessions race** — `sessions.insert` + `user_sessions.entry().
    push` atomik değil. İki concurrent create yanlış token evict edebilir.
    Fix: tek mutex altında veya DashMap entry-based transaction.
16. **Sessions last_activity persist edilmiyor** — `validate()` memory'de
    update eder, SQLite'a yazmaz → restart sonrası idle-timeout bozulur.
    Fix: validate'te persist call (frekansı throttled).
17. **update_role audit_log row'una yazılmıyor** — tracing::warn structured
    log var, append-only `audit_log` tablosuna gitmiyor. Privilege change
    audit trail eksik. Fix: ayrı `identity_audit` tablo veya `audit_log`'a
    type field ekle.
18. **SecretBox `from_passphrase` SHA-256 KDF** — argon2 var, password için
    kullanılıyor; master key için tek hash. 32-char password girilirse
    entropy düşük → tüm at-rest zayıflar. Fix: `from_passphrase` sil
    (sadece `from_random_32_bytes`) veya Argon2 ile genişlet.
19. **SecretBox key rotation flow yok** — single-byte version field var ama
    rotate path yok. Key kaybı = MFA seed kaybı. Fix: 2-key transition
    (current + previous) read-side, write-only-current.
20. **JWT RSA PEM her validate'te parse** — `src/middleware/jwt.rs`. Gateway
    hot-path. Fix: boot'ta tek parse, `Arc<DecodingKey>` veya `OnceLock`.
21. **`hash_token` SHA-256 (HMAC değil)** — DB leak senaryosunda defansive
    layer eksik. Mevcut token entropy 128-bit olduğu için pratikte
    preimage infeasible, ama HMAC-server-key bağlasaydık DB-leak-only
    attacker hashları validate'e geçiremezdi. Fix: HMAC-SHA256 with
    XIRA_SECRETS_KEY (SecretBox'la aynı kasa).
22. **DUMMY_ARGON2_HASH version drift** — `src/identity/users.rs`. Hardcoded
    hash, ama argon2 crate default params upgrade'inde live hash vs dummy
    farklı params → timing equalization bozulur → account enumeration.
    Fix: Argon2 explicit params pin (m=19456, t=2, p=1) hem dummy hem live
    için.

### MEDIUM
23. **WAF_BLOCKS / WAF_DETECTS dashboard ayırımı net ama dokümante eksik** —
    Block mode'da BLOCKS, DetectOnly'de DETECTS. Dashboard JSON ikisini de
    gösteriyor (xira-security.json). Ama SIEM operator ilk bakışta hangisi
    hangisi anlamayabilir. Fix: README'de açık tablo + dashboard panel
    title'larında "(active mode)" / "(observe mode)" suffix'leri.
24. **Hop-by-hop headers eksik** — `src/gateway/proxy.rs::SKIP_HEADERS`
    `te`, `proxy-authorization`, `proxy-connection` yok. RFC 7230 hop-by-hop
    smuggling. Fix: tam liste.
25. **Bus subscriber için ikinci RedisBus instance** — `main.rs`. `XiraBus`
    trait'i `spawn_subscriber` içermediği için ayrı instance. Connection
    sayısı 2×. Fix: trait'e `spawn_subscriber(&self, dispatcher) -> JoinHandle`
    ekle.

---

## OPEN — Yarı C (öncelik 2, yapısal)

### HIGH
26. **main.rs 912-line god function** — her domain (auth/gateway/mesh/mfa/
    telemetry/plugins/...) tek async fn main'de Arc::new + manuel wire.
    Bir feature değiştirmek için 800 satır okumak gerek. Fix: domain başına
    `bootstrap::auth`, `bootstrap::gateway` modülleri, her biri `(state,
    app_builder)` döndürür; main sadece compose eder.
27. **CI workspace=["."], `crates/` type-check edilmez** — 7K satır kod
    repo'da ama ne build ne lint. Future refactor'da silent regression
    riski. Fix: ya `members = ["."]` + `[workspace.exclude] crates/*`
    açıkça, ya da crates/'i sil. Aradaki "kasıtlı orphan" karar dürüst
    değil.
28. **`cargo install ... || true` + `cargo audit` `--deny warnings` yok** —
    CI gate'i raporlu ama enforcing değil. Advisory artarsa CI yine yeşil.
    Fix: `--locked` + exit code respect + `--deny warnings`.
29. **Test suite adversarial coverage yok** — WAF testleri sadece raw
    payload. URL-encoded, comment-obfuscation, JWT alg=none, session race,
    SSRF DNS rebinding mock yok. Fix: WAF kuralı başına min 3 obfuscation
    variant + protocol-level negative tests.

### MEDIUM
30. **`crates/` belgesel yalan (FIXED bu commit'te)** — README "v3.0.0'da
    silindi" diyor, repo'da hâlâ duruyor. Bu commit'te README dürüst hale
    geldi; gerçekten silme veya member-yap kararı CI gate'iyle (madde 27)
    birlikte halledilecek.
31. **`crates/xira-auth/src/jwt.rs::JwtClaims.exp: Option<usize>`** — main
    crate `usize` (zorunlu); fork `Option` (opsiyonel). Fork compile
    edilmiyor ama divergent semantics ileride toplanırsa zayıf. Madde 27
    ile çözülür.

---

## CLOSED — Gerçekten yapıldı + test edildi

- K1 — Session validation `/auth/*` middleware'ine wired (SessionAuth)
- K2 — SSRF guards: webhook strict mode + cron/service register upstream
  mode (metadata IP'ler her durumda bloke)
- K3 — Admin API key `subtle::ConstantTimeEq`
- JWT default-secret guard (boot'ta reddet) + min 32-byte HMAC + RS256 PEM
  boot-time parse + algorithm pinning
- CORS `allow_any_origin` kaldırıldı, explicit listesi
- MFA at-rest AES-256-GCM `SecretBox` (KDF zayıflığı OPEN madde 18'de)
- MFA enrollment endpoint'leri (`/auth/mfa/{enroll,verify,login}`)
- WAF SQLi pattern sıkılaştırma (standalone `;`/`--`/`@` artık match etmiyor)
- WAF non-UTF-8 body lossy convert (byte-prefix bypass kapalı)
- Proxy X-Forwarded-Proto connection scheme'den
- OAuth2 token cache SHA-256 hashed key (raw token memory'de yok)
- Sessions SQLite persistence (create/invalidate path; last_activity OPEN
  madde 16'da)
- Datapipeline three-phase lock (RwLock-across-await fix)
- Discovery: Consul multi-instance fix + hickory DNS SRV + Docker labels
- Plugin libloading dynamic load (Rust ABI)
- OAuth2Gateway + ServiceMesh admin endpoint'leri
- Audit log SQLite UPDATE/DELETE trigger (tabloyu DROP/ALTER hâlâ mümkün)
- Audit log remote sink (file JSONL + HTTP webhook, paralel, SSRF guard'lı)
- RBAC `UserRole` hierarchy + `RequireRole` middleware + `/auth/admin/*`
- Prometheus security counter ailesi (WAF/SSRF/auth/DB/session/MFA/JWT)
- Grafana auto-provisioned dashboard'lar (Security + Gateway)
- CLI session token persistence (`~/.config/xira/session` 0600)
- CLI admin subcommand (users/role/disable/logout/mfa-reset/login/logoff/whoami)
- CLI destructive op confirmation prompt + `--yes` flag
- Multi-node `XiraBus` (NoOpBus / RedisBus) + session invalidation
  broadcast + WAF rule add/remove broadcast (rule ID divergence OPEN madde 2'de)
- CI Redis service for bus tests (REDIS_URL env)
- `xira system validate` + `xira system doctor` + CI config-gate
- `cargo audit` ile 5 vulnerability → 0

---

## Sıra

1. **Yarı A** (1-9) — production öncesi minimum
2. **Yarı B** (10-25) — sertleştirme; bunlar olmadan "production-grade"
   ibaresi haksızdır
3. **Yarı C** (26-31) — yapısal, sürdürülebilirlik

Bu dosya commit'lerde güncellenir. Bir madde CLOSED'a geçtiğinde commit
message'ında `audit-finding: closes #N` yaz.
