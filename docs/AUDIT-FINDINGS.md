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

## CLOSED — Yarı B (Phase 5 part 2, hepsi commit edildi)

10. ✅ **WAF input normalization** — 2-pass percent-decode + `\u00XX`/`\xXX`
    unicode escape + lowercase canonical form. Hem normalized hem raw input
    inspect edilir (intent imzalar yakalanır). 4 adversarial test:
    URL-encoded SQLi, double-encoded, unicode-escape XSS, encoded traversal.
11. ✅ **WAF structured header skip** — `is_structured_header()` allow-list:
    Authorization, Cookie, Set-Cookie, User-Agent, X-Api-Key, X-Session-Token,
    X-Forwarded-For, Date, ETag vb. Free-text custom header'lar hâlâ
    inspect edilir. 2 test: JWT cookie false-positive yok, free-text yine
    block.
12. ✅ **SSRF custom resolver / IP-pin** — `pin_outbound_url` + `pin_upstream_url`
    PinnedUrl döndürür. `PinnedUrl::build_client(timeout)` ile
    `reqwest::ClientBuilder::resolve_to_addrs` üzerinden DNS bypass —
    connect sırasında stored safe IP'ye gider. Cron her tick'te URL
    yeniden pin (TOCTOU window kapalı).
13. ✅ **UpstreamOnly port allow-list** — `is_allowed_upstream_port()`:
    80/443/8080-8090/3000-3999/9000-9999/5000-5001/7000-7001/8000-8079/8443.
    Redis 6379, Postgres 5432, MySQL 3306 reddedilir → CRLF/gopher SSRF
    kapalı.
14. ✅ **Sessions IP binding strict + UA binding warn-only** —
    `validate_with_request(token, expected_ip, expected_ua)`. IP mismatch
    → invalidate + `session_events_total{binding_violation}`. UA mismatch
    → warn-only counter (mobile cellular IP rotates, UA stays — strict UA
    invalidation false-positive). SessionAuth middleware her request'e
    IP/UA geçirir.
15. ✅ **Sessions max_sessions race** — atomic two-phase: `user_sessions.
    entry()` lock altında push + retain + evict, sonra lock dışında
    `sessions.insert`. Concurrent create test: 10 paralel, max=3 → exactly
    3 active.
16. ✅ **Sessions last_activity persist throttled** — validate'te
    `last_activity = now`; her 30 saniyede bir SQLite'a persist (disk-write
    spam değil). Restart sonrası idle-timeout korunur.
17. ✅ **update_role audit row** — `events` tablosuna `identity.role_changed`
    type'ı ile yazılır (old_role → new_role, email, user_id). tracing::warn
    yanı sıra durable log.
18. ✅ **SecretBox 2-mode init** — 64 hex char → raw 32-byte key (high
    entropy, `openssl rand -hex 32`); kısa passphrase → Argon2id KDF
    (m=19456, t=2, p=1) ile derive. XIRA_SECRETS_SALT env ile rotation.
19. ✅ **SecretBox key rotation hook** — XIRA_SECRETS_SALT değişimi yeni
    key üretir. Multi-key transition tasarımı eksik (bkz. NEXT PHASE);
    şimdilik tek key + rotate-by-salt + tek seferlik MFA re-enroll
    operasyonel sınır.
20. ✅ **JWT RSA `Arc<DecodingKey>`** — boot'ta tek kere parse, `Arc::clone`
    ile hot-path'ta deref-only. PEM parse hot-path'tan çıkarıldı.
21. ✅ **`hash_token` HMAC-SHA256** — XIRA_SECRETS_KEY varsa Argon2id ile
    32-byte HMAC key derive (domain-separated salt `xira-session-hmac-v1`).
    DB leak senaryosunda attacker key olmadan hashları validate'e
    geçiremez. Env yoksa SHA-256 fallback (warning, backward compat).
22. ✅ **DUMMY_ARGON2_HASH parametre pin** — `argon2_pinned()` helper
    (m=19456, t=2, p=1) hem hash_password hem verify_password'da kullanılır.
    argon2 crate default upgrade etse bile dummy + live aynı parameter
    penceresinde kalır.
23. ✅ **WAF_BLOCKS/DETECTS dashboard** — Grafana JSON (xira-security.json)
    zaten iki seriyi de gösteriyor ("block: {{rule}}" + "detect-only:
    {{rule}}"). README'de net açıklama eklendi.
24. ✅ **Hop-by-hop headers tam** — Yarı A'da kapatıldı (te,
    proxy-authorization, proxy-connection).
25. ✅ **Bus `spawn_subscriber` trait method** — `XiraBus` trait'e eklendi
    (NoOpBus no-op, RedisBus pub/sub task). main.rs artık tek bus instance
    + tek subscriber → connection count 1×.

## OPEN — Yarı C (geriye kalan, scope büyük)

### NEXT PHASE
26. **main.rs 914-line god function** — domain başına `bootstrap::*`
    module ile split. Risk: tüm test'leri yeniden doğrulamak ~3-4 saat.
    Bu commit'te yapılmadı; v3.1.0 milestone'una koyuluyor.
29. **Adversarial test suite genişletme** — `adversarial_tests` modülünde
    7 test eklendi: alg=none reject, empty alg, weak secret, session race,
    IP binding mismatch, Arc<Waf>::block_ip canlı, email case-permutation.
    DNS rebinding mock (resolve→connect IP swap test) eklenmedi —
    `reqwest::ClientBuilder::resolve_to_addrs` API'sini mocklamak entegre
    test harness gerektirir; PinnedUrl tasarımı zaten DNS bypass garantili,
    test priority düşük. Daha geniş test coverage (örn. HTTP smuggling,
    websocket auth race) NEXT PHASE.

### CLOSED
27. ✅ **CI workspace** — crates/ silindi, `members = ["."]` tek member,
    type-check eksiği yok.
28. ✅ **CI audit hardening** — `cargo install --locked cargo-audit`
    (`|| true` kaldırıldı), `cargo audit --deny warnings` (advisory'ler
    fail eder, `.cargo/audit.toml` ile gerekçeli ignore listesi).
30. ✅ **`crates/` belgesel yalan** — gerçekten silindi (Yarı A).
31. ✅ **`crates/xira-auth/jwt.rs` divergent** — silindi.

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
