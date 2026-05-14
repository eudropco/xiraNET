use crate::bus::{BusEvent, NoOpBus, XiraBus};
use dashmap::DashSet;
use regex::Regex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// WAF input normalization — bypass variant'larını canonical form'a çevirir.
///
/// 1. Percent-decode 2 pass (double-encoded `%2520` → `%20` → ` `)
/// 2. JSON unicode escape `\u00XX` → ASCII char (printable range)
/// 3. C-style escape `\xXX` → ASCII char
/// 4. Lowercase (regex (?i) ile redundant ama tutarlı canonical form)
fn normalize_input(s: &str) -> String {
    let pass1 = percent_decode(s);
    let pass2 = percent_decode(&pass1);
    let pass3 = unicode_escape_decode(&pass2);
    pass3.to_ascii_lowercase()
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// `\u00XX` (JSON) ve `\xXX` (C) escape sequence'larını ASCII'ye çevir.
/// Sadece printable ASCII (0x20-0x7E) hedeflenir; non-printable atılır.
fn unicode_escape_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // \uXXXX
        if i + 5 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'u' {
            let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).ok();
            if let Some(h) = hex {
                if let Ok(code) = u32::from_str_radix(h, 16) {
                    if let Some(c) = char::from_u32(code) {
                        out.push(c);
                        i += 6;
                        continue;
                    }
                }
            }
        }
        // \xXX
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).ok();
            if let Some(h) = hex {
                if let Ok(code) = u8::from_str_radix(h, 16) {
                    out.push(code as char);
                    i += 4;
                    continue;
                }
            }
        }
        // Default — UTF-8 safe copy
        let c = s[i..].chars().next();
        if let Some(ch) = c {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }
    out
}

/// Structured/credential-carrier header'lar — WAF regex inspection'a girmez.
/// Bu liste request smuggling yüzeyi değil, content semantic'i; JWT/base64
/// byte'larında SQL keyword görünüşü false-positive üretiyordu.
fn is_structured_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "user-agent"
            | "x-api-key"
            | "x-session-token"
            | "x-request-id"
            | "x-trace-id"
            | "x-forwarded-for"
            | "x-real-ip"
            | "etag"
            | "if-none-match"
            | "if-match"
            | "date"
            | "expires"
            | "last-modified"
    )
}

/// UTF-8 boundary'i kırmadan, en fazla `max` karakter alır.
/// `&s[..s.len().min(N)]` byte-slicing multibyte char ortasında panic yapar.
fn safe_truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Web Application Firewall — SQL injection, XSS, path traversal detection.
///
/// Built-in pattern'lar immutable. `custom_patterns` runtime'da admin endpoint'i
/// veya config hot-reload üzerinden eklenebilir; RwLock altında tutulur.
/// Custom rule label: "CUSTOM".
pub struct Waf {
    enabled: bool,
    sql_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    traversal_patterns: Vec<Regex>,
    custom_patterns: RwLock<Vec<CustomRule>>,
    /// Process-wide monoton ID — concurrent add/remove + multi-node node-local'da
    /// unique. Eski `len() + 1` patterni race + divergent ID üretiyordu.
    next_rule_id: AtomicU64,
    /// Arc<Waf> altında çağrılabilir blocklama — eski `HashSet + &mut self` Arc
    /// üzerinden borrow alamadığı için dead code'du.
    blocked_ips: DashSet<String>,
    mode: WafMode,
    bus: RwLock<Arc<dyn XiraBus>>,
}

#[derive(Clone)]
pub struct CustomRule {
    pub id: u64,
    pub pattern_src: String,
    pub pattern: Regex,
    pub label: String,
    pub created_at: u64,
}

impl serde::Serialize for CustomRule {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("CustomRule", 4)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("pattern", &self.pattern_src)?;
        st.serialize_field("label", &self.label)?;
        st.serialize_field("created_at", &self.created_at)?;
        st.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafMode {
    /// Detect + block
    Block,
    /// Detect + log only
    DetectOnly,
}

#[derive(Debug)]
pub enum WafVerdict {
    Allow,
    Block { reason: String, rule: String },
}

/// Verdict'in rule label'ını çek (metric label'ı için). Allow için "ALLOW".
fn verdict_rule(v: &WafVerdict) -> String {
    match v {
        WafVerdict::Allow => "ALLOW".to_string(),
        WafVerdict::Block { rule, .. } => rule.clone(),
    }
}

impl Waf {
    pub fn new(enabled: bool, mode: WafMode) -> Self {
        Self {
            enabled,
            sql_patterns: vec![
                // Açık SQL DDL/DML zincirleri.
                Regex::new(r"(?i)\b(union|select|insert|update|delete|drop|alter|create|exec)\b.{0,80}\b(from|into|table|where|set)\b").unwrap(),
                // SQL özel karakterler — SADECE SQL keyword bağlamı yakınında.
                // ';--', '/*', '*/', '@@version' gibi kombinasyonlar; tek başına ';' veya '@' false positive üretir.
                Regex::new(r"(?i)(;\s*(drop|delete|update|insert|union|select|truncate|alter)\b|--\s*$|/\*[^*]*\*/|@@\w+|\bxp_cmdshell\b)").unwrap(),
                // Klasik '1=1' / 'OR 1=1' style boolean injection.
                Regex::new(r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+").unwrap(),
                // Time-based blind SQLi.
                Regex::new(r"(?i)\b(sleep|benchmark|waitfor|pg_sleep)\s*\(").unwrap(),
                // Quote + SQL keyword payload.
                Regex::new(r"'\s*(or|and|union)\s+").unwrap(),
            ],
            xss_patterns: vec![
                Regex::new(r"(?i)<\s*script[^>]*>").unwrap(),
                Regex::new(r"(?i)(javascript|vbscript|expression)\s*:").unwrap(),
                Regex::new(r"(?i)on(load|error|click|mouseover|submit|focus|blur)\s*=").unwrap(),
                Regex::new(r"(?i)<\s*(iframe|object|embed|applet|form|input)").unwrap(),
                Regex::new(r"(?i)(document\.(cookie|write|location)|window\.(location|open))").unwrap(),
            ],
            traversal_patterns: vec![
                Regex::new(r"\.\./").unwrap(),
                Regex::new(r"\.\.\\").unwrap(),
                Regex::new(r"(?i)(/etc/passwd|/etc/shadow|/proc/self)").unwrap(),
                Regex::new(r"(?i)(cmd\.exe|powershell|/bin/(sh|bash))").unwrap(),
                Regex::new(r"%2e%2e[%/\\]").unwrap(),
            ],
            custom_patterns: RwLock::new(Vec::new()),
            next_rule_id: AtomicU64::new(1),
            blocked_ips: DashSet::new(),
            mode,
            bus: RwLock::new(Arc::new(NoOpBus) as Arc<dyn XiraBus>),
        }
    }

    /// Bus inject — multi-node rule sync için.
    pub fn set_bus(&self, bus: Arc<dyn XiraBus>) {
        if let Ok(mut g) = self.bus.write() {
            *g = bus;
        }
    }

    /// Yeni custom block pattern ekle. Geçersiz regex `Err`. Başarılıysa rule ID döner.
    /// Bus üzerinden tüm node'lara yayılır.
    pub fn add_custom_pattern(&self, pattern_src: &str, label: &str) -> Result<u64, String> {
        let id = self.apply_add_pattern(pattern_src, label)?;
        // Broadcast
        let bus = self.bus.read().map(|g| g.clone()).ok();
        if let Some(bus) = bus {
            let pattern_src = pattern_src.to_string();
            let label = label.to_string();
            tokio::spawn(async move {
                bus.publish(&BusEvent::WafRuleAdded {
                    id,
                    pattern: pattern_src,
                    label,
                })
                .await;
            });
        }
        Ok(id)
    }

    /// Bus-driven apply — local state'i mutate eder ama bus'a YENİDEN yayınlamaz.
    /// Atomic ID: `len() + 1` patterni eski sürümde race + sil/ekle çakışması
    /// üretiyordu. `next_rule_id.fetch_add(1)` monoton + race-free.
    pub fn apply_add_pattern(&self, pattern_src: &str, label: &str) -> Result<u64, String> {
        let re = Regex::new(pattern_src).map_err(|e| format!("invalid regex: {e}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id = self.next_rule_id.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.custom_patterns.write().map_err(|_| "lock poisoned")?;
        guard.push(CustomRule {
            id,
            pattern_src: pattern_src.to_string(),
            pattern: re,
            label: if label.is_empty() {
                "CUSTOM".into()
            } else {
                label.to_string()
            },
            created_at: now,
        });
        Ok(id)
    }

    /// Custom pattern'i ID ile sil. Bus broadcast.
    pub fn remove_custom_pattern(&self, id: u64) -> bool {
        let removed = self.apply_remove_pattern(id);
        if removed {
            let bus = self.bus.read().map(|g| g.clone()).ok();
            if let Some(bus) = bus {
                tokio::spawn(async move {
                    bus.publish(&BusEvent::WafRuleRemoved { id }).await;
                });
            }
        }
        removed
    }

    /// Bus-driven apply — yayınlamaz.
    pub fn apply_remove_pattern(&self, id: u64) -> bool {
        let mut guard = match self.custom_patterns.write() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let len = guard.len();
        guard.retain(|r| r.id != id);
        guard.len() < len
    }

    /// Tüm custom pattern'leri listele (serializable snapshot).
    pub fn list_custom_patterns(&self) -> Vec<CustomRule> {
        self.custom_patterns
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Config'den load — initial set veya hot-reload sırasında çağrılır.
    /// Mevcut custom_patterns tamamen değiştirilir.
    /// Config-based load — mevcut custom_patterns tamamen değiştirilir, ID'ler
    /// atomic counter'dan alınır.
    pub fn load_custom_patterns_from_strings(&self, patterns: &[String]) {
        let mut compiled: Vec<CustomRule> = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for src in patterns.iter() {
            match Regex::new(src) {
                Ok(re) => compiled.push(CustomRule {
                    id: self.next_rule_id.fetch_add(1, Ordering::Relaxed),
                    pattern_src: src.clone(),
                    pattern: re,
                    label: "CUSTOM".to_string(),
                    created_at: now,
                }),
                Err(e) => {
                    tracing::warn!(error = %e, pattern = %src, "skip invalid WAF custom pattern");
                }
            }
        }
        if let Ok(mut g) = self.custom_patterns.write() {
            *g = compiled;
        }
    }

    /// Request'i WAF kurallarına karşı kontrol et
    pub fn inspect(
        &self,
        path: &str,
        query: Option<&str>,
        body: &str,
        headers: &[(String, String)],
        ip: &str,
    ) -> WafVerdict {
        if !self.enabled {
            return WafVerdict::Allow;
        }

        // IP block check
        if self.blocked_ips.contains(ip) {
            return WafVerdict::Block {
                reason: format!("Blocked IP: {ip}"),
                rule: "IP_BLOCK".to_string(),
            };
        }

        // Input normalization — eski sürüm raw payload üzerinde regex match
        // yapıyordu, bu yüzden URL-encoded (`%55nion`), double-encoded (`%2520`)
        // ve unicode escape (`select`) variantlar bypass'lıyordu.
        //
        // Her input için: 2-pass percent-decode (double-encoding kapalı) +
        // JSON unicode escape (`\u00XX`) → ASCII char + lowercase. Regex'lerimiz
        // case-insensitive (?i) ama bazı pattern'ler için yine de tutarlı
        // canonical form üretir.
        //
        // Original input da incele — bazı imzalar (örn. `%2e%2e/`) decoded
        // halde görünmüyor ama traversal niyetini gösteriyor.
        let path_norm = normalize_input(path);
        let query_norm = normalize_input(query.unwrap_or(""));
        let body_norm = normalize_input(body);

        // Structured header'lar (Authorization, Cookie, User-Agent, X-Api-Key,
        // X-Session-Token) regex inspection'a girmemeli — JWT/base64 random
        // byte'ları false-positive üretir, legitimate login block edilir.
        // Sadece "free-text" header'lar inspect ediliyor.
        let header_values: Vec<String> = headers
            .iter()
            .filter(|(k, _)| !is_structured_header(k))
            .map(|(_, v)| normalize_input(v))
            .collect();

        let raw_inputs = [
            path.to_string(),
            query.unwrap_or("").to_string(),
            body.to_string(),
        ];
        let normalized = [path_norm, query_norm, body_norm];

        // Both raw + normalized: decoded form'da bypass kapalı, raw form'da
        // `%2e%2e/` gibi niyet imzaları yakalanır.
        let all_inputs: Vec<&str> = normalized
            .iter()
            .chain(raw_inputs.iter())
            .chain(header_values.iter())
            .map(|s| s.as_str())
            .collect();

        // SQL Injection check
        for input in &all_inputs {
            for pattern in &self.sql_patterns {
                if pattern.is_match(input) {
                    let verdict = WafVerdict::Block {
                        reason: format!(
                            "SQL injection detected in: {}...",
                            safe_truncate(input, 50)
                        ),
                        rule: "SQLI".to_string(),
                    };
                    tracing::warn!("🛡️ WAF SQLI: {} from {}", safe_truncate(input, 80), ip);
                    if self.mode == WafMode::DetectOnly {
                        crate::metrics::WAF_DETECTS.with_label_values(&[&verdict_rule(&verdict)]).inc();
                        return WafVerdict::Allow;
                    }
                    return verdict;
                }
            }
        }

        // XSS check
        for input in &all_inputs {
            for pattern in &self.xss_patterns {
                if pattern.is_match(input) {
                    let verdict = WafVerdict::Block {
                        reason: format!("XSS detected in: {}...", safe_truncate(input, 50)),
                        rule: "XSS".to_string(),
                    };
                    tracing::warn!("🛡️ WAF XSS: {} from {}", safe_truncate(input, 80), ip);
                    if self.mode == WafMode::DetectOnly {
                        crate::metrics::WAF_DETECTS.with_label_values(&[&verdict_rule(&verdict)]).inc();
                        return WafVerdict::Allow;
                    }
                    return verdict;
                }
            }
        }

        // Path traversal check
        for input in &all_inputs {
            for pattern in &self.traversal_patterns {
                if pattern.is_match(input) {
                    let verdict = WafVerdict::Block {
                        reason: format!(
                            "Path traversal detected: {}...",
                            safe_truncate(input, 50)
                        ),
                        rule: "TRAVERSAL".to_string(),
                    };
                    tracing::warn!(
                        "🛡️ WAF TRAVERSAL: {} from {}",
                        safe_truncate(input, 80),
                        ip
                    );
                    if self.mode == WafMode::DetectOnly {
                        crate::metrics::WAF_DETECTS.with_label_values(&[&verdict_rule(&verdict)]).inc();
                        return WafVerdict::Allow;
                    }
                    return verdict;
                }
            }
        }

        // Custom patterns (runtime-mutable) — son sırada, built-in'ler önceliklidir.
        if let Ok(custom) = self.custom_patterns.read() {
            for rule in custom.iter() {
                for input in &all_inputs {
                    if rule.pattern.is_match(input) {
                        let verdict = WafVerdict::Block {
                            reason: format!(
                                "Custom rule '{}' matched: {}...",
                                rule.label,
                                safe_truncate(input, 50)
                            ),
                            rule: rule.label.clone(),
                        };
                        tracing::warn!(
                            "🛡️ WAF CUSTOM[{}]: {} from {}",
                            rule.label,
                            safe_truncate(input, 80),
                            ip
                        );
                        if self.mode == WafMode::DetectOnly {
                            crate::metrics::WAF_DETECTS
                                .with_label_values(&[&verdict_rule(&verdict)])
                                .inc();
                            return WafVerdict::Allow;
                        }
                        return verdict;
                    }
                }
            }
        }

        WafVerdict::Allow
    }

    /// IP'yi engelle
    /// IP'yi engelle — `Arc<Waf>` altında çağrılabilir (`&self`). Eski
    /// `&mut self` versiyonu Arc borrow yapamadığı için dead code'du.
    pub fn block_ip(&self, ip: String) {
        self.blocked_ips.insert(ip);
    }

    /// IP engelini kaldır
    pub fn unblock_ip(&self, ip: &str) -> bool {
        self.blocked_ips.remove(ip).is_some()
    }

    pub fn list_blocked_ips(&self) -> Vec<String> {
        self.blocked_ips.iter().map(|e| e.clone()).collect()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn mode(&self) -> &WafMode {
        &self.mode
    }
}

/// WAF istatistikleri
#[derive(Default, Clone, serde::Serialize)]
pub struct WafStats {
    pub total_inspected: u64,
    pub blocked: u64,
    pub sqli_detected: u64,
    pub xss_detected: u64,
    pub traversal_detected: u64,
}

/// Bus-driven WAF rule sync. Remote node'lar rule add/remove olaylarını
/// local pattern listesine uygular.
#[async_trait::async_trait]
impl crate::bus::BusEventHandler for Waf {
    async fn handle(&self, event: crate::bus::BusEvent) {
        match event {
            crate::bus::BusEvent::WafRuleAdded {
                id: _,
                pattern,
                label,
            } => {
                if let Err(e) = self.apply_add_pattern(&pattern, &label) {
                    tracing::warn!(error = %e, pattern, "WAF: bus add failed");
                } else {
                    tracing::debug!(pattern, label, "WAF: rule added via bus");
                }
            }
            crate::bus::BusEvent::WafRuleRemoved { id } => {
                let removed = self.apply_remove_pattern(id);
                if removed {
                    tracing::debug!(id, "WAF: rule removed via bus");
                }
            }
            _ => {}
        }
    }
}
