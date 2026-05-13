use regex::Regex;
use std::collections::HashSet;
use std::sync::RwLock;

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
    blocked_ips: HashSet<String>,
    mode: WafMode,
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
            blocked_ips: HashSet::new(),
            mode,
        }
    }

    /// Yeni custom block pattern ekle. Geçersiz regex `Err`. Başarılıysa rule ID döner.
    pub fn add_custom_pattern(&self, pattern_src: &str, label: &str) -> Result<u64, String> {
        let re = Regex::new(pattern_src).map_err(|e| format!("invalid regex: {e}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut guard = self.custom_patterns.write().map_err(|_| "lock poisoned")?;
        let id = guard.len() as u64 + 1;
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

    /// Custom pattern'i ID ile sil.
    pub fn remove_custom_pattern(&self, id: u64) -> bool {
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
    pub fn load_custom_patterns_from_strings(&self, patterns: &[String]) {
        let mut compiled: Vec<CustomRule> = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for (i, src) in patterns.iter().enumerate() {
            match Regex::new(src) {
                Ok(re) => compiled.push(CustomRule {
                    id: (i + 1) as u64,
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

        // Tüm inputları birleştir
        let inputs = [
            path.to_string(),
            query.unwrap_or("").to_string(),
            body.to_string(),
        ];

        // Header değerlerini de kontrol et
        let header_values: Vec<String> = headers.iter().map(|(_, v)| v.clone()).collect();

        let all_inputs: Vec<&str> = inputs
            .iter()
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
    pub fn block_ip(&mut self, ip: String) {
        self.blocked_ips.insert(ip);
    }

    /// IP engelini kaldır
    pub fn unblock_ip(&mut self, ip: &str) {
        self.blocked_ips.remove(ip);
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
