use regex::Regex;
use std::collections::HashSet;

/// Web Application Firewall — SQL injection, XSS, path traversal detection
pub struct Waf {
    enabled: bool,
    sql_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    traversal_patterns: Vec<Regex>,
    blocked_ips: HashSet<String>,
    mode: WafMode,
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

impl Waf {
    pub fn new(enabled: bool, mode: WafMode) -> Self {
        Self {
            enabled,
            sql_patterns: vec![
                Regex::new(r"(?i)(\b(union|select|insert|update|delete|drop|alter|create|exec)\b.*\b(from|into|table|where|set)\b)").unwrap(),
                Regex::new(r"(?i)(--|;|/\*|\*/|@@|@)").unwrap(),
                Regex::new(r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+").unwrap(),
                Regex::new(r"(?i)(sleep|benchmark|waitfor|delay)\s*\(").unwrap(),
                Regex::new(r"'(\s|\+)*(or|and|union)(\s|\+)+").unwrap(),
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
            blocked_ips: HashSet::new(),
            mode,
        }
    }

    /// Request'i WAF kurallarına karşı kontrol et
    pub fn inspect(&self, path: &str, query: Option<&str>, body: &str, headers: &[(String, String)], ip: &str) -> WafVerdict {
        if !self.enabled {
            return WafVerdict::Allow;
        }

        // IP block check
        if self.blocked_ips.contains(ip) {
            return WafVerdict::Block {
                reason: format!("Blocked IP: {}", ip),
                rule: "IP_BLOCK".to_string(),
            };
        }

        // Tüm inputları birleştir
        let inputs = vec![
            path.to_string(),
            query.unwrap_or("").to_string(),
            body.to_string(),
        ];

        // Header değerlerini de kontrol et
        let header_values: Vec<String> = headers.iter().map(|(_, v)| v.clone()).collect();

        let all_inputs: Vec<&str> = inputs.iter().chain(header_values.iter()).map(|s| s.as_str()).collect();

        // SQL Injection check
        for input in &all_inputs {
            for pattern in &self.sql_patterns {
                if pattern.is_match(input) {
                    let verdict = WafVerdict::Block {
                        reason: format!("SQL injection detected in: {}...", &input[..input.len().min(50)]),
                        rule: "SQLI".to_string(),
                    };
                    tracing::warn!("🛡️ WAF SQLI: {} from {}", &input[..input.len().min(80)], ip);
                    if self.mode == WafMode::DetectOnly { return WafVerdict::Allow; }
                    return verdict;
                }
            }
        }

        // XSS check
        for input in &all_inputs {
            for pattern in &self.xss_patterns {
                if pattern.is_match(input) {
                    let verdict = WafVerdict::Block {
                        reason: format!("XSS detected in: {}...", &input[..input.len().min(50)]),
                        rule: "XSS".to_string(),
                    };
                    tracing::warn!("🛡️ WAF XSS: {} from {}", &input[..input.len().min(80)], ip);
                    if self.mode == WafMode::DetectOnly { return WafVerdict::Allow; }
                    return verdict;
                }
            }
        }

        // Path traversal check
        for input in &all_inputs {
            for pattern in &self.traversal_patterns {
                if pattern.is_match(input) {
                    let verdict = WafVerdict::Block {
                        reason: format!("Path traversal detected: {}...", &input[..input.len().min(50)]),
                        rule: "TRAVERSAL".to_string(),
                    };
                    tracing::warn!("🛡️ WAF TRAVERSAL: {} from {}", &input[..input.len().min(80)], ip);
                    if self.mode == WafMode::DetectOnly { return WafVerdict::Allow; }
                    return verdict;
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
