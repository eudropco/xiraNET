/// IP Geolocation — country-level IP lookup (MaxMind-compatible format)
use std::collections::HashMap;

pub struct GeoIpLookup {
    enabled: bool,
    // In-memory country map (for lite usage without MaxMind binary)
    ip_ranges: HashMap<String, GeoInfo>,
    blocked_countries: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: String,
    pub continent: String,
}

impl GeoIpLookup {
    pub fn new(enabled: bool, blocked_countries: Vec<String>) -> Self {
        Self {
            enabled,
            ip_ranges: HashMap::new(),
            blocked_countries,
        }
    }

    /// IP'den ülke bilgisi çıkar (basit prefix-based lookup)
    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        if !self.enabled { return None; }

        // Private IP ranges → Local
        if ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") || ip == "::1" {
            return Some(GeoInfo {
                country_code: "LO".into(),
                country_name: "Local".into(),
                continent: "Local".into(),
            });
        }

        // Cache lookup
        if let Some(info) = self.ip_ranges.get(ip) {
            return Some(info.clone());
        }

        None // External lookup disabled for now (would use MaxMind DB)
    }

    /// Ülke engeli kontrolü
    pub fn is_blocked(&self, ip: &str) -> bool {
        if !self.enabled || self.blocked_countries.is_empty() { return false; }

        if let Some(info) = self.lookup(ip) {
            return self.blocked_countries.contains(&info.country_code);
        }
        false
    }

    /// Manuel IP-country kayıt (test/override)
    pub fn register(&mut self, ip: String, country_code: String, country_name: String) {
        self.ip_ranges.insert(ip, GeoInfo {
            country_code,
            country_name,
            continent: "Unknown".into(),
        });
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn blocked_countries(&self) -> &[String] {
        &self.blocked_countries
    }
}
