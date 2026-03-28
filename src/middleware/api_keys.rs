use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Multi-key API key management with rotation, per-key rate limits, and access control
pub struct ApiKeyManager {
    keys: DashMap<String, ApiKeyEntry>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ApiKeyEntry {
    pub key: String,
    pub name: String,
    pub role: ApiKeyRole,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub rate_limit: Option<u32>,
    pub allowed_prefixes: Vec<String>,
    pub enabled: bool,
    pub request_count: u64,
    pub last_used: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ApiKeyRole {
    Admin,
    ReadOnly,
    Service,
    Custom(Vec<String>), // custom permissions
}

#[derive(Debug)]
pub enum KeyValidation {
    Valid(ApiKeyEntry),
    Expired,
    Disabled,
    NotFound,
    RateLimited,
    PrefixDenied,
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyManager {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
        }
    }

    /// Yeni key oluştur
    pub fn create_key(&self, name: String, role: ApiKeyRole, rate_limit: Option<u32>, allowed_prefixes: Vec<String>, ttl_secs: Option<u64>) -> String {
        let key = format!("xira_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let entry = ApiKeyEntry {
            key: key.clone(),
            name,
            role,
            created_at: now,
            expires_at: ttl_secs.map(|ttl| now + ttl),
            rate_limit,
            allowed_prefixes,
            enabled: true,
            request_count: 0,
            last_used: 0,
        };

        self.keys.insert(key.clone(), entry);
        tracing::info!("API key created: {}... (total: {})", &key[..8], self.keys.len());
        key
    }

    /// Key doğrula
    pub fn validate(&self, key: &str, path: &str) -> KeyValidation {
        match self.keys.get(key) {
            None => KeyValidation::NotFound,
            Some(entry) => {
                let entry = entry.value();

                if !entry.enabled {
                    return KeyValidation::Disabled;
                }

                // TTL kontrolü
                if let Some(expires) = entry.expires_at {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    if now > expires {
                        return KeyValidation::Expired;
                    }
                }

                // Prefix kontrolü
                if !entry.allowed_prefixes.is_empty() {
                    let allowed = entry.allowed_prefixes.iter().any(|p| path.starts_with(p));
                    if !allowed {
                        return KeyValidation::PrefixDenied;
                    }
                }

                KeyValidation::Valid(entry.clone())
            }
        }
    }

    /// Key kullanım istatistiğini güncelle
    pub fn record_usage(&self, key: &str) {
        if let Some(mut entry) = self.keys.get_mut(key) {
            entry.request_count += 1;
            entry.last_used = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        }
    }

    /// Key'i devre dışı bırak
    pub fn disable_key(&self, key: &str) -> bool {
        if let Some(mut entry) = self.keys.get_mut(key) {
            entry.enabled = false;
            true
        } else {
            false
        }
    }

    /// Key'i rotate et (yeni key oluştur, eskiyi devre dışı bırak)
    pub fn rotate_key(&self, old_key: &str) -> Option<String> {
        if let Some(entry) = self.keys.get(old_key) {
            let entry = entry.value().clone();
            self.disable_key(old_key);
            Some(self.create_key(entry.name, entry.role, entry.rate_limit, entry.allowed_prefixes, None))
        } else {
            None
        }
    }

    /// Tüm key'leri listele (key hariç — güvenlik)
    pub fn list_keys(&self) -> Vec<serde_json::Value> {
        self.keys.iter().map(|entry| {
            let e = entry.value();
            serde_json::json!({
                "name": e.name,
                "role": format!("{:?}", e.role),
                "enabled": e.enabled,
                "created_at": e.created_at,
                "expires_at": e.expires_at,
                "rate_limit": e.rate_limit,
                "request_count": e.request_count,
                "last_used": e.last_used,
                "key_preview": format!("{}...{}", &e.key[..8], &e.key[e.key.len()-4..]),
            })
        }).collect()
    }

    /// Eski admin key'i import et (backwards compat)
    pub fn import_legacy_key(&self, key: String) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let entry = ApiKeyEntry {
            key: key.clone(),
            name: "legacy-admin".to_string(),
            role: ApiKeyRole::Admin,
            created_at: now,
            expires_at: None,
            rate_limit: None,
            allowed_prefixes: vec![],
            enabled: true,
            request_count: 0,
            last_used: 0,
        };
        self.keys.insert(key, entry);
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}
