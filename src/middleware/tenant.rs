use dashmap::DashMap;
use std::sync::Arc;

/// Multi-tenant isolation — header/domain bazlı tenant routing
pub struct TenantManager {
    tenants: Arc<DashMap<String, TenantConfig>>,
    enabled: bool,
    header_name: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TenantConfig {
    pub id: String,
    pub name: String,
    pub rate_limit: u32,
    pub rate_window_secs: u64,
    pub quota_daily: Option<u64>,
    pub allowed_prefixes: Vec<String>,
    pub custom_headers: Vec<(String, String)>,
    pub request_count: u64,
    pub daily_count: u64,
}

impl TenantManager {
    pub fn new(enabled: bool, header_name: String) -> Self {
        Self {
            tenants: Arc::new(DashMap::new()),
            enabled,
            header_name,
        }
    }

    /// Tenant oluştur
    pub fn create_tenant(&self, id: String, name: String, rate_limit: u32, quota_daily: Option<u64>) -> TenantConfig {
        let config = TenantConfig {
            id: id.clone(),
            name,
            rate_limit,
            rate_window_secs: 60,
            quota_daily,
            allowed_prefixes: vec![],
            custom_headers: vec![],
            request_count: 0,
            daily_count: 0,
        };
        self.tenants.insert(id, config.clone());
        config
    }

    /// Request'den tenant'ı belirle
    pub fn identify_tenant(&self, headers: &actix_web::http::header::HeaderMap, host: &str) -> Option<TenantConfig> {
        if !self.enabled {
            return None;
        }

        // Header-based identification
        if let Some(tenant_id) = headers.get(self.header_name.as_str()) {
            if let Ok(id) = tenant_id.to_str() {
                if let Some(tenant) = self.tenants.get(id) {
                    return Some(tenant.value().clone());
                }
            }
        }

        // Domain-based identification
        if let Some(tenant) = self.tenants.get(host) {
            return Some(tenant.value().clone());
        }

        None
    }

    /// Tenant quota kontrolü
    pub fn check_quota(&self, tenant_id: &str) -> bool {
        if let Some(tenant) = self.tenants.get(tenant_id) {
            if let Some(quota) = tenant.quota_daily {
                return tenant.daily_count < quota;
            }
        }
        true // Quota yoksa izin ver
    }

    /// Request kaydı
    pub fn record_request(&self, tenant_id: &str) {
        if let Some(mut tenant) = self.tenants.get_mut(tenant_id) {
            tenant.request_count += 1;
            tenant.daily_count += 1;
        }
    }

    /// Günlük sayaçları sıfırla
    pub fn reset_daily_counts(&self) {
        for mut entry in self.tenants.iter_mut() {
            entry.daily_count = 0;
        }
    }

    /// Tüm tenant'ları listele
    pub fn list_tenants(&self) -> Vec<TenantConfig> {
        self.tenants.iter().map(|e| e.value().clone()).collect()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn header_name(&self) -> &str {
        &self.header_name
    }
}
