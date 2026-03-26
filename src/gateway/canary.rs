use std::collections::HashMap;

/// Canary / Traffic split configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct CanaryConfig {
    /// Enabled
    #[serde(default)]
    pub enabled: bool,
    /// Weight mapping: upstream_url → weight (0-100)
    #[serde(default)]
    pub weights: HashMap<String, u32>,
    /// Header-based canary routing
    #[serde(default)]
    pub header_name: Option<String>,
    /// Header value that triggers canary upstream
    #[serde(default)]
    pub header_value: Option<String>,
    /// Canary target upstream
    #[serde(default)]
    pub canary_upstream: Option<String>,
}

impl CanaryConfig {
    /// Weight-based upstream seçimi
    pub fn select_upstream(&self, upstreams: &[String]) -> Option<String> {
        if !self.enabled || self.weights.is_empty() {
            return None; // Normal LB kullan
        }

        let total_weight: u32 = self.weights.values().sum();
        if total_weight == 0 {
            return None;
        }

        let roll = rand::random::<u32>() % total_weight;
        let mut cumulative = 0u32;

        for (upstream, weight) in &self.weights {
            cumulative += weight;
            if roll < cumulative {
                return Some(upstream.clone());
            }
        }

        // Fallback
        upstreams.first().cloned()
    }

    /// Header-based canary routing
    pub fn check_header_routing(&self, headers: &actix_web::http::header::HeaderMap) -> Option<String> {
        if !self.enabled {
            return None;
        }

        if let (Some(ref header_name), Some(ref header_value), Some(ref canary_upstream)) =
            (&self.header_name, &self.header_value, &self.canary_upstream)
        {
            if let Some(val) = headers.get(header_name.as_str()) {
                if let Ok(val_str) = val.to_str() {
                    if val_str == header_value {
                        tracing::debug!("Canary header match: {} = {} → {}", header_name, header_value, canary_upstream);
                        return Some(canary_upstream.clone());
                    }
                }
            }
        }

        None
    }
}

/// Gateway handler'a canary desteği ekle
pub fn select_canary_or_lb(
    canary: &Option<CanaryConfig>,
    headers: &actix_web::http::header::HeaderMap,
    upstreams: &[String],
) -> Option<String> {
    if let Some(ref config) = canary {
        // Önce header-based kontrol
        if let Some(upstream) = config.check_header_routing(headers) {
            return Some(upstream);
        }

        // Sonra weight-based kontrol
        if let Some(upstream) = config.select_upstream(upstreams) {
            return Some(upstream);
        }
    }

    None // Normal LB'ye bırak
}
