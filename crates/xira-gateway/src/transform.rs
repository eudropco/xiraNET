use std::collections::HashMap;

/// Request/Response header transformation
#[derive(Debug, Clone)]
pub struct TransformRules {
    pub add_request_headers: HashMap<String, String>,
    pub remove_request_headers: Vec<String>,
    pub add_response_headers: HashMap<String, String>,
    pub remove_response_headers: Vec<String>,
}

impl TransformRules {
    pub fn from_config(config: &xira_common::config::TransformConfig) -> Self {
        Self {
            add_request_headers: config.add_request_headers.clone(),
            remove_request_headers: config.remove_request_headers.clone(),
            add_response_headers: config.add_response_headers.clone(),
            remove_response_headers: config.remove_response_headers.clone(),
        }
    }

    /// Request header'larını dönüştür
    pub fn apply_request_headers(&self, headers: &mut reqwest::header::HeaderMap) {
        // Header'ları kaldır
        for key in &self.remove_request_headers {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                headers.remove(&name);
            }
        }

        // Header'ları ekle
        for (key, value) in &self.add_request_headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }
    }

    /// Response header'larını dönüştür (actix HTTP response)
    pub fn apply_response_headers(&self, response: &mut actix_web::HttpResponseBuilder) {
        for key in &self.remove_response_headers {
            // actix response builder'da remove yok, header ekleme ile override ederiz
            let _ = key;
        }

        for (key, value) in &self.add_response_headers {
            response.insert_header((key.as_str(), value.as_str()));
        }
    }
}
