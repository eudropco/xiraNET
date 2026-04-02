use serde_json::Value;

/// Body transformation rules
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct BodyTransformConfig {
    /// Request body'den alan sil
    #[serde(default)]
    pub remove_fields: Vec<String>,
    /// Request body'ye alan ekle
    #[serde(default)]
    pub add_fields: std::collections::HashMap<String, Value>,
    /// Alan adı değiştir (old_name → new_name)
    #[serde(default)]
    pub rename_fields: std::collections::HashMap<String, String>,
    /// Response body'den alan sil (PII maskeleme)
    #[serde(default)]
    pub redact_fields: Vec<String>,
    /// Response body'den alan sil
    #[serde(default)]
    pub remove_response_fields: Vec<String>,
    /// Redact replacement value
    #[serde(default = "default_redact_value")]
    pub redact_value: String,
}

fn default_redact_value() -> String {
    "***REDACTED***".to_string()
}

impl BodyTransformConfig {
    /// Request body'yi dönüştür
    pub fn transform_request_body(&self, body: &[u8]) -> Option<Vec<u8>> {
        if self.remove_fields.is_empty()
            && self.add_fields.is_empty()
            && self.rename_fields.is_empty()
        {
            return None; // Değişiklik yok
        }

        let mut json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return None, // JSON değilse dokunma
        };

        if let Value::Object(ref mut map) = json {
            // Alanları sil
            for field in &self.remove_fields {
                map.remove(field);
            }

            // Alanları ekle
            for (key, value) in &self.add_fields {
                map.insert(key.clone(), value.clone());
            }

            // Alanları yeniden adlandır
            for (old_name, new_name) in &self.rename_fields {
                if let Some(val) = map.remove(old_name) {
                    map.insert(new_name.clone(), val);
                }
            }
        }

        serde_json::to_vec(&json).ok()
    }

    /// Response body'yi dönüştür (redaction + field removal)
    pub fn transform_response_body(&self, body: &[u8]) -> Option<Vec<u8>> {
        if self.redact_fields.is_empty() && self.remove_response_fields.is_empty() {
            return None;
        }

        let mut json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let redact_value = Value::String(self.redact_value.clone());

        Self::transform_value(&mut json, &self.redact_fields, &self.remove_response_fields, &redact_value);

        serde_json::to_vec(&json).ok()
    }

    /// Recursive field transform
    fn transform_value(
        value: &mut Value,
        redact: &[String],
        remove: &[String],
        redact_value: &Value,
    ) {
        match value {
            Value::Object(map) => {
                // Remove fields
                for field in remove {
                    map.remove(field);
                }

                // Redact fields
                for field in redact {
                    if map.contains_key(field) {
                        map.insert(field.clone(), redact_value.clone());
                    }
                }

                // Recurse into nested objects
                for (_, v) in map.iter_mut() {
                    Self::transform_value(v, redact, remove, redact_value);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::transform_value(item, redact, remove, redact_value);
                }
            }
            _ => {}
        }
    }
}
