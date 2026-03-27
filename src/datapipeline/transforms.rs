/// Request/Response Transforms — JSON manipulation, field masking, format conversion
use serde_json::Value;

pub struct TransformEngine {
    rules: Vec<TransformRule>,
}

#[derive(Clone, Debug)]
pub struct TransformRule {
    pub name: String,
    pub path_match: String,
    pub action: TransformAction,
}

#[derive(Clone, Debug)]
pub enum TransformAction {
    /// Field'ı maskele (e.g., credit card → ****1234)
    MaskField { field: String, visible_chars: usize },
    /// Field'ı kaldır
    RemoveField { field: String },
    /// Field ekle (enrichment)
    AddField { field: String, value: String },
    /// Field'ı yeniden adlandır
    RenameField { from: String, to: String },
    /// Değeri dönüştür (uppercase, lowercase, trim)
    TransformValue { field: String, transform: ValueTransform },
}

#[derive(Clone, Debug)]
pub enum ValueTransform { Uppercase, Lowercase, Trim, Hash }

impl TransformEngine {
    pub fn new() -> Self { Self { rules: Vec::new() } }

    pub fn add_rule(&mut self, rule: TransformRule) {
        self.rules.push(rule);
    }

    /// JSON body'ye transformları uygula
    pub fn apply(&self, path: &str, body: &mut Value) {
        for rule in &self.rules {
            if !path.starts_with(&rule.path_match) { continue; }

            match &rule.action {
                TransformAction::MaskField { field, visible_chars } => {
                    if let Some(val) = body.pointer_mut(&format!("/{}", field.replace('.', "/"))) {
                        if let Some(s) = val.as_str() {
                            let masked = if s.len() > *visible_chars {
                                format!("{}{}",
                                    "*".repeat(s.len() - visible_chars),
                                    &s[s.len() - visible_chars..])
                            } else { "*".repeat(s.len()) };
                            *val = Value::String(masked);
                        }
                    }
                },
                TransformAction::RemoveField { field } => {
                    if let Some(obj) = body.as_object_mut() {
                        obj.remove(field);
                    }
                },
                TransformAction::AddField { field, value } => {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert(field.clone(), Value::String(value.clone()));
                    }
                },
                TransformAction::RenameField { from, to } => {
                    if let Some(obj) = body.as_object_mut() {
                        if let Some(val) = obj.remove(from) {
                            obj.insert(to.clone(), val);
                        }
                    }
                },
                TransformAction::TransformValue { field, transform } => {
                    if let Some(val) = body.pointer_mut(&format!("/{}", field.replace('.', "/"))) {
                        if let Some(s) = val.as_str() {
                            let transformed = match transform {
                                ValueTransform::Uppercase => s.to_uppercase(),
                                ValueTransform::Lowercase => s.to_lowercase(),
                                ValueTransform::Trim => s.trim().to_string(),
                                ValueTransform::Hash => {
                                    use std::hash::{Hash, Hasher};
                                    let mut h = std::collections::hash_map::DefaultHasher::new();
                                    s.hash(&mut h);
                                    format!("{:x}", h.finish())
                                },
                            };
                            *val = Value::String(transformed);
                        }
                    }
                },
            }
        }
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}
