/// Feature Flags — runtime feature toggle with targeting rules
use dashmap::DashMap;

pub struct FeatureFlagManager {
    flags: DashMap<String, FeatureFlag>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FeatureFlag {
    pub name: String,
    pub enabled: bool,
    pub description: String,
    pub percentage: u32, // 0-100, gradual rollout
    pub rules: Vec<TargetRule>,
    pub created_at: u64,
    pub updated_at: u64,
    pub eval_count: u64,
    pub true_count: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TargetRule {
    pub attribute: String, // "user_id", "country", "header:X-Tenant"
    pub operator: Operator,
    pub value: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Operator { Equals, NotEquals, Contains, StartsWith, InList }

impl FeatureFlagManager {
    pub fn new() -> Self { Self { flags: DashMap::new() } }

    /// Flag oluştur
    pub fn create(&self, name: String, description: String, enabled: bool, percentage: u32) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        self.flags.insert(name.clone(), FeatureFlag {
            name, enabled, description, percentage, rules: vec![],
            created_at: now, updated_at: now, eval_count: 0, true_count: 0,
        });
    }

    /// Flag değerlendir
    pub fn evaluate(&self, name: &str, context: &std::collections::HashMap<String, String>) -> bool {
        if let Some(mut flag) = self.flags.get_mut(name) {
            flag.eval_count += 1;

            if !flag.enabled { return false; }

            // Targeting rules check
            for rule in &flag.rules {
                let attr_value = context.get(&rule.attribute).map(|s| s.as_str()).unwrap_or("");
                let matches = match &rule.operator {
                    Operator::Equals => attr_value == rule.value,
                    Operator::NotEquals => attr_value != rule.value,
                    Operator::Contains => attr_value.contains(&rule.value),
                    Operator::StartsWith => attr_value.starts_with(&rule.value),
                    Operator::InList => rule.value.split(',').any(|v| v.trim() == attr_value),
                };
                if !matches { return false; }
            }

            // Percentage rollout (deterministic based on context hash)
            if flag.percentage < 100 {
                let hash = {
                    use std::hash::{Hash, Hasher};
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    // Hash sorted key-value pairs (HashMap itself doesn't implement Hash)
                    let mut entries: Vec<_> = context.iter().collect();
                    entries.sort_by_key(|(k, _)| k.clone());
                    for (k, v) in &entries { k.hash(&mut h); v.hash(&mut h); }
                    name.hash(&mut h);
                    (h.finish() % 100) as u32
                };
                if hash >= flag.percentage { return false; }
            }

            flag.true_count += 1;
            true
        } else {
            false // Unknown flag = disabled
        }
    }

    /// Targeting rule ekle
    pub fn add_rule(&self, flag_name: &str, rule: TargetRule) -> bool {
        if let Some(mut flag) = self.flags.get_mut(flag_name) {
            flag.rules.push(rule);
            true
        } else { false }
    }

    /// Toggle
    pub fn toggle(&self, name: &str) -> Option<bool> {
        self.flags.get_mut(name).map(|mut f| { f.enabled = !f.enabled; f.enabled })
    }

    /// Tüm flag'ları listele
    pub fn list(&self) -> Vec<FeatureFlag> {
        self.flags.iter().map(|e| e.value().clone()).collect()
    }
}
