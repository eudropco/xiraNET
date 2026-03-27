/// OAuth2/OIDC Gateway — token introspection/validation
use reqwest::Client;
use std::time::Duration;
use dashmap::DashMap;

#[allow(dead_code)]
pub struct OAuth2Gateway {
    enabled: bool,
    issuer_url: String,
    introspection_url: Option<String>,
    jwks_url: Option<String>,
    client_id: String,
    client_secret: String,
    client: Client,
    token_cache: DashMap<String, TokenCacheEntry>,
}

#[derive(Clone)]
struct TokenCacheEntry {
    valid: bool,
    claims: serde_json::Value,
    cached_at: u64,
    ttl: u64,
}

#[derive(Debug)]
pub enum TokenValidation {
    Valid { sub: String, claims: serde_json::Value },
    Invalid { reason: String },
    Error { reason: String },
}

impl OAuth2Gateway {
    pub fn new(
        enabled: bool,
        issuer_url: String,
        introspection_url: Option<String>,
        client_id: String,
        client_secret: String,
    ) -> Self {
        let jwks_url = if !issuer_url.is_empty() {
            Some(format!("{}/.well-known/openid-configuration", issuer_url))
        } else {
            None
        };

        Self {
            enabled,
            issuer_url,
            introspection_url,
            jwks_url,
            client_id,
            client_secret,
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build().unwrap(),
            token_cache: DashMap::new(),
        }
    }

    /// Token'ı doğrula (introspection endpoint ile)
    pub async fn validate_token(&self, token: &str) -> TokenValidation {
        if !self.enabled {
            return TokenValidation::Valid {
                sub: "anonymous".to_string(),
                claims: serde_json::json!({}),
            };
        }

        // Cache check
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if let Some(cached) = self.token_cache.get(token) {
            if now < cached.cached_at + cached.ttl {
                if cached.valid {
                    return TokenValidation::Valid {
                        sub: cached.claims.get("sub").and_then(|s| s.as_str()).unwrap_or("?").to_string(),
                        claims: cached.claims.clone(),
                    };
                } else {
                    return TokenValidation::Invalid { reason: "Cached invalid token".to_string() };
                }
            }
        }

        // Introspection
        if let Some(ref intro_url) = self.introspection_url {
            match self.client.post(intro_url)
                .form(&[("token", token), ("client_id", &self.client_id), ("client_secret", &self.client_secret)])
                .send().await
            {
                Ok(resp) => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(body) => {
                            let active = body.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                            self.token_cache.insert(token.to_string(), TokenCacheEntry {
                                valid: active,
                                claims: body.clone(),
                                cached_at: now,
                                ttl: 300, // 5 min cache
                            });

                            if active {
                                return TokenValidation::Valid {
                                    sub: body.get("sub").and_then(|s| s.as_str()).unwrap_or("?").to_string(),
                                    claims: body,
                                };
                            } else {
                                return TokenValidation::Invalid { reason: "Token not active".to_string() };
                            }
                        }
                        Err(e) => return TokenValidation::Error { reason: format!("Parse error: {}", e) },
                    }
                }
                Err(e) => return TokenValidation::Error { reason: format!("Introspection failed: {}", e) },
            }
        }

        TokenValidation::Error { reason: "No introspection endpoint configured".to_string() }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn cache_size(&self) -> usize {
        self.token_cache.len()
    }
}
