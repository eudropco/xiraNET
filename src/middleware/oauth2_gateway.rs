use dashmap::DashMap;
/// OAuth2/OIDC Gateway — token introspection/validation.
///
/// Cache key: token'ın SHA-256 hash'i (raw token memory'de tutulmaz; heap dump'tan
/// bearer token sızdırmaz).
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub struct OAuth2Gateway {
    enabled: bool,
    issuer_url: String,
    introspection_url: Option<String>,
    jwks_url: Option<String>,
    client_id: String,
    client_secret: String,
    client: Client,
    /// Key: SHA-256(token). Value: introspection sonucu metadata (claims hariç bearer içermez).
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
    Valid {
        sub: String,
        claims: serde_json::Value,
    },
    Invalid {
        reason: String,
    },
    Error {
        reason: String,
    },
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
            Some(format!("{issuer_url}/.well-known/openid-configuration"))
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
                .build()
                .unwrap(),
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = hash_token(token);
        if let Some(cached) = self.token_cache.get(&key) {
            if now < cached.cached_at + cached.ttl {
                if cached.valid {
                    return TokenValidation::Valid {
                        sub: cached
                            .claims
                            .get("sub")
                            .and_then(|s| s.as_str())
                            .unwrap_or("?")
                            .to_string(),
                        claims: cached.claims.clone(),
                    };
                } else {
                    return TokenValidation::Invalid {
                        reason: "Cached invalid token".to_string(),
                    };
                }
            }
        }

        // Introspection
        if let Some(ref intro_url) = self.introspection_url {
            match self
                .client
                .post(intro_url)
                .form(&[
                    ("token", token),
                    ("client_id", &self.client_id),
                    ("client_secret", &self.client_secret),
                ])
                .send()
                .await
            {
                Ok(resp) => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(body) => {
                            let active = body
                                .get("active")
                                .and_then(|a| a.as_bool())
                                .unwrap_or(false);
                            self.token_cache.insert(
                                key.clone(),
                                TokenCacheEntry {
                                    valid: active,
                                    claims: body.clone(),
                                    cached_at: now,
                                    ttl: 300, // 5 min cache
                                },
                            );

                            if active {
                                return TokenValidation::Valid {
                                    sub: body
                                        .get("sub")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("?")
                                        .to_string(),
                                    claims: body,
                                };
                            } else {
                                return TokenValidation::Invalid {
                                    reason: "Token not active".to_string(),
                                };
                            }
                        }
                        Err(e) => {
                            return TokenValidation::Error {
                                reason: format!("Parse error: {e}"),
                            }
                        }
                    }
                }
                Err(e) => {
                    return TokenValidation::Error {
                        reason: format!("Introspection failed: {e}"),
                    }
                }
            }
        }

        TokenValidation::Error {
            reason: "No introspection endpoint configured".to_string(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn cache_size(&self) -> usize {
        self.token_cache.len()
    }

    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    pub fn jwks_url(&self) -> Option<&str> {
        self.jwks_url.as_deref()
    }

    pub fn clear_cache(&self) {
        self.token_cache.clear();
    }
}
