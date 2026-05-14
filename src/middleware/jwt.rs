use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

/// JWT init hatası — boot-time'da raporlanır, başlatmayı engeller.
#[derive(Debug, thiserror::Error)]
pub enum JwtInitError {
    #[error("JWT secret too short ({0} bytes); HMAC algorithms require >= 32 bytes")]
    WeakSecret(usize),
    #[error("JWT secret is a known default/example value; refuse to start")]
    DefaultSecret,
    #[error("RS256 selected but secret could not be parsed as PEM: {0}")]
    InvalidRsaPem(String),
    #[error("unsupported algorithm: {0} (supported: HS256, HS384, HS512, RS256)")]
    UnsupportedAlgorithm(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: Option<String>,
    /// Expiration timestamp. JWT validation requires this — token without exp reddedilir.
    pub exp: usize,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub roles: Option<Vec<String>>,
}

/// JWT secret/key materyali — algoritmaya göre HMAC byte'ları veya RSA PEM.
/// v3.0 audit fix (Yarı B madde 20): RS256 için DecodingKey artık boot'ta tek
/// kere parse edilip `Arc`'a sarılıyor; her validate'te yeniden PEM parse
/// (hot-path overhead) yok.
#[derive(Clone)]
enum JwtKey {
    /// HMAC algoritmaları için byte secret. Validate'te `from_secret`.
    Hmac(Arc<Vec<u8>>),
    /// RS256: boot'ta parse edilmiş `DecodingKey`, Arc-clonable.
    RsaPem(Arc<DecodingKey>),
}

/// JWT Authentication middleware
#[derive(Clone)]
pub struct JwtAuth {
    key: JwtKey,
    algorithm: Algorithm,
    issuer: Option<String>,
    audience: Option<String>,
    enabled: bool,
}

/// Default/örnek JWT secret değerleri — production guard.
fn is_default_jwt_secret(s: &str) -> bool {
    matches!(
        s,
        ""
            | "your-jwt-secret-key-here"
            | "change-me"
            | "changeme"
            | "secret"
            | "jwt-secret"
            | "xira-secret-key-change-me"
    )
}

impl JwtAuth {
    /// Geriye dönük uyumluluk: enabled=false ise validate edilmez.
    /// enabled=true ise sıkı boot-time guard: zayıf/default secret + geçersiz RS256 PEM
    /// reddedilir; bunlar `JwtInitError` olarak döner.
    pub fn new(
        secret: String,
        algorithm_str: &str,
        issuer: Option<String>,
        enabled: bool,
    ) -> Result<Self, JwtInitError> {
        Self::new_with_audience(secret, algorithm_str, issuer, None, enabled)
    }

    pub fn new_with_audience(
        secret: String,
        algorithm_str: &str,
        issuer: Option<String>,
        audience: Option<String>,
        enabled: bool,
    ) -> Result<Self, JwtInitError> {
        let algorithm = match algorithm_str.to_uppercase().as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            other => return Err(JwtInitError::UnsupportedAlgorithm(other.to_string())),
        };

        // Disabled iken validation çalışmıyor; struct dummy HMAC ile kurulur.
        if !enabled {
            let key = JwtKey::Hmac(Arc::new(secret.into_bytes()));
            return Ok(Self {
                key,
                algorithm,
                issuer,
                audience,
                enabled,
            });
        }

        if is_default_jwt_secret(&secret) {
            return Err(JwtInitError::DefaultSecret);
        }

        let key = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                if secret.len() < 32 {
                    return Err(JwtInitError::WeakSecret(secret.len()));
                }
                JwtKey::Hmac(Arc::new(secret.into_bytes()))
            }
            Algorithm::RS256 => {
                // Boot'ta TEK kere parse + Arc'a sar. Validate hot-path'ta yeniden
                // parse YOK — eski sürüm her isteğe PEM parse ediyordu.
                let dk = DecodingKey::from_rsa_pem(secret.as_bytes())
                    .map_err(|e| JwtInitError::InvalidRsaPem(e.to_string()))?;
                JwtKey::RsaPem(Arc::new(dk))
            }
            _ => return Err(JwtInitError::UnsupportedAlgorithm(format!("{algorithm:?}"))),
        };

        Ok(Self {
            key,
            algorithm,
            issuer,
            audience,
            enabled,
        })
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware {
            service,
            key: self.key.clone(),
            algorithm: self.algorithm,
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            enabled: self.enabled,
        }))
    }
}

pub struct JwtAuthMiddleware<S> {
    service: S,
    key: JwtKey,
    algorithm: Algorithm,
    issuer: Option<String>,
    audience: Option<String>,
    enabled: bool,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if !self.enabled {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Admin API, dashboard shell ve admin websocket'leri kendi auth
        // mekanizmalarını kullandığı için JWT'den muaf tutulur.
        // Path normalize: trailing-slash ve duplicate-slash'ları temizle ki
        // `..` segment'leri gerçekten çıkarılır → "/xira/../api/secret" → "/api/secret".
        // Aksi halde traversal ile exempt path'leri (örn. /xira/) suistimal edilebilir.
        let raw_path = req.path();
        let normalized = normalize_path(raw_path);
        if is_exempt_path(&normalized) {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Authorization header'dan token al
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        let token = match token {
            Some(t) => t,
            None => {
                return Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Missing or invalid Authorization header",
                        "hint": "Use: Authorization: Bearer <token>"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                });
            }
        };

        // Token doğrula. Algorithm pinning: middleware konfigürasyonuyla gelen
        // tek algoritmaya bağlanır — `alg=none` veya farklı algoritma confusion engellenir.
        let mut validation = Validation::new(self.algorithm);
        validation.algorithms = vec![self.algorithm];
        validation.validate_exp = true;
        validation.leeway = 0;
        validation.set_required_spec_claims(&["exp"]);
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        // Boot'ta parse edilen key — RSA için PEM parse hot-path'ta YOK.
        let decode_result = match &self.key {
            JwtKey::Hmac(b) => {
                let key = DecodingKey::from_secret(b);
                decode::<JwtClaims>(&token, &key, &validation)
            }
            JwtKey::RsaPem(dk) => decode::<JwtClaims>(&token, dk.as_ref(), &validation),
        };

        match decode_result {
            Ok(_token_data) => {
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                })
            }
            Err(e) => {
                // Detaylı hatayı server-side log'la ama client'a generic mesaj dön.
                // Aksi halde endpoint forged-vs-expired-vs-wrong-issuer için oracle olur.
                crate::metrics::JWT_REJECTS.inc();
                crate::metrics::AUTH_REJECTS
                    .with_label_values(&["jwt_invalid"])
                    .inc();
                tracing::warn!(error = %e, "JWT validation failed");
                Box::pin(async move {
                    let response = HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Invalid or expired token"
                    }));
                    Ok(req.into_response(response).map_into_right_body())
                })
            }
        }
    }
}

/// Path normalize: duplicate slash kollaps + `..`/`.` segment resolution.
///
/// v3.0 audit fix: önceki versiyon yorumda "/xira/../api/secret traversal'ı
/// önlüyoruz" iddia ediyordu ama gerçekte `..` segment'lerini KALDIRMIYORDU,
/// sadece `//` → `/` yapıyordu. Bu commit'te gerçek normalization implement
/// edildi — segment stack ile `..` parent pop, `.` skip.
fn normalize_path(p: &str) -> String {
    let leading_slash = p.starts_with('/');
    let trailing_slash = p.len() > 1 && p.ends_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let mut out = String::with_capacity(p.len());
    if leading_slash {
        out.push('/');
    }
    out.push_str(&stack.join("/"));
    if trailing_slash && !out.ends_with('/') {
        out.push('/');
    }
    out
}

fn is_exempt_path(path: &str) -> bool {
    // /xira ve /auth route'ları kendi auth mekanizmalarına sahip.
    // /metrics, /health, /dashboard ve /ws/* ayrı koruma katmanı kullanır.
    matches!(
        path,
        "/metrics" | "/health" | "/dashboard" | "/ws/dashboard" | "/ws/metrics"
    ) || path.starts_with("/xira/")
        || path == "/xira"
        || path.starts_with("/auth/")
        || path == "/auth"
}

#[cfg(test)]
mod normalize_tests {
    use super::normalize_path;

    #[test]
    fn collapses_duplicate_slashes() {
        assert_eq!(normalize_path("/a//b///c"), "/a/b/c");
    }

    #[test]
    fn resolves_dot_dot_traversal() {
        // Önceki sürümde "/xira/../api/secret" → "/xira/../api/secret" (yalan)
        // Şimdi: doğru çözüm "/api/secret"
        assert_eq!(normalize_path("/xira/../api/secret"), "/api/secret");
    }

    #[test]
    fn resolves_multiple_dot_dot() {
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn drops_single_dot() {
        assert_eq!(normalize_path("/a/./b"), "/a/b");
    }

    #[test]
    fn preserves_trailing_slash() {
        assert_eq!(normalize_path("/a/b/"), "/a/b/");
    }

    #[test]
    fn dot_dot_above_root_pops_to_root() {
        assert_eq!(normalize_path("/../../foo"), "/foo");
    }
}
