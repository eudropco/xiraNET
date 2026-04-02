/// Request/Response Interceptors — pipeline'a middleware chain inject et
use std::sync::Arc;
use async_trait::async_trait;

#[async_trait]
pub trait Interceptor: Send + Sync {
    fn name(&self) -> &str;
    fn priority(&self) -> i32 { 0 } // düşük = önce çalışır

    /// Request intercept — None döndürürse devam eder, Some döndürürse pipeline durur
    async fn on_request(&self, _ctx: &mut InterceptorContext) -> Option<InterceptorAction> {
        None
    }

    /// Response intercept — response'u değiştirebilir
    async fn on_response(&self, _ctx: &mut InterceptorContext, _status: u16, _body: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

pub struct InterceptorContext {
    pub method: String,
    pub path: String,
    pub ip: String,
    pub headers: Vec<(String, String)>,
    pub body_size: usize,
    pub service_name: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

pub enum InterceptorAction {
    Reject { status: u16, body: String },
    Redirect { url: String },
    ModifyHeaders { headers: Vec<(String, String)> },
}

/// Interceptor chain manager
pub struct InterceptorChain {
    interceptors: Vec<Arc<dyn Interceptor>>,
}

impl Default for InterceptorChain {
    fn default() -> Self {
        Self::new()
    }
}

impl InterceptorChain {
    pub fn new() -> Self {
        Self { interceptors: Vec::new() }
    }

    pub fn add(&mut self, interceptor: Arc<dyn Interceptor>) {
        self.interceptors.push(interceptor);
        self.interceptors.sort_by_key(|i| i.priority());
    }

    pub async fn run_request(&self, ctx: &mut InterceptorContext) -> Option<InterceptorAction> {
        for interceptor in &self.interceptors {
            if let Some(action) = interceptor.on_request(ctx).await {
                tracing::debug!("Interceptor '{}' blocked request", interceptor.name());
                return Some(action);
            }
        }
        None
    }

    pub async fn run_response(&self, ctx: &mut InterceptorContext, status: u16, body: &[u8]) -> Option<Vec<u8>> {
        for interceptor in &self.interceptors {
            if let Some(modified) = interceptor.on_response(ctx, status, body).await {
                return Some(modified);
            }
        }
        None
    }

    pub fn count(&self) -> usize {
        self.interceptors.len()
    }
}

/// Request Size Limiter interceptor
pub struct SizeLimiter {
    max_body_bytes: usize,
}

impl SizeLimiter {
    pub fn new(max_body_bytes: usize) -> Self {
        Self { max_body_bytes }
    }
}

#[async_trait]
impl Interceptor for SizeLimiter {
    fn name(&self) -> &str { "size_limiter" }
    fn priority(&self) -> i32 { -100 } // çok erken çalışır

    async fn on_request(&self, ctx: &mut InterceptorContext) -> Option<InterceptorAction> {
        if ctx.body_size > self.max_body_bytes {
            tracing::warn!("Request body too large: {} > {} bytes from {}", ctx.body_size, self.max_body_bytes, ctx.ip);
            return Some(InterceptorAction::Reject {
                status: 413,
                body: format!("{{\"error\":\"Request body too large\",\"max_bytes\":{}}}", self.max_body_bytes),
            });
        }
        None
    }
}

/// HSTS + CSP header injector interceptor
pub struct SecurityHeaders {
    pub hsts_max_age: u64,
    pub hsts_preload: bool,
    pub csp: Option<String>,
}

impl SecurityHeaders {
    pub fn new(hsts_max_age: u64, hsts_preload: bool, csp: Option<String>) -> Self {
        Self { hsts_max_age, hsts_preload, csp }
    }
}

#[async_trait]
impl Interceptor for SecurityHeaders {
    fn name(&self) -> &str { "security_headers" }
    fn priority(&self) -> i32 { 100 } // response'da çalışır

    async fn on_request(&self, _ctx: &mut InterceptorContext) -> Option<InterceptorAction> {
        let mut headers = vec![
            ("Strict-Transport-Security".to_string(),
             format!("max-age={}; includeSubDomains{}", self.hsts_max_age, if self.hsts_preload { "; preload" } else { "" })),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ("X-Frame-Options".to_string(), "DENY".to_string()),
            ("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string()),
        ];

        if let Some(ref csp) = self.csp {
            headers.push(("Content-Security-Policy".to_string(), csp.clone()));
        }

        Some(InterceptorAction::ModifyHeaders { headers })
    }
}
