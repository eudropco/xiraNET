/// Session Management — token lifecycle, devices, force logout
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SessionManager {
    sessions: DashMap<String, Session>, // token → session
    user_sessions: DashMap<String, Vec<String>>, // user_id → [tokens]
    max_sessions_per_user: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Session {
    pub token: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity: u64,
    pub ip: String,
    pub user_agent: String,
    pub device_name: String,
    pub active: bool,
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            user_sessions: DashMap::new(),
            max_sessions_per_user: max_sessions,
        }
    }

    /// Yeni session oluştur
    pub fn create(&self, user_id: &str, token: &str, ip: &str, user_agent: &str, ttl_secs: u64) -> Session {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let device = detect_device(user_agent);

        let session = Session {
            token: token.to_string(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + ttl_secs,
            last_activity: now,
            ip: ip.to_string(),
            user_agent: user_agent.to_string(),
            device_name: device,
            active: true,
        };

        self.sessions.insert(token.to_string(), session.clone());

        // User→sessions mapping
        let mut user_tokens = self.user_sessions.entry(user_id.to_string()).or_insert(Vec::new());
        user_tokens.push(token.to_string());

        // Max session kontrolü — en eski session'ı kapat
        if user_tokens.len() > self.max_sessions_per_user {
            if let Some(oldest) = user_tokens.first().cloned() {
                self.invalidate(&oldest);
                user_tokens.retain(|t| t != &oldest);
            }
        }

        session
    }

    /// Token doğrula
    pub fn validate(&self, token: &str) -> Option<Session> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if let Some(mut session) = self.sessions.get_mut(token) {
            if !session.active || now > session.expires_at {
                return None;
            }
            session.last_activity = now;
            return Some(session.clone());
        }
        None
    }

    /// Session'ı kapat
    pub fn invalidate(&self, token: &str) -> bool {
        if let Some(mut session) = self.sessions.get_mut(token) {
            session.active = false;
            true
        } else { false }
    }

    /// Kullanıcının tüm session'larını kapat (force logout)
    pub fn invalidate_all(&self, user_id: &str) -> usize {
        let mut count = 0;
        if let Some(tokens) = self.user_sessions.get(user_id) {
            for token in tokens.value() {
                if self.invalidate(token) { count += 1; }
            }
        }
        count
    }

    /// Kullanıcının aktif session'ları
    pub fn user_sessions(&self, user_id: &str) -> Vec<Session> {
        if let Some(tokens) = self.user_sessions.get(user_id) {
            tokens.iter()
                .filter_map(|t| self.sessions.get(t).map(|s| s.value().clone()))
                .filter(|s| s.active)
                .collect()
        } else { vec![] }
    }

    /// Expired session temizliği
    pub fn cleanup_expired(&self) -> usize {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut cleaned = 0;
        self.sessions.retain(|_, s| {
            if now > s.expires_at || !s.active {
                cleaned += 1;
                false
            } else { true }
        });
        cleaned
    }

    pub fn active_count(&self) -> usize {
        self.sessions.iter().filter(|s| s.value().active).count()
    }

    pub fn total_count(&self) -> usize { self.sessions.len() }
}

fn detect_device(ua: &str) -> String {
    let ua_lower = ua.to_lowercase();
    if ua_lower.contains("mobile") || ua_lower.contains("android") || ua_lower.contains("iphone") {
        "Mobile".into()
    } else if ua_lower.contains("tablet") || ua_lower.contains("ipad") {
        "Tablet".into()
    } else if ua_lower.contains("curl") || ua_lower.contains("httpie") || ua_lower.contains("postman") {
        "CLI/API Client".into()
    } else {
        "Desktop".into()
    }
}
