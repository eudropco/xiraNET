/// Session Management — token lifecycle, devices, force logout.
///
/// Token'lar SHA-256 hash'lenmiş halde saklanır. Plaintext token sadece
/// üretildiği anda caller'a döner; map'te yer almaz. DB/memory dump'tan
/// elde edilen hash kullanılarak doğrudan auth yapılamaz.
///
/// Opsiyonel SQLite persistence: `with_storage` ile başlatılırsa restart sonrası
/// session'lar yüklenir + her create/invalidate persist edilir.
use crate::registry::storage::SqliteStorage;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SessionManager {
    /// hashed_token → session
    sessions: DashMap<String, Session>,
    /// user_id → [hashed_tokens] — invalidate_all + max_session enforcement için
    user_sessions: DashMap<String, Vec<String>>,
    max_sessions_per_user: usize,
    storage: Option<Arc<SqliteStorage>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Session {
    /// Plaintext token DİKKAT: sadece create() return'ünde döner; storage'da hash tutuluyor.
    /// Validate() çağrısı plaintext token'ı içeriden hash'leyip lookup yapar.
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            user_sessions: DashMap::new(),
            max_sessions_per_user: max_sessions.max(1),
            storage: None,
        }
    }

    /// SQLite persistent storage ile başlat — tabloyu oluştur, mevcut session'ları yükle.
    pub fn with_storage(max_sessions: usize, storage: Arc<SqliteStorage>) -> Self {
        if let Err(e) = storage.execute_raw(
            "CREATE TABLE IF NOT EXISTS identity_sessions (
                hashed_token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_activity INTEGER NOT NULL,
                ip TEXT,
                user_agent TEXT,
                device_name TEXT,
                active INTEGER DEFAULT 1
            )",
        ) {
            tracing::warn!(error = %e, "failed to create identity_sessions table");
        }

        let mgr = Self {
            sessions: DashMap::new(),
            user_sessions: DashMap::new(),
            max_sessions_per_user: max_sessions.max(1),
            storage: Some(storage.clone()),
        };

        // Restart sonrası: aktif + non-expired session'ları yükle.
        let now = now_secs();
        if let Ok(rows) = storage.query_raw(
            "SELECT hashed_token, user_id, created_at, expires_at, last_activity, ip, user_agent, device_name, active FROM identity_sessions",
        ) {
            let mut loaded = 0usize;
            for row in rows {
                let hashed = row.get("hashed_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let user_id = row.get("user_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let created_at = row.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let expires_at = row.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let last_activity = row.get("last_activity").and_then(|v| v.as_u64()).unwrap_or(0);
                let ip = row.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let user_agent = row.get("user_agent").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let device_name = row.get("device_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let active = row.get("active").and_then(|v| v.as_u64()).unwrap_or(0) == 1;

                if !active || expires_at <= now {
                    // Expired/inactive — yüklemeden geç
                    continue;
                }
                let session = Session {
                    token: hashed.clone(),
                    user_id: user_id.clone(),
                    created_at,
                    expires_at,
                    last_activity,
                    ip,
                    user_agent,
                    device_name,
                    active,
                };
                mgr.sessions.insert(hashed.clone(), session);
                mgr.user_sessions.entry(user_id).or_default().push(hashed);
                loaded += 1;
            }
            if loaded > 0 {
                tracing::info!("Sessions: loaded {} active session(s) from SQLite", loaded);
            }
        }

        mgr
    }

    fn persist(&self, hashed: &str, session: &Session) {
        if let Some(ref storage) = self.storage {
            let active: i64 = if session.active { 1 } else { 0 };
            if let Err(e) = storage.execute_params(
                "INSERT OR REPLACE INTO identity_sessions (hashed_token, user_id, created_at, expires_at, last_activity, ip, user_agent, device_name, active) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    &hashed as &dyn rusqlite::types::ToSql,
                    &session.user_id,
                    &(session.created_at as i64),
                    &(session.expires_at as i64),
                    &(session.last_activity as i64),
                    &session.ip,
                    &session.user_agent,
                    &session.device_name,
                    &active,
                ],
            ) {
                crate::metrics::DB_PERSIST_ERRORS
                    .with_label_values(&["sessions"])
                    .inc();
                tracing::warn!(error = %e, "session persist failed");
            }
        }
    }

    fn delete_persisted(&self, hashed: &str) {
        if let Some(ref storage) = self.storage {
            let _ = storage.execute_params(
                "DELETE FROM identity_sessions WHERE hashed_token = ?1",
                &[&hashed as &dyn rusqlite::types::ToSql],
            );
        }
    }

    /// Yeni session oluştur. `token` plaintext olarak alınır; storage'a hash'lenmiş hali yazılır.
    /// Caller `Session.token` üzerinden plaintext token'ı kullanmaya devam eder; bu döndürülen
    /// `Session` örneği client-facing'dir, kalıcı kayıt değil.
    pub fn create(
        &self,
        user_id: &str,
        token: &str,
        ip: &str,
        user_agent: &str,
        ttl_secs: u64,
    ) -> Session {
        let now = now_secs();
        let device = detect_device(user_agent);
        let hashed = hash_token(token);

        // Storage'a hash'lenmiş kopya
        let stored = Session {
            token: hashed.clone(), // hash'lenmiş, server-side
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + ttl_secs,
            last_activity: now,
            ip: ip.to_string(),
            user_agent: user_agent.to_string(),
            device_name: device.clone(),
            active: true,
        };

        self.sessions.insert(hashed.clone(), stored.clone());
        self.persist(&hashed, &stored);
        crate::metrics::SESSION_EVENTS.with_label_values(&["created"]).inc();
        crate::metrics::SESSIONS_ACTIVE.set(self.active_count() as i64);

        // User→hashed_tokens mapping
        let mut user_tokens = self.user_sessions.entry(user_id.to_string()).or_default();
        user_tokens.push(hashed.clone());

        // Max session: en eski + inactive olanları temizle
        // Önce zaten kapalı/expired token'ları index'ten düş
        let now = now_secs();
        user_tokens.retain(|t| {
            self.sessions
                .get(t)
                .map(|s| s.active && now <= s.expires_at)
                .unwrap_or(false)
        });

        while user_tokens.len() > self.max_sessions_per_user {
            let oldest = user_tokens.remove(0);
            if let Some(mut s) = self.sessions.get_mut(&oldest) {
                s.active = false;
                let snap = s.clone();
                drop(s);
                self.persist(&oldest, &snap);
            }
        }

        // Caller'a plaintext token'ı döndür (storage'daki hash değil)
        Session {
            token: token.to_string(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + ttl_secs,
            last_activity: now,
            ip: ip.to_string(),
            user_agent: user_agent.to_string(),
            device_name: device,
            active: true,
        }
    }

    /// Plaintext token doğrula
    pub fn validate(&self, token: &str) -> Option<Session> {
        let now = now_secs();
        let hashed = hash_token(token);

        if let Some(mut session) = self.sessions.get_mut(&hashed) {
            if !session.active || now > session.expires_at {
                crate::metrics::SESSION_EVENTS
                    .with_label_values(&["expired"])
                    .inc();
                return None;
            }
            session.last_activity = now;
            crate::metrics::SESSION_EVENTS
                .with_label_values(&["validated"])
                .inc();
            // Caller'a plaintext token'ı geri ver (kullanım kolaylığı)
            let mut clone = session.clone();
            clone.token = token.to_string();
            return Some(clone);
        }
        crate::metrics::SESSION_EVENTS
            .with_label_values(&["not_found"])
            .inc();
        None
    }

    /// Session'ı kapat (plaintext token ile)
    pub fn invalidate(&self, token: &str) -> bool {
        let hashed = hash_token(token);
        if let Some(mut session) = self.sessions.get_mut(&hashed) {
            session.active = false;
            let user_id = session.user_id.clone();
            drop(session);
            if let Some(mut tokens) = self.user_sessions.get_mut(&user_id) {
                tokens.retain(|t| t != &hashed);
            }
            // Persist: tamamen sil, stale row bırakma.
            self.delete_persisted(&hashed);
            self.sessions.remove(&hashed);
            crate::metrics::SESSION_EVENTS
                .with_label_values(&["invalidated"])
                .inc();
            crate::metrics::SESSIONS_ACTIVE.set(self.active_count() as i64);
            true
        } else {
            false
        }
    }

    /// Kullanıcının tüm session'larını kapat (force logout) + index'i temizle
    pub fn invalidate_all(&self, user_id: &str) -> usize {
        let hashed_tokens: Vec<String> = self
            .user_sessions
            .get(user_id)
            .map(|t| t.value().clone())
            .unwrap_or_default();

        let mut count = 0;
        for hashed in &hashed_tokens {
            if let Some(mut s) = self.sessions.get_mut(hashed) {
                if s.active {
                    s.active = false;
                    count += 1;
                }
            }
            self.delete_persisted(hashed);
            self.sessions.remove(hashed);
        }
        // Index'i tamamen sıfırla — invalidate_all sonrası user_sessions'ta stale entry kalmasın
        self.user_sessions.remove(user_id);
        count
    }

    /// Kullanıcının aktif session'ları
    pub fn user_sessions(&self, user_id: &str) -> Vec<Session> {
        if let Some(tokens) = self.user_sessions.get(user_id) {
            tokens
                .iter()
                .filter_map(|t| self.sessions.get(t).map(|s| s.value().clone()))
                .filter(|s| s.active)
                .collect()
        } else {
            vec![]
        }
    }

    /// Expired session temizliği — sessions ve user_sessions index'i sync'ler
    pub fn cleanup_expired(&self) -> usize {
        let now = now_secs();
        let mut to_remove: Vec<(String, String)> = Vec::new(); // (hashed, user_id)
        for entry in self.sessions.iter() {
            let s = entry.value();
            if now > s.expires_at || !s.active {
                to_remove.push((entry.key().clone(), s.user_id.clone()));
            }
        }
        let cleaned = to_remove.len();
        for (hashed, user_id) in to_remove {
            self.sessions.remove(&hashed);
            self.delete_persisted(&hashed);
            if let Some(mut tokens) = self.user_sessions.get_mut(&user_id) {
                tokens.retain(|t| t != &hashed);
            }
        }
        crate::metrics::SESSIONS_ACTIVE.set(self.active_count() as i64);
        cleaned
    }

    pub fn active_count(&self) -> usize {
        self.sessions.iter().filter(|s| s.value().active).count()
    }

    pub fn total_count(&self) -> usize {
        self.sessions.len()
    }
}

fn detect_device(ua: &str) -> String {
    let ua_lower = ua.to_lowercase();
    if ua_lower.contains("mobile") || ua_lower.contains("android") || ua_lower.contains("iphone") {
        "Mobile".into()
    } else if ua_lower.contains("tablet") || ua_lower.contains("ipad") {
        "Tablet".into()
    } else if ua_lower.contains("curl")
        || ua_lower.contains("httpie")
        || ua_lower.contains("postman")
    {
        "CLI/API Client".into()
    } else {
        "Desktop".into()
    }
}
