use crate::identity::secret_box::SecretBox;
use crate::registry::storage::SqliteStorage;
/// User Management — register, login, profiles, roles, permissions
/// SQLite persistent + DashMap in-memory cache
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FAILED_ATTEMPTS: u32 = 10;
const LOCKOUT_WINDOW_SECS: u64 = 900; // 15 dk

pub struct UserManager {
    users: DashMap<String, User>,
    email_index: DashMap<String, String>, // email → user_id
    storage: Option<Arc<SqliteStorage>>,
    /// Brute-force koruması: email başına başarısız deneme sayacı
    failed_attempts: DashMap<String, FailedAttempt>,
    /// At-rest secret kasası (MFA seed'leri için). None ise düz metin
    /// saklanır + boot-time warning verilmiş olur.
    secrets: Option<SecretBox>,
}

struct FailedAttempt {
    count: AtomicU32,
    first_failure_at: AtomicU64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub permissions: Vec<String>,
    pub created_at: u64,
    pub last_login: u64,
    pub login_count: u64,
    pub enabled: bool,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum UserRole {
    SuperAdmin,
    Admin,
    Developer,
    Viewer,
    Service,
    Custom(String),
}

impl UserRole {
    /// Hierarchy level — büyük olan daha yetkili. Custom her zaman 0 (Viewer ile eşit;
    /// permissions üzerinden ayrıştırılmalı).
    pub fn level(&self) -> u8 {
        match self {
            UserRole::SuperAdmin => 100,
            UserRole::Admin => 80,
            UserRole::Developer => 60,
            UserRole::Service => 40,
            UserRole::Viewer => 20,
            UserRole::Custom(_) => 0,
        }
    }

    /// `self` rolü `required` rolünün hak ettiği işlemleri yapabilir mi?
    /// SuperAdmin her şeyi, Admin Developer'ı kapsar vs. Custom hiçbir built-in
    /// rolün altına düşmez/üstüne çıkmaz — explicit permission grant'ler gerekir.
    pub fn satisfies(&self, required: &UserRole) -> bool {
        if let UserRole::Custom(_) = required {
            return self == required;
        }
        if matches!(self, UserRole::Custom(_)) {
            return false;
        }
        self.level() >= required.level()
    }

    pub fn as_str(&self) -> &str {
        match self {
            UserRole::SuperAdmin => "SuperAdmin",
            UserRole::Admin => "Admin",
            UserRole::Developer => "Developer",
            UserRole::Viewer => "Viewer",
            UserRole::Service => "Service",
            UserRole::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AuthResult {
    Success { user: User, token: String },
    /// Email enumeration'ı önlemek için NotFound bu varyanta katlanmıştır.
    InvalidCredentials,
    AccountDisabled,
    MfaRequired { user_id: String },
    /// Çok fazla başarısız deneme — geçici kilit.
    LockedOut { retry_after_secs: u64 },
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            users: DashMap::new(),
            email_index: DashMap::new(),
            storage: None,
            failed_attempts: DashMap::new(),
            secrets: None,
        }
    }

    /// SecretBox enjekte et — MFA seed'leri at-rest şifreli saklanır.
    pub fn with_secrets(mut self, secrets: SecretBox) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// MFA seed'i (varsa) düz metne çöz — okuma hatasında None.
    fn decrypt_mfa_secret(&self, stored: Option<String>) -> Option<String> {
        let stored = stored?;
        match &self.secrets {
            Some(sb) => match sb.open(&stored) {
                Ok(bytes) => String::from_utf8(bytes).ok(),
                Err(e) => {
                    // Plaintext legacy fallback'ine düş — encrypted store'a geçmeden önce
                    // yazılmış kayıtlar için. Boot-time warning eşliğinde.
                    tracing::warn!(error = %e, "failed to decrypt mfa_secret; treating as legacy plaintext");
                    Some(stored)
                }
            },
            None => Some(stored),
        }
    }

    /// MFA seed'i sealing — varsa SecretBox kullanır.
    fn encrypt_mfa_secret(&self, plain: Option<&str>) -> Option<String> {
        let plain = plain?;
        match &self.secrets {
            Some(sb) => match sb.seal(plain.as_bytes()) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::error!(error = %e, "failed to seal mfa_secret; storing plaintext");
                    Some(plain.to_string())
                }
            },
            None => Some(plain.to_string()),
        }
    }

    /// SQLite persistent storage ile başlat + tabloyu oluştur + mevcut kayıtları yükle.
    /// Geriye dönük uyumluluk için secrets parametresiz çağrı: at-rest encryption yok.
    pub fn with_storage(storage: Arc<SqliteStorage>) -> Self {
        Self::with_storage_and_secrets(storage, None)
    }

    /// SQLite persistent storage + opsiyonel SecretBox ile başlat. SecretBox verilirse
    /// kayıtlı `mfa_secret` değerleri load sırasında çözümlenir; persist'te şifrelenir.
    pub fn with_storage_and_secrets(
        storage: Arc<SqliteStorage>,
        secrets: Option<SecretBox>,
    ) -> Self {
        // Create identity_users table
        if let Err(e) = storage.execute_raw(
            "CREATE TABLE IF NOT EXISTS identity_users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer',
                permissions TEXT DEFAULT '[]',
                created_at INTEGER NOT NULL,
                last_login INTEGER DEFAULT 0,
                login_count INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                mfa_enabled INTEGER DEFAULT 0,
                mfa_secret TEXT
            )",
        ) {
            tracing::warn!(error = %e, "identity_users schema create failed");
        }

        let mgr = Self {
            users: DashMap::new(),
            email_index: DashMap::new(),
            storage: Some(storage.clone()),
            failed_attempts: DashMap::new(),
            secrets,
        };

        // Load existing users from SQLite
        if let Ok(rows) = storage.query_raw(
            "SELECT id, email, username, password_hash, role, permissions, created_at, last_login, login_count, enabled, mfa_enabled, mfa_secret FROM identity_users"
        ) {
            for row in rows {
                let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let email = row.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let username = row.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let password_hash = row.get("password_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let role_str = row.get("role").and_then(|v| v.as_str()).unwrap_or("Viewer");
                let perms_str = row.get("permissions").and_then(|v| v.as_str()).unwrap_or("[]");
                let created_at = row.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let last_login = row.get("last_login").and_then(|v| v.as_u64()).unwrap_or(0);
                let login_count = row.get("login_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let enabled = row.get("enabled").and_then(|v| v.as_u64()).unwrap_or(1) == 1;
                let mfa_enabled = row.get("mfa_enabled").and_then(|v| v.as_u64()).unwrap_or(0) == 1;
                let mfa_secret_raw = row.get("mfa_secret").and_then(|v| v.as_str()).map(String::from);
                // Load sırasında çöz: SecretBox varsa şifreli kayıtları decrypt et.
                let mfa_secret = mgr.decrypt_mfa_secret(mfa_secret_raw);

                let role = match role_str {
                    "SuperAdmin" => UserRole::SuperAdmin,
                    "Admin" => UserRole::Admin,
                    "Developer" => UserRole::Developer,
                    "Service" => UserRole::Service,
                    s if s.starts_with("Custom(") => UserRole::Custom(s[7..s.len()-1].to_string()),
                    _ => UserRole::Viewer,
                };
                let permissions: Vec<String> = serde_json::from_str(perms_str).unwrap_or_default();

                let user = User {
                    id: id.clone(), email: email.clone(), username, password_hash,
                    role, permissions, created_at, last_login, login_count,
                    enabled, mfa_enabled, mfa_secret,
                    metadata: std::collections::HashMap::new(),
                };

                mgr.email_index.insert(email, id.clone());
                mgr.users.insert(id, user);
            }
            tracing::info!("Identity: loaded {} users from SQLite", mgr.users.len());
        }

        mgr
    }

    /// SQLite'a kullanıcıyı persist et. MFA seed varsa SecretBox ile sealed yazılır.
    fn persist_user(&self, user: &User) {
        if let Some(ref storage) = self.storage {
            let role_str = format!("{:?}", user.role);
            let perms_json = serde_json::to_string(&user.permissions).unwrap_or_default();
            let enabled: i32 = if user.enabled { 1 } else { 0 };
            let mfa_enabled: i32 = if user.mfa_enabled { 1 } else { 0 };
            let created_at = user.created_at as i64;
            let last_login = user.last_login as i64;
            let login_count = user.login_count as i64;
            // mfa_secret'ı sealing'le yaz.
            let mfa_secret_stored = self.encrypt_mfa_secret(user.mfa_secret.as_deref());
            if let Err(e) = storage.execute_params(
                "INSERT OR REPLACE INTO identity_users (id, email, username, password_hash, role, permissions, created_at, last_login, login_count, enabled, mfa_enabled, mfa_secret) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                &[
                    &user.id as &dyn rusqlite::types::ToSql,
                    &user.email,
                    &user.username,
                    &user.password_hash,
                    &role_str,
                    &perms_json,
                    &created_at,
                    &last_login,
                    &login_count,
                    &enabled,
                    &mfa_enabled,
                    &mfa_secret_stored as &dyn rusqlite::types::ToSql,
                ],
            ) {
                crate::metrics::DB_PERSIST_ERRORS
                    .with_label_values(&["identity_users"])
                    .inc();
                tracing::warn!(error = %e, user_id = %user.id, "failed to persist user");
            }
        }
    }

    /// Kullanıcı kayıt
    pub fn register(
        &self,
        email: String,
        username: String,
        password: &str,
        role: UserRole,
    ) -> Result<User, String> {
        if self.email_index.contains_key(&email) {
            return Err("Email already registered".to_string());
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = now_secs();
        let password_hash = hash_password(password);

        let user = User {
            id: id.clone(),
            email: email.clone(),
            username,
            password_hash,
            role,
            permissions: vec![],
            created_at: now,
            last_login: 0,
            login_count: 0,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            metadata: std::collections::HashMap::new(),
        };

        self.persist_user(&user);
        self.email_index.insert(email, id.clone());
        self.users.insert(id, user.clone());
        tracing::info!("User registered: {} ({})", user.email, user.id);
        Ok(user)
    }

    /// Login. Email enumeration ve timing attack'a karşı:
    /// - NotFound → InvalidCredentials'a katlanır
    /// - User yoksa bile constant-time dummy verify yapılır
    /// - Per-email failed-attempt counter ile rate-limit
    pub fn authenticate(&self, email: &str, password: &str) -> AuthResult {
        // Lockout kontrolü (timing-safe değil ama açık account için bilgi sızdırmıyor)
        if let Some(retry) = self.lockout_check(email) {
            return AuthResult::LockedOut { retry_after_secs: retry };
        }

        let user_id = self.email_index.get(email).map(|id| id.clone());
        let mut user_opt = user_id
            .as_ref()
            .and_then(|id| self.users.get_mut(id));

        // Timing-attack koruması: kullanıcı yoksa da dummy hash verify yap.
        // Argon2 pahalı; iki dal eşit süre almalı.
        let password_ok = match user_opt.as_mut() {
            Some(user) => verify_password(password, &user.password_hash),
            None => {
                // Constant-cost dummy verify
                let _ = verify_password(password, DUMMY_ARGON2_HASH);
                false
            }
        };

        let mut user = match user_opt {
            Some(u) => u,
            None => {
                self.record_failure(email);
                return AuthResult::InvalidCredentials;
            }
        };

        if !user.enabled {
            // Disabled account leak'i kabul ediyoruz çünkü self-service login bunu zaten ortaya çıkarıyor
            return AuthResult::AccountDisabled;
        }

        if !password_ok {
            self.record_failure(email);
            return AuthResult::InvalidCredentials;
        }

        // Başarı: counter sıfırla
        self.failed_attempts.remove(email);

        if user.mfa_enabled {
            return AuthResult::MfaRequired {
                user_id: user.id.clone(),
            };
        }

        let now = now_secs();
        user.last_login = now;
        user.login_count += 1;

        self.persist_user(&user);

        let token = format!(
            "xira_tok_{}",
            uuid::Uuid::new_v4().to_string().replace("-", "")
        );
        AuthResult::Success {
            user: user.clone(),
            token,
        }
    }

    fn lockout_check(&self, email: &str) -> Option<u64> {
        let entry = self.failed_attempts.get(email)?;
        let count = entry.count.load(Ordering::Relaxed);
        if count < MAX_FAILED_ATTEMPTS {
            return None;
        }
        let first = entry.first_failure_at.load(Ordering::Relaxed);
        let now = now_secs();
        if now.saturating_sub(first) >= LOCKOUT_WINDOW_SECS {
            // Pencere doldu, sıfırla
            drop(entry);
            self.failed_attempts.remove(email);
            None
        } else {
            Some(LOCKOUT_WINDOW_SECS - (now - first))
        }
    }

    fn record_failure(&self, email: &str) {
        let now = now_secs();
        self.failed_attempts
            .entry(email.to_string())
            .and_modify(|fa| {
                fa.count.fetch_add(1, Ordering::Relaxed);
            })
            .or_insert_with(|| FailedAttempt {
                count: AtomicU32::new(1),
                first_failure_at: AtomicU64::new(now),
            });
    }

    pub fn get_user(&self, id: &str) -> Option<User> {
        self.users.get(id).map(|u| u.value().clone())
    }

    /// Kullanıcının rolünü döndür — middleware role check'i için hızlı erişim.
    pub fn user_role(&self, id: &str) -> Option<UserRole> {
        self.users.get(id).map(|u| u.value().role.clone())
    }

    /// MFA enrollment başlat: yeni TOTP seed üret, sealed olarak persist et.
    /// Kullanıcıya QR URL döndür; verify_mfa_setup ile aktive edilene kadar `mfa_enabled`
    /// false kalır.
    pub fn start_mfa_enrollment(&self, user_id: &str) -> Result<(String, String), String> {
        let mut user = self
            .users
            .get_mut(user_id)
            .ok_or_else(|| "user not found".to_string())?;
        let secret = crate::identity::mfa::MfaEngine::generate_secret();
        let qr = crate::identity::mfa::MfaEngine::generate_qr_url(&user.email, &secret);
        user.mfa_secret = Some(secret.clone());
        // Henüz mfa_enabled false — verify ile aktif olacak.
        self.persist_user(&user);
        crate::metrics::MFA_EVENTS
            .with_label_values(&["enroll_started"])
            .inc();
        Ok((secret, qr))
    }

    /// MFA enrollment'ı doğrula: kullanıcı QR'ı scan edip ilk kod ile geri çağırır.
    /// Doğru kod → mfa_enabled = true.
    pub fn verify_mfa_setup(&self, user_id: &str, code: &str) -> bool {
        let mut user = match self.users.get_mut(user_id) {
            Some(u) => u,
            None => return false,
        };
        let secret = match &user.mfa_secret {
            Some(s) => s.clone(),
            None => return false,
        };
        if !crate::identity::mfa::MfaEngine::verify_totp(&secret, code) {
            return false;
        }
        user.mfa_enabled = true;
        self.persist_user(&user);
        crate::metrics::MFA_EVENTS
            .with_label_values(&["enroll_verified"])
            .inc();
        true
    }

    /// MfaRequired akışında çağrılır: kod doğruysa Success token döndür.
    pub fn complete_mfa_login(&self, user_id: &str, code: &str) -> AuthResult {
        let mut user = match self.users.get_mut(user_id) {
            Some(u) => u,
            None => return AuthResult::InvalidCredentials,
        };
        if !user.enabled {
            return AuthResult::AccountDisabled;
        }
        if !user.mfa_enabled {
            return AuthResult::InvalidCredentials;
        }
        let secret = match &user.mfa_secret {
            Some(s) => s.clone(),
            None => return AuthResult::InvalidCredentials,
        };
        if !crate::identity::mfa::MfaEngine::verify_totp(&secret, code) {
            crate::metrics::MFA_EVENTS
                .with_label_values(&["login_failed"])
                .inc();
            return AuthResult::InvalidCredentials;
        }
        crate::metrics::MFA_EVENTS
            .with_label_values(&["login_success"])
            .inc();
        let now = now_secs();
        user.last_login = now;
        user.login_count += 1;
        self.persist_user(&user);
        let token = format!(
            "xira_tok_{}",
            uuid::Uuid::new_v4().to_string().replace("-", "")
        );
        AuthResult::Success {
            user: user.clone(),
            token,
        }
    }

    /// MFA'yı kapat (panik durumu için admin/superadmin tarafından çağrılır).
    pub fn disable_mfa(&self, user_id: &str) -> bool {
        if let Some(mut user) = self.users.get_mut(user_id) {
            user.mfa_enabled = false;
            user.mfa_secret = None;
            self.persist_user(&user);
            crate::metrics::MFA_EVENTS
                .with_label_values(&["disabled_by_admin"])
                .inc();
            true
        } else {
            false
        }
    }

    pub fn disable_user(&self, id: &str) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            user.enabled = false;
            self.persist_user(&user);
            true
        } else {
            false
        }
    }

    pub fn update_role(&self, id: &str, role: UserRole) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            user.role = role;
            self.persist_user(&user);
            true
        } else {
            false
        }
    }

    pub fn add_permission(&self, id: &str, permission: String) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            if !user.permissions.contains(&permission) {
                user.permissions.push(permission);
            }
            self.persist_user(&user);
            true
        } else {
            false
        }
    }

    pub fn has_permission(&self, id: &str, permission: &str) -> bool {
        self.users
            .get(id)
            .map(|u| {
                u.permissions.contains(&permission.to_string()) || u.role == UserRole::SuperAdmin
            })
            .unwrap_or(false)
    }

    pub fn list_users(&self) -> Vec<serde_json::Value> {
        self.users
            .iter()
            .map(|e| {
                let u = e.value();
                serde_json::json!({
                    "id": u.id, "email": u.email, "username": u.username,
                    "role": format!("{:?}", u.role), "enabled": u.enabled,
                    "created_at": u.created_at, "last_login": u.last_login,
                    "login_count": u.login_count, "mfa_enabled": u.mfa_enabled,
                    "permissions": u.permissions,
                })
            })
            .collect()
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

/// Hash password with Argon2id (production-grade)
fn hash_password(password: &str) -> String {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 hash failed")
        .to_string()
}

/// Verify password — Argon2id only. Legacy hash formatları reddedilir.
fn verify_password(password: &str, stored: &str) -> bool {
    if !stored.starts_with("$argon2") {
        // Argon2 olmayan tüm formatlar reddedilir (legacy DefaultHasher dahil).
        // Bu kullanıcılar admin tarafından sıfırlanmalı.
        return false;
    }
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let parsed = match PasswordHash::new(stored) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Constant-cost dummy hash, kullanıcı yokken timing eşitlemesi için.
/// "dummy_password" için Argon2id default parametreleriyle hesaplanmış sabit hash.
const DUMMY_ARGON2_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Ck5kQ7BkVZx2g4Cv9b4GZ1QF5mHRT7FzfA8YV2W6cKw";
