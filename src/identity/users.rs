/// User Management — register, login, profiles, roles, permissions
/// SQLite persistent + DashMap in-memory cache
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::registry::storage::SqliteStorage;

pub struct UserManager {
    users: DashMap<String, User>,
    email_index: DashMap<String, String>, // email → user_id
    storage: Option<Arc<SqliteStorage>>,
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum UserRole {
    SuperAdmin,
    Admin,
    Developer,
    Viewer,
    Service,
    Custom(String),
}

#[derive(Debug)]
pub enum AuthResult {
    Success { user: User, token: String },
    InvalidCredentials,
    AccountDisabled,
    MfaRequired { user_id: String },
    NotFound,
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            users: DashMap::new(),
            email_index: DashMap::new(),
            storage: None,
        }
    }

    /// SQLite persistent storage ile başlat + tabloyu oluştur + mevcut kayıtları yükle
    pub fn with_storage(storage: Arc<SqliteStorage>) -> Self {
        // Create identity_users table
        let _ = storage.execute_raw(
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
            )"
        );

        let mgr = Self {
            users: DashMap::new(),
            email_index: DashMap::new(),
            storage: Some(storage.clone()),
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
                let mfa_secret = row.get("mfa_secret").and_then(|v| v.as_str()).map(String::from);

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

    /// SQLite'a kullanıcıyı persist et
    fn persist_user(&self, user: &User) {
        if let Some(ref storage) = self.storage {
            let role_str = format!("{:?}", user.role);
            let perms_json = serde_json::to_string(&user.permissions).unwrap_or_default();
            let _ = storage.execute_raw(&format!(
                "INSERT OR REPLACE INTO identity_users (id, email, username, password_hash, role, permissions, created_at, last_login, login_count, enabled, mfa_enabled, mfa_secret) VALUES ('{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {})",
                user.id,
                user.email.replace('\'', "''"),
                user.username.replace('\'', "''"),
                user.password_hash.replace('\'', "''"),
                role_str.replace('\'', "''"),
                perms_json.replace('\'', "''"),
                user.created_at,
                user.last_login,
                user.login_count,
                if user.enabled { 1 } else { 0 },
                if user.mfa_enabled { 1 } else { 0 },
                user.mfa_secret.as_ref().map(|s| format!("'{}'", s.replace('\'', "''"))).unwrap_or("NULL".to_string()),
            ));
        }
    }

    /// Kullanıcı kayıt
    pub fn register(&self, email: String, username: String, password: &str, role: UserRole) -> Result<User, String> {
        if self.email_index.contains_key(&email) {
            return Err("Email already registered".to_string());
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let salt = generate_salt();
        let password_hash = hash_password(password, &salt);

        let user = User {
            id: id.clone(), email: email.clone(), username, password_hash,
            role, permissions: vec![], created_at: now, last_login: 0, login_count: 0,
            enabled: true, mfa_enabled: false, mfa_secret: None,
            metadata: std::collections::HashMap::new(),
        };

        self.persist_user(&user);
        self.email_index.insert(email, id.clone());
        self.users.insert(id, user.clone());
        tracing::info!("User registered: {} ({})", user.email, user.id);
        Ok(user)
    }

    /// Login
    pub fn authenticate(&self, email: &str, password: &str) -> AuthResult {
        let user_id = match self.email_index.get(email) {
            Some(id) => id.clone(),
            None => return AuthResult::NotFound,
        };

        let mut user = match self.users.get_mut(&user_id) {
            Some(u) => u,
            None => return AuthResult::NotFound,
        };

        if !user.enabled {
            return AuthResult::AccountDisabled;
        }

        if !verify_password(password, &user.password_hash) {
            return AuthResult::InvalidCredentials;
        }

        if user.mfa_enabled {
            return AuthResult::MfaRequired { user_id: user.id.clone() };
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        user.last_login = now;
        user.login_count += 1;

        // Persist login state update
        self.persist_user(&user);

        let token = format!("xira_tok_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        AuthResult::Success { user: user.clone(), token }
    }

    pub fn get_user(&self, id: &str) -> Option<User> {
        self.users.get(id).map(|u| u.value().clone())
    }

    pub fn disable_user(&self, id: &str) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            user.enabled = false;
            self.persist_user(&user);
            true
        } else { false }
    }

    pub fn update_role(&self, id: &str, role: UserRole) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            user.role = role;
            self.persist_user(&user);
            true
        } else { false }
    }

    pub fn add_permission(&self, id: &str, permission: String) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            if !user.permissions.contains(&permission) {
                user.permissions.push(permission);
            }
            self.persist_user(&user);
            true
        } else { false }
    }

    pub fn has_permission(&self, id: &str, permission: &str) -> bool {
        self.users.get(id)
            .map(|u| u.permissions.contains(&permission.to_string()) || u.role == UserRole::SuperAdmin)
            .unwrap_or(false)
    }

    pub fn list_users(&self) -> Vec<serde_json::Value> {
        self.users.iter().map(|e| {
            let u = e.value();
            serde_json::json!({
                "id": u.id, "email": u.email, "username": u.username,
                "role": format!("{:?}", u.role), "enabled": u.enabled,
                "created_at": u.created_at, "last_login": u.last_login,
                "login_count": u.login_count, "mfa_enabled": u.mfa_enabled,
                "permissions": u.permissions,
            })
        }).collect()
    }

    pub fn user_count(&self) -> usize { self.users.len() }
}

/// Generate a random 16-byte hex salt
fn generate_salt() -> String {
    use rand::Rng;
    let salt: [u8; 16] = rand::thread_rng().gen();
    salt.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hash password with salt (iterative stretching, 1000 rounds)
fn hash_password(password: &str, salt: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let salted = format!("{}:{}:{}", salt, password, salt);
    for _ in 0..1000 {
        salted.hash(&mut hasher);
    }
    let hash = hasher.finish();
    format!("{}${:016x}", salt, hash)
}

/// Verify password against stored hash (salt$hash format)
fn verify_password(password: &str, stored: &str) -> bool {
    if let Some(salt) = stored.split('$').next() {
        hash_password(password, salt) == stored
    } else {
        false
    }
}
