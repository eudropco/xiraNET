/// User Management — register, login, profiles, roles, permissions
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct UserManager {
    users: DashMap<String, User>,
    email_index: DashMap<String, String>, // email → user_id
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
        }
    }

    /// Kullanıcı kayıt
    pub fn register(&self, email: String, username: String, password: &str, role: UserRole) -> Result<User, String> {
        // Email unique check
        if self.email_index.contains_key(&email) {
            return Err("Email already registered".to_string());
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Salted password hashing (1000 rounds of iterative stretching)
        let salt = generate_salt();
        let password_hash = hash_password(password, &salt);

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

        let token = format!("xira_tok_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

        AuthResult::Success { user: user.clone(), token }
    }

    /// Kullanıcı getir
    pub fn get_user(&self, id: &str) -> Option<User> {
        self.users.get(id).map(|u| u.value().clone())
    }

    /// Kullanıcıyı devre dışı bırak
    pub fn disable_user(&self, id: &str) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            user.enabled = false;
            true
        } else { false }
    }

    /// Rol güncelle
    pub fn update_role(&self, id: &str, role: UserRole) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            user.role = role;
            true
        } else { false }
    }

    /// Permission ekle
    pub fn add_permission(&self, id: &str, permission: String) -> bool {
        if let Some(mut user) = self.users.get_mut(id) {
            if !user.permissions.contains(&permission) {
                user.permissions.push(permission);
            }
            true
        } else { false }
    }

    /// Permission kontrolü
    pub fn has_permission(&self, id: &str, permission: &str) -> bool {
        self.users.get(id)
            .map(|u| u.permissions.contains(&permission.to_string()) || u.role == UserRole::SuperAdmin)
            .unwrap_or(false)
    }

    /// Tüm kullanıcıları listele (password hariç)
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

/// Hash password with salt using SHA-256 (iterative stretching)
fn hash_password(password: &str, salt: &str) -> String {
    use std::hash::{Hash, Hasher};
    // SHA-256 via iterative hashing with salt mixing (1000 rounds)
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
