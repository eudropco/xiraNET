//! UserManager + SessionManager arasındaki contract'i type sisteminde
//! garanti eden authenticator façade.
//!
//! v3.0 audit fix (Yarı A, madde 9): önceki sürümde `users.authenticate()`
//! ham token string döndürüyordu; handler `sessions.create()` çağırmayı
//! unutursa token client'a issued ama validate hep 401. Tip sisteminde
//! sözleşme yoktu.
//!
//! Bu modülde `Authenticator::login()` AuthOutcome döner. AuthOutcome::Success
//! ham token taşımaz — sadece doğrulanmış session handle taşır. Token issued
//! olmak için session create de yapılmış demektir.

use crate::identity::sessions::{Session, SessionManager};
use crate::identity::users::{AuthResult, UserManager};
use std::sync::Arc;

#[derive(Clone)]
pub struct Authenticator {
    users: Arc<UserManager>,
    sessions: Arc<SessionManager>,
    /// Session TTL (saniye). Default 24h.
    session_ttl_secs: u64,
}

#[derive(Debug)]
pub enum AuthOutcome {
    /// Login + session create atomik tamamlandı. `session.token` client'a verilebilir.
    Success {
        user_id: String,
        email: String,
        session: Session,
    },
    /// İkinci aşama gerekli — MFA TOTP doğrulanmalı (`/auth/mfa/login`).
    MfaRequired { user_id: String },
    AccountDisabled,
    LockedOut {
        retry_after_secs: u64,
    },
    InvalidCredentials,
}

impl Authenticator {
    pub fn new(users: Arc<UserManager>, sessions: Arc<SessionManager>) -> Self {
        Self {
            users,
            sessions,
            session_ttl_secs: 86_400,
        }
    }

    pub fn with_session_ttl(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs.max(60);
        self
    }

    /// Standart login akışı — başarılı kimlik doğrulama session create ile
    /// AYNI fonksiyonda olur. Handler tarafında `sessions.create()` çağırmayı
    /// unutma tehlikesi yok.
    pub fn login(
        &self,
        email: &str,
        password: &str,
        ip: &str,
        user_agent: &str,
    ) -> AuthOutcome {
        match self.users.authenticate(email, password) {
            AuthResult::Success { user, token } => {
                let session = self
                    .sessions
                    .create(&user.id, &token, ip, user_agent, self.session_ttl_secs);
                AuthOutcome::Success {
                    user_id: user.id,
                    email: user.email,
                    session,
                }
            }
            AuthResult::MfaRequired { user_id } => AuthOutcome::MfaRequired { user_id },
            AuthResult::AccountDisabled => AuthOutcome::AccountDisabled,
            AuthResult::LockedOut { retry_after_secs } => {
                AuthOutcome::LockedOut { retry_after_secs }
            }
            AuthResult::InvalidCredentials => AuthOutcome::InvalidCredentials,
        }
    }

    /// MFA challenge sonrası 2. aşama — TOTP doğru ise session yaratır.
    pub fn complete_mfa(
        &self,
        user_id: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> AuthOutcome {
        match self.users.complete_mfa_login(user_id, code) {
            AuthResult::Success { user, token } => {
                let session = self
                    .sessions
                    .create(&user.id, &token, ip, user_agent, self.session_ttl_secs);
                AuthOutcome::Success {
                    user_id: user.id,
                    email: user.email,
                    session,
                }
            }
            AuthResult::AccountDisabled => AuthOutcome::AccountDisabled,
            _ => AuthOutcome::InvalidCredentials,
        }
    }
}
