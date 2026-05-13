/// At-rest secret encryption — AES-256-GCM zarflama.
///
/// MFA seed'leri ve diğer hassas materyaller SQLite'a düz metin olarak yazılmamalı.
/// Bu modül `XIRA_SECRETS_KEY` ortam değişkeninden alınan 32-byte master key ile
/// AES-256-GCM şifreleme sunar. Key yoksa init() hata döner — operatör açıkça
/// `XIRA_SECRETS_KEY` ayarlamadan persistent identity başlatılamaz.
///
/// Format: base64(version=0x01 || nonce(12) || ciphertext || tag(16))
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SecretBoxError {
    #[error("XIRA_SECRETS_KEY environment variable is not set")]
    MissingKey,
    #[error("XIRA_SECRETS_KEY too short ({0} bytes); need at least 32")]
    WeakKey(usize),
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
}

#[derive(Clone)]
pub struct SecretBox {
    cipher: Arc<Aes256Gcm>,
}

impl SecretBox {
    /// `XIRA_SECRETS_KEY` ortam değişkeninden initialize et.
    pub fn from_env() -> Result<Self, SecretBoxError> {
        let raw = std::env::var("XIRA_SECRETS_KEY").map_err(|_| SecretBoxError::MissingKey)?;
        Self::from_passphrase(&raw)
    }

    /// İsteğe bağlı: dev/test fallback. Production'da from_env kullan.
    pub fn from_passphrase(pass: &str) -> Result<Self, SecretBoxError> {
        if pass.len() < 32 {
            return Err(SecretBoxError::WeakKey(pass.len()));
        }
        // SHA-256 ile 32-byte'a sıkıştır.
        let digest = Sha256::digest(pass.as_bytes());
        let key = Key::<Aes256Gcm>::from_slice(&digest);
        Ok(Self {
            cipher: Arc::new(Aes256Gcm::new(key)),
        })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<String, SecretBoxError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        for b in nonce_bytes.iter_mut() {
            *b = rand::random();
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| SecretBoxError::EncryptionFailed(e.to_string()))?;

        let mut buf = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        buf.push(VERSION);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ciphertext);
        Ok(B64.encode(buf))
    }

    pub fn open(&self, sealed: &str) -> Result<Vec<u8>, SecretBoxError> {
        let buf = B64
            .decode(sealed.as_bytes())
            .map_err(|e| SecretBoxError::InvalidCiphertext(e.to_string()))?;
        if buf.len() < 1 + NONCE_LEN + 16 {
            return Err(SecretBoxError::InvalidCiphertext("too short".to_string()));
        }
        if buf[0] != VERSION {
            return Err(SecretBoxError::InvalidCiphertext(format!(
                "unknown version 0x{:02x}",
                buf[0]
            )));
        }
        let nonce = Nonce::from_slice(&buf[1..1 + NONCE_LEN]);
        let ct = &buf[1 + NONCE_LEN..];
        self.cipher
            .decrypt(nonce, ct)
            .map_err(|e| SecretBoxError::DecryptionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pass = "0123456789abcdef0123456789abcdef".to_string();
        let sb = SecretBox::from_passphrase(&pass).unwrap();
        let plaintext = b"super-secret-mfa-seed-XYZ";
        let sealed = sb.seal(plaintext).unwrap();
        let opened = sb.open(&sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn weak_key_rejected() {
        assert!(SecretBox::from_passphrase("short").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let pass = "0123456789abcdef0123456789abcdef".to_string();
        let sb = SecretBox::from_passphrase(&pass).unwrap();
        let mut sealed = sb.seal(b"x").unwrap();
        // Mutate one base64 char
        unsafe {
            let bytes = sealed.as_bytes_mut();
            // pick a char in the middle, swap to a different valid base64 char
            let mid = bytes.len() / 2;
            bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        }
        assert!(sb.open(&sealed).is_err());
    }
}
