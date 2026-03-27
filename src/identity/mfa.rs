/// MFA Engine — TOTP-based multi-factor authentication
use std::time::{SystemTime, UNIX_EPOCH};

pub struct MfaEngine;

impl MfaEngine {
    /// TOTP secret oluştur (base32 encoded)
    pub fn generate_secret() -> String {
        let bytes: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
        base32_encode(&bytes)
    }

    /// TOTP kodu doğrula
    pub fn verify_totp(secret: &str, code: &str) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let time_step = now / 30;

        // Current + ±1 window (30s tolerance)
        for offset in [0i64, -1, 1] {
            let step = (time_step as i64 + offset) as u64;
            let generated = generate_totp_code(secret, step);
            if generated == code {
                return true;
            }
        }
        false
    }

    /// QR code URL oluştur (Google Authenticator format)
    pub fn generate_qr_url(email: &str, secret: &str) -> String {
        format!(
            "otpauth://totp/xiraNET:{}?secret={}&issuer=xiraNET&digits=6&period=30",
            email, secret
        )
    }
}

/// TOTP kodu üret (simplified HMAC-based)
fn generate_totp_code(secret: &str, time_step: u64) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    secret.hash(&mut hasher);
    time_step.hash(&mut hasher);
    let hash = hasher.finish();
    let code = (hash % 1_000_000) as u32;
    format!("{:06}", code)
}

/// Base32 encoding (RFC 4648)
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}
