/// MFA Engine — RFC 6238 TOTP (HMAC-SHA1) multi-factor authentication
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

const TOTP_DIGITS: u32 = 6;
const TOTP_PERIOD: u64 = 30;

pub struct MfaEngine;

impl MfaEngine {
    /// TOTP secret oluştur (base32 encoded, 20 random bytes)
    pub fn generate_secret() -> String {
        let bytes: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
        base32_encode(&bytes)
    }

    /// TOTP kodu doğrula (constant-time karşılaştırma + ±1 step pencere)
    pub fn verify_totp(secret: &str, code: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let time_step = now / TOTP_PERIOD;

        let key = match base32_decode(secret) {
            Some(k) => k,
            None => return false,
        };

        let code_bytes = code.as_bytes();
        for offset in [0i64, -1, 1] {
            let step = (time_step as i64).saturating_add(offset).max(0) as u64;
            let generated = generate_totp_code(&key, step);
            if generated.as_bytes().ct_eq(code_bytes).into() {
                return true;
            }
        }
        false
    }

    /// QR code URL oluştur (Google Authenticator format)
    pub fn generate_qr_url(email: &str, secret: &str) -> String {
        format!(
            "otpauth://totp/XIRA:{email}?secret={secret}&issuer=XIRA&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
        )
    }
}

/// RFC 6238 / RFC 4226 TOTP/HOTP code generation
fn generate_totp_code(key: &[u8], time_step: u64) -> String {
    let counter = time_step.to_be_bytes();
    let mut mac = match HmacSha1::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return "000000".to_string(),
    };
    mac.update(&counter);
    let hash = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin_code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulus = 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", bin_code % modulus, width = TOTP_DIGITS as usize)
}

/// Base32 encoding (RFC 4648, no padding)
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

/// Base32 decoding (RFC 4648, padding optional, case-insensitive)
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;

    for c in input.chars().filter(|c| *c != '=' && !c.is_whitespace()) {
        let val: u32 = match c.to_ascii_uppercase() {
            'A'..='Z' => (c.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => (c as u32) - ('2' as u32) + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            result.push(((buffer >> bits_left) & 0xff) as u8);
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        let data = b"hello world!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn rfc6238_test_vector() {
        // RFC 6238 Appendix B: secret = "12345678901234567890" (ASCII), T=59 -> 94287082
        let key = b"12345678901234567890";
        let code = generate_totp_code(key, 59 / TOTP_PERIOD);
        assert_eq!(code, "287082");
    }

    #[test]
    fn invalid_secret_rejects() {
        assert!(!MfaEngine::verify_totp("not-base32!@#", "123456"));
    }
}
