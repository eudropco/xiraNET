//! CLI session token persistence — `xira admin login` ile alınan token
//! dosyaya yazılır; sonraki admin komutları --token / XIRA_SESSION_TOKEN olmadan
//! da çalışır.
//!
//! Dosya: `$XDG_CONFIG_HOME/xira/session` veya `~/.config/xira/session`.
//! Permission: 0600 (sadece owner okur/yazar). Token plaintext; sahip dosya
//! sistemine yetkili kullanıcı bunu görebilir — bu kabul edilen trade-off.
//! Daha güçlü koruma için OS keychain (Phase 4.6+) düşünülebilir.

use std::path::PathBuf;

fn config_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XDG_CONFIG_HOME") {
        if !p.is_empty() {
            return Some(PathBuf::from(p).join("xira"));
        }
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".config").join("xira"))
}

fn session_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("session"))
}

pub fn save(token: &str, gateway: &str) -> Result<PathBuf, String> {
    let path = session_file().ok_or("HOME / XDG_CONFIG_HOME not set")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    // Format: TOML benzeri minimal (TOML dep'i import etmemek için inline yazıyoruz).
    let content = format!("# xiraNET CLI session — auto-managed, do not edit by hand\ntoken = \"{token}\"\ngateway = \"{gateway}\"\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        use std::io::Write;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, content).map_err(|e| format!("write: {e}"))?;
    }
    Ok(path)
}

pub fn load() -> Option<(String, String)> {
    let path = session_file()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let mut token: Option<String> = None;
    let mut gateway: Option<String> = None;
    for line in content.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix("token") {
            token = parse_quoted(rest);
        } else if let Some(rest) = l.strip_prefix("gateway") {
            gateway = parse_quoted(rest);
        }
    }
    match (token, gateway) {
        (Some(t), Some(g)) => Some((t, g)),
        _ => None,
    }
}

pub fn clear() -> Result<(), String> {
    let path = session_file().ok_or("no config dir")?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("rm {}: {e}", path.display()))?;
    }
    Ok(())
}

pub fn path_display() -> String {
    session_file()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// `= "value"` parse — minimal, tırnak içi.
fn parse_quoted(s: &str) -> Option<String> {
    let s = s.trim_start();
    let s = s.strip_prefix('=')?.trim_start();
    let s = s.strip_prefix('"')?;
    let end = s.find('"')?;
    Some(s[..end].to_string())
}

/// `provided` boşsa stored token'ı dene. Boş döndürmez (hata mesajı için Result).
pub fn resolve_token(provided: &str) -> Result<(String, Option<String>), String> {
    if !provided.is_empty() {
        return Ok((provided.to_string(), None));
    }
    if let Ok(env) = std::env::var("XIRA_SESSION_TOKEN") {
        if !env.is_empty() {
            return Ok((env, None));
        }
    }
    match load() {
        Some((t, g)) => Ok((t, Some(g))),
        None => Err(format!(
            "no session token — try: `xira admin login <email> <password>` (will save to {})",
            path_display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_roundtrip() {
        // Test için XDG override
        let tmp = std::env::temp_dir().join(format!("xira-cli-test-{}", uuid::Uuid::new_v4()));
        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        let _ = save("xira_tok_abcd", "http://localhost:9000").unwrap();
        let (t, g) = load().expect("load");
        assert_eq!(t, "xira_tok_abcd");
        assert_eq!(g, "http://localhost:9000");
        clear().unwrap();
        assert!(load().is_none());
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn parse_quoted_basic() {
        assert_eq!(parse_quoted(r#" = "abc""#), Some("abc".to_string()));
        assert_eq!(parse_quoted("invalid"), None);
    }
}
