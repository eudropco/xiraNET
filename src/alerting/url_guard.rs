/// SSRF koruması — webhook URL'leri için scheme/host allow-list.
///
/// Engellenen kategoriler:
/// - http/https dışı şemalar (file://, gopher://, ldap://, ...)
/// - Loopback (127.0.0.0/8, ::1)
/// - Cloud metadata (169.254.169.254, fd00:ec2::254, metadata.google.internal)
/// - Link-local (169.254.0.0/16, fe80::/10)
/// - RFC1918 / unique-local IPv6 (10/8, 172.16/12, 192.168/16, fc00::/7)
/// - Unspecified (0.0.0.0, ::)
/// - Multicast / broadcast / reserved aralıklar
///
/// DNS hostname'leri için `tokio::net::lookup_host` ile resolve edip
/// dönen tüm IP'leri kontrol ederiz. Bu, DNS rebinding'e karşı tam koruma
/// vermez (IP, resolve ile reqwest connect arasında değişebilir) ama temel
/// SSRF saldırılarını durdurur. Tam koruma için custom resolver gerekir.
use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum UrlGuardError {
    #[error("invalid URL: {0}")]
    Invalid(String),
    #[error("scheme not allowed: {0} (use http or https)")]
    BadScheme(String),
    #[error("missing host")]
    MissingHost,
    #[error("DNS resolution failed: {0}")]
    DnsError(String),
    #[error("destination address is forbidden (private/loopback/metadata): {0}")]
    Forbidden(String),
}

/// URL'i validate et ve resolve edilen tüm IP'lerin güvenli olduğunu doğrula.
/// Webhook/cron gibi attacker-controllable URL'ler için strict mod.
pub async fn validate_outbound_url(raw_url: &str) -> Result<(), UrlGuardError> {
    validate_url(raw_url, GuardLevel::Strict).await
}

/// Upstream service için: yalnızca cloud metadata adreslerini ve kötü scheme'leri reddet,
/// RFC1918/loopback'e izin ver (gateway'in alongside backend service kullanımı yaygın).
pub async fn validate_upstream_url(raw_url: &str) -> Result<(), UrlGuardError> {
    validate_url(raw_url, GuardLevel::UpstreamOnly).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardLevel {
    /// Tam SSRF koruması: loopback, RFC1918, link-local, metadata, multicast vb. block.
    Strict,
    /// Sadece cloud metadata + non-http(s) scheme block. RFC1918/loopback OK.
    UpstreamOnly,
}

async fn validate_url(raw_url: &str, level: GuardLevel) -> Result<(), UrlGuardError> {
    let url = reqwest::Url::parse(raw_url).map_err(|e| UrlGuardError::Invalid(e.to_string()))?;

    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(UrlGuardError::BadScheme(scheme.to_string()));
    }

    let host = url.host_str().ok_or(UrlGuardError::MissingHost)?;

    // Hostname normalize: bilinen metadata DNS isimlerini her iki modda da reddet.
    let host_lower = host.to_ascii_lowercase();
    if is_blocked_metadata_hostname(&host_lower) {
        return Err(UrlGuardError::Forbidden(format!(
            "blocked metadata hostname: {host}"
        )));
    }
    if level == GuardLevel::Strict && is_blocked_hostname_strict(&host_lower) {
        return Err(UrlGuardError::Forbidden(format!(
            "blocked hostname: {host}"
        )));
    }

    // Doğrudan IP literal'i ise resolve etmeye gerek yok
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_ip_allowed(&ip, level) {
            return Err(UrlGuardError::Forbidden(ip.to_string()));
        }
        return Ok(());
    }

    // DNS resolve — port önemli değil ama lookup_host port istiyor
    let port = url.port_or_known_default().unwrap_or(443);
    let target = format!("{host}:{port}");

    let addrs = tokio::net::lookup_host(target.as_str())
        .await
        .map_err(|e| UrlGuardError::DnsError(e.to_string()))?;

    let mut any = false;
    for sa in addrs {
        any = true;
        if !is_ip_allowed(&sa.ip(), level) {
            return Err(UrlGuardError::Forbidden(format!(
                "{} resolves to {}",
                host,
                sa.ip()
            )));
        }
    }

    if !any {
        return Err(UrlGuardError::DnsError(
            "no addresses resolved".to_string(),
        ));
    }

    Ok(())
}

/// Cloud metadata DNS isimleri — her iki modda da block edilir.
fn is_blocked_metadata_hostname(host: &str) -> bool {
    matches!(
        host,
        "metadata.google.internal"
            | "metadata.goog"
            | "instance-data"
            | "metadata"
    )
}

/// Strict modda ek olarak block edilen isimler.
fn is_blocked_hostname_strict(host: &str) -> bool {
    matches!(host, "localhost")
}

/// IP'nin verilen guard seviyesinde kabul edilebilir olup olmadığı.
fn is_ip_allowed(ip: &IpAddr, level: GuardLevel) -> bool {
    // Metadata IP her zaman block.
    if is_metadata_ip(ip) {
        return false;
    }
    if level == GuardLevel::UpstreamOnly {
        // Upstream modunda RFC1918/loopback OK; sadece metadata bloke.
        return true;
    }
    is_safe_ip(ip)
}

fn is_metadata_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets() == [169, 254, 169, 254],
        IpAddr::V6(v6) => {
            // fd00:ec2::254 (AWS), fd00:ec2::255
            let segs = v6.segments();
            segs[0] == 0xfd00 && segs[1] == 0xec2
        }
    }
}

/// Public, routable, non-internal IP'leri kabul eder.
fn is_safe_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return false;
            }
            // 100.64.0.0/10 — Carrier-grade NAT (RFC 6598)
            let octets = v4.octets();
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return false;
            }
            if octets[0] == 0 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let segs = v6.segments();
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            if segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xffff {
                let v4 = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                return is_safe_ip(&IpAddr::V4(v4));
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback() {
        assert!(!is_safe_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_safe_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn blocks_imds() {
        assert!(!is_safe_ip(&"169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918() {
        assert!(!is_safe_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_safe_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!is_safe_ip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_public() {
        assert!(is_safe_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_safe_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn blocks_unique_local_v6() {
        assert!(!is_safe_ip(&"fc00::1".parse().unwrap()));
        assert!(!is_safe_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn upstream_mode_allows_loopback_blocks_metadata() {
        let imds: IpAddr = "169.254.169.254".parse().unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let priv_ip: IpAddr = "10.0.0.5".parse().unwrap();
        let pub_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_ip_allowed(&imds, GuardLevel::UpstreamOnly));
        assert!(is_ip_allowed(&lo, GuardLevel::UpstreamOnly));
        assert!(is_ip_allowed(&priv_ip, GuardLevel::UpstreamOnly));
        assert!(is_ip_allowed(&pub_ip, GuardLevel::UpstreamOnly));

        assert!(!is_ip_allowed(&imds, GuardLevel::Strict));
        assert!(!is_ip_allowed(&lo, GuardLevel::Strict));
        assert!(!is_ip_allowed(&priv_ip, GuardLevel::Strict));
        assert!(is_ip_allowed(&pub_ip, GuardLevel::Strict));
    }
}
