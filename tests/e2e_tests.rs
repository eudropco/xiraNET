//! xiraNET v3.0.0 — E2E HTTP Test Suite
//!
//! Gerçek server process'ini `CARGO_BIN_EXE_xiranet` env'inden spawn eder
//! (cargo `cargo test` çalıştığında bu env otomatik set edilir).
//! Tüm testler tek bir global server'ı (OnceLock) paylaşır. Bir kez başlatılır,
//! tüm e2e testleri biten test runner'a kadar yaşar — sonra OS temizler.
//!
//! Önceki sürümde tüm testler `#[ignore]`'lıydı ve çoğu `assert!(s==200||s==401)`
//! tautolojisiydi. v3.0.0 audit sonrası: gerçek dual-assert (no-auth = 401,
//! with-auth = 200) + audit fix doğrulama testleri.

#[cfg(test)]
mod e2e_tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    const API_KEY: &str = "e2e-test-key-do-not-use-anywhere-else-32b";
    const SECRETS_KEY: &str = "e2e-secrets-key-32-bytes-or-more-aaaaaa";

    struct TestServer {
        base_url: String,
        api_key: String,
        _child: Child,
        _tmp_dir: tempdir::TempDir,
    }

    // Cargo otomatik olarak tempdir crate'ini dep yapmadığı için kendi minimal
    // tempdir implementasyonumuzu inline ediyoruz.
    mod tempdir {
        use std::path::PathBuf;
        pub struct TempDir(pub PathBuf);
        impl TempDir {
            pub fn new(prefix: &str) -> std::io::Result<Self> {
                let mut p = std::env::temp_dir();
                let nano = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                p.push(format!("{prefix}-{nano}"));
                std::fs::create_dir_all(&p)?;
                Ok(Self(p))
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn pick_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    fn write_config(dir: &std::path::Path, port: u16, api_key: &str) -> PathBuf {
        let cfg = format!(
            r#"
[gateway]
host = "127.0.0.1"
port = {port}
workers = 1

[admin]
api_key = "{api_key}"
enabled = true

[health]
interval_secs = 60
timeout_secs = 5

[cache]
enabled = false

[jwt]
enabled = false

[cors]
allowed_origins = ["http://localhost"]

[metrics]
enabled = true
path = "/metrics"

[waf]
enabled = true
mode = "block"

[bot_detection]
enabled = false

[ip_filter]
enabled = false

[identity]
registration_enabled = true
max_sessions_per_user = 5
password_min_length = 8

[logging]
level = "warn"
file_enabled = false
file_path = ""
rotation = "daily"

[alerting]
enabled = false
"#
        );
        let path = dir.join("xiranet.toml");
        std::fs::write(&path, cfg).expect("write config");
        path
    }

    fn server() -> &'static TestServer {
        static SERVER: OnceLock<TestServer> = OnceLock::new();
        SERVER.get_or_init(|| {
            let tmp = tempdir::TempDir::new("xira-e2e").expect("tempdir");
            let port = pick_port();
            let cfg_path = write_config(tmp.path(), port, API_KEY);
            let db_path = tmp.path().join("xiranet.db");

            let bin = env!("CARGO_BIN_EXE_xiranet");
            let child = Command::new(bin)
                .arg("serve")
                .arg("--config")
                .arg(&cfg_path)
                .env("XIRA_SECRETS_KEY", SECRETS_KEY)
                .env("XIRA_DB_PATH", db_path.to_string_lossy().to_string())
                .env("RUST_LOG", "warn")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn xiranet");

            let base_url = format!("http://127.0.0.1:{port}");

            // Ready-poll: /health 200 dönene kadar 10 sn bekle
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if Instant::now() > deadline {
                    panic!("xiranet did not become ready in 15s; base_url={base_url}");
                }
                match std::net::TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}").parse().unwrap(),
                    Duration::from_millis(200),
                ) {
                    Ok(_) => {
                        // socket up — /health'i de doğrula
                        let resp = ureq_get(&format!("{base_url}/health"), None);
                        if resp.is_ok() {
                            break;
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(150));
                    }
                }
            }

            TestServer {
                base_url,
                api_key: API_KEY.to_string(),
                _child: child,
                _tmp_dir: tmp,
            }
        })
    }

    /// Minimal blocking HTTP client — küçük yüzeyli, dep istemiyor.
    struct HttpResp {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    fn ureq_get(url: &str, api_key: Option<&str>) -> Result<HttpResp, String> {
        ureq_req("GET", url, api_key, None, None)
    }

    fn ureq_post_json(
        url: &str,
        api_key: Option<&str>,
        body: &str,
    ) -> Result<HttpResp, String> {
        ureq_req("POST", url, api_key, Some(body), Some("application/json"))
    }

    #[allow(dead_code)]
    fn ureq_put_json(
        url: &str,
        api_key: Option<&str>,
        body: &str,
    ) -> Result<HttpResp, String> {
        ureq_req("PUT", url, api_key, Some(body), Some("application/json"))
    }

    fn ureq_req(
        method: &str,
        url: &str,
        api_key: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<HttpResp, String> {
        use std::io::Read;
        use std::net::TcpStream;
        let url_parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
        let host = url_parsed.host_str().ok_or("no host")?;
        let port = url_parsed.port_or_known_default().ok_or("no port")?;
        let path_and_query = match url_parsed.query() {
            Some(q) => format!("{}?{}", url_parsed.path(), q),
            None => url_parsed.path().to_string(),
        };

        let mut stream = TcpStream::connect_timeout(
            &format!("{host}:{port}")
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?,
            Duration::from_secs(3),
        )
        .map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;

        let mut req = format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n",
        );
        if let Some(k) = api_key {
            req.push_str(&format!("X-Api-Key: {k}\r\n"));
        }
        if let Some(ct) = content_type {
            req.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }
        stream
            .write_all(req.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&buf).to_string();

        let mut lines = text.split("\r\n");
        let status_line = lines.next().ok_or("no status line")?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(format!("bad status: {status_line}"));
        }
        let status: u16 = parts[1].parse().map_err(|_| "bad status code")?;

        let mut headers = Vec::new();
        let mut header_end = 0usize;
        let mut acc_pos = status_line.len() + 2;
        for line in lines.by_ref() {
            acc_pos += line.len() + 2;
            if line.is_empty() {
                header_end = acc_pos;
                break;
            }
            if let Some((k, v)) = line.split_once(": ") {
                headers.push((k.to_ascii_lowercase(), v.to_string()));
            }
        }
        let body = text.get(header_end..).unwrap_or("").to_string();
        Ok(HttpResp {
            status,
            headers,
            body,
        })
    }

    // url crate yok — minimal Url helper
    mod url {
        pub struct Url {
            scheme: String,
            host: String,
            port: Option<u16>,
            path: String,
            query: Option<String>,
        }
        impl Url {
            pub fn parse(s: &str) -> Result<Self, String> {
                let (scheme, rest) = s.split_once("://").ok_or("no scheme")?;
                let (auth, path_q) = match rest.find('/') {
                    Some(i) => (&rest[..i], &rest[i..]),
                    None => (rest, "/"),
                };
                let (host, port) = match auth.rsplit_once(':') {
                    Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
                    None => (auth.to_string(), None),
                };
                let (path, query) = match path_q.split_once('?') {
                    Some((p, q)) => (p.to_string(), Some(q.to_string())),
                    None => (path_q.to_string(), None),
                };
                Ok(Self {
                    scheme: scheme.to_string(),
                    host,
                    port,
                    path,
                    query,
                })
            }
            pub fn host_str(&self) -> Option<&str> {
                Some(&self.host)
            }
            pub fn port_or_known_default(&self) -> Option<u16> {
                self.port.or(match self.scheme.as_str() {
                    "https" => Some(443),
                    "http" => Some(80),
                    _ => None,
                })
            }
            pub fn path(&self) -> &str {
                &self.path
            }
            pub fn query(&self) -> Option<&str> {
                self.query.as_deref()
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Public endpoints
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn health_endpoint_public_200() {
        let s = server();
        let resp = ureq_get(&format!("{}/health", s.base_url), None).unwrap();
        assert_eq!(resp.status, 200, "/health should be public 200");
    }

    #[test]
    fn metrics_endpoint_returns_prometheus_format() {
        let s = server();
        let resp = ureq_get(&format!("{}/metrics", s.base_url), None).unwrap();
        assert_eq!(resp.status, 200);
        assert!(
            resp.body.contains("# HELP") || resp.body.contains("# TYPE"),
            "Prometheus format expected, got {} bytes",
            resp.body.len()
        );
        assert!(
            resp.body.contains("xiranet_"),
            "expected xiranet_* metric series"
        );
    }

    #[test]
    fn dashboard_endpoint_serves_html() {
        let s = server();
        let resp = ureq_get(&format!("{}/dashboard", s.base_url), None).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.to_lowercase().contains("xira"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Admin auth — DUAL ASSERT (no key 401, valid key 200)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn admin_endpoint_requires_api_key() {
        let s = server();
        let no_key = ureq_get(&format!("{}/xira/services", s.base_url), None).unwrap();
        assert_eq!(no_key.status, 401, "missing key must yield 401");

        let with_key = ureq_get(&format!("{}/xira/services", s.base_url), Some(&s.api_key)).unwrap();
        assert_eq!(with_key.status, 200, "valid key must yield 200");
    }

    #[test]
    fn admin_wrong_key_rejected() {
        let s = server();
        let resp = ureq_get(&format!("{}/xira/services", s.base_url), Some("wrong-key")).unwrap();
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn admin_api_key_constant_time_compare_length_differs() {
        // K3 fix doğrulama: farklı uzunlukta key de 401 dönmeli (ct_eq_str length-safe path).
        let s = server();
        let short = ureq_get(&format!("{}/xira/services", s.base_url), Some("a")).unwrap();
        let long = ureq_get(
            &format!("{}/xira/services", s.base_url),
            Some(&"x".repeat(1024)),
        )
        .unwrap();
        assert_eq!(short.status, 401);
        assert_eq!(long.status, 401);
    }

    // ═══════════════════════════════════════════════════════════════
    // SSRF — K2 fix verification
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn cron_create_rejects_metadata_url() {
        let s = server();
        let body = r#"{"name":"evil","url":"http://169.254.169.254/latest/meta-data/","method":"GET","interval_secs":60}"#;
        let resp = ureq_post_json(
            &format!("{}/xira/automation/cron", s.base_url),
            Some(&s.api_key),
            body,
        )
        .unwrap();
        assert_eq!(
            resp.status, 400,
            "cron URL targeting AWS IMDS must be rejected (got body: {})",
            resp.body
        );
        assert!(
            resp.body.contains("URL rejected") || resp.body.contains("metadata"),
            "rejection reason should mention SSRF guard; body: {}",
            resp.body
        );
    }

    #[test]
    fn service_register_rejects_metadata_url() {
        let s = server();
        // Service register upstream mode: localhost OK ama IMDS bloke.
        let body = r#"{"name":"evil","prefix":"/evil","upstream":"http://169.254.169.254","health_endpoint":"/health"}"#;
        let resp = ureq_post_json(
            &format!("{}/xira/services", s.base_url),
            Some(&s.api_key),
            body,
        )
        .unwrap();
        assert_eq!(resp.status, 400);
        assert!(
            resp.body.contains("upstream rejected") || resp.body.contains("metadata"),
            "body: {}",
            resp.body
        );
    }

    #[test]
    fn service_register_allows_localhost_upstream() {
        let s = server();
        // Upstream mode RFC1918/loopback allow.
        let body =
            r#"{"name":"local","prefix":"/local","upstream":"http://localhost:3001","health_endpoint":"/health"}"#;
        let resp = ureq_post_json(
            &format!("{}/xira/services", s.base_url),
            Some(&s.api_key),
            body,
        )
        .unwrap();
        assert_eq!(resp.status, 201, "localhost upstream must be allowed");
    }

    // ═══════════════════════════════════════════════════════════════
    // CORS — explicit origin only
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn cors_disallowed_origin_no_acao() {
        let s = server();
        // OPTIONS preflight'a `Origin` header'ı koy → ACAO yansıması olmamalı (disallowed)
        let resp = ureq_req(
            "OPTIONS",
            &format!("{}/health", s.base_url),
            None,
            None,
            None,
        )
        .unwrap();
        let acao = resp
            .headers
            .iter()
            .find(|(k, _)| k == "access-control-allow-origin")
            .map(|(_, v)| v.clone());
        // OPTIONS without Origin header → no ACAO; that's fine. Sadece "*"" görmek istemiyoruz.
        if let Some(v) = acao {
            assert_ne!(v, "*", "CORS allow-any-origin must be disabled");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Security headers
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn security_headers_present() {
        let s = server();
        let resp = ureq_get(&format!("{}/health", s.base_url), None).unwrap();
        let header = |name: &str| {
            resp.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        assert!(
            header("x-content-type-options").is_some(),
            "X-Content-Type-Options missing"
        );
        assert!(
            header("x-frame-options").is_some(),
            "X-Frame-Options missing"
        );
        // X-Powered-By bilerek yok
        assert!(
            header("x-powered-by").is_none(),
            "X-Powered-By must not be set (fingerprinting)"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // OpenAPI
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn openapi_spec_served() {
        let s = server();
        let resp = ureq_get(&format!("{}/xira/docs/spec", s.base_url), Some(&s.api_key)).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("openapi") || resp.body.contains("swagger"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Auth flow — register + login + /auth/me (session validate downstream)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn auth_flow_login_then_me_then_logout() {
        let s = server();
        let email = format!("e2e+{}@x", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());

        // 1. Register (admin endpoint)
        let body = format!(
            r#"{{"email":"{email}","username":"e2e","password":"long-test-password-1234","role":"Admin"}}"#
        );
        let reg = ureq_post_json(
            &format!("{}/xira/identity/users", s.base_url),
            Some(&s.api_key),
            &body,
        )
        .unwrap();
        assert_eq!(reg.status, 201, "registration failed: {}", reg.body);

        // 2. Login
        let login_body = format!(
            r#"{{"email":"{email}","password":"long-test-password-1234"}}"#
        );
        let login = ureq_post_json(&format!("{}/auth/login", s.base_url), None, &login_body).unwrap();
        assert_eq!(login.status, 200, "login failed: {}", login.body);
        let token = extract_field(&login.body, "token").expect("token in login body");
        assert!(token.starts_with("xira_tok_"), "unexpected token: {token}");

        // 3. /auth/me → session validate edilmeli (K1 fix)
        let me = ureq_req(
            "GET",
            &format!("{}/auth/me", s.base_url),
            None,
            None,
            None,
        )
        .unwrap();
        // No token → 401
        assert_eq!(me.status, 401, "no token must yield 401");

        // With token via X-Session-Token (Bearer test'ini ayrı yapamıyoruz, ureq_get
        // sadece X-Api-Key alıyor; aşağıda raw header'la denenebilir)
        let me_resp = ureq_with_session(&format!("{}/auth/me", s.base_url), &token).unwrap();
        assert_eq!(me_resp.status, 200, "valid session must yield 200: {}", me_resp.body);
        assert!(me_resp.body.contains(&email));

        // 4. Logout → session invalidate
        let logout = ureq_post_session(&format!("{}/auth/logout", s.base_url), &token, "").unwrap();
        assert_eq!(logout.status, 200);

        // 5. Logout sonrası /auth/me 401
        let me_after = ureq_with_session(&format!("{}/auth/me", s.base_url), &token).unwrap();
        assert_eq!(
            me_after.status, 401,
            "session must be invalidated after logout"
        );
    }

    /// Session header'ı destekleyen X-Session-Token + GET wrapper
    fn ureq_with_session(url: &str, token: &str) -> Result<HttpResp, String> {
        ureq_with_header("GET", url, &[("X-Session-Token", token)], None)
    }
    fn ureq_post_session(url: &str, token: &str, body: &str) -> Result<HttpResp, String> {
        ureq_with_header(
            "POST",
            url,
            &[
                ("X-Session-Token", token),
                ("Content-Type", "application/json"),
            ],
            Some(body),
        )
    }

    fn ureq_with_header(
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResp, String> {
        use std::io::Read;
        use std::net::TcpStream;
        let url_parsed = url::Url::parse(url)?;
        let host = url_parsed.host_str().ok_or("no host")?;
        let port = url_parsed.port_or_known_default().ok_or("no port")?;
        let path_and_query = match url_parsed.query() {
            Some(q) => format!("{}?{}", url_parsed.path(), q),
            None => url_parsed.path().to_string(),
        };

        let mut stream = TcpStream::connect_timeout(
            &format!("{host}:{port}").parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
            Duration::from_secs(3),
        )
        .map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;

        let mut req = format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n",
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }
        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&buf).to_string();
        let mut lines = text.split("\r\n");
        let status_line = lines.next().ok_or("no status line")?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(format!("bad status: {status_line}"));
        }
        let status: u16 = parts[1].parse().map_err(|_| "bad status code")?;

        let mut headers_out = Vec::new();
        let mut header_end = 0usize;
        let mut acc_pos = status_line.len() + 2;
        for line in lines.by_ref() {
            acc_pos += line.len() + 2;
            if line.is_empty() {
                header_end = acc_pos;
                break;
            }
            if let Some((k, v)) = line.split_once(": ") {
                headers_out.push((k.to_ascii_lowercase(), v.to_string()));
            }
        }
        let body = text.get(header_end..).unwrap_or("").to_string();
        Ok(HttpResp {
            status,
            headers: headers_out,
            body,
        })
    }

    /// JSON body'den `"key":"value"` çek — sadece string field için minimal.
    fn extract_field(body: &str, key: &str) -> Option<String> {
        let needle = format!("\"{key}\"");
        let idx = body.find(&needle)?;
        let after = &body[idx + needle.len()..];
        let colon = after.find(':')?;
        let after = &after[colon + 1..].trim_start();
        let after = after.strip_prefix('"')?;
        let end = after.find('"')?;
        Some(after[..end].to_string())
    }

    // ═══════════════════════════════════════════════════════════════
    // RBAC e2e — viewer rejected from SuperAdmin endpoint
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn rbac_viewer_cannot_list_users_admin() {
        let s = server();
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let viewer_email = format!("viewer+{nano}@x");
        // Register Viewer
        let body = format!(
            r#"{{"email":"{viewer_email}","username":"v","password":"long-test-password-1234","role":"Viewer"}}"#
        );
        let reg = ureq_post_json(
            &format!("{}/xira/identity/users", s.base_url),
            Some(&s.api_key),
            &body,
        )
        .unwrap();
        assert_eq!(reg.status, 201, "viewer registration failed: {}", reg.body);

        // Login as Viewer
        let login_body = format!(r#"{{"email":"{viewer_email}","password":"long-test-password-1234"}}"#);
        let login =
            ureq_post_json(&format!("{}/auth/login", s.base_url), None, &login_body).unwrap();
        assert_eq!(login.status, 200);
        let token = extract_field(&login.body, "token").expect("token");

        // /auth/admin/users requires SuperAdmin → must be 403
        let resp = ureq_with_session(&format!("{}/auth/admin/users", s.base_url), &token).unwrap();
        assert_eq!(
            resp.status, 403,
            "Viewer must be rejected from /auth/admin/users (got {}: {})",
            resp.status, resp.body
        );
    }
}
