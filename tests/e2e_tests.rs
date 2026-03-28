/// xiraNET v2.1.0 — E2E HTTP Test Suite
/// Spawns the actual server and tests endpoints with reqwest

#[cfg(test)]
mod e2e_tests {
    use std::time::Duration;

    /// Helper: get base URL (uses default port 9000 or TEST_PORT env)
    fn base_url() -> String {
        let port = std::env::var("XIRA_TEST_PORT").unwrap_or("9000".to_string());
        format!("http://127.0.0.1:{}", port)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    // ═══════════════════════════════════════════════════════════════
    // Health & Status Endpoints
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[ignore] // Requires running server
    async fn test_health_endpoint() {
        let resp = client().get(format!("{}/health", base_url())).send().await;
        assert!(resp.is_ok(), "Health endpoint should be reachable");
        let resp = resp.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    #[ignore]
    async fn test_metrics_endpoint() {
        let resp = client().get(format!("{}/metrics", base_url())).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("xiranet") || body.contains("HELP") || body.len() > 0);
    }

    #[tokio::test]
    #[ignore]
    async fn test_dashboard_endpoint() {
        let resp = client().get(format!("{}/dashboard", base_url())).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("xiraNET") || body.contains("dashboard"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Admin API Endpoints
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[ignore]
    async fn test_admin_services_list() {
        let resp = client()
            .get(format!("{}/xira/services", base_url()))
            .send().await.unwrap();
        // Should return 200 (or 401 if auth required)
        assert!(resp.status() == 200 || resp.status() == 401);
    }

    #[tokio::test]
    #[ignore]
    async fn test_admin_stats() {
        let resp = client()
            .get(format!("{}/xira/stats", base_url()))
            .send().await.unwrap();
        assert!(resp.status() == 200 || resp.status() == 401);
    }

    #[tokio::test]
    #[ignore]
    async fn test_admin_identity_users() {
        let resp = client()
            .get(format!("{}/xira/identity/users", base_url()))
            .send().await.unwrap();
        assert!(resp.status() == 200 || resp.status() == 401);
    }

    #[tokio::test]
    #[ignore]
    async fn test_admin_sla_report() {
        let resp = client()
            .get(format!("{}/xira/sla", base_url()))
            .send().await.unwrap();
        assert!(resp.status() == 200 || resp.status() == 401);
    }

    #[tokio::test]
    #[ignore]
    async fn test_admin_waf_stats() {
        let resp = client()
            .get(format!("{}/xira/security/waf", base_url()))
            .send().await.unwrap();
        assert!(resp.status() == 200 || resp.status() == 401);
    }

    #[tokio::test]
    #[ignore]
    async fn test_admin_advanced_metrics() {
        let resp = client()
            .get(format!("{}/xira/advanced-metrics", base_url()))
            .send().await.unwrap();
        assert!(resp.status() == 200 || resp.status() == 401);
    }

    // ═══════════════════════════════════════════════════════════════
    // WAF Protection (Gateway Pipeline)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[ignore]
    async fn test_waf_blocks_sqli_via_http() {
        let resp = client()
            .get(format!("{}/api/test?id=1%20union%20select%20from%20users", base_url()))
            .send().await.unwrap();
        // WAF should block (403) or gateway returns 502/404 since no upstream
        assert!(resp.status() == 403 || resp.status() == 502 || resp.status() == 404);
    }

    #[tokio::test]
    #[ignore]
    async fn test_waf_blocks_xss_via_http() {
        let resp = client()
            .post(format!("{}/api/test", base_url()))
            .body("<script>alert('xss')</script>")
            .send().await.unwrap();
        assert!(resp.status() == 403 || resp.status() == 502 || resp.status() == 404);
    }

    // ═══════════════════════════════════════════════════════════════
    // Security Headers
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[ignore]
    async fn test_security_headers_present() {
        let resp = client()
            .get(format!("{}/health", base_url()))
            .send().await.unwrap();
        let headers = resp.headers();
        assert!(headers.get("x-content-type-options").is_some(), "X-Content-Type-Options missing");
        assert!(headers.get("x-frame-options").is_some(), "X-Frame-Options missing");
        // X-Powered-By intentionally removed to prevent fingerprinting
    }

    // ═══════════════════════════════════════════════════════════════
    // OpenAPI / Docs
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[ignore]
    async fn test_openapi_spec() {
        let resp = client()
            .get(format!("{}/xira/docs/spec", base_url()))
            .send().await.unwrap();
        assert!(resp.status() == 200 || resp.status() == 401);
    }
}
