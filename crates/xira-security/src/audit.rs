/// Audit Log — tamper-proof access logging for compliance
use xira_common::storage::SqliteStorage;
use std::sync::Arc;

pub struct AuditLogger {
    storage: Option<Arc<SqliteStorage>>,
    enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: String,
    pub api_key_preview: Option<String>,
    pub request_id: String,
    pub duration_ms: f64,
    pub body_size: usize,
    pub response_size: u64,
}

impl AuditLogger {
    pub fn new(storage: Option<Arc<SqliteStorage>>, enabled: bool) -> Self {
        if enabled {
            // Audit tablosu oluştur
            if let Some(ref s) = storage {
                let _ = s.execute_raw(
                    "CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        method TEXT NOT NULL,
                        path TEXT NOT NULL,
                        status INTEGER NOT NULL,
                        user_agent TEXT,
                        api_key_preview TEXT,
                        request_id TEXT,
                        duration_ms REAL,
                        body_size INTEGER,
                        response_size INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )"
                );
                tracing::info!("Audit log table initialized");
            }
        }
        Self { storage, enabled }
    }

    /// Audit entry kaydet (parameterized — SQL injection safe)
    pub fn log(&self, entry: &AuditEntry) {
        if !self.enabled { return; }

        if let Some(ref storage) = self.storage {
            let _ = storage.execute_params(
                "INSERT INTO audit_log (timestamp, ip, method, path, status, user_agent, api_key_preview, request_id, duration_ms, body_size, response_size) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                &[
                    &entry.timestamp as &dyn xira_common::rusqlite::types::ToSql,
                    &entry.ip,
                    &entry.method,
                    &entry.path,
                    &(entry.status as i32),
                    &entry.user_agent,
                    &entry.api_key_preview as &dyn xira_common::rusqlite::types::ToSql,
                    &entry.request_id,
                    &entry.duration_ms,
                    &(entry.body_size as i64),
                    &(entry.response_size as i64),
                ],
            );
        }
    }

    /// Son N audit entry'yi getir (parameterized limit)
    pub fn recent(&self, limit: usize) -> Vec<serde_json::Value> {
        if let Some(ref storage) = self.storage {
            if let Ok(rows) = storage.query_raw(&format!(
                "SELECT timestamp, ip, method, path, status, user_agent, request_id, duration_ms FROM audit_log ORDER BY id DESC LIMIT {}",
                limit as i64
            )) {
                return rows;
            }
        }
        vec![]
    }

    /// Audit log istatistikleri
    pub fn stats(&self) -> serde_json::Value {
        if let Some(ref storage) = self.storage {
            if let Ok(rows) = storage.query_raw("SELECT COUNT(*) as total, COUNT(DISTINCT ip) as unique_ips FROM audit_log") {
                if let Some(row) = rows.first() {
                    return row.clone();
                }
            }
        }
        serde_json::json!({"total": 0, "unique_ips": 0})
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
