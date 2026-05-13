/// Audit Log — tamper-proof access logging for compliance
use crate::registry::storage::SqliteStorage;
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
            if let Some(ref s) = storage {
                // 1) Tabloyu oluştur
                if let Err(e) = s.execute_raw(
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
                    )",
                ) {
                    tracing::warn!(error = %e, "audit_log table create failed");
                }

                // 2) Append-only trigger'lar: UPDATE ve DELETE reddedilir.
                //    DB'ye yazma erişimi olan bir saldırgan bile audit entry'lerini
                //    silemez/değiştiremez. ALTER TABLE veya DROP TABLE hala
                //    mümkün — tam tamper-evident için WORM volume veya remote
                //    syslog ek olarak önerilir.
                if let Err(e) = s.execute_raw(
                    "CREATE TRIGGER IF NOT EXISTS audit_log_no_update
                     BEFORE UPDATE ON audit_log
                     BEGIN
                         SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE forbidden');
                     END;",
                ) {
                    tracing::warn!(error = %e, "audit_log UPDATE trigger create failed");
                }
                if let Err(e) = s.execute_raw(
                    "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
                     BEFORE DELETE ON audit_log
                     BEGIN
                         SELECT RAISE(ABORT, 'audit_log is append-only: DELETE forbidden');
                     END;",
                ) {
                    tracing::warn!(error = %e, "audit_log DELETE trigger create failed");
                }

                tracing::info!("Audit log table initialized (append-only triggers active)");
            }
        }
        Self { storage, enabled }
    }

    /// Audit entry kaydet (parameterized — SQL injection safe)
    pub fn log(&self, entry: &AuditEntry) {
        if !self.enabled {
            return;
        }

        if let Some(ref storage) = self.storage {
            if let Err(e) = storage.execute_params(
                "INSERT INTO audit_log (timestamp, ip, method, path, status, user_agent, api_key_preview, request_id, duration_ms, body_size, response_size) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                &[
                    &entry.timestamp as &dyn rusqlite::types::ToSql,
                    &entry.ip,
                    &entry.method,
                    &entry.path,
                    &(entry.status as i32),
                    &entry.user_agent,
                    &entry.api_key_preview as &dyn rusqlite::types::ToSql,
                    &entry.request_id,
                    &entry.duration_ms,
                    &(entry.body_size as i64),
                    &(entry.response_size as i64),
                ],
            ) {
                crate::metrics::DB_PERSIST_ERRORS
                    .with_label_values(&["audit_log"])
                    .inc();
                tracing::warn!(error = %e, "audit_log persist failed");
            }
        }
    }

    /// Son N audit entry'yi getir (parameterized limit — SQL injection safe)
    pub fn recent(&self, limit: usize) -> Vec<serde_json::Value> {
        if let Some(ref storage) = self.storage {
            // Defansif clamp: tek query'de aşırı sayfa yüklemeyi engelle
            let bounded = (limit as i64).clamp(1, 10_000);
            if let Ok(rows) = storage.query_params(
                "SELECT timestamp, ip, method, path, status, user_agent, request_id, duration_ms FROM audit_log ORDER BY id DESC LIMIT ?1",
                &[&bounded as &dyn rusqlite::types::ToSql],
            ) {
                return rows;
            }
        }
        vec![]
    }

    /// Audit log istatistikleri
    pub fn stats(&self) -> serde_json::Value {
        if let Some(ref storage) = self.storage {
            if let Ok(rows) = storage.query_raw(
                "SELECT COUNT(*) as total, COUNT(DISTINCT ip) as unique_ips FROM audit_log",
            ) {
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
