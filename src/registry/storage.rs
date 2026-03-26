use rusqlite::{Connection, params};
use std::sync::Mutex;
use crate::registry::models::ServiceEntry;

/// SQLite-based persistent storage for services
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        // Dizin yoksa oluştur
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let conn = Connection::open(db_path)?;

        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA foreign_keys=ON;
        ")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL UNIQUE,
                upstream TEXT NOT NULL,
                health_endpoint TEXT NOT NULL DEFAULT '/health',
                upstreams TEXT DEFAULT '[]',
                load_balance TEXT,
                version TEXT,
                validation_schema TEXT,
                registered_at TEXT NOT NULL,
                request_count INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                peer_ip TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (service_id) REFERENCES services(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                service_id TEXT,
                service_name TEXT,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            [],
        )?;

        tracing::info!("SQLite storage initialized: {}", db_path);
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Servis kaydet
    pub fn save_service(&self, entry: &ServiceEntry) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let upstreams_json = serde_json::to_string(&entry.upstreams).unwrap_or_default();

        conn.execute(
            "INSERT OR REPLACE INTO services (id, name, prefix, upstream, health_endpoint, upstreams, load_balance, version, validation_schema, registered_at, request_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                entry.id.to_string(),
                entry.name,
                entry.prefix,
                entry.upstream,
                entry.health_endpoint,
                upstreams_json,
                entry.load_balance,
                entry.version,
                entry.validation_schema,
                entry.registered_at.to_rfc3339(),
                entry.request_count as i64,
            ],
        )?;
        Ok(())
    }

    /// Tüm servisleri yükle
    pub fn load_all_services(&self) -> Result<Vec<ServiceEntry>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, prefix, upstream, health_endpoint, upstreams, load_balance, version, validation_schema, registered_at, request_count FROM services"
        )?;

        let entries = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let upstreams_str: String = row.get(5)?;
            let registered_str: String = row.get(9)?;
            let request_count: i64 = row.get(10)?;

            Ok(ServiceEntry {
                id: uuid::Uuid::parse_str(&id_str).unwrap_or_default(),
                name: row.get(1)?,
                prefix: row.get(2)?,
                upstream: row.get(3)?,
                health_endpoint: row.get(4)?,
                upstreams: serde_json::from_str(&upstreams_str).unwrap_or_default(),
                load_balance: row.get(6)?,
                version: row.get(7)?,
                validation_schema: row.get(8)?,
                status: crate::registry::models::ServiceStatus::Unknown,
                registered_at: chrono::DateTime::parse_from_rfc3339(&registered_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                last_health_check: None,
                request_count: request_count as u64,
            })
        })?;

        let mut result = Vec::new();
        for entry in entries {
            if let Ok(e) = entry {
                result.push(e);
            }
        }
        Ok(result)
    }

    /// Servis kaldır
    pub fn remove_service(&self, id: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM services WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Request log kaydet
    pub fn log_request(
        &self,
        service_id: Option<&str>,
        method: &str,
        path: &str,
        status: u16,
        duration_ms: u64,
        peer_ip: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO request_logs (service_id, method, path, status, duration_ms, peer_ip, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                service_id,
                method,
                path,
                status as i64,
                duration_ms as i64,
                peer_ip,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Event kaydet
    pub fn log_event(&self, event_type: &str, service_id: Option<&str>, service_name: Option<&str>, message: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (event_type, service_id, service_name, message, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![event_type, service_id, service_name, message, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// İstek sayacını güncelle
    pub fn update_request_count(&self, id: &str, count: u64) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE services SET request_count = ?1 WHERE id = ?2",
            params![count as i64, id],
        )?;
        Ok(())
    }

    /// Son N request log'u getir
    pub fn get_recent_logs(&self, limit: usize) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT service_id, method, path, status, duration_ms, peer_ip, timestamp
             FROM request_logs ORDER BY id DESC LIMIT ?1"
        )?;

        let logs = stmt.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "service_id": row.get::<_, Option<String>>(0)?,
                "method": row.get::<_, String>(1)?,
                "path": row.get::<_, String>(2)?,
                "status": row.get::<_, i64>(3)?,
                "duration_ms": row.get::<_, i64>(4)?,
                "peer_ip": row.get::<_, String>(5)?,
                "timestamp": row.get::<_, String>(6)?,
            }))
        })?;

        let mut result = Vec::new();
        for log in logs {
            if let Ok(l) = log {
                result.push(l);
            }
        }
        Ok(result)
    }

    /// Son N event'i getir
    pub fn get_recent_events(&self, limit: usize) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, service_id, service_name, message, timestamp
             FROM events ORDER BY id DESC LIMIT ?1"
        )?;

        let events = stmt.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "event_type": row.get::<_, String>(0)?,
                "service_id": row.get::<_, Option<String>>(1)?,
                "service_name": row.get::<_, Option<String>>(2)?,
                "message": row.get::<_, String>(3)?,
                "timestamp": row.get::<_, String>(4)?,
            }))
        })?;

        let mut result = Vec::new();
        for event in events {
            if let Ok(e) = event {
                result.push(e);
            }
        }
        Ok(result)
    }

    /// İstatistik al
    pub fn get_stats(&self) -> Result<serde_json::Value, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let total_requests: i64 = conn.query_row(
            "SELECT COUNT(*) FROM request_logs", [], |row| row.get(0)
        ).unwrap_or(0);

        let avg_duration: f64 = conn.query_row(
            "SELECT COALESCE(AVG(duration_ms), 0) FROM request_logs", [], |row| row.get(0)
        ).unwrap_or(0.0);

        let error_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM request_logs WHERE status >= 500", [], |row| row.get(0)
        ).unwrap_or(0);

        Ok(serde_json::json!({
            "total_requests_logged": total_requests,
            "avg_duration_ms": avg_duration,
            "error_count_5xx": error_count,
        }))
    }
}
