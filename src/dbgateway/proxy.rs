/// DB Connection Proxy — generic database connection management
use dashmap::DashMap;

pub struct DbProxy {
    connections: DashMap<String, DbConnection>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DbConnection {
    pub name: String,
    pub db_type: DbType,
    pub primary_url: String,
    pub replica_urls: Vec<String>,
    pub pool_size: usize,
    pub query_count: u64,
    pub error_count: u64,
    pub avg_query_ms: f64,
    pub enabled: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum DbType { PostgreSQL, MySQL, SQLite, Redis, MongoDB }

impl DbProxy {
    pub fn new() -> Self { Self { connections: DashMap::new() } }

    /// DB bağlantısı kaydet
    pub fn register(&self, name: String, db_type: DbType, primary: String, replicas: Vec<String>, pool_size: usize) {
        self.connections.insert(name.clone(), DbConnection {
            name, db_type, primary_url: primary, replica_urls: replicas,
            pool_size, query_count: 0, error_count: 0, avg_query_ms: 0.0, enabled: true,
        });
    }

    /// Bağlantı al
    pub fn get(&self, name: &str) -> Option<DbConnection> {
        self.connections.get(name).map(|c| c.value().clone())
    }

    /// Query istatistiği güncelle
    pub fn record_query(&self, name: &str, duration_ms: f64, success: bool) {
        if let Some(mut conn) = self.connections.get_mut(name) {
            conn.query_count += 1;
            if !success { conn.error_count += 1; }
            conn.avg_query_ms = (conn.avg_query_ms * (conn.query_count - 1) as f64 + duration_ms) / conn.query_count as f64;
        }
    }

    /// Tüm bağlantıları listele
    pub fn list(&self) -> Vec<DbConnection> {
        self.connections.iter().map(|c| c.value().clone()).collect()
    }

    pub fn count(&self) -> usize { self.connections.len() }
}
