/// Cron Scheduler — zamanlanmış HTTP çağrıları (SQLite persistent)
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CronScheduler {
    jobs: Arc<RwLock<Vec<CronJob>>>,
    client: reqwest::Client,
    storage: Option<Arc<crate::registry::storage::SqliteStorage>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CronJob {
    pub id: String,
    pub name: String,
    pub schedule: CronSchedule,
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub enabled: bool,
    pub last_run: u64,
    pub next_run: u64,
    pub run_count: u64,
    pub last_status: Option<u16>,
    pub last_duration_ms: f64,
    pub failure_count: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum CronSchedule {
    EverySeconds(u64),
    EveryMinutes(u64),
    EveryHours(u64),
    Daily { hour: u32, minute: u32 },
    Custom(String), // cron expression placeholder
}

impl CronSchedule {
    pub fn interval_secs(&self) -> u64 {
        match self {
            CronSchedule::EverySeconds(s) => *s,
            CronSchedule::EveryMinutes(m) => m * 60,
            CronSchedule::EveryHours(h) => h * 3600,
            CronSchedule::Daily { .. } => 86400,
            CronSchedule::Custom(_) => 3600, // fallback
        }
    }
}

impl CronScheduler {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(Vec::new())),
            client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap(),
            storage: None,
        }
    }

    /// SQLite persistent storage ile başlat
    pub fn with_storage(storage: Arc<crate::registry::storage::SqliteStorage>) -> Self {
        let _ = storage.execute_raw(
            "CREATE TABLE IF NOT EXISTS cron_jobs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                schedule TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'GET',
                enabled INTEGER DEFAULT 1,
                last_run INTEGER DEFAULT 0,
                next_run INTEGER DEFAULT 0,
                run_count INTEGER DEFAULT 0,
                last_status INTEGER,
                failure_count INTEGER DEFAULT 0
            )"
        );

        let mut loaded_jobs = Vec::new();
        if let Ok(rows) = storage.query_raw(
            "SELECT id, name, schedule, url, method, enabled, last_run, next_run, run_count, last_status, failure_count FROM cron_jobs"
        ) {
            for row in rows {
                let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let schedule_str = row.get("schedule").and_then(|v| v.as_str()).unwrap_or("3600");
                let url = row.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let method = row.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
                let enabled = row.get("enabled").and_then(|v| v.as_u64()).unwrap_or(1) == 1;
                let last_run = row.get("last_run").and_then(|v| v.as_u64()).unwrap_or(0);
                let next_run = row.get("next_run").and_then(|v| v.as_u64()).unwrap_or(0);
                let run_count = row.get("run_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let last_status = row.get("last_status").and_then(|v| v.as_u64()).map(|v| v as u16);
                let failure_count = row.get("failure_count").and_then(|v| v.as_u64()).unwrap_or(0);

                let schedule = serde_json::from_str(schedule_str)
                    .unwrap_or(CronSchedule::EverySeconds(schedule_str.parse().unwrap_or(3600)));

                loaded_jobs.push(CronJob {
                    id, name, schedule, url, method,
                    headers: vec![], body: None,
                    enabled, last_run, next_run, run_count,
                    last_status, last_duration_ms: 0.0, failure_count,
                });
            }
            tracing::info!("Cron: loaded {} jobs from SQLite", loaded_jobs.len());
        }

        Self {
            jobs: Arc::new(RwLock::new(loaded_jobs)),
            client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap(),
            storage: Some(storage),
        }
    }

    /// SQLite'a job persist et
    fn persist_job(&self, job: &CronJob) {
        if let Some(ref storage) = self.storage {
            let schedule_json = serde_json::to_string(&job.schedule).unwrap_or_default();
            let last_status = job.last_status.map(|s| s.to_string()).unwrap_or("NULL".to_string());
            let _ = storage.execute_raw(&format!(
                "INSERT OR REPLACE INTO cron_jobs (id, name, schedule, url, method, enabled, last_run, next_run, run_count, last_status, failure_count) VALUES ('{}', '{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {})",
                job.id, job.name.replace('\'', "''"), schedule_json.replace('\'', "''"),
                job.url.replace('\'', "''"), job.method, if job.enabled { 1 } else { 0 },
                job.last_run, job.next_run, job.run_count, last_status, job.failure_count,
            ));
        }
    }

    /// İş ekle
    pub async fn add_job(&self, name: String, schedule: CronSchedule, url: String, method: String) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let job = CronJob {
            id: id.clone(), name, schedule: schedule.clone(),
            url, method, headers: vec![], body: None,
            enabled: true, last_run: 0, next_run: now + schedule.interval_secs(),
            run_count: 0, last_status: None, last_duration_ms: 0.0, failure_count: 0,
        };

        self.persist_job(&job);
        self.jobs.write().await.push(job);
        tracing::info!("Cron job added: {}", id);
        id
    }

    /// Zamanı gelen işleri çalıştır
    pub async fn tick(&self) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut jobs = self.jobs.write().await;

        for job in jobs.iter_mut() {
            if !job.enabled || now < job.next_run { continue; }

            let start = std::time::Instant::now();
            let result = match job.method.to_uppercase().as_str() {
                "POST" => self.client.post(&job.url).send().await,
                "PUT" => self.client.put(&job.url).send().await,
                "DELETE" => self.client.delete(&job.url).send().await,
                _ => self.client.get(&job.url).send().await,
            };

            job.last_run = now;
            job.run_count += 1;
            job.last_duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            job.next_run = now + job.schedule.interval_secs();

            match result {
                Ok(resp) => {
                    job.last_status = Some(resp.status().as_u16());
                    if !resp.status().is_success() { job.failure_count += 1; }
                    tracing::info!("Cron [{}] → {} ({}ms)", job.name, resp.status(), job.last_duration_ms as u64);
                }
                Err(e) => {
                    job.failure_count += 1;
                    tracing::warn!("Cron [{}] failed: {}", job.name, e);
                }
            }

            // Persist updated state after each run
            self.persist_job(job);
        }
    }

    /// Daemon başlat (background loop)
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                self.tick().await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        })
    }

    /// Tüm işleri listele
    pub async fn list_jobs(&self) -> Vec<CronJob> {
        self.jobs.read().await.clone()
    }

    /// İş kaldır
    pub async fn remove_job(&self, id: &str) -> bool {
        if let Some(ref storage) = self.storage {
            let _ = storage.execute_raw(&format!("DELETE FROM cron_jobs WHERE id = '{}'", id));
        }
        let mut jobs = self.jobs.write().await;
        let len = jobs.len();
        jobs.retain(|j| j.id != id);
        jobs.len() < len
    }
}
