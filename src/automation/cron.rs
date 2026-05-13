/// Cron Scheduler — zamanlanmış HTTP çağrıları (SQLite persistent)
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub struct CronScheduler {
    jobs: Arc<RwLock<Vec<CronJob>>>,
    client: reqwest::Client,
    storage: Option<Arc<crate::registry::storage::SqliteStorage>>,
    /// Aynı job'un overlapping run koruması: çalışmakta olan job id'leri.
    in_flight: Arc<dashmap::DashSet<String>>,
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl CronSchedule {
    pub fn interval_secs(&self) -> u64 {
        match self {
            CronSchedule::EverySeconds(s) => (*s).max(1),
            CronSchedule::EveryMinutes(m) => m.max(&1) * 60,
            CronSchedule::EveryHours(h) => h.max(&1) * 3600,
            CronSchedule::Daily { .. } => 86400,
            CronSchedule::Custom(_) => 3600, // fallback
        }
    }

    /// Bir sonraki çalışma zamanı (UTC saniye). Daily için bugün/yarının
    /// HH:MM'sine senkronlanır; diğerleri için `now + interval`.
    pub fn next_after(&self, now: u64) -> u64 {
        match self {
            CronSchedule::Daily { hour, minute } => {
                let secs_in_day = 86400u64;
                let day_start = now - (now % secs_in_day);
                let target_today =
                    day_start + (*hour as u64) * 3600 + (*minute as u64) * 60;
                if target_today > now {
                    target_today
                } else {
                    target_today + secs_in_day
                }
            }
            other => now.saturating_add(other.interval_secs()),
        }
    }
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl CronScheduler {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(Vec::new())),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            storage: None,
            in_flight: Arc::new(dashmap::DashSet::new()),
        }
    }

    /// SQLite persistent storage ile başlat
    pub fn with_storage(storage: Arc<crate::registry::storage::SqliteStorage>) -> Self {
        if let Err(e) = storage.execute_raw(
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
            )",
        ) {
            tracing::warn!(error = %e, "cron_jobs schema create failed");
        }

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
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            storage: Some(storage),
            in_flight: Arc::new(dashmap::DashSet::new()),
        }
    }

    /// SQLite'a job persist et (parameterized — SQL injection safe)
    fn persist_job(&self, job: &CronJob) {
        if let Some(ref storage) = self.storage {
            let schedule_json = serde_json::to_string(&job.schedule).unwrap_or_default();
            if let Err(e) = storage.execute_params(
                "INSERT OR REPLACE INTO cron_jobs (id, name, schedule, url, method, enabled, last_run, next_run, run_count, last_status, failure_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                &[
                    &job.id as &dyn rusqlite::types::ToSql,
                    &job.name,
                    &schedule_json,
                    &job.url,
                    &job.method,
                    &(if job.enabled { 1i64 } else { 0 }),
                    &(job.last_run as i64),
                    &(job.next_run as i64),
                    &(job.run_count as i64),
                    &job.last_status.map(|s| s as i64) as &dyn rusqlite::types::ToSql,
                    &(job.failure_count as i64),
                ],
            ) {
                crate::metrics::DB_PERSIST_ERRORS
                    .with_label_values(&["cron_jobs"])
                    .inc();
                tracing::warn!(error = %e, job_id = %job.id, "persist_job failed");
            }
        }
    }

    /// İş ekle. SSRF kontrolü trust boundary'de (admin handler) yapılır;
    /// burada URL doğrulaması yoktur, çağıran tarafın guard çalıştırması beklenir.
    pub async fn add_job(
        &self,
        name: String,
        schedule: CronSchedule,
        url: String,
        method: String,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_secs();

        let job = CronJob {
            id: id.clone(),
            name,
            schedule: schedule.clone(),
            url,
            method,
            headers: vec![],
            body: None,
            enabled: true,
            last_run: 0,
            next_run: schedule.next_after(now),
            run_count: 0,
            last_status: None,
            last_duration_ms: 0.0,
            failure_count: 0,
        };

        self.persist_job(&job);
        self.jobs.write().await.push(job);
        tracing::info!("Cron job added: {}", id);
        id
    }

    /// Zamanı gelen işleri çalıştır.
    /// Strateji:
    /// 1. Brief write-lock altında due-job snapshot al + next_run'ı ileri çek
    ///    (re-entrancy ve overlapping-run koruması için).
    /// 2. Lock'u DROP et.
    /// 3. Job'ları paralel çalıştır.
    /// 4. Brief write-lock altında stats'i geri yaz + persist et.
    pub async fn tick(&self) {
        let now = now_secs();

        // 1. Due snapshot + next_run advance
        let due: Vec<(String, String, String)> = {
            let mut jobs = self.jobs.write().await;
            let mut due = Vec::new();
            for job in jobs.iter_mut() {
                if !job.enabled || now < job.next_run {
                    continue;
                }
                if !self.in_flight.insert(job.id.clone()) {
                    // Aynı job zaten çalışıyor — bu tick'i atla
                    continue;
                }
                // next_run'ı ileri çek ki bu tick içinde tekrar tetiklenmesin
                job.next_run = job.schedule.next_after(now);
                due.push((job.id.clone(), job.url.clone(), job.method.clone()));
            }
            due
        };

        if due.is_empty() {
            return;
        }

        // 2. Job'ları concurrent çalıştır
        let mut handles = Vec::with_capacity(due.len());
        for (id, url, method) in due {
            let client = self.client.clone();
            let in_flight = self.in_flight.clone();
            handles.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                let result = match method.to_uppercase().as_str() {
                    "POST" => client.post(&url).send().await,
                    "PUT" => client.put(&url).send().await,
                    "DELETE" => client.delete(&url).send().await,
                    _ => client.get(&url).send().await,
                };
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
                let outcome = match result {
                    Ok(resp) => {
                        let status = resp.status();
                        Ok((status.as_u16(), status.is_success()))
                    }
                    Err(e) => Err(e.to_string()),
                };
                in_flight.remove(&id);
                (id, duration_ms, outcome)
            }));
        }

        // 3. Sonuçları topla, jobs vector'una uygula
        for h in handles {
            if let Ok((id, duration_ms, outcome)) = h.await {
                let mut jobs = self.jobs.write().await;
                if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
                    job.last_run = now;
                    job.run_count = job.run_count.saturating_add(1);
                    job.last_duration_ms = duration_ms;
                    match &outcome {
                        Ok((status, success)) => {
                            job.last_status = Some(*status);
                            if !success {
                                job.failure_count = job.failure_count.saturating_add(1);
                            }
                            tracing::info!(
                                "Cron [{}] → {} ({}ms)",
                                job.name,
                                status,
                                job.last_duration_ms as u64
                            );
                        }
                        Err(e) => {
                            job.failure_count = job.failure_count.saturating_add(1);
                            tracing::warn!("Cron [{}] failed: {}", job.name, e);
                        }
                    }
                    let snap = job.clone();
                    drop(jobs);
                    self.persist_job(&snap);
                }
            }
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

    /// İş kaldır (parameterized — SQL injection safe)
    pub async fn remove_job(&self, id: &str) -> bool {
        if let Some(ref storage) = self.storage {
            let _ = storage.execute_params(
                "DELETE FROM cron_jobs WHERE id = ?1",
                &[&id as &dyn rusqlite::types::ToSql],
            );
        }
        let mut jobs = self.jobs.write().await;
        let len = jobs.len();
        jobs.retain(|j| j.id != id);
        self.in_flight.remove(id);
        jobs.len() < len
    }
}
