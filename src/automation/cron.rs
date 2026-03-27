/// Cron Scheduler — zamanlanmış HTTP çağrıları
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CronScheduler {
    jobs: Arc<RwLock<Vec<CronJob>>>,
    client: reqwest::Client,
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
        let mut jobs = self.jobs.write().await;
        let len = jobs.len();
        jobs.retain(|j| j.id != id);
        jobs.len() < len
    }
}
