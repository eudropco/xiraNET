/// Workflow Orchestration — A→B→C sequential/parallel step chains
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct WorkflowEngine {
    workflows: Arc<RwLock<Vec<Workflow>>>,
    client: reqwest::Client,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub status: WorkflowStatus,
    pub current_step: usize,
    pub created_at: u64,
    pub finished_at: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub url: String,
    pub method: String,
    pub body: Option<String>,
    pub timeout_secs: u64,
    pub on_failure: FailureAction,
    pub status: StepStatus,
    pub response_status: Option<u16>,
    pub duration_ms: f64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum StepStatus {
    Pending,
    Running,
    Success,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum FailureAction {
    Stop,
    Skip,
    Retry(u32),
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkflowEngine {
    pub fn new() -> Self {
        Self {
            workflows: Arc::new(RwLock::new(Vec::new())),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap(),
        }
    }

    /// Yeni workflow oluştur
    pub async fn create(&self, name: String, steps: Vec<WorkflowStep>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_secs();
        let wf = Workflow {
            id: id.clone(),
            name,
            steps,
            status: WorkflowStatus::Pending,
            current_step: 0,
            created_at: now,
            finished_at: None,
            error: None,
        };
        self.workflows.write().await.push(wf);
        id
    }

    /// Workflow'u çalıştır (sequential).
    /// Lock disiplini: HTTP `await` sırasında write-lock TUTULMAZ; her step
    /// öncesi/sonrası kısa write-lock alınır. Aksi halde tek slow upstream
    /// tüm engine'i kilitler.
    pub async fn execute(&self, workflow_id: &str) -> Result<(), String> {
        let (steps, wf_name) = {
            let mut workflows = self.workflows.write().await;
            let wf = workflows
                .iter_mut()
                .find(|w| w.id == workflow_id)
                .ok_or("Workflow not found")?;
            wf.status = WorkflowStatus::Running;
            (wf.steps.clone(), wf.name.clone())
        };

        tracing::info!("Workflow started: {} ({} steps)", wf_name, steps.len());

        // İlk başarısızlık nedeni — terminal status için saklanır.
        let mut first_failure: Option<String> = None;

        for (i, step) in steps.iter().enumerate() {
            let start = std::time::Instant::now();

            let result = match step.method.to_uppercase().as_str() {
                "POST" => {
                    let mut req = self.client.post(&step.url);
                    if let Some(ref body) = step.body {
                        req = req.body(body.clone());
                    }
                    req.send().await
                }
                "PUT" => self.client.put(&step.url).send().await,
                "DELETE" => self.client.delete(&step.url).send().await,
                _ => self.client.get(&step.url).send().await,
            };

            let duration = start.elapsed().as_secs_f64() * 1000.0;
            let mut workflows = self.workflows.write().await;
            let wf = match workflows.iter_mut().find(|w| w.id == workflow_id) {
                Some(w) => w,
                None => return Err("Workflow disappeared during execution".to_string()),
            };
            wf.current_step = i;

            match result {
                Ok(resp) => {
                    let status_code = resp.status();
                    wf.steps[i].response_status = Some(status_code.as_u16());
                    wf.steps[i].duration_ms = duration;

                    if status_code.is_success() {
                        wf.steps[i].status = StepStatus::Success;
                        tracing::info!(
                            "  Step {}: {} → {} ({:.0}ms)",
                            i + 1,
                            step.name,
                            status_code,
                            duration
                        );
                    } else {
                        let err_msg =
                            format!("Step {} failed: HTTP {}", step.name, status_code);
                        match &step.on_failure {
                            FailureAction::Stop => {
                                wf.steps[i].status = StepStatus::Failed;
                                wf.status = WorkflowStatus::Failed;
                                wf.error = Some(err_msg.clone());
                                wf.finished_at = Some(now_secs());
                                return Err(err_msg);
                            }
                            FailureAction::Skip => {
                                // Skip: bu step başarısız oldu ama akış devam ediyor.
                                // Adım statusu 'Skipped' olarak işaretlenir, neden
                                // ilk failure olarak saklanır ki workflow Failed olarak
                                // final'lensin (sessiz başarısızlık olmasın).
                                wf.steps[i].status = StepStatus::Skipped;
                                if first_failure.is_none() {
                                    first_failure = Some(err_msg);
                                }
                                continue;
                            }
                            FailureAction::Retry(max) => {
                                // Basit retry: sabit kısa backoff ile en fazla `max` deneme
                                wf.steps[i].status = StepStatus::Failed;
                                drop(workflows);
                                let attempts = (*max).max(1);
                                let mut succeeded = false;
                                let mut last_status = status_code.as_u16();
                                let mut last_duration = duration;
                                for attempt in 1..=attempts {
                                    tokio::time::sleep(std::time::Duration::from_millis(
                                        100u64 * attempt as u64,
                                    ))
                                    .await;
                                    let retry_start = std::time::Instant::now();
                                    let retry_result = match step.method.to_uppercase().as_str() {
                                        "POST" => {
                                            let mut req = self.client.post(&step.url);
                                            if let Some(ref body) = step.body {
                                                req = req.body(body.clone());
                                            }
                                            req.send().await
                                        }
                                        "PUT" => self.client.put(&step.url).send().await,
                                        "DELETE" => self.client.delete(&step.url).send().await,
                                        _ => self.client.get(&step.url).send().await,
                                    };
                                    last_duration =
                                        retry_start.elapsed().as_secs_f64() * 1000.0;
                                    if let Ok(r) = retry_result {
                                        last_status = r.status().as_u16();
                                        if r.status().is_success() {
                                            succeeded = true;
                                            break;
                                        }
                                    }
                                }
                                let mut workflows = self.workflows.write().await;
                                let wf =
                                    match workflows.iter_mut().find(|w| w.id == workflow_id) {
                                        Some(w) => w,
                                        None => {
                                            return Err(
                                                "Workflow disappeared during retry".to_string()
                                            )
                                        }
                                    };
                                wf.steps[i].duration_ms = last_duration;
                                wf.steps[i].response_status = Some(last_status);
                                if succeeded {
                                    wf.steps[i].status = StepStatus::Success;
                                } else {
                                    wf.steps[i].status = StepStatus::Failed;
                                    let final_err = format!(
                                        "Step {} failed after {} retries: last HTTP {}",
                                        step.name, attempts, last_status
                                    );
                                    wf.status = WorkflowStatus::Failed;
                                    wf.error = Some(final_err.clone());
                                    wf.finished_at = Some(now_secs());
                                    return Err(final_err);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    wf.steps[i].status = StepStatus::Failed;
                    wf.steps[i].duration_ms = duration;
                    let err_msg = format!("Step {} error: {}", step.name, e);
                    match &step.on_failure {
                        FailureAction::Skip => {
                            wf.steps[i].status = StepStatus::Skipped;
                            if first_failure.is_none() {
                                first_failure = Some(err_msg);
                            }
                            continue;
                        }
                        _ => {
                            wf.status = WorkflowStatus::Failed;
                            wf.error = Some(err_msg.clone());
                            wf.finished_at = Some(now_secs());
                            return Err(err_msg);
                        }
                    }
                }
            }
        }

        let mut workflows = self.workflows.write().await;
        if let Some(wf) = workflows.iter_mut().find(|w| w.id == workflow_id) {
            // Skip ile geçen başarısızlıklar varsa workflow Failed olarak final'lensin.
            if let Some(err) = first_failure {
                wf.status = WorkflowStatus::Failed;
                wf.error = Some(err);
            } else {
                wf.status = WorkflowStatus::Completed;
            }
            wf.finished_at = Some(now_secs());
        }

        Ok(())
    }

    pub async fn list(&self) -> Vec<Workflow> {
        self.workflows.read().await.clone()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
