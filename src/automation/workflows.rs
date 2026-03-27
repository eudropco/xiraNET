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
pub enum WorkflowStatus { Pending, Running, Completed, Failed, Cancelled }

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum StepStatus { Pending, Running, Success, Failed, Skipped }

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum FailureAction { Stop, Skip, Retry(u32) }

impl WorkflowEngine {
    pub fn new() -> Self {
        Self {
            workflows: Arc::new(RwLock::new(Vec::new())),
            client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap(),
        }
    }

    /// Yeni workflow oluştur
    pub async fn create(&self, name: String, steps: Vec<WorkflowStep>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let wf = Workflow {
            id: id.clone(), name, steps, status: WorkflowStatus::Pending,
            current_step: 0, created_at: now, finished_at: None, error: None,
        };
        self.workflows.write().await.push(wf);
        id
    }

    /// Workflow'u çalıştır (sequential)
    pub async fn execute(&self, workflow_id: &str) -> Result<(), String> {
        let mut workflows = self.workflows.write().await;
        let wf = workflows.iter_mut().find(|w| w.id == workflow_id)
            .ok_or("Workflow not found")?;

        wf.status = WorkflowStatus::Running;
        let steps = wf.steps.clone();
        let wf_name = wf.name.clone();
        drop(workflows);

        tracing::info!("Workflow started: {} ({} steps)", wf_name, steps.len());

        for (i, step) in steps.iter().enumerate() {
            let start = std::time::Instant::now();

            let result = match step.method.to_uppercase().as_str() {
                "POST" => {
                    let mut req = self.client.post(&step.url);
                    if let Some(ref body) = step.body { req = req.body(body.clone()); }
                    req.send().await
                },
                "PUT" => self.client.put(&step.url).send().await,
                "DELETE" => self.client.delete(&step.url).send().await,
                _ => self.client.get(&step.url).send().await,
            };

            let duration = start.elapsed().as_secs_f64() * 1000.0;
            let mut workflows = self.workflows.write().await;
            let wf = workflows.iter_mut().find(|w| w.id == workflow_id).unwrap();
            wf.current_step = i;

            match result {
                Ok(resp) => {
                    wf.steps[i].response_status = Some(resp.status().as_u16());
                    wf.steps[i].duration_ms = duration;

                    if resp.status().is_success() {
                        wf.steps[i].status = StepStatus::Success;
                        tracing::info!("  Step {}: {} → {} ({:.0}ms)", i + 1, step.name, resp.status(), duration);
                    } else {
                        wf.steps[i].status = StepStatus::Failed;
                        match &step.on_failure {
                            FailureAction::Stop => {
                                wf.status = WorkflowStatus::Failed;
                                wf.error = Some(format!("Step {} failed: HTTP {}", step.name, resp.status()));
                                return Err(wf.error.clone().unwrap());
                            },
                            FailureAction::Skip => { wf.steps[i].status = StepStatus::Skipped; },
                            FailureAction::Retry(_) => { /* retry logic simplified */ },
                        }
                    }
                },
                Err(e) => {
                    wf.steps[i].status = StepStatus::Failed;
                    wf.steps[i].duration_ms = duration;
                    wf.status = WorkflowStatus::Failed;
                    wf.error = Some(format!("Step {} error: {}", step.name, e));
                    return Err(wf.error.clone().unwrap());
                }
            }
        }

        let mut workflows = self.workflows.write().await;
        if let Some(wf) = workflows.iter_mut().find(|w| w.id == workflow_id) {
            wf.status = WorkflowStatus::Completed;
            wf.finished_at = Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
        }

        Ok(())
    }

    pub async fn list(&self) -> Vec<Workflow> { self.workflows.read().await.clone() }
}
