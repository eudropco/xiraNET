/// Incident Management — olay oluştur, timeline tut, postmortem
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct IncidentManager {
    incidents: Arc<RwLock<Vec<Incident>>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub affected_services: Vec<String>,
    pub timeline: Vec<TimelineEntry>,
    pub created_at: u64,
    pub resolved_at: Option<u64>,
    pub postmortem: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub enum Severity {
    Critical,
    Major,
    Minor,
    Info,
}
#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum IncidentStatus {
    Investigating,
    Identified,
    Monitoring,
    Resolved,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TimelineEntry {
    pub timestamp: u64,
    pub message: String,
    pub author: String,
}

impl Default for IncidentManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentManager {
    pub fn new() -> Self {
        Self {
            incidents: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Yeni incident oluştur
    pub async fn create(&self, title: String, severity: Severity, services: Vec<String>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_secs();

        let incident = Incident {
            id: id.clone(),
            title: title.clone(),
            severity,
            status: IncidentStatus::Investigating,
            affected_services: services,
            created_at: now,
            resolved_at: None,
            postmortem: None,
            timeline: vec![TimelineEntry {
                timestamp: now,
                message: format!("Incident created: {title}"),
                author: "system".into(),
            }],
        };

        self.incidents.write().await.push(incident);
        tracing::warn!("🚨 Incident created: {} ({})", title, id);
        id
    }

    /// Timeline'a güncelleme ekle
    pub async fn add_update(&self, id: &str, message: String, author: String) -> bool {
        let now = now_secs();
        let mut incidents = self.incidents.write().await;
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == id) {
            incident.timeline.push(TimelineEntry {
                timestamp: now,
                message,
                author,
            });
            true
        } else {
            false
        }
    }

    /// Durumu güncelle
    pub async fn update_status(&self, id: &str, status: IncidentStatus) -> bool {
        let now = now_secs();
        let mut incidents = self.incidents.write().await;
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == id) {
            incident.status = status.clone();
            if status == IncidentStatus::Resolved {
                incident.resolved_at = Some(now);
            }
            incident.timeline.push(TimelineEntry {
                timestamp: now,
                message: format!("Status changed to {status:?}"),
                author: "system".into(),
            });
            true
        } else {
            false
        }
    }

    /// Postmortem ekle
    pub async fn add_postmortem(&self, id: &str, postmortem: String) -> bool {
        let mut incidents = self.incidents.write().await;
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == id) {
            incident.postmortem = Some(postmortem);
            true
        } else {
            false
        }
    }

    /// Aktif incident'lar
    pub async fn active(&self) -> Vec<Incident> {
        self.incidents
            .read()
            .await
            .iter()
            .filter(|i| i.status != IncidentStatus::Resolved)
            .cloned()
            .collect()
    }

    /// Tümü
    pub async fn list(&self) -> Vec<Incident> {
        self.incidents.read().await.clone()
    }

    /// Servis için aktif (Resolved olmayan) incident'lardan ilkinin id'si.
    /// Health flap dedup için kullanılır.
    pub async fn find_active_for_service(&self, service: &str) -> Option<String> {
        self.incidents
            .read()
            .await
            .iter()
            .find(|i| {
                i.status != IncidentStatus::Resolved
                    && i.affected_services.iter().any(|s| s == service)
            })
            .map(|i| i.id.clone())
    }

    /// Servis recovery: o servis için açık tüm incident'ları Resolved yap.
    /// Geri dönen sayı kapatılan incident sayısıdır.
    pub async fn resolve_for_service(&self, service: &str) -> usize {
        let now = now_secs();
        let mut incidents = self.incidents.write().await;
        let mut resolved = 0usize;
        for i in incidents.iter_mut() {
            if i.status != IncidentStatus::Resolved
                && i.affected_services.iter().any(|s| s == service)
            {
                i.status = IncidentStatus::Resolved;
                i.resolved_at = Some(now);
                i.timeline.push(TimelineEntry {
                    timestamp: now,
                    message: format!("Auto-resolved: {service} recovered"),
                    author: "system".into(),
                });
                resolved += 1;
            }
        }
        resolved
    }
}
