/// Release Engine — blue/green switching, auto-rollback on error spike
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ReleaseManager {
    releases: DashMap<String, Release>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Release {
    pub id: String,
    pub service: String,
    pub strategy: ReleaseStrategy,
    pub status: ReleaseStatus,
    pub blue_upstream: String,
    pub green_upstream: String,
    pub active_color: String, // "blue" | "green"
    pub error_threshold: f64, // auto-rollback threshold
    pub created_at: u64,
    pub switched_at: Option<u64>,
    pub rollback_count: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub enum ReleaseStrategy {
    BlueGreen,
    Canary { percentage: u32 },
}
#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum ReleaseStatus {
    Active,
    RolledBack,
    Completed,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flip_color(c: &str) -> String {
    if c == "blue" {
        "green".to_string()
    } else {
        "blue".to_string()
    }
}

impl Default for ReleaseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReleaseManager {
    pub fn new() -> Self {
        Self {
            releases: DashMap::new(),
        }
    }

    /// Yeni release oluştur
    pub fn create(
        &self,
        service: String,
        blue: String,
        green: String,
        strategy: ReleaseStrategy,
        error_threshold: f64,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_secs();
        self.releases.insert(
            id.clone(),
            Release {
                id: id.clone(),
                service,
                strategy,
                status: ReleaseStatus::Active,
                blue_upstream: blue,
                green_upstream: green,
                active_color: "blue".into(),
                error_threshold,
                created_at: now,
                switched_at: None,
                rollback_count: 0,
            },
        );
        id
    }

    /// Blue ↔ Green switch — sadece Active iken çalışır (idempotent).
    pub fn switch(&self, release_id: &str) -> Option<String> {
        let now = now_secs();
        if let Some(mut rel) = self.releases.get_mut(release_id) {
            // RolledBack veya Completed durumda switch'i reddet — aksi halde
            // rollback sonrası tekrar switch çağrısı stale upstream'e döner.
            if rel.status != ReleaseStatus::Active {
                tracing::warn!(
                    "Switch ignored: release {} is in non-Active status {:?}",
                    release_id,
                    rel.status
                );
                return None;
            }
            rel.active_color = flip_color(&rel.active_color);
            rel.switched_at = Some(now);
            tracing::info!("🔄 Release switch: {} → {}", release_id, rel.active_color);
            Some(rel.active_color.clone())
        } else {
            None
        }
    }

    /// Aktif upstream'i döndür
    pub fn active_upstream(&self, release_id: &str) -> Option<String> {
        self.releases.get(release_id).map(|r| {
            if r.active_color == "blue" {
                r.blue_upstream.clone()
            } else {
                r.green_upstream.clone()
            }
        })
    }

    /// Error rate kontrol — threshold aşılırsa otomatik rollback.
    /// Atomicity: status check + status set + color flip aynı `get_mut`
    /// (per-key write lock) altında yapılır. İki paralel çağrıdan biri
    /// status'u RolledBack'e çevirir; diğeri status'un Active olmadığını
    /// görüp early return yapar — çift rollback olmaz.
    pub fn check_rollback(&self, release_id: &str, current_error_rate: f64) -> bool {
        let mut rel = match self.releases.get_mut(release_id) {
            Some(r) => r,
            None => return false,
        };
        // Status kontrolü ve mutate aynı kilit altında: idempotent.
        if rel.status != ReleaseStatus::Active {
            return false;
        }
        if current_error_rate <= rel.error_threshold {
            return false;
        }
        rel.active_color = flip_color(&rel.active_color);
        rel.rollback_count = rel.rollback_count.saturating_add(1);
        rel.status = ReleaseStatus::RolledBack;
        rel.switched_at = Some(now_secs());
        tracing::warn!(
            "⚠️ Auto-rollback: {} (error rate {:.2}% > {:.2}%)",
            release_id,
            current_error_rate * 100.0,
            rel.error_threshold * 100.0
        );
        true
    }

    /// Tüm release'leri listele
    pub fn list(&self) -> Vec<Release> {
        self.releases.iter().map(|e| e.value().clone()).collect()
    }
}
