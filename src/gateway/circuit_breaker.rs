use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Circuit Breaker durumları
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal — istekler geçer
    Open,     // Devre açık — istekler reddedilir
    HalfOpen, // Yarı açık — sınırlı istek test amaçlı geçer
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "CLOSED"),
            CircuitState::Open => write!(f, "OPEN"),
            CircuitState::HalfOpen => write!(f, "HALF_OPEN"),
        }
    }
}

struct CircuitBreakerEntry {
    state: CircuitState,
    failure_count: u32,
    /// HalfOpen sırasında tamamlanmış başarılı probe sayısı.
    success_count_half_open: u32,
    /// HalfOpen sırasında şu an in-flight probe sayısı.
    /// Half-open thundering herd koruması için: allow_request artırır,
    /// record_success/failure azaltır.
    in_flight_probes: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

struct CircuitBreakerConfigState {
    failure_threshold: AtomicU32,
    reset_timeout_secs: AtomicU64,
    half_open_max_requests: AtomicU32,
}

/// Per-service circuit breaker manager
#[derive(Clone)]
pub struct CircuitBreakerManager {
    breakers: Arc<DashMap<Uuid, CircuitBreakerEntry>>,
    config: Arc<CircuitBreakerConfigState>,
}

impl CircuitBreakerManager {
    pub fn new(
        failure_threshold: u32,
        reset_timeout_secs: u64,
        half_open_max_requests: u32,
    ) -> Self {
        Self {
            breakers: Arc::new(DashMap::new()),
            config: Arc::new(CircuitBreakerConfigState {
                failure_threshold: AtomicU32::new(failure_threshold.max(1)),
                reset_timeout_secs: AtomicU64::new(reset_timeout_secs),
                half_open_max_requests: AtomicU32::new(half_open_max_requests.max(1)),
            }),
        }
    }

    pub fn update_config(
        &self,
        failure_threshold: u32,
        reset_timeout_secs: u64,
        half_open_max_requests: u32,
    ) {
        self.config
            .failure_threshold
            .store(failure_threshold.max(1), Ordering::Relaxed);
        self.config
            .reset_timeout_secs
            .store(reset_timeout_secs, Ordering::Relaxed);
        self.config
            .half_open_max_requests
            .store(half_open_max_requests.max(1), Ordering::Relaxed);
    }

    pub fn snapshot_config(&self) -> (u32, u64, u32) {
        (
            self.config.failure_threshold.load(Ordering::Relaxed),
            self.config.reset_timeout_secs.load(Ordering::Relaxed),
            self.config.half_open_max_requests.load(Ordering::Relaxed),
        )
    }

    /// İsteğe izin verilip verilmediğini kontrol et
    pub fn allow_request(&self, service_id: &Uuid) -> Result<(), CircuitState> {
        let reset_timeout =
            Duration::from_secs(self.config.reset_timeout_secs.load(Ordering::Relaxed));
        let half_open_max_requests = self
            .config
            .half_open_max_requests
            .load(Ordering::Relaxed)
            .max(1);

        let mut entry = self
            .breakers
            .entry(*service_id)
            .or_insert(CircuitBreakerEntry {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count_half_open: 0,
                in_flight_probes: 0,
                last_failure_time: None,
                last_state_change: Instant::now(),
            });

        // Tek shard kilidi altında: state check + probe counter increment atomik.
        // Bu, Open→HalfOpen geçiş sırasında N paralel isteğin hepsinin geçmesini
        // engeller (thundering herd koruması).
        match entry.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                if let Some(last_failure) = entry.last_failure_time {
                    if last_failure.elapsed() >= reset_timeout {
                        entry.state = CircuitState::HalfOpen;
                        entry.success_count_half_open = 0;
                        entry.in_flight_probes = 1; // bu istek ilk probe
                        entry.last_state_change = Instant::now();
                        tracing::info!("Circuit breaker {} → HALF_OPEN", service_id);
                        Ok(())
                    } else {
                        Err(CircuitState::Open)
                    }
                } else {
                    Err(CircuitState::Open)
                }
            }
            CircuitState::HalfOpen => {
                // In-flight probe sayısı upper bound'da ise reddet
                if entry.in_flight_probes < half_open_max_requests {
                    entry.in_flight_probes = entry.in_flight_probes.saturating_add(1);
                    Ok(())
                } else {
                    Err(CircuitState::HalfOpen)
                }
            }
        }
    }

    /// Başarılı istek kaydet
    pub fn record_success(&self, service_id: &Uuid) {
        if let Some(mut entry) = self.breakers.get_mut(service_id) {
            let half_open_max_requests = self
                .config
                .half_open_max_requests
                .load(Ordering::Relaxed)
                .max(1);
            match entry.state {
                CircuitState::HalfOpen => {
                    entry.success_count_half_open =
                        entry.success_count_half_open.saturating_add(1);
                    entry.in_flight_probes = entry.in_flight_probes.saturating_sub(1);
                    if entry.success_count_half_open >= half_open_max_requests {
                        entry.state = CircuitState::Closed;
                        entry.failure_count = 0;
                        entry.in_flight_probes = 0;
                        entry.last_state_change = Instant::now();
                        tracing::info!("Circuit breaker {} → CLOSED (recovered)", service_id);
                    }
                }
                CircuitState::Closed => {
                    // Closed state'te başarılı istekler failure_count'u etkilemez
                }
                _ => {}
            }
        }
    }

    /// Başarısız istek kaydet
    pub fn record_failure(&self, service_id: &Uuid) {
        let failure_threshold = self.config.failure_threshold.load(Ordering::Relaxed).max(1);
        let mut entry = self
            .breakers
            .entry(*service_id)
            .or_insert(CircuitBreakerEntry {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count_half_open: 0,
                in_flight_probes: 0,
                last_failure_time: None,
                last_state_change: Instant::now(),
            });

        entry.failure_count = entry.failure_count.saturating_add(1);
        entry.last_failure_time = Some(Instant::now());

        match entry.state {
            CircuitState::Closed => {
                if entry.failure_count >= failure_threshold {
                    entry.state = CircuitState::Open;
                    entry.last_state_change = Instant::now();
                    tracing::warn!(
                        "🔴 Circuit breaker {} → OPEN (failures: {})",
                        service_id,
                        entry.failure_count
                    );
                }
            }
            CircuitState::HalfOpen => {
                entry.state = CircuitState::Open;
                entry.in_flight_probes = 0;
                entry.success_count_half_open = 0;
                entry.last_state_change = Instant::now();
                tracing::warn!(
                    "🔴 Circuit breaker {} → OPEN (half-open failed)",
                    service_id
                );
            }
            _ => {}
        }
    }

    /// Servis circuit breaker durumunu al
    pub fn get_state(&self, service_id: &Uuid) -> CircuitState {
        self.breakers
            .get(service_id)
            .map(|e| e.state.clone())
            .unwrap_or(CircuitState::Closed)
    }

    /// Tüm breaker durumlarını raporla
    pub fn report(&self) -> Vec<serde_json::Value> {
        self.breakers
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "service_id": entry.key().to_string(),
                    "state": entry.state.to_string(),
                    "failure_count": entry.failure_count,
                    "since": format!("{}s ago", entry.last_state_change.elapsed().as_secs()),
                })
            })
            .collect()
    }
}
