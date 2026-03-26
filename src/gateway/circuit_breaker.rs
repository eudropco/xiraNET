use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Circuit Breaker durumları
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,     // Normal — istekler geçer
    Open,       // Devre açık — istekler reddedilir
    HalfOpen,   // Yarı açık — sınırlı istek test amaçlı geçer
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
    success_count_half_open: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

/// Per-service circuit breaker manager
#[derive(Clone)]
pub struct CircuitBreakerManager {
    breakers: Arc<DashMap<Uuid, CircuitBreakerEntry>>,
    failure_threshold: u32,
    reset_timeout: Duration,
    half_open_max_requests: u32,
}

impl CircuitBreakerManager {
    pub fn new(failure_threshold: u32, reset_timeout_secs: u64, half_open_max_requests: u32) -> Self {
        Self {
            breakers: Arc::new(DashMap::new()),
            failure_threshold,
            reset_timeout: Duration::from_secs(reset_timeout_secs),
            half_open_max_requests,
        }
    }

    /// İsteğe izin verilip verilmediğini kontrol et
    pub fn allow_request(&self, service_id: &Uuid) -> Result<(), CircuitState> {
        let mut entry = self.breakers.entry(*service_id).or_insert(CircuitBreakerEntry {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count_half_open: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
        });

        match entry.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Timeout doldu mu kontrol et
                if let Some(last_failure) = entry.last_failure_time {
                    if last_failure.elapsed() >= self.reset_timeout {
                        // Half-Open'a geç
                        entry.state = CircuitState::HalfOpen;
                        entry.success_count_half_open = 0;
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
                if entry.success_count_half_open < self.half_open_max_requests {
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
            match entry.state {
                CircuitState::HalfOpen => {
                    entry.success_count_half_open += 1;
                    if entry.success_count_half_open >= self.half_open_max_requests {
                        entry.state = CircuitState::Closed;
                        entry.failure_count = 0;
                        entry.last_state_change = Instant::now();
                        tracing::info!("Circuit breaker {} → CLOSED (recovered)", service_id);
                    }
                }
                CircuitState::Closed => {
                    // Closed state'te başarılı istekler failure_count'u etkilemez
                    // Failure count sadece threshold aşımında sıfırlanır
                }
                _ => {}
            }
        }
    }

    /// Başarısız istek kaydet
    pub fn record_failure(&self, service_id: &Uuid) {
        let mut entry = self.breakers.entry(*service_id).or_insert(CircuitBreakerEntry {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count_half_open: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
        });

        entry.failure_count += 1;
        entry.last_failure_time = Some(Instant::now());

        match entry.state {
            CircuitState::Closed => {
                if entry.failure_count >= self.failure_threshold {
                    entry.state = CircuitState::Open;
                    entry.last_state_change = Instant::now();
                    tracing::warn!(
                        "🔴 Circuit breaker {} → OPEN (failures: {})",
                        service_id, entry.failure_count
                    );
                }
            }
            CircuitState::HalfOpen => {
                entry.state = CircuitState::Open;
                entry.last_state_change = Instant::now();
                tracing::warn!("🔴 Circuit breaker {} → OPEN (half-open failed)", service_id);
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
