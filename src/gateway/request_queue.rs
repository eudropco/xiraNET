use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::time::Instant;

/// Request queue ile backpressure yönetimi
pub struct RequestQueue {
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
    queue: Arc<Mutex<QueueStats>>,
    enabled: bool,
}

#[derive(Default, Clone, serde::Serialize)]
pub struct QueueStats {
    pub queued: u64,
    pub processed: u64,
    pub rejected: u64,
    pub max_queue_depth: u64,
    pub current_depth: u64,
    pub avg_wait_ms: f64,
    wait_times: VecDeque<f64>,
}

pub enum QueueResult {
    Acquired(QueuePermit),
    Rejected { reason: String },
}

pub struct QueuePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    enqueued_at: Instant,
    stats: Arc<Mutex<QueueStats>>,
}

impl Drop for QueuePermit {
    fn drop(&mut self) {
        let stats = self.stats.clone();
        let wait_ms = self.enqueued_at.elapsed().as_secs_f64() * 1000.0;
        tokio::spawn(async move {
            let mut s = stats.lock().await;
            s.processed += 1;
            s.current_depth = s.current_depth.saturating_sub(1);
            s.wait_times.push_back(wait_ms);
            if s.wait_times.len() > 100 {
                s.wait_times.pop_front();
            }
            s.avg_wait_ms = s.wait_times.iter().sum::<f64>() / s.wait_times.len() as f64;
        });
    }
}

impl RequestQueue {
    pub fn new(max_concurrent: usize, enabled: bool) -> Self {
        tracing::info!("Request queue initialized: max_concurrent={}, enabled={}", max_concurrent, enabled);
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
            queue: Arc::new(Mutex::new(QueueStats::default())),
            enabled,
        }
    }

    /// Request'i kuyruğa al veya reddet
    pub async fn acquire(&self) -> QueueResult {
        if !self.enabled {
            // Disabled modda direkt geçir
            match self.semaphore.clone().try_acquire_owned() {
                Ok(permit) => QueueResult::Acquired(QueuePermit {
                    _permit: permit,
                    enqueued_at: Instant::now(),
                    stats: self.queue.clone(),
                }),
                Err(_) => QueueResult::Acquired(QueuePermit {
                    _permit: self.semaphore.clone().acquire_owned().await.unwrap(),
                    enqueued_at: Instant::now(),
                    stats: self.queue.clone(),
                }),
            }
        } else {
            // Backpressure — try_acquire ile kontrol et
            let mut stats = self.queue.lock().await;
            stats.queued += 1;
            stats.current_depth += 1;
            if stats.current_depth > stats.max_queue_depth {
                stats.max_queue_depth = stats.current_depth;
            }

            // Eğer kuyruk çok doluysa reddet
            if stats.current_depth > self.max_concurrent as u64 * 2 {
                stats.rejected += 1;
                stats.current_depth -= 1;
                return QueueResult::Rejected {
                    reason: format!("Queue full: {}/{} (backpressure)", stats.current_depth, self.max_concurrent * 2),
                };
            }
            drop(stats);

            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                self.semaphore.clone().acquire_owned(),
            ).await {
                Ok(Ok(permit)) => QueueResult::Acquired(QueuePermit {
                    _permit: permit,
                    enqueued_at: Instant::now(),
                    stats: self.queue.clone(),
                }),
                _ => {
                    let mut stats = self.queue.lock().await;
                    stats.rejected += 1;
                    stats.current_depth -= 1;
                    QueueResult::Rejected {
                        reason: "Queue timeout (30s)".to_string(),
                    }
                }
            }
        }
    }

    pub async fn stats(&self) -> QueueStats {
        self.queue.lock().await.clone()
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
