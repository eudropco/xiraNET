/// Upstream Health Scoring — latency-based weighted routing
use dashmap::DashMap;
use std::collections::VecDeque;

pub struct HealthScorer {
    scores: DashMap<String, UpstreamScore>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct UpstreamScore {
    pub upstream: String,
    pub score: f64,            // 0.0 (worst) → 100.0 (best)
    pub avg_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub error_rate: f64,       // 0.0 → 1.0
    pub total_requests: u64,
    pub total_errors: u64,
    latency_window: VecDeque<f64>,
    error_window: VecDeque<bool>,
}

impl HealthScorer {
    pub fn new() -> Self {
        Self { scores: DashMap::new() }
    }

    /// Request sonucu kaydet
    pub fn record(&self, upstream: &str, latency_ms: f64, success: bool) {
        let mut entry = self.scores.entry(upstream.to_string()).or_insert_with(|| UpstreamScore {
            upstream: upstream.to_string(),
            score: 100.0,
            avg_latency_ms: 0.0, p99_latency_ms: 0.0,
            error_rate: 0.0,
            total_requests: 0, total_errors: 0,
            latency_window: VecDeque::with_capacity(200),
            error_window: VecDeque::with_capacity(200),
        });

        let s = entry.value_mut();
        s.total_requests += 1;
        if !success { s.total_errors += 1; }

        // Sliding window
        s.latency_window.push_back(latency_ms);
        s.error_window.push_back(!success);
        if s.latency_window.len() > 200 { s.latency_window.pop_front(); }
        if s.error_window.len() > 200 { s.error_window.pop_front(); }

        // Recalc
        let len = s.latency_window.len() as f64;
        s.avg_latency_ms = s.latency_window.iter().sum::<f64>() / len;
        let mut sorted: Vec<f64> = s.latency_window.iter().cloned().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        s.p99_latency_ms = sorted[(sorted.len() as f64 * 0.99) as usize];
        s.error_rate = s.error_window.iter().filter(|&&e| e).count() as f64 / len;

        // Score: 100 - (latency_penalty + error_penalty)
        let latency_penalty = (s.avg_latency_ms / 10.0).min(50.0);   // max 50 pts
        let error_penalty = (s.error_rate * 100.0).min(50.0);          // max 50 pts
        s.score = (100.0 - latency_penalty - error_penalty).max(0.0);
    }

    /// En iyi upstream'i seç (en yüksek score)
    pub fn best_upstream(&self, upstreams: &[String]) -> Option<String> {
        upstreams.iter()
            .filter_map(|u| self.scores.get(u).map(|s| (u.clone(), s.score)))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(u, _)| u)
            .or_else(|| upstreams.first().cloned())
    }

    /// Tüm score'ları al
    pub fn all_scores(&self) -> Vec<UpstreamScore> {
        self.scores.iter().map(|e| e.value().clone()).collect()
    }

    /// Belirli upstream'in score'u
    pub fn get_score(&self, upstream: &str) -> Option<UpstreamScore> {
        self.scores.get(upstream).map(|e| e.value().clone())
    }
}
