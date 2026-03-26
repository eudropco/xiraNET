/// Distributed tracing — trace tree visualization data
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TraceCollector {
    traces: DashMap<String, TraceTree>,
    max_traces: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceTree {
    pub trace_id: String,
    pub spans: Vec<TraceSpan>,
    pub started_at: u64,
    pub total_duration_ms: f64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceSpan {
    pub span_id: String,
    pub parent_id: Option<String>,
    pub service: String,
    pub operation: String,
    pub start_ms: f64,
    pub duration_ms: f64,
    pub status: u16,
    pub tags: Vec<(String, String)>,
}

impl TraceCollector {
    pub fn new(max_traces: usize) -> Self {
        Self {
            traces: DashMap::new(),
            max_traces,
        }
    }

    /// Yeni trace başlat
    pub fn start_trace(&self, request_id: &str) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Eviction
        if self.traces.len() >= self.max_traces {
            if let Some(oldest) = self.traces.iter().min_by_key(|e| e.value().started_at).map(|e| e.key().clone()) {
                self.traces.remove(&oldest);
            }
        }

        self.traces.insert(request_id.to_string(), TraceTree {
            trace_id: request_id.to_string(),
            spans: Vec::new(),
            started_at: now,
            total_duration_ms: 0.0,
        });

        request_id.to_string()
    }

    /// Trace'e span ekle
    pub fn add_span(&self, trace_id: &str, span: TraceSpan) {
        if let Some(mut tree) = self.traces.get_mut(trace_id) {
            tree.spans.push(span);
            // total duration recalc
            tree.total_duration_ms = tree.spans.iter().map(|s| s.start_ms + s.duration_ms).fold(0.0f64, f64::max);
        }
    }

    /// Trace'i al
    pub fn get_trace(&self, trace_id: &str) -> Option<TraceTree> {
        self.traces.get(trace_id).map(|e| e.value().clone())
    }

    /// Son N trace
    pub fn recent_traces(&self, limit: usize) -> Vec<TraceTree> {
        let mut traces: Vec<_> = self.traces.iter().map(|e| e.value().clone()).collect();
        traces.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        traces.truncate(limit);
        traces
    }

    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }
}
