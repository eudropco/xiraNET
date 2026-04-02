/// Bot Detection — User-Agent analysis + crawl rate limiting
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct BotDetector {
    enabled: bool,
    known_bots: Vec<String>,
    ip_tracker: DashMap<String, BotTracker>,
    block_bots: bool,
    crawl_rate_limit: u32, // max req/min for detected bots
}

struct BotTracker {
    request_count: u32,
    window_start: u64,
    is_bot: bool,
    _user_agent: String,
}

#[derive(Debug)]
pub enum BotVerdict {
    Human,
    Bot { name: String },
    RateLimited,
    Blocked,
}

impl BotDetector {
    pub fn new(enabled: bool, block_bots: bool, crawl_rate_limit: u32) -> Self {
        Self {
            enabled,
            known_bots: vec![
                "Googlebot".into(), "Bingbot".into(), "Slurp".into(),
                "DuckDuckBot".into(), "Baiduspider".into(), "YandexBot".into(),
                "Sogou".into(), "facebookexternalhit".into(), "Twitterbot".into(),
                "rogerbot".into(), "linkedinbot".into(), "embedly".into(),
                "quora link preview".into(), "showyoubot".into(), "outbrain".into(),
                "pinterest".into(), "applebot".into(), "Scrapy".into(),
                "python-requests".into(), "curl".into(), "wget".into(),
                "httpie".into(), "Go-http-client".into(), "Java".into(),
                "Apache-HttpClient".into(), "okhttp".into(),
            ],
            ip_tracker: DashMap::new(),
            block_bots,
            crawl_rate_limit,
        }
    }

    /// User-Agent ve IP analiz et
    pub fn check(&self, ip: &str, user_agent: &str) -> BotVerdict {
        if !self.enabled { return BotVerdict::Human; }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Known bot check
        let bot_name = self.known_bots.iter()
            .find(|bot| user_agent.to_lowercase().contains(&bot.to_lowercase()))
            .cloned();

        // Empty/missing UA → suspicious
        let is_bot = bot_name.is_some() || user_agent.is_empty() || user_agent.len() < 10;

        // Rate tracking per IP
        let mut tracker = self.ip_tracker.entry(ip.to_string()).or_insert(BotTracker {
            request_count: 0,
            window_start: now,
            is_bot,
            _user_agent: user_agent.to_string(),
        });

        // Reset window every 60s
        if now - tracker.window_start > 60 {
            tracker.request_count = 0;
            tracker.window_start = now;
        }
        tracker.request_count += 1;
        tracker.is_bot = is_bot;

        if is_bot {
            if self.block_bots {
                return BotVerdict::Blocked;
            }
            if tracker.request_count > self.crawl_rate_limit {
                tracing::warn!("Bot rate limited: {} ({}) — {}/min", ip, user_agent, tracker.request_count);
                return BotVerdict::RateLimited;
            }
            return BotVerdict::Bot {
                name: bot_name.unwrap_or_else(|| "unknown-bot".to_string()),
            };
        }

        BotVerdict::Human
    }

    /// Bot istatistikleri
    pub fn stats(&self) -> serde_json::Value {
        let total = self.ip_tracker.len();
        let bots = self.ip_tracker.iter().filter(|e| e.value().is_bot).count();
        serde_json::json!({
            "total_tracked_ips": total,
            "detected_bots": bots,
            "humans": total - bots,
            "block_mode": self.block_bots,
            "crawl_rate_limit": self.crawl_rate_limit,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
