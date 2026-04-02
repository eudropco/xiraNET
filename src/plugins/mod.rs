pub mod lua_engine;

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;
use dashmap::DashMap;

/// Plugin trait — tüm XIRA pluginleri bunu implement eder
#[async_trait]
pub trait XiraPlugin: Send + Sync {
    /// Plugin adı
    fn name(&self) -> &str;

    /// Plugin başlatıldığında çalışır
    async fn on_init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Request geldiğinde çalışır (before proxy)
    async fn on_request(
        &self,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> PluginAction;

    /// Response döndüğünde çalışır (after proxy)
    async fn on_response(
        &self,
        status: u16,
        path: &str,
    ) -> PluginAction;

    /// Plugin kapatıldığında çalışır
    async fn on_shutdown(&self);
}

/// Plugin'in kararı
#[derive(Debug)]
pub enum PluginAction {
    /// İsteğe devam et
    Continue,
    /// İsteği engelle (status code + mesaj)
    Block(u16, String),
    /// Header ekle
    AddHeader(String, String),
}

/// Plugin manager — pluginleri yükler ve çalıştırır
#[derive(Clone)]
pub struct PluginManager {
    plugins: Arc<DashMap<String, Arc<dyn XiraPlugin>>>,
    enabled: bool,
}

impl PluginManager {
    pub fn new(enabled: bool) -> Self {
        Self {
            plugins: Arc::new(DashMap::new()),
            enabled,
        }
    }

    /// Built-in plugin kaydet
    pub async fn register(&self, plugin: Arc<dyn XiraPlugin>) {
        if !self.enabled {
            return;
        }

        let name = plugin.name().to_string();
        match plugin.on_init().await {
            Ok(()) => {
                tracing::info!("Plugin loaded: {}", name);
                self.plugins.insert(name, plugin);
            }
            Err(e) => {
                tracing::error!("Plugin '{}' init failed: {}", name, e);
            }
        }
    }

    /// Plugin dizininden dynamic pluginleri yükle
    pub fn scan_directory(&self, dir: &str) {
        if !self.enabled {
            return;
        }

        let path = Path::new(dir);
        if !path.exists() {
            tracing::debug!("Plugin directory not found: {}", dir);
            return;
        }

        tracing::info!("Scanning plugin directory: {}", dir);

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "so" || e == "dylib" || e == "dll").unwrap_or(false) {
                    tracing::info!("Found plugin library: {:?}", path);
                    // Dynamic loading ile plugin yükleme
                    // libloading kullanılarak yapılabilir
                }
            }
        }
    }

    /// Tüm pluginlerde on_request çalıştır
    pub async fn execute_on_request(
        &self,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> Vec<PluginAction> {
        if !self.enabled {
            return vec![PluginAction::Continue];
        }

        let mut actions = Vec::new();
        for entry in self.plugins.iter() {
            let action = entry.value().on_request(method, path, headers).await;
            actions.push(action);
        }
        actions
    }

    /// Tüm pluginlerde on_response çalıştır
    pub async fn execute_on_response(&self, status: u16, path: &str) -> Vec<PluginAction> {
        if !self.enabled {
            return vec![PluginAction::Continue];
        }

        let mut actions = Vec::new();
        for entry in self.plugins.iter() {
            let action = entry.value().on_response(status, path).await;
            actions.push(action);
        }
        actions
    }

    /// Plugin listesi
    pub fn list_plugins(&self) -> Vec<String> {
        self.plugins.iter().map(|e| e.key().clone()).collect()
    }

    /// Tüm pluginleri kapat
    pub async fn shutdown_all(&self) {
        for entry in self.plugins.iter() {
            entry.value().on_shutdown().await;
        }
    }
}

// ========= Built-in Plugins =========

/// Logging plugin — her isteği loglar
pub struct LoggingPlugin;

#[async_trait]
impl XiraPlugin for LoggingPlugin {
    fn name(&self) -> &str { "builtin:logging" }

    async fn on_init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn on_request(&self, method: &str, path: &str, _headers: &std::collections::HashMap<String, String>) -> PluginAction {
        tracing::debug!("[plugin:logging] {} {}", method, path);
        PluginAction::Continue
    }

    async fn on_response(&self, status: u16, path: &str) -> PluginAction {
        tracing::debug!("[plugin:logging] {} → {}", path, status);
        PluginAction::Continue
    }

    async fn on_shutdown(&self) {
        tracing::info!("[plugin:logging] shutting down");
    }
}

/// Security headers plugin — güvenlik header'ları ekler
pub struct SecurityHeadersPlugin;

#[async_trait]
impl XiraPlugin for SecurityHeadersPlugin {
    fn name(&self) -> &str { "builtin:security-headers" }

    async fn on_init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn on_request(&self, _method: &str, _path: &str, _headers: &std::collections::HashMap<String, String>) -> PluginAction {
        PluginAction::Continue
    }

    async fn on_response(&self, _status: u16, _path: &str) -> PluginAction {
        // Bu header'lar main.rs'deki DefaultHeaders ile de eklenebilir
        PluginAction::AddHeader("X-Content-Type-Options".to_string(), "nosniff".to_string())
    }

    async fn on_shutdown(&self) {}
}
