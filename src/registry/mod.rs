pub mod models;
pub mod storage;

use crate::config::ServiceConfig;
use dashmap::DashMap;
use models::{ServiceEntry, ServiceStatus};
use storage::SqliteStorage;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct ServiceRegistry {
    services: Arc<DashMap<Uuid, ServiceEntry>>,
    storage: Option<Arc<SqliteStorage>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: Arc::new(DashMap::new()),
            storage: None,
        }
    }

    pub fn with_storage(storage: Arc<SqliteStorage>) -> Self {
        let registry = Self {
            services: Arc::new(DashMap::new()),
            storage: Some(storage.clone()),
        };

        // SQLite'dan mevcut servisleri yükle
        match storage.load_all_services() {
            Ok(entries) => {
                for entry in entries {
                    tracing::info!("Loaded service from DB: {} → {}", entry.name, entry.upstream);
                    registry.services.insert(entry.id, entry);
                }
            }
            Err(e) => {
                tracing::error!("Failed to load services from DB: {}", e);
            }
        }

        registry
    }

    pub fn storage(&self) -> Option<&Arc<SqliteStorage>> {
        self.storage.as_ref()
    }

    /// Konfigürasyondan servisleri yükle
    pub fn load_from_config(&self, service_configs: &[ServiceConfig]) {
        for svc in service_configs {
            // Zaten bu prefix ile kayıtlı mı kontrol et
            if self.find_by_prefix(&svc.prefix).is_some() {
                tracing::debug!("Service already registered for prefix: {}", svc.prefix);
                continue;
            }

            let mut entry = ServiceEntry::new(
                svc.name.clone(),
                svc.prefix.clone(),
                svc.upstream.clone(),
                svc.health_endpoint.clone(),
            );
            entry.upstreams = svc.upstreams.clone();
            entry.load_balance = svc.load_balance.clone();
            entry.version = svc.version.clone();
            entry.validation_schema = svc.validation_schema.clone();

            tracing::info!(
                "Service registered from config: {} → {} (prefix: {})",
                entry.name, entry.upstream, entry.prefix
            );

            // SQLite'a kaydet
            if let Some(ref storage) = self.storage {
                let _ = storage.save_service(&entry);
            }

            self.services.insert(entry.id, entry);
        }
    }

    /// Yeni servis kaydet
    pub fn register(&self, name: String, prefix: String, upstream: String, health_endpoint: String) -> ServiceEntry {
        if let Some(existing) = self.find_by_prefix(&prefix) {
            tracing::warn!("Prefix '{}' already registered by '{}', replacing", prefix, existing.name);
            self.services.remove(&existing.id);
            if let Some(ref storage) = self.storage {
                let _ = storage.remove_service(&existing.id.to_string());
            }
        }

        let entry = ServiceEntry::new(name, prefix, upstream, health_endpoint);
        let result = entry.clone();

        // SQLite'a kaydet
        if let Some(ref storage) = self.storage {
            let _ = storage.save_service(&entry);
            let _ = storage.log_event("service_registered", Some(&entry.id.to_string()), Some(&entry.name), &format!("Service '{}' registered", entry.name));
        }

        self.services.insert(entry.id, entry);
        tracing::info!("Service registered: {} ({})", result.name, result.id);
        result
    }

    /// Gelişmiş servis kayıt (load balancing, versioning vb.)
    pub fn register_advanced(&self, req: models::RegisterServiceRequest) -> ServiceEntry {
        if let Some(existing) = self.find_by_prefix(&req.prefix) {
            self.services.remove(&existing.id);
            if let Some(ref storage) = self.storage {
                let _ = storage.remove_service(&existing.id.to_string());
            }
        }

        let mut entry = ServiceEntry::new(req.name, req.prefix, req.upstream, req.health_endpoint);
        entry.upstreams = req.upstreams;
        entry.load_balance = req.load_balance;
        entry.version = req.version;
        entry.validation_schema = req.validation_schema;

        let result = entry.clone();

        if let Some(ref storage) = self.storage {
            let _ = storage.save_service(&entry);
            let _ = storage.log_event("service_registered", Some(&entry.id.to_string()), Some(&entry.name), &format!("Service '{}' registered", entry.name));
        }

        self.services.insert(entry.id, entry);
        tracing::info!("Service registered: {} ({})", result.name, result.id);
        result
    }

    /// Servisi ID ile kaldır
    pub fn unregister(&self, id: &Uuid) -> Option<ServiceEntry> {
        let removed = self.services.remove(id).map(|(_, v)| v);
        if let Some(ref entry) = removed {
            if let Some(ref storage) = self.storage {
                let _ = storage.remove_service(&entry.id.to_string());
                let _ = storage.log_event("service_unregistered", Some(&entry.id.to_string()), Some(&entry.name), &format!("Service '{}' unregistered", entry.name));
            }
            tracing::info!("Service unregistered: {} ({})", entry.name, entry.id);
        }
        removed
    }

    /// Prefix'e göre servis bul (en uzun eşleşen prefix)
    pub fn lookup(&self, path: &str) -> Option<ServiceEntry> {
        let mut best_match: Option<ServiceEntry> = None;
        let mut best_len = 0;

        for entry in self.services.iter() {
            let prefix = &entry.prefix;
            if path == prefix || path.starts_with(&format!("{}/", prefix)) {
                if prefix.len() > best_len {
                    best_len = prefix.len();
                    best_match = Some(entry.value().clone());
                }
            }
        }

        best_match
    }

    /// Tüm servisleri listele
    pub fn list_all(&self) -> Vec<ServiceEntry> {
        self.services.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Prefix'e göre servis bul
    pub fn find_by_prefix(&self, prefix: &str) -> Option<ServiceEntry> {
        let normalized = if prefix.starts_with('/') {
            prefix.trim_end_matches('/').to_string()
        } else {
            format!("/{}", prefix.trim_end_matches('/'))
        };

        self.services
            .iter()
            .find(|entry| entry.prefix == normalized)
            .map(|entry| entry.value().clone())
    }

    /// Servis durumunu güncelle
    pub fn update_status(&self, id: &Uuid, status: ServiceStatus) {
        if let Some(mut entry) = self.services.get_mut(id) {
            entry.status = status;
            entry.last_health_check = Some(chrono::Utc::now());
        }
    }

    /// İstek sayacını artır
    pub fn increment_request_count(&self, id: &Uuid) {
        if let Some(mut entry) = self.services.get_mut(id) {
            entry.request_count += 1;
            // Her 100 istekte bir SQLite'a yaz
            if entry.request_count % 100 == 0 {
                if let Some(ref storage) = self.storage {
                    let _ = storage.update_request_count(&entry.id.to_string(), entry.request_count);
                }
            }
        }
    }

    pub fn total_requests(&self) -> u64 {
        self.services.iter().map(|e| e.request_count).sum()
    }

    pub fn count_by_status(&self, status: &ServiceStatus) -> usize {
        self.services.iter().filter(|e| e.status == *status).count()
    }

    pub fn count(&self) -> usize {
        self.services.len()
    }
}
