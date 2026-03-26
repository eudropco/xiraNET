/// File-based log export module
/// tracing_ext/mod.rs zaten file logging yapıyor, bu modül ek export fonksiyonları sağlar

pub fn get_log_dir() -> &'static str {
    "logs"
}

/// Log dosyalarını listele
pub fn list_log_files(log_dir: &str) -> Vec<String> {
    let path = std::path::Path::new(log_dir);
    if !path.exists() {
        return vec![];
    }

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.ends_with(".log") || name.contains("xiranet") {
                    files.push(name);
                }
            }
        }
    }
    files.sort();
    files
}

/// Log dosyası boyutunu al
pub fn get_log_size(log_dir: &str) -> u64 {
    let path = std::path::Path::new(log_dir);
    if !path.exists() {
        return 0;
    }

    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// Log istatistikleri
pub fn log_stats(log_dir: &str) -> serde_json::Value {
    let files = list_log_files(log_dir);
    let total_size = get_log_size(log_dir);

    serde_json::json!({
        "log_directory": log_dir,
        "file_count": files.len(),
        "total_size_bytes": total_size,
        "total_size_mb": format!("{:.2}", total_size as f64 / 1_048_576.0),
        "files": files,
    })
}
