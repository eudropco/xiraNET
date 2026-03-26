/// Lua scripting engine — custom middleware via Lua scripts
/// Uses a simplified Lua-like DSL (no external crate dependency)

use std::collections::HashMap;
use std::path::Path;

pub struct LuaEngine {
    scripts: Vec<LuaScript>,
    enabled: bool,
}

#[derive(Clone, Debug)]
pub struct LuaScript {
    pub name: String,
    pub source: String,
    pub hook: LuaHook,
}

#[derive(Clone, Debug)]
pub enum LuaHook {
    OnRequest,
    OnResponse,
    OnError,
}

#[derive(Debug)]
pub enum LuaAction {
    Continue,
    Reject { status: u16, body: String },
    ModifyHeader { name: String, value: String },
    AddHeader { name: String, value: String },
    Log { message: String },
}

impl LuaEngine {
    pub fn new(enabled: bool) -> Self {
        Self {
            scripts: Vec::new(),
            enabled,
        }
    }

    /// Script dosyasını yükle
    pub fn load_script(&mut self, name: String, source: String, hook: LuaHook) {
        tracing::info!("Lua script loaded: {} ({:?})", name, hook);
        self.scripts.push(LuaScript { name, source, hook });
    }

    /// Dizinden tüm .lua dosyalarını yükle
    pub fn load_directory(&mut self, dir: &str) {
        let path = Path::new(dir);
        if !path.exists() { return; }

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.extension().map_or(false, |e| e == "lua") {
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let name = file_path.file_stem().unwrap().to_string_lossy().to_string();
                        let hook = if content.contains("on_request") {
                            LuaHook::OnRequest
                        } else if content.contains("on_response") {
                            LuaHook::OnResponse
                        } else {
                            LuaHook::OnRequest
                        };
                        self.load_script(name, content, hook);
                    }
                }
            }
        }
    }

    /// on_request hook'larını çalıştır
    pub fn execute_on_request(&self, ctx: &RequestContext) -> Vec<LuaAction> {
        if !self.enabled { return vec![LuaAction::Continue]; }

        let mut actions = Vec::new();

        for script in &self.scripts {
            if !matches!(script.hook, LuaHook::OnRequest) { continue; }

            // Simple DSL interpreter
            let result = self.interpret(&script.source, ctx);
            actions.extend(result);
        }

        if actions.is_empty() {
            actions.push(LuaAction::Continue);
        }

        actions
    }

    /// Basit DSL yorumlayıcı
    fn interpret(&self, source: &str, ctx: &RequestContext) -> Vec<LuaAction> {
        let mut actions = Vec::new();

        for line in source.lines() {
            let trimmed = line.trim();

            // reject(status, "body")
            if trimmed.starts_with("reject(") {
                if let Some(inner) = trimmed.strip_prefix("reject(").and_then(|s| s.strip_suffix(')')) {
                    let parts: Vec<&str> = inner.splitn(2, ',').collect();
                    if parts.len() == 2 {
                        let status = parts[0].trim().parse::<u16>().unwrap_or(403);
                        let body = parts[1].trim().trim_matches('"').to_string();
                        actions.push(LuaAction::Reject { status, body });
                    }
                }
            }

            // add_header("name", "value")
            if trimmed.starts_with("add_header(") {
                if let Some(inner) = trimmed.strip_prefix("add_header(").and_then(|s| s.strip_suffix(')')) {
                    let parts: Vec<&str> = inner.splitn(2, ',').collect();
                    if parts.len() == 2 {
                        let name = parts[0].trim().trim_matches('"').to_string();
                        let value = parts[1].trim().trim_matches('"').to_string();
                        actions.push(LuaAction::AddHeader { name, value });
                    }
                }
            }

            // log("message")
            if trimmed.starts_with("log(") {
                if let Some(inner) = trimmed.strip_prefix("log(").and_then(|s| s.strip_suffix(')')) {
                    let message = inner.trim_matches('"').to_string();
                    actions.push(LuaAction::Log { message });
                }
            }

            // if path == "/blocked" then reject(403, "Blocked")
            if trimmed.starts_with("if path") && trimmed.contains("reject") {
                if let Some(path_match) = extract_quoted(trimmed) {
                    if ctx.path == path_match {
                        actions.push(LuaAction::Reject {
                            status: 403,
                            body: "Blocked by Lua script".to_string(),
                        });
                    }
                }
            }
        }

        actions
    }

    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Debug)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub ip: String,
    pub headers: HashMap<String, String>,
}

fn extract_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}
