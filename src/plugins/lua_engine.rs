/// Script DSL — request/response hook'ları için basit komut dili.
///
/// Bu Lua değildir; isim geriye dönük uyumluluk için korundu (`LuaEngine`).
/// Desteklenen komutlar (her satırda bir komut):
///
/// ```text
///   reject(<status>, "<body>")          → 403 || verilen status, gövde body
///   add_header("<name>", "<value>")     → response/request'e header ekle
///   log("<message>")                    → tracing::info! ile loga yaz
///   if path == "<P>" then <command>     → P ile eşleşen path'te <command>
/// ```
///
/// Tırnaklı stringler virgül içerebilir; basit state machine `"..."` parser'ı
/// kullanıyoruz. Yorum: `--` ile başlayan satırlar atlanır.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LuaHook {
    OnRequest,
    OnResponse,
    OnError,
}

#[derive(Debug, PartialEq, Eq)]
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

    pub fn load_script(&mut self, name: String, source: String, hook: LuaHook) {
        tracing::info!("Script loaded: {} ({:?})", name, hook);
        self.scripts.push(LuaScript { name, source, hook });
    }

    pub fn load_directory(&mut self, dir: &str) {
        let path = Path::new(dir);
        if !path.exists() {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                let ext_ok = file_path
                    .extension()
                    .map(|e| e == "lua" || e == "xira")
                    .unwrap_or(false);
                if !ext_ok {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let name = file_path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "anon".to_string());
                    let hook = if content.contains("on_response") {
                        LuaHook::OnResponse
                    } else {
                        LuaHook::OnRequest
                    };
                    self.load_script(name, content, hook);
                }
            }
        }
    }

    pub fn execute_on_request(&self, ctx: &RequestContext) -> Vec<LuaAction> {
        self.execute_for_hook(ctx, LuaHook::OnRequest)
    }

    pub fn execute_on_response(&self, ctx: &RequestContext) -> Vec<LuaAction> {
        self.execute_for_hook(ctx, LuaHook::OnResponse)
    }

    fn execute_for_hook(&self, ctx: &RequestContext, hook: LuaHook) -> Vec<LuaAction> {
        if !self.enabled {
            return vec![LuaAction::Continue];
        }
        let mut actions = Vec::new();
        for script in &self.scripts {
            if script.hook != hook {
                continue;
            }
            actions.extend(self.interpret(&script.source, ctx));
        }
        if actions.is_empty() {
            actions.push(LuaAction::Continue);
        }
        actions
    }

    fn interpret(&self, source: &str, ctx: &RequestContext) -> Vec<LuaAction> {
        let mut actions = Vec::new();

        for raw_line in source.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("--") {
                continue;
            }

            // if path == "P" then <cmd>
            let executable = if let Some(rest) = line.strip_prefix("if ") {
                if let Some((cond, then_part)) = rest.split_once("then") {
                    if check_condition(cond.trim(), ctx) {
                        Some(then_part.trim().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                Some(line.to_string())
            };

            let Some(stmt) = executable else { continue };
            if let Some(action) = parse_statement(&stmt) {
                actions.push(action);
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

/// `path == "X"`, `method == "POST"`, `ip == "1.2.3.4"` koşullarını destekler.
fn check_condition(cond: &str, ctx: &RequestContext) -> bool {
    let parts: Vec<&str> = cond.split("==").map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return false;
    }
    let target = match parts[1].chars().next() {
        Some('"') => parts[1].trim_matches('"').to_string(),
        _ => return false,
    };
    match parts[0] {
        "path" => ctx.path == target,
        "method" => ctx.method.eq_ignore_ascii_case(&target),
        "ip" => ctx.ip == target,
        _ => false,
    }
}

fn parse_statement(stmt: &str) -> Option<LuaAction> {
    let (head, args_str) = split_call(stmt)?;
    let args = parse_args(args_str);
    match head.as_str() {
        "reject" => {
            let status = args.first()?.parse::<u16>().ok().unwrap_or(403);
            let body = args.get(1).cloned().unwrap_or_else(|| "blocked".to_string());
            Some(LuaAction::Reject { status, body })
        }
        "add_header" => {
            let name = args.first()?.clone();
            let value = args.get(1)?.clone();
            Some(LuaAction::AddHeader { name, value })
        }
        "modify_header" => {
            let name = args.first()?.clone();
            let value = args.get(1)?.clone();
            Some(LuaAction::ModifyHeader { name, value })
        }
        "log" => {
            let msg = args.first().cloned().unwrap_or_default();
            Some(LuaAction::Log { message: msg })
        }
        _ => None,
    }
}

/// `name(...)` çağrısını `(name, içerik)` olarak ayır.
fn split_call(s: &str) -> Option<(String, &str)> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close <= open {
        return None;
    }
    Some((s[..open].trim().to_string(), &s[open + 1..close]))
}

/// Virgülle ayrılmış argümanları parse et — string'lerin içindeki virgülleri yutmaz.
fn parse_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_str = false;
    let mut escape = false;
    for c in s.chars() {
        if escape {
            current.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' if in_str => escape = true,
            '"' => {
                in_str = !in_str;
                // Tırnağı string içeriğine alma; biz unquoted argüman üreteceğiz.
            }
            ',' if !in_str => {
                out.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(path: &str) -> RequestContext {
        RequestContext {
            method: "GET".to_string(),
            path: path.to_string(),
            ip: "127.0.0.1".to_string(),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn parses_string_with_commas() {
        let args = parse_args(r#""hello, world", 200"#);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "hello, world");
        assert_eq!(args[1], "200");
    }

    #[test]
    fn reject_action() {
        let mut e = LuaEngine::new(true);
        e.load_script(
            "blocker".to_string(),
            r#"reject(403, "no")"#.to_string(),
            LuaHook::OnRequest,
        );
        let acts = e.execute_on_request(&ctx("/foo"));
        assert!(matches!(acts[0], LuaAction::Reject { status: 403, .. }));
    }

    #[test]
    fn if_path_then_reject() {
        let mut e = LuaEngine::new(true);
        e.load_script(
            "path-block".to_string(),
            r#"if path == "/blocked" then reject(403, "no")"#.to_string(),
            LuaHook::OnRequest,
        );
        let blocked = e.execute_on_request(&ctx("/blocked"));
        assert!(matches!(blocked[0], LuaAction::Reject { .. }));
        let allowed = e.execute_on_request(&ctx("/ok"));
        assert!(matches!(allowed[0], LuaAction::Continue));
    }

    #[test]
    fn comments_skipped() {
        let mut e = LuaEngine::new(true);
        e.load_script(
            "with-comment".to_string(),
            "-- this is a comment\nlog(\"hello\")".to_string(),
            LuaHook::OnRequest,
        );
        let acts = e.execute_on_request(&ctx("/x"));
        assert!(matches!(acts[0], LuaAction::Log { .. }));
    }
}
