use actix_web::{HttpResponse, HttpRequest, web};
use tokio::sync::RwLock;
use std::sync::Arc;
use crate::config::XiraConfig;

/// Embedded Web Dashboard v2.1 — Theme toggle + Service detail + Latency + Upstream badges
pub async fn dashboard_handler(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(DASHBOARD_HTML)
}

/// Authenticated WebSocket handler for dashboard live updates
/// Requires `?token=<api_key>` query param to connect
pub async fn ws_dashboard_handler(
    req: HttpRequest,
    stream: web::Payload,
    config: web::Data<Arc<RwLock<XiraConfig>>>,
    registry: web::Data<crate::registry::ServiceRegistry>,
    start_time: web::Data<std::time::Instant>,
) -> Result<HttpResponse, actix_web::Error> {
    // Auth check: validate token query param against admin API key
    let query = req.query_string();
    let token = query.split('&')
        .find(|p| p.starts_with("token="))
        .and_then(|p| p.strip_prefix("token="))
        .unwrap_or("");

    {
        let cfg = config.read().await;
        if token.is_empty() || token != cfg.admin.api_key {
            return Ok(HttpResponse::Unauthorized().json(
                serde_json::json!({"error": "Missing or invalid token. Use ?token=<api_key>"})
            ));
        }
    }

    let (response, mut session, _msg_stream) = actix_ws::handle(&req, stream)?;

    let registry = registry.into_inner();
    let start = *start_time.into_inner();

    actix_rt::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            let services = registry.list_all();
            let up = services.iter().filter(|s| s.status == crate::registry::models::ServiceStatus::Up).count();
            let total_requests: u64 = services.iter().map(|s| s.request_count).sum();
            let uptime = start.elapsed().as_secs();

            let payload = serde_json::json!({
                "type": "stats",
                "data": {
                    "total_services": services.len(),
                    "services_up": up,
                    "services_down": services.len() - up,
                    "total_requests": total_requests,
                    "uptime_seconds": uptime,
                }
            });

            if session.text(payload.to_string()).await.is_err() {
                break;
            }
        }
    });

    Ok(response)
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XIRA Platform Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
[data-theme="dark"]{--bg:#0a0e17;--card:#111827;--border:#1e293b;--accent:#6366f1;--accent2:#8b5cf6;--text:#e2e8f0;--text2:#94a3b8;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--blue:#3b82f6;--hover:rgba(99,102,241,.05)}
[data-theme="light"]{--bg:#f1f5f9;--card:#ffffff;--border:#e2e8f0;--accent:#4f46e5;--accent2:#7c3aed;--text:#1e293b;--text2:#64748b;--green:#059669;--red:#dc2626;--yellow:#d97706;--blue:#2563eb;--hover:rgba(79,70,229,.05)}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background .3s,color .3s}
.header{background:linear-gradient(135deg,#0f172a,#1e1b4b);border-bottom:1px solid var(--border);padding:.8rem 2rem;display:flex;align-items:center;justify-content:space-between}
[data-theme="light"] .header{background:linear-gradient(135deg,#e0e7ff,#c7d2fe)}
.header h1{font-size:1.4rem;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:800}
.header-right{display:flex;align-items:center;gap:1rem}
.header .status{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:var(--green)}
.header .status::before{content:'';width:7px;height:7px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
.ws-badge{font-size:.65rem;padding:.1rem .35rem;border-radius:4px;font-weight:600}
.ws-connected{background:rgba(16,185,129,.2);color:var(--green)}
.ws-disconnected{background:rgba(239,68,68,.2);color:var(--red)}
.theme-toggle{background:var(--card);border:1px solid var(--border);color:var(--text);padding:.3rem .6rem;border-radius:6px;cursor:pointer;font-size:.8rem;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.container{max-width:1400px;margin:0 auto;padding:1.2rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.8rem;margin-bottom:1.2rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem;transition:all .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card .label{color:var(--text2);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.4rem}
.stat-card .value{font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem;margin-bottom:1.2rem}
@media(max-width:900px){.grid-2{grid-template-columns:1fr}}
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:1.2rem;overflow:hidden}
.section-header{padding:.8rem 1rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.section-header h2{font-size:.9rem;font-weight:600}
.section-header .badge{background:var(--accent);color:#fff;padding:.1rem .4rem;border-radius:5px;font-size:.7rem}
.chart-container{padding:.8rem;height:200px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.5rem 1rem;color:var(--text2);font-size:.65rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
td{padding:.5rem 1rem;border-bottom:1px solid var(--border);font-size:.8rem}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--hover)}
tr{cursor:pointer}
.status-badge{display:inline-flex;align-items:center;gap:.25rem;padding:.1rem .4rem;border-radius:5px;font-size:.65rem;font-weight:600}
.status-up{background:rgba(16,185,129,.15);color:var(--green)}
.status-down{background:rgba(239,68,68,.15);color:var(--red)}
.status-unknown{background:rgba(245,158,11,.15);color:var(--yellow)}
.cb-closed{color:var(--green)}.cb-open{color:var(--red)}.cb-half{color:var(--yellow)}
.btn{padding:.35rem .7rem;border-radius:6px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-size:.75rem;transition:all .2s}
.btn:hover{border-color:var(--accent);background:var(--hover)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-danger{border-color:var(--red);color:var(--red)}
.actions{display:flex;gap:.3rem}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal.active{display:flex}
.modal-content{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.5rem;width:90%;max-width:500px}
.modal-content h3{margin-bottom:.8rem;font-size:1rem}
.form-group{margin-bottom:.6rem}
.form-group label{display:block;color:var(--text2);font-size:.75rem;margin-bottom:.25rem}
.form-group input{width:100%;padding:.4rem .6rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.8rem}
.form-group input:focus{outline:none;border-color:var(--accent)}
.modal-actions{display:flex;gap:.4rem;justify-content:flex-end;margin-top:1rem}
.logs{max-height:220px;overflow-y:auto;padding:.8rem;font-family:'JetBrains Mono',monospace;font-size:.7rem;line-height:1.4}
.log-entry{color:var(--text2);border-left:2px solid var(--border);padding-left:.5rem;margin-bottom:.3rem}
.log-entry .time{color:var(--blue);margin-right:.3rem}
.log-entry.error{border-color:var(--red)}.log-entry.success{border-color:var(--green)}
#apiKeyInput{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;z-index:200}
#apiKeyInput .inner{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.5rem;width:90%;max-width:360px;text-align:center}
#apiKeyInput h2{margin-bottom:.8rem;font-size:1.1rem}
#apiKeyInput input{width:100%;padding:.7rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.9rem;text-align:center;margin-bottom:.8rem}
.feature-tag{padding:.1rem .35rem;border-radius:4px;font-size:.6rem;font-weight:600;background:rgba(99,102,241,.15);color:var(--accent);display:inline-block;margin:.1rem}
.detail-panel{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;margin:.8rem;display:none}
.detail-panel.active{display:block}
.detail-panel h4{margin-bottom:.5rem;font-size:.85rem}
.detail-row{display:flex;justify-content:space-between;padding:.2rem 0;font-size:.75rem;border-bottom:1px solid var(--border)}
.detail-row:last-child{border-bottom:none}
.detail-label{color:var(--text2)}
.latency-badge{font-size:.65rem;padding:.1rem .3rem;border-radius:3px;font-weight:600}
.latency-fast{background:rgba(16,185,129,.15);color:var(--green)}
.latency-mid{background:rgba(245,158,11,.15);color:var(--yellow)}
.latency-slow{background:rgba(239,68,68,.15);color:var(--red)}
</style>
</head>
<body>
<div id="apiKeyInput">
<div class="inner">
<h2>🔐 XIRA Platform Dashboard</h2>
<p style="color:var(--text2);margin-bottom:.8rem;font-size:.8rem">Enter your Admin API Key</p>
<input type="password" id="keyInput" placeholder="API Key" autofocus>
<button class="btn btn-primary" style="width:100%" onclick="authenticate()">Connect</button>
</div>
</div>
<header class="header">
<h1>⚡ XIRA</h1>
<div class="header-right">
<div class="status"><span>Online</span><span class="ws-badge ws-disconnected" id="wsBadge">WS: —</span></div>
<button class="theme-toggle" onclick="toggleTheme()" id="themeBtn">🌙</button>
</div>
</header>
<div class="container">
<div class="stats" id="statsGrid"></div>
<div class="grid-2">
<div class="section">
<div class="section-header"><h2>📈 Request Rate</h2><span class="badge" id="rpsLabel">0 req/s</span></div>
<div class="chart-container"><canvas id="reqChart"></canvas></div>
</div>
<div class="section">
<div class="section-header"><h2>🛡️ Circuit Breakers</h2></div>
<table>
<thead><tr><th>Service</th><th>State</th><th>Failures</th></tr></thead>
<tbody id="cbTable"><tr><td colspan="3" style="text-align:center;color:var(--text2)">Loading...</td></tr></tbody>
</table>
</div>
</div>
<div class="section">
<div class="section-header">
<h2>📡 Services</h2>
<button class="btn btn-primary" onclick="showAddModal()">+ Add</button>
</div>
<table>
<thead><tr><th>Status</th><th>Name</th><th>Prefix</th><th>Upstream</th><th>Requests</th><th>Actions</th></tr></thead>
<tbody id="servicesTable"></tbody>
</table>
<div class="detail-panel" id="detailPanel">
<h4 id="detailName">Service Detail</h4>
<div id="detailContent"></div>
</div>
</div>
<div class="grid-2">
<div class="section">
<div class="section-header"><h2>📋 Events</h2><span class="badge" id="eventCount">0</span></div>
<div class="logs" id="eventsLog"></div>
</div>
<div class="section">
<div class="section-header"><h2>🔧 Info</h2></div>
<div style="padding:.8rem" id="featuresPanel"></div>
</div>
</div>
<!-- v2.0.0 Panels -->
<div class="grid-2">
<div class="section">
<div class="section-header"><h2>🛡️ Security</h2></div>
<div style="padding:.8rem" id="securityPanel"><span style="color:var(--text2);font-size:.8rem">Loading...</span></div>
</div>
<div class="section">
<div class="section-header"><h2>📊 SLA Monitor</h2></div>
<div style="padding:.8rem" id="slaPanel"><span style="color:var(--text2);font-size:.8rem">Loading...</span></div>
</div>
</div>
<div class="grid-2">
<div class="section">
<div class="section-header"><h2>🌐 Uptime Status</h2><span class="badge" id="uptimeStatus">—</span></div>
<table>
<thead><tr><th>Service</th><th>Status</th><th>Uptime</th><th>Response</th></tr></thead>
<tbody id="uptimeTable"><tr><td colspan="4" style="text-align:center;color:var(--text2)">Loading...</td></tr></tbody>
</table>
</div>
<div class="section">
<div class="section-header"><h2>🚨 Active Incidents</h2><span class="badge" id="incidentCount">0</span></div>
<div style="padding:.8rem" id="incidentsPanel"><span style="color:var(--text2);font-size:.8rem">No incidents</span></div>
</div>
</div>
<!-- v3.0.0 — Platform Crates Panel -->
<div class="section">
<div class="section-header"><h2>📦 Platform Crates</h2><span class="badge" style="background:rgba(139,92,246,.2);color:#a78bfa">v3.0</span></div>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.6rem;padding:.8rem" id="cratesPanel">
<div class="crate-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:.5rem;padding:.75rem">
<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem"><span style="color:#22c55e">●</span><strong style="font-size:.85rem">xira-common</strong></div>
<div style="font-size:.7rem;color:var(--text2)">Storage · Config · Models</div>
<div style="font-size:.65rem;color:var(--text2);margin-top:.2rem">Foundation layer</div>
</div>
<div class="crate-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:.5rem;padding:.75rem">
<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem"><span style="color:#22c55e">●</span><strong style="font-size:.85rem">xira-security</strong></div>
<div style="font-size:.7rem;color:var(--text2)">WAF · Bot Detection · Audit</div>
<div style="font-size:.65rem;color:var(--text2);margin-top:.2rem">5 modules</div>
</div>
<div class="crate-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:.5rem;padding:.75rem">
<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem"><span style="color:#22c55e">●</span><strong style="font-size:.85rem">xira-auth</strong></div>
<div style="font-size:.7rem;color:var(--text2)">Users · Sessions · OAuth2</div>
<div style="font-size:.65rem;color:var(--text2);margin-top:.2rem">4 modules</div>
</div>
<div class="crate-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:.5rem;padding:.75rem">
<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem"><span style="color:#22c55e">●</span><strong style="font-size:.85rem">xira-ops</strong></div>
<div style="font-size:.7rem;color:var(--text2)">Metrics · SLA · Uptime · Alerts</div>
<div style="font-size:.65rem;color:var(--text2);margin-top:.2rem">10 modules</div>
</div>
<div class="crate-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:.5rem;padding:.75rem">
<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem"><span style="color:#22c55e">●</span><strong style="font-size:.85rem">xira-flow</strong></div>
<div style="font-size:.7rem;color:var(--text2)">Cron · Events · Workflows</div>
<div style="font-size:.65rem;color:var(--text2);margin-top:.2rem">5 modules</div>
</div>
<div class="crate-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:.5rem;padding:.75rem">
<div style="display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem"><span style="color:#22c55e">●</span><strong style="font-size:.85rem">xira-gateway</strong></div>
<div style="font-size:.7rem;color:var(--text2)">Proxy · Cache · LB · Circuit</div>
<div style="font-size:.65rem;color:var(--text2);margin-top:.2rem">14 modules</div>
</div>
</div>
</div>
<div class="section">
<div class="section-header"><h2>📈 Advanced Metrics</h2></div>
<table>
<thead><tr><th>Service</th><th>Requests</th><th>Error Rate</th><th>2xx</th><th>5xx</th><th>Bandwidth In</th></tr></thead>
<tbody id="metricsTable"><tr><td colspan="6" style="text-align:center;color:var(--text2)">Loading...</td></tr></tbody>
</table>
</div>
</div>
<div class="modal" id="addModal">
<div class="modal-content">
<h3>Add New Service</h3>
<div class="form-group"><label>Service Name</label><input id="svcName" placeholder="my-api"></div>
<div class="form-group"><label>URL Prefix</label><input id="svcPrefix" placeholder="/api"></div>
<div class="form-group"><label>Upstream URL</label><input id="svcUpstream" placeholder="http://localhost:3001"></div>
<div class="modal-actions">
<button class="btn" onclick="hideAddModal()">Cancel</button>
<button class="btn btn-primary" onclick="addService()">Register</button>
</div></div></div>
<script>
let API_KEY='',BASE='',ws=null,reqChart=null,lastTotal=0,allServices=[];
const MAX_POINTS=60;

function authenticate(){
  API_KEY=document.getElementById('keyInput').value;
  BASE=window.location.origin;
  document.getElementById('apiKeyInput').style.display='none';
  initChart();loadAll();connectWS();setInterval(loadAll,5000);
}

function api(path,opts={}){
  return fetch(BASE+path,{...opts,headers:{'X-Api-Key':API_KEY,'Content-Type':'application/json',...(opts.headers||{})}}).then(r=>r.json()).catch(()=>({}));
}

function connectWS(){
  try{
    const proto=location.protocol==='https:'?'wss:':'ws:';
    ws=new WebSocket(`${proto}//${location.host}/ws/dashboard?token=${encodeURIComponent(API_KEY)}`);
    ws.onopen=()=>{document.getElementById('wsBadge').className='ws-badge ws-connected';document.getElementById('wsBadge').textContent='WS: Live'};
    ws.onclose=()=>{document.getElementById('wsBadge').className='ws-badge ws-disconnected';document.getElementById('wsBadge').textContent='WS: Off';setTimeout(connectWS,5000)};
    ws.onmessage=(e)=>{try{const d=JSON.parse(e.data);if(d.type==='stats')updateStats(d.data)}catch(err){}};
  }catch(e){}
}

function toggleTheme(){
  const html=document.documentElement;
  const current=html.getAttribute('data-theme');
  const next=current==='dark'?'light':'dark';
  html.setAttribute('data-theme',next);
  document.getElementById('themeBtn').textContent=next==='dark'?'🌙':'☀️';
  localStorage.setItem('xira-theme',next);
  if(reqChart){reqChart.options.scales.y.grid.color=next==='dark'?'#1e293b':'#e2e8f0';reqChart.options.scales.y.ticks.color=next==='dark'?'#94a3b8':'#64748b';reqChart.update('none')}
}
(function(){const t=localStorage.getItem('xira-theme');if(t){document.documentElement.setAttribute('data-theme',t);document.addEventListener('DOMContentLoaded',()=>{document.getElementById('themeBtn').textContent=t==='dark'?'🌙':'☀️'})}})();

function initChart(){
  const ctx=document.getElementById('reqChart').getContext('2d');
  const isDark=document.documentElement.getAttribute('data-theme')==='dark';
  reqChart=new Chart(ctx,{type:'line',data:{labels:Array(MAX_POINTS).fill(''),datasets:[{label:'req/s',data:Array(MAX_POINTS).fill(0),borderColor:'#6366f1',backgroundColor:'rgba(99,102,241,.1)',fill:true,tension:.4,pointRadius:0,borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{display:false},y:{beginAtZero:true,grid:{color:isDark?'#1e293b':'#e2e8f0'},ticks:{color:isDark?'#94a3b8':'#64748b',font:{size:10}}}}}});
}

function loadAll(){loadStats();loadServices();loadEvents();loadCBs();loadConfig();loadSecurity();loadUptime();loadIncidents();loadSLA();loadAdvMetrics()}

function loadStats(){api('/xira/stats').then(d=>{if(d&&d.data)updateStats(d.data)})}

function updateStats(s){
  const rps=lastTotal>0?Math.max(0,s.total_requests-lastTotal)/5:0;lastTotal=s.total_requests;
  if(reqChart){reqChart.data.datasets[0].data.push(rps);if(reqChart.data.datasets[0].data.length>MAX_POINTS)reqChart.data.datasets[0].data.shift();reqChart.data.labels.push('');if(reqChart.data.labels.length>MAX_POINTS)reqChart.data.labels.shift();reqChart.update('none')}
  document.getElementById('rpsLabel').textContent=rps.toFixed(1)+' req/s';
  document.getElementById('statsGrid').innerHTML=`
<div class="stat-card"><div class="label">Services</div><div class="value">${s.total_services}</div></div>
<div class="stat-card"><div class="label">🟢 Up</div><div class="value">${s.services_up}</div></div>
<div class="stat-card"><div class="label">🔴 Down</div><div class="value">${s.services_down}</div></div>
<div class="stat-card"><div class="label">Requests</div><div class="value">${s.total_requests.toLocaleString()}</div></div>
<div class="stat-card"><div class="label">Uptime</div><div class="value">${formatUptime(s.uptime_seconds)}</div></div>`;
}

function loadServices(){api('/xira/services').then(d=>{if(!d||!d.data)return;allServices=d.data.services||[];
document.getElementById('servicesTable').innerHTML=allServices.map(s=>`<tr onclick="showDetail('${s.id}')">
<td><span class="status-badge status-${s.status.toLowerCase()}">${s.status==='Up'?'🟢':s.status==='Down'?'🔴':'⚪'} ${s.status}</span></td>
<td><strong>${s.name}</strong></td><td><code>${s.prefix}</code></td><td>${s.upstream}</td>
<td>${s.request_count.toLocaleString()}</td>
<td><div class="actions"><button class="btn btn-danger" onclick="event.stopPropagation();removeSvc('${s.id}')">✕</button></div></td></tr>`).join('')})}

function showDetail(id){
  const svc=allServices.find(s=>s.id===id);if(!svc)return;
  const panel=document.getElementById('detailPanel');
  document.getElementById('detailName').textContent=svc.name+' — Detail';
  document.getElementById('detailContent').innerHTML=`
<div class="detail-row"><span class="detail-label">ID</span><span>${svc.id}</span></div>
<div class="detail-row"><span class="detail-label">Prefix</span><span>${svc.prefix}</span></div>
<div class="detail-row"><span class="detail-label">Upstream</span><span>${svc.upstream} <span class="status-badge status-${svc.status.toLowerCase()}">${svc.status}</span></span></div>
<div class="detail-row"><span class="detail-label">Requests</span><span>${svc.request_count.toLocaleString()}</span></div>
<div class="detail-row"><span class="detail-label">Version</span><span>${svc.version||'default'}</span></div>
<div class="detail-row"><span class="detail-label">Load Balance</span><span>${svc.load_balance||'round-robin'}</span></div>
<div class="detail-row"><span class="detail-label">Health Endpoint</span><span>${svc.health_endpoint||'/health'}</span></div>`;
  panel.classList.add('active');
}

function loadEvents(){api('/xira/events').then(d=>{if(!d||!d.data)return;const events=d.data.events||[];document.getElementById('eventCount').textContent=events.length;document.getElementById('eventsLog').innerHTML=events.slice(0,25).map(e=>`<div class="log-entry ${e.event_type.includes('down')?'error':e.event_type.includes('up')?'success':''}"><span class="time">${new Date(e.timestamp).toLocaleTimeString()}</span>${e.message}</div>`).join('')}).catch(()=>{})}

function loadCBs(){api('/xira/circuit-breakers').then(d=>{if(!d||!d.data)return;const cbs=d.data;if(!cbs.length){document.getElementById('cbTable').innerHTML='<tr><td colspan="3" style="text-align:center;color:var(--text2)">All OK</td></tr>';return}document.getElementById('cbTable').innerHTML=cbs.map(cb=>`<tr><td>${cb.service_id.slice(0,8)}…</td><td class="cb-${cb.state==='CLOSED'?'closed':cb.state==='OPEN'?'open':'half'}">${cb.state}</td><td>${cb.failure_count}</td></tr>`).join('')}).catch(()=>{})}

function loadConfig(){api('/xira/config').then(d=>{if(!d)return;
document.getElementById('featuresPanel').innerHTML=`
<div style="margin-bottom:.4rem;color:var(--text2);font-size:.7rem">Features</div>
<div><span class="feature-tag">Compression</span><span class="feature-tag">Prometheus</span><span class="feature-tag">SQLite</span><span class="feature-tag">Request-ID</span>${d.cache&&d.cache.enabled?'<span class="feature-tag">Cache</span>':''}${d.jwt&&d.jwt.enabled?'<span class="feature-tag">JWT</span>':''}</div>
<div style="margin-top:.6rem;font-size:.7rem;color:var(--text2)">v${d.version||'2.0.0'} | <a href="/xira/docs" style="color:var(--accent)">API Docs</a> | <a href="/metrics" style="color:var(--accent)">Metrics</a> | <a href="/xira/observability/uptime" style="color:var(--accent)">Status Page</a></div>`}).catch(()=>{})}

function loadSecurity(){
  Promise.all([api('/xira/security/waf'),api('/xira/security/bots'),api('/xira/security/audit?limit=5')]).then(([waf,bots,audit])=>{
    const w=waf?.waf||{};const b=bots?.bots||{};const a=audit?.stats||{};
    document.getElementById('securityPanel').innerHTML=`
<div class="detail-row"><span class="detail-label">WAF</span><span><span class="status-badge ${w.enabled?'status-up':'status-down'}">${w.enabled?'Active':'Off'}</span> Mode: ${w.mode||'—'}</span></div>
<div class="detail-row"><span class="detail-label">Bot Detector</span><span>Tracked: ${b.total_tracked_ips||0} | Bots: ${b.detected_bots||0} | Humans: ${b.humans||0}</span></div>
<div class="detail-row"><span class="detail-label">Audit Log</span><span>Total: ${a.total||0} | Unique IPs: ${a.unique_ips||0}</span></div>`;
  }).catch(()=>{})}

function loadUptime(){
  api('/xira/observability/uptime').then(d=>{
    if(!d)return;
    document.getElementById('uptimeStatus').textContent=d.status||'—';
    const svcs=d.services||[];
    document.getElementById('uptimeTable').innerHTML=svcs.length?svcs.map(s=>`<tr>
<td>${s.name}</td>
<td><span class="status-badge ${s.status==='Operational'?'status-up':'status-down'}">${s.status}</span></td>
<td>${s.uptime}</td>
<td><span class="latency-badge ${s.response_ms<100?'latency-fast':s.response_ms<500?'latency-mid':'latency-slow'}">${s.response_ms?.toFixed(0)||'—'}ms</span></td>
</tr>`).join(''):'<tr><td colspan="4" style="text-align:center;color:var(--text2)">No services monitored</td></tr>';
  }).catch(()=>{})}

function loadIncidents(){
  api('/xira/observability/incidents').then(d=>{
    if(!d)return;
    const active=d.active||[];
    document.getElementById('incidentCount').textContent=d.active_count||0;
    document.getElementById('incidentsPanel').innerHTML=active.length?active.map(i=>`
<div style="border:1px solid var(--border);border-radius:6px;padding:.5rem;margin-bottom:.4rem">
<div style="display:flex;justify-content:space-between;align-items:center">
<strong style="font-size:.8rem">${i.title}</strong>
<span class="status-badge ${i.severity==='Critical'?'status-down':i.severity==='Major'?'status-down':'status-unknown'}">${i.severity}</span>
</div>
<div style="font-size:.7rem;color:var(--text2);margin-top:.2rem">Status: ${i.status} | Services: ${(i.affected_services||[]).join(', ')}</div>
</div>`).join(''):'<span style="color:var(--text2);font-size:.8rem">✅ No active incidents</span>';
  }).catch(()=>{})}

function loadSLA(){
  api('/xira/sla').then(d=>{
    if(!d)return;
    const metrics=d.sla||[];
    const violations=d.violations||[];
    document.getElementById('slaPanel').innerHTML=metrics.length?metrics.map(m=>`
<div class="detail-row"><span class="detail-label">${m.service_name}</span>
<span>Uptime: <strong style="color:${m.uptime_percent<99.9?'var(--red)':'var(--green)'}">${m.uptime_percent?.toFixed(2)}%</strong> | P99: ${m.latency_p99?.toFixed(0)}ms | Checks: ${m.total_checks} | Violations: ${m.sla_violations}</span>
</div>`).join('')+(violations.length?'<div style="margin-top:.4rem;font-size:.7rem;color:var(--red)">⚠️ '+violations.map(v=>v[0]+': '+v[1]).join(' | ')+'</div>':''):'<span style="color:var(--text2);font-size:.8rem">No SLA data yet</span>';
  }).catch(()=>{})}

function loadAdvMetrics(){
  api('/xira/advanced-metrics').then(d=>{
    if(!d)return;
    const svcs=d.services||[];
    document.getElementById('metricsTable').innerHTML=svcs.length?svcs.map(s=>`<tr>
<td><strong>${s.service}</strong></td>
<td>${(s.requests||0).toLocaleString()}</td>
<td><span style="color:${(s.error_rate||0)<0.05?'var(--green)':'var(--red)'}">${((s.error_rate||0)*100).toFixed(1)}%</span></td>
<td style="color:var(--green)">${s['2xx']||0}</td>
<td style="color:var(--red)">${s['5xx']||0}</td>
<td>${formatBytes(s.bytes_in||0)}</td>
</tr>`).join(''):'<tr><td colspan="6" style="text-align:center;color:var(--text2)">No traffic yet</td></tr>';
  }).catch(()=>{})}

function formatBytes(b){if(!b)return '0 B';const k=1024;const s=['B','KB','MB','GB'];const i=Math.floor(Math.log(b)/Math.log(k));return (b/Math.pow(k,i)).toFixed(1)+' '+s[i]}

function addService(){const n=document.getElementById('svcName').value,p=document.getElementById('svcPrefix').value,u=document.getElementById('svcUpstream').value;if(!n||!p||!u)return;api('/xira/services',{method:'POST',body:JSON.stringify({name:n,prefix:p,upstream:u,health_endpoint:'/health'})}).then(()=>{hideAddModal();loadAll()})}
function removeSvc(id){if(!confirm('Remove?'))return;api('/xira/services/'+id,{method:'DELETE'}).then(()=>loadAll())}
function showAddModal(){document.getElementById('addModal').classList.add('active')}
function hideAddModal(){document.getElementById('addModal').classList.remove('active')}
function formatUptime(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h>0?`${h}h ${m}m`:`${m}m ${s%60}s`}
document.getElementById('keyInput').addEventListener('keypress',e=>{if(e.key==='Enter')authenticate()});
</script>
</body>
</html>"#;
