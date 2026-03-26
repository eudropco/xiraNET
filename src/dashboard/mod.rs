use actix_web::{HttpResponse, HttpRequest};

/// Embedded Web Dashboard HTML
pub async fn dashboard_handler(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xiraNET Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e17;--card:#111827;--border:#1e293b;--accent:#6366f1;--accent2:#8b5cf6;--text:#e2e8f0;--text2:#94a3b8;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--blue:#3b82f6}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:linear-gradient(135deg,#0f172a,#1e1b4b);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:1.5rem;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:800}
.header .status{display:flex;align-items:center;gap:.5rem;font-size:.85rem;color:var(--green)}
.header .status::before{content:'';width:8px;height:8px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.container{max-width:1400px;margin:0 auto;padding:1.5rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card .label{color:var(--text2);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}
.stat-card .value{font-size:2rem;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat-card .sub{color:var(--text2);font-size:.75rem;margin-top:.25rem}
.section{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:1.5rem;overflow:hidden}
.section-header{padding:1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.section-header h2{font-size:1rem;font-weight:600}
.section-header .badge{background:var(--accent);color:#fff;padding:.15rem .5rem;border-radius:6px;font-size:.75rem}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.75rem 1.25rem;color:var(--text2);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
td{padding:.75rem 1.25rem;border-bottom:1px solid var(--border);font-size:.9rem}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(99,102,241,.05)}
.status-badge{display:inline-flex;align-items:center;gap:.35rem;padding:.2rem .6rem;border-radius:6px;font-size:.75rem;font-weight:600}
.status-up{background:rgba(16,185,129,.15);color:var(--green)}
.status-down{background:rgba(239,68,68,.15);color:var(--red)}
.status-unknown{background:rgba(245,158,11,.15);color:var(--yellow)}
.btn{padding:.5rem 1rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-size:.85rem;transition:all .2s}
.btn:hover{border-color:var(--accent);background:rgba(99,102,241,.1)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2)}
.btn-danger{border-color:var(--red);color:var(--red)}
.btn-danger:hover{background:rgba(239,68,68,.1)}
.actions{display:flex;gap:.5rem}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal.active{display:flex}
.modal-content{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;width:90%;max-width:500px}
.modal-content h3{margin-bottom:1rem;font-size:1.1rem}
.form-group{margin-bottom:1rem}
.form-group label{display:block;color:var(--text2);font-size:.8rem;margin-bottom:.35rem}
.form-group input{width:100%;padding:.6rem .8rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.9rem}
.form-group input:focus{outline:none;border-color:var(--accent)}
.modal-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:1.5rem}
.logs{max-height:300px;overflow-y:auto;padding:1rem 1.25rem;font-family:'JetBrains Mono',monospace;font-size:.8rem;line-height:1.6}
.log-entry{color:var(--text2);border-left:2px solid var(--border);padding-left:.75rem;margin-bottom:.5rem}
.log-entry .time{color:var(--blue);margin-right:.5rem}
.log-entry.error{border-color:var(--red)}
.log-entry.success{border-color:var(--green)}
#apiKeyInput{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;z-index:200}
#apiKeyInput .inner{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;width:90%;max-width:400px;text-align:center}
#apiKeyInput h2{margin-bottom:1rem;font-size:1.2rem}
#apiKeyInput input{width:100%;padding:.8rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:1rem;text-align:center;margin-bottom:1rem}
.refresh-bar{display:flex;align-items:center;gap:1rem;margin-bottom:1rem;color:var(--text2);font-size:.8rem}
.refresh-bar select{background:var(--card);border:1px solid var(--border);color:var(--text);padding:.3rem .5rem;border-radius:6px;font-size:.8rem}
</style>
</head>
<body>
<div id="apiKeyInput">
<div class="inner">
<h2>🔐 xiraNET Dashboard</h2>
<p style="color:var(--text2);margin-bottom:1rem;font-size:.9rem">Enter your Admin API Key</p>
<input type="password" id="keyInput" placeholder="API Key" autofocus>
<button class="btn btn-primary" style="width:100%" onclick="authenticate()">Connect</button>
</div>
</div>
<header class="header">
<h1>⚡ xiraNET</h1>
<div class="status"><span>Gateway Online</span></div>
</header>
<div class="container">
<div class="refresh-bar">
<span>Auto-refresh:</span>
<select id="refreshInterval" onchange="setRefresh(this.value)">
<option value="0">Off</option>
<option value="5" selected>5s</option>
<option value="10">10s</option>
<option value="30">30s</option>
</select>
<span id="lastUpdate" style="margin-left:auto"></span>
</div>
<div class="stats" id="statsGrid"></div>
<div class="section">
<div class="section-header">
<h2>📡 Registered Services</h2>
<button class="btn btn-primary" onclick="showAddModal()">+ Add Service</button>
</div>
<table>
<thead><tr><th>Status</th><th>Name</th><th>Prefix</th><th>Upstream</th><th>Requests</th><th>Actions</th></tr></thead>
<tbody id="servicesTable"></tbody>
</table>
</div>
<div class="section">
<div class="section-header"><h2>📋 Recent Events</h2><span class="badge" id="eventCount">0</span></div>
<div class="logs" id="eventsLog"></div>
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
let API_KEY='',BASE='',refreshTimer=null;
function authenticate(){API_KEY=document.getElementById('keyInput').value;BASE=window.location.origin;document.getElementById('apiKeyInput').style.display='none';loadAll();setRefresh(document.getElementById('refreshInterval').value)}
function api(path,opts={}){return fetch(BASE+path,{...opts,headers:{'X-Api-Key':API_KEY,'Content-Type':'application/json',...(opts.headers||{})}}).then(r=>r.json())}
function loadAll(){loadStats();loadServices();loadEvents();document.getElementById('lastUpdate').textContent='Updated: '+new Date().toLocaleTimeString()}
function loadStats(){api('/xira/stats').then(d=>{if(!d.data)return;const s=d.data;document.getElementById('statsGrid').innerHTML=`
<div class="stat-card"><div class="label">Services</div><div class="value">${s.total_services}</div></div>
<div class="stat-card"><div class="label">🟢 Up</div><div class="value">${s.services_up}</div></div>
<div class="stat-card"><div class="label">🔴 Down</div><div class="value">${s.services_down}</div></div>
<div class="stat-card"><div class="label">Total Requests</div><div class="value">${s.total_requests.toLocaleString()}</div></div>
<div class="stat-card"><div class="label">Uptime</div><div class="value">${formatUptime(s.uptime_seconds)}</div></div>
<div class="stat-card"><div class="label">⚪ Unknown</div><div class="value">${s.services_unknown}</div></div>`})}
function loadServices(){api('/xira/services').then(d=>{if(!d.data)return;const tbody=document.getElementById('servicesTable');tbody.innerHTML=d.data.services.map(s=>`<tr>
<td><span class="status-badge status-${s.status.toLowerCase()}">${s.status==='Up'?'🟢':'status'==='Down'?'🔴':'⚪'} ${s.status}</span></td>
<td><strong>${s.name}</strong></td><td><code>${s.prefix}</code></td><td>${s.upstream}</td>
<td>${s.request_count.toLocaleString()}</td>
<td><div class="actions"><button class="btn btn-danger" onclick="removeSvc('${s.id}')">Remove</button></div></td></tr>`).join('')})}
function loadEvents(){api('/xira/events').then(d=>{if(!d.data)return;const el=document.getElementById('eventsLog');const events=d.data.events||[];document.getElementById('eventCount').textContent=events.length;el.innerHTML=events.slice(0,50).map(e=>`<div class="log-entry ${e.event_type.includes('down')?'error':e.event_type.includes('up')?'success':''}"><span class="time">${new Date(e.timestamp).toLocaleTimeString()}</span>${e.message}</div>`).join('')}).catch(()=>{})}
function addService(){const n=document.getElementById('svcName').value,p=document.getElementById('svcPrefix').value,u=document.getElementById('svcUpstream').value;if(!n||!p||!u)return;api('/xira/services',{method:'POST',body:JSON.stringify({name:n,prefix:p,upstream:u,health_endpoint:'/health'})}).then(()=>{hideAddModal();loadAll()})}
function removeSvc(id){if(!confirm('Remove this service?'))return;api('/xira/services/'+id,{method:'DELETE'}).then(()=>loadAll())}
function showAddModal(){document.getElementById('addModal').classList.add('active')}
function hideAddModal(){document.getElementById('addModal').classList.remove('active')}
function setRefresh(secs){if(refreshTimer)clearInterval(refreshTimer);if(secs>0)refreshTimer=setInterval(loadAll,secs*1000)}
function formatUptime(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h>0?`${h}h ${m}m`:`${m}m ${s%60}s`}
document.getElementById('keyInput').addEventListener('keypress',e=>{if(e.key==='Enter')authenticate()});
</script>
</body>
</html>"#;
