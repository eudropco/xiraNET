use actix_web::{HttpResponse, HttpRequest};

/// Embedded Web Dashboard HTML v2 — WebSocket live updates + Chart.js
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
<title>xiraNET Dashboard v2</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e17;--card:#111827;--border:#1e293b;--accent:#6366f1;--accent2:#8b5cf6;--text:#e2e8f0;--text2:#94a3b8;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--blue:#3b82f6}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:linear-gradient(135deg,#0f172a,#1e1b4b);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:1.5rem;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:800}
.header .status{display:flex;align-items:center;gap:.5rem;font-size:.85rem;color:var(--green)}
.header .status::before{content:'';width:8px;height:8px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
.ws-badge{font-size:.7rem;padding:.15rem .4rem;border-radius:4px;margin-left:.5rem;font-weight:600}
.ws-connected{background:rgba(16,185,129,.2);color:var(--green)}
.ws-disconnected{background:rgba(239,68,68,.2);color:var(--red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.container{max-width:1400px;margin:0 auto;padding:1.5rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card .label{color:var(--text2);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}
.stat-card .value{font-size:1.8rem;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat-card .sub{color:var(--text2);font-size:.7rem;margin-top:.25rem}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem}
@media(max-width:900px){.grid-2{grid-template-columns:1fr}}
.section{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:1.5rem;overflow:hidden}
.section-header{padding:1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.section-header h2{font-size:1rem;font-weight:600}
.section-header .badge{background:var(--accent);color:#fff;padding:.15rem .5rem;border-radius:6px;font-size:.75rem}
.chart-container{padding:1rem;height:220px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.65rem 1.25rem;color:var(--text2);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
td{padding:.65rem 1.25rem;border-bottom:1px solid var(--border);font-size:.85rem}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(99,102,241,.05)}
.status-badge{display:inline-flex;align-items:center;gap:.3rem;padding:.15rem .5rem;border-radius:6px;font-size:.7rem;font-weight:600}
.status-up{background:rgba(16,185,129,.15);color:var(--green)}
.status-down{background:rgba(239,68,68,.15);color:var(--red)}
.status-unknown{background:rgba(245,158,11,.15);color:var(--yellow)}
.cb-closed{color:var(--green)}.cb-open{color:var(--red)}.cb-half{color:var(--yellow)}
.btn{padding:.4rem .8rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-size:.8rem;transition:all .2s}
.btn:hover{border-color:var(--accent);background:rgba(99,102,241,.1)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-danger{border-color:var(--red);color:var(--red)}
.actions{display:flex;gap:.4rem}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal.active{display:flex}
.modal-content{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;width:90%;max-width:500px}
.modal-content h3{margin-bottom:1rem}
.form-group{margin-bottom:.8rem}
.form-group label{display:block;color:var(--text2);font-size:.8rem;margin-bottom:.3rem}
.form-group input{width:100%;padding:.5rem .7rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.85rem}
.form-group input:focus{outline:none;border-color:var(--accent)}
.modal-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:1rem}
.logs{max-height:250px;overflow-y:auto;padding:1rem;font-family:'JetBrains Mono',monospace;font-size:.75rem;line-height:1.5}
.log-entry{color:var(--text2);border-left:2px solid var(--border);padding-left:.5rem;margin-bottom:.4rem}
.log-entry .time{color:var(--blue);margin-right:.4rem}
.log-entry.error{border-color:var(--red)}.log-entry.success{border-color:var(--green)}
#apiKeyInput{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;z-index:200}
#apiKeyInput .inner{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;width:90%;max-width:400px;text-align:center}
#apiKeyInput h2{margin-bottom:1rem}
#apiKeyInput input{width:100%;padding:.8rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:1rem;text-align:center;margin-bottom:1rem}
.feature-tags{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}
.feature-tag{padding:.15rem .4rem;border-radius:4px;font-size:.65rem;font-weight:600;background:rgba(99,102,241,.15);color:var(--accent)}
</style>
</head>
<body>
<div id="apiKeyInput">
<div class="inner">
<h2>🔐 xiraNET Dashboard v2</h2>
<p style="color:var(--text2);margin-bottom:1rem;font-size:.85rem">Enter your Admin API Key</p>
<input type="password" id="keyInput" placeholder="API Key" autofocus>
<button class="btn btn-primary" style="width:100%" onclick="authenticate()">Connect</button>
</div>
</div>
<header class="header">
<h1>⚡ xiraNET v2</h1>
<div>
<div class="status"><span>Gateway Online</span><span class="ws-badge ws-disconnected" id="wsBadge">WS: —</span></div>
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
<thead><tr><th>Service</th><th>State</th><th>Failures</th><th>Since</th></tr></thead>
<tbody id="cbTable"><tr><td colspan="4" style="text-align:center;color:var(--text2)">Loading...</td></tr></tbody>
</table>
</div>
</div>
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
<div class="grid-2">
<div class="section">
<div class="section-header"><h2>📋 Recent Events</h2><span class="badge" id="eventCount">0</span></div>
<div class="logs" id="eventsLog"></div>
</div>
<div class="section">
<div class="section-header"><h2>🔧 Features</h2></div>
<div style="padding:1rem" id="featuresPanel"></div>
</div>
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
let API_KEY='',BASE='',ws=null,reqData=[],reqChart=null;
const MAX_POINTS=60;

function authenticate(){
  API_KEY=document.getElementById('keyInput').value;
  BASE=window.location.origin;
  document.getElementById('apiKeyInput').style.display='none';
  initChart();
  loadAll();
  connectWS();
  setInterval(loadAll,5000);
}

function api(path,opts={}){
  return fetch(BASE+path,{...opts,headers:{'X-Api-Key':API_KEY,'Content-Type':'application/json',...(opts.headers||{})}
  }).then(r=>r.json()).catch(()=>({}));
}

function connectWS(){
  try{
    const proto=location.protocol==='https:'?'wss:':'ws:';
    ws=new WebSocket(`${proto}//${location.host}/ws/dashboard`);
    ws.onopen=()=>{document.getElementById('wsBadge').className='ws-badge ws-connected';document.getElementById('wsBadge').textContent='WS: Live'};
    ws.onclose=()=>{document.getElementById('wsBadge').className='ws-badge ws-disconnected';document.getElementById('wsBadge').textContent='WS: Off';setTimeout(connectWS,5000)};
    ws.onmessage=(e)=>{try{const d=JSON.parse(e.data);handleWSMessage(d)}catch(err){}};
    ws.onerror=()=>{};
  }catch(e){}
}

function handleWSMessage(msg){
  if(msg.type==='stats')updateStats(msg.data);
  if(msg.type==='request')pushReqDataPoint();
}

function initChart(){
  const ctx=document.getElementById('reqChart').getContext('2d');
  reqChart=new Chart(ctx,{
    type:'line',
    data:{labels:Array(MAX_POINTS).fill(''),datasets:[{
      label:'Requests/s',data:Array(MAX_POINTS).fill(0),
      borderColor:'#6366f1',backgroundColor:'rgba(99,102,241,.1)',
      fill:true,tension:.4,pointRadius:0,borderWidth:2
    }]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{x:{display:false},y:{beginAtZero:true,grid:{color:'#1e293b'},ticks:{color:'#94a3b8',font:{size:10}}}}
    }
  });
}

let lastTotal=0;
function pushReqDataPoint(){reqData.push(1);if(reqData.length>MAX_POINTS)reqData.shift()}

function loadAll(){loadStats();loadServices();loadEvents();loadCBs();loadConfig()}

function loadStats(){api('/xira/stats').then(d=>{if(!d.data)return;updateStats(d.data)})}

function updateStats(s){
  const rps=lastTotal>0?Math.max(0,s.total_requests-lastTotal)/5:0;
  lastTotal=s.total_requests;
  if(reqChart){reqChart.data.datasets[0].data.push(rps);if(reqChart.data.datasets[0].data.length>MAX_POINTS)reqChart.data.datasets[0].data.shift();reqChart.data.labels.push('');if(reqChart.data.labels.length>MAX_POINTS)reqChart.data.labels.shift();reqChart.update('none')}
  document.getElementById('rpsLabel').textContent=rps.toFixed(1)+' req/s';
  document.getElementById('statsGrid').innerHTML=`
<div class="stat-card"><div class="label">Services</div><div class="value">${s.total_services}</div></div>
<div class="stat-card"><div class="label">🟢 Up</div><div class="value">${s.services_up}</div></div>
<div class="stat-card"><div class="label">🔴 Down</div><div class="value">${s.services_down}</div></div>
<div class="stat-card"><div class="label">Total Requests</div><div class="value">${s.total_requests.toLocaleString()}</div></div>
<div class="stat-card"><div class="label">Uptime</div><div class="value">${formatUptime(s.uptime_seconds)}</div></div>
<div class="stat-card"><div class="label">⚪ Unknown</div><div class="value">${s.services_unknown}</div></div>`;
}

function loadServices(){api('/xira/services').then(d=>{if(!d.data)return;document.getElementById('servicesTable').innerHTML=d.data.services.map(s=>`<tr>
<td><span class="status-badge status-${s.status.toLowerCase()}">${s.status==='Up'?'🟢':s.status==='Down'?'🔴':'⚪'} ${s.status}</span></td>
<td><strong>${s.name}</strong></td><td><code>${s.prefix}</code></td><td>${s.upstream}</td>
<td>${s.request_count.toLocaleString()}</td>
<td><div class="actions"><button class="btn btn-danger" onclick="removeSvc('${s.id}')">Remove</button></div></td></tr>`).join('')})}

function loadEvents(){api('/xira/events').then(d=>{if(!d.data)return;const events=d.data.events||[];document.getElementById('eventCount').textContent=events.length;document.getElementById('eventsLog').innerHTML=events.slice(0,30).map(e=>`<div class="log-entry ${e.event_type.includes('down')?'error':e.event_type.includes('up')?'success':''}"><span class="time">${new Date(e.timestamp).toLocaleTimeString()}</span>${e.message}</div>`).join('')}).catch(()=>{})}

function loadCBs(){api('/xira/circuit-breakers').then(d=>{if(!d.data)return;const cbs=d.data;if(!cbs.length){document.getElementById('cbTable').innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--text2)">All circuits closed</td></tr>';return}document.getElementById('cbTable').innerHTML=cbs.map(cb=>`<tr><td>${cb.service_id.slice(0,8)}…</td><td class="cb-${cb.state==='CLOSED'?'closed':cb.state==='OPEN'?'open':'half'}">${cb.state}</td><td>${cb.failure_count}</td><td>${cb.since}</td></tr>`).join('')}).catch(()=>{})}

function loadConfig(){api('/xira/config').then(d=>{if(!d)return;const features=[];if(d.cache&&d.cache.enabled)features.push('Cache');if(d.jwt&&d.jwt.enabled)features.push('JWT');document.getElementById('featuresPanel').innerHTML=`
<div style="margin-bottom:.5rem;color:var(--text2);font-size:.8rem">Active Features</div>
<div class="feature-tags">
<span class="feature-tag">Compression</span>
<span class="feature-tag">Prometheus</span>
<span class="feature-tag">SQLite</span>
${features.map(f=>`<span class="feature-tag">${f}</span>`).join('')}
</div>
<div style="margin-top:1rem;color:var(--text2);font-size:.75rem">v${d.version||'1.0.0'} | <a href="/xira/docs" style="color:var(--accent)">API Docs</a> | <a href="/metrics" style="color:var(--accent)">Metrics</a></div>`}).catch(()=>{})}

function addService(){const n=document.getElementById('svcName').value,p=document.getElementById('svcPrefix').value,u=document.getElementById('svcUpstream').value;if(!n||!p||!u)return;api('/xira/services',{method:'POST',body:JSON.stringify({name:n,prefix:p,upstream:u,health_endpoint:'/health'})}).then(()=>{hideAddModal();loadAll()})}
function removeSvc(id){if(!confirm('Remove this service?'))return;api('/xira/services/'+id,{method:'DELETE'}).then(()=>loadAll())}
function showAddModal(){document.getElementById('addModal').classList.add('active')}
function hideAddModal(){document.getElementById('addModal').classList.remove('active')}
function formatUptime(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h>0?`${h}h ${m}m`:`${m}m ${s%60}s`}
document.getElementById('keyInput').addEventListener('keypress',e=>{if(e.key==='Enter')authenticate()});
</script>
</body>
</html>"#;
