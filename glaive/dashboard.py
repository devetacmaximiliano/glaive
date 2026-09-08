"""Dashboard local en tiempo real — sin gastar un solo token de LLM.

Vista de SOLO LECTURA sobre el/los mismo(s) Store (SQLite) que usa el agente.
Como no calcula nada ni llama a ningún LLM, agregarlo (y ampliarlo) es gratis.

Dos modos, mismo servidor y misma página:
- **por sesión** (``start_dashboard``): lo abre ``glaive run`` sobre la sesión en curso.
- **multi-sesión** (``start_multi_dashboard``): lo abre ``glaive dashboard``; escanea
  ``runs/*/state.db`` y muestra todas las sesiones a la vez, con un selector.

La página trae: estado de actividad EN VIVO (pensando / esperando tu respuesta /
ejecutando tool / esperando confirmación / pausado), indicador de conexión,
superficie de ataque descubierta (scope_assets), hallazgos con drill-down
(evidencia/PoC/CVSS/CWE/WSTG/chains), distribución de severidad, pendientes, feed
de actividad y la conversación completa. Servidor stdlib (http.server), sin deps.
"""

from __future__ import annotations

import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from glaive.report import write_report
from glaive.state import Store

_PAGE = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>glaive</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: #0b0f14; color: #d8e0e8;
    font: 14px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
  }
  header {
    padding: 12px 20px; border-bottom: 1px solid #1c2530;
    display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  }
  header h1 { font-size: 15px; margin: 0; color: #4fd1c5; letter-spacing: .5px; }
  select {
    background: #12181f; color: #d8e0e8; border: 1px solid #26313d; border-radius: 6px;
    padding: 4px 8px; font: inherit; font-size: 12px;
  }
  .pill { padding: 2px 9px; border-radius: 999px; font-size: 12px; background: #1c2530; white-space: nowrap; }
  .pill.status-running { background: #1c3a2e; color: #4ade80; }
  .pill.status-finished { background: #1c2f3a; color: #38bdf8; }
  .pill.status-stopped { background: #3a1c1c; color: #f87171; }
  .act { padding: 2px 9px; border-radius: 999px; font-size: 12px; background: #26313d; color: #c6d2de; }
  .act.a-thinking, .act.a-streaming { background: #3a3413; color: #f0d264; }
  .act.a-running_tool { background: #10303a; color: #5fd0e6; }
  .act.a-awaiting_input { background: #16283f; color: #79b8ff; }
  .act.a-awaiting_confirmation { background: #402d10; color: #ffbe5c; font-weight: 600; }
  .act.a-compacting { background: #23262c; color: #9aa6b2; }
  .act.a-paused, .act.a-idle, .act.a-done, .act.a-interrupted { background: #1c2530; color: #7c8a99; }
  .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 5px; vertical-align: middle; }
  .dot.live { background: #4ade80; box-shadow: 0 0 6px #4ade80; }
  .dot.stale { background: #f87171; }
  .pulse { animation: pulse 1.1s ease-in-out infinite; }
  @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: .35 } }
  .spacer { flex: 1; }
  .usage { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12.5px; color: #9fb0c0; }
  .usage b { color: #d8e0e8; }
  button {
    background: #16212c; color: #cfe0ef; border: 1px solid #2a3a49; border-radius: 6px;
    padding: 4px 10px; font: inherit; font-size: 12px; cursor: pointer;
  }
  button:hover { background: #1d2c3a; }
  main { display: grid; grid-template-columns: 1.25fr 1fr; height: calc(100vh - 52px); }
  @media (max-width: 900px) { main { grid-template-columns: 1fr; height: auto; } }
  section { padding: 14px 18px; overflow-y: auto; }
  section + section { border-left: 1px solid #1c2530; }
  h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #7c8a99; margin: 16px 0 8px;
       display: flex; align-items: center; gap: 8px; }
  h2:first-child { margin-top: 0; }
  h2 .count { color: #4fd1c5; }
  table { width: 100%; border-collapse: collapse; }
  td, th { text-align: left; padding: 6px; border-bottom: 1px solid #16202b; vertical-align: top; }
  tr.finding { cursor: pointer; }
  tr.finding:hover { background: #111a23; }
  .sev { font-weight: 600; padding: 1px 7px; border-radius: 4px; font-size: 11px; display: inline-block; }
  .sev-critical { background: #4a1414; color: #ff8080; }
  .sev-high { background: #4a2c14; color: #ffb366; }
  .sev-medium { background: #4a4614; color: #f0e070; }
  .sev-low { background: #14304a; color: #7ec8ff; }
  .sev-info { background: #1c2530; color: #9fb0c0; }
  .tag { font-size: 10.5px; color: #8b98a6; }
  .badge { font-size: 10px; padding: 0 5px; border-radius: 3px; background: #26313d; color: #9fb0c0; }
  .badge.potential { background: #3a3413; color: #f0d264; }
  .badge.confirmed { background: #14361f; color: #6ee79e; }
  .empty { color: #55606c; font-style: italic; }
  .dist { display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: #12181f; margin-bottom: 4px; }
  .dist span { display: block; height: 100%; }
  .filters { display: flex; gap: 6px; flex-wrap: wrap; margin: 6px 0 4px; }
  .filters button.on { background: #24485f; color: #cfe9ff; border-color: #2f6a8a; }
  .event { padding: 5px 0; border-bottom: 1px solid #131b24; font-size: 12.5px; }
  .event .k { color: #4fd1c5; }
  .event .l { color: #d8e0e8; font-weight: 600; }
  .event .d { color: #8b98a6; display: block; white-space: pre-wrap; word-break: break-word; }
  .event .t { color: #55606c; float: right; font-size: 11px; }
  .tabs { display: flex; gap: 6px; margin-bottom: 10px; }
  .tabs button.on { background: #24485f; color: #cfe9ff; border-color: #2f6a8a; }
  .msg { padding: 7px 0; border-bottom: 1px solid #131b24; }
  .msg .role { font-size: 10.5px; text-transform: uppercase; letter-spacing: .5px; }
  .msg.user .role { color: #79b8ff; }
  .msg.assistant .role { color: #4fd1c5; }
  .msg.tool .role { color: #b58cff; }
  .msg .body { white-space: pre-wrap; word-break: break-word; color: #cbd5e0; }
  .msg .tc { color: #8b98a6; font-size: 12px; }
  /* modal drill-down */
  .modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: none; z-index: 10; }
  .modal-bg.open { display: block; }
  .modal { position: fixed; top: 5vh; left: 50%; transform: translateX(-50%); width: min(760px, 92vw);
           max-height: 90vh; overflow-y: auto; background: #0e141b; border: 1px solid #26313d;
           border-radius: 10px; padding: 20px 22px; z-index: 11; display: none; }
  .modal.open { display: block; }
  .modal h3 { margin: 0 0 4px; font-size: 16px; }
  .modal .close { position: absolute; top: 12px; right: 14px; }
  .modal .meta { color: #8b98a6; font-size: 12px; margin-bottom: 12px; }
  .modal .field { margin: 12px 0; }
  .modal .field .lbl { font-size: 10.5px; text-transform: uppercase; letter-spacing: 1px; color: #7c8a99; margin-bottom: 3px; }
  .modal pre { background: #0a0e13; border: 1px solid #1c2530; border-radius: 6px; padding: 10px;
               white-space: pre-wrap; word-break: break-word; margin: 0; font-size: 12.5px; }
  footer { padding: 7px 20px; color: #55606c; font-size: 11px; border-top: 1px solid #1c2530; }
  a { color: #6cc4ff; }
</style>
</head>
<body>
<header>
  <h1>glaive</h1>
  <select id="sessionSel" style="display:none"></select>
  <span id="target" class="pill"></span>
  <span id="status" class="pill"></span>
  <span id="activity" class="act"></span>
  <span class="spacer"></span>
  <span id="conn"><span class="dot stale"></span><span id="connText">conectando…</span></span>
  <span id="usage" class="usage"></span>
  <button id="reportBtn" title="Genera el reporte Markdown (no gasta tokens)">reporte</button>
</header>
<main>
  <section>
    <h2>Superficie de ataque <span class="count" id="scopeCount"></span></h2>
    <div id="scope"></div>

    <h2>Hallazgos <span class="count" id="findingCount"></span></h2>
    <div class="dist" id="dist"></div>
    <div class="filters" id="sevFilters"></div>
    <table id="findings"><tbody></tbody></table>

    <h2>Pendientes</h2>
    <table id="todos"><tbody></tbody></table>
  </section>
  <section>
    <div class="tabs">
      <button data-tab="activity" class="on">Actividad</button>
      <button data-tab="chat">Conversación</button>
    </div>
    <div id="tab-activity"><div id="events"></div></div>
    <div id="tab-chat" style="display:none"><div id="chat"></div></div>
  </section>
</main>
<footer>actualiza cada 1.5s · solo lectura · no consume tokens</footer>

<div class="modal-bg" id="modalBg"></div>
<div class="modal" id="modal">
  <button class="close" onclick="closeModal()">cerrar ✕</button>
  <div id="modalBody"></div>
</div>

<script>
const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
const sevColor = {critical:'#ff6b6b', high:'#ffa552', medium:'#e6d24d', low:'#5aa6e6', info:'#5a6b7a'};
let sid = new URLSearchParams(location.search).get('sid') || '';
let sevFilter = null;         // null = todas
let tab = 'activity';
let lastFindings = [];
let multi = false;

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function rel(ts) {
  if (!ts) return '';
  const d = Date.now()/1000 - ts;
  if (d < 60) return 'hace ' + Math.floor(d) + 's';
  if (d < 3600) return 'hace ' + Math.floor(d/60) + 'm';
  if (d < 86400) return 'hace ' + Math.floor(d/3600) + 'h';
  return 'hace ' + Math.floor(d/86400) + 'd';
}
const ACT_LABEL = {
  thinking:'🧠 pensando…', streaming:'✍ respondiendo…', running_tool:'⚙ ejecutando',
  awaiting_input:'⏳ esperando tu respuesta', awaiting_confirmation:'❓ esperando confirmación',
  compacting:'🗜 compactando contexto', paused:'⏸ pausado', idle:'· inactivo',
  done:'✓ turno terminado', interrupted:'⛔ interrumpido'
};

async function loadSessions() {
  try {
    const list = await (await fetch('/api/sessions')).json();
    multi = list.length > 1 || (list.length >= 1 && !sid);
    const sel = document.getElementById('sessionSel');
    if (list.length > 1) {
      sel.style.display = '';
      if (!sid && list.length) sid = list[0].id;
      sel.innerHTML = list.map(s =>
        `<option value="${s.id}" ${s.id===sid?'selected':''}>${escapeHtml(s.target||s.id)} · ${s.findings} hallazgos · ${escapeHtml(s.activity||s.status||'')}</option>`
      ).join('');
      sel.onchange = () => { sid = sel.value; history.replaceState(null,'','?sid='+sid); tick(); };
    } else if (list.length === 1) {
      sid = sid || list[0].id;
    }
  } catch (e) { /* modo por-sesión sin /api/sessions poblado */ }
}

async function tick() {
  let data;
  try {
    data = await (await fetch('/api/state' + (sid ? '?sid='+encodeURIComponent(sid) : ''))).json();
    setConn(true, data);
  } catch (e) { setConn(false); return; }

  const s = data.session || {};
  document.getElementById('target').textContent = s.target || '—';
  const st = document.getElementById('status');
  st.textContent = s.status || '—';
  st.className = 'pill status-' + (s.status || '');

  const act = document.getElementById('activity');
  const a = s.activity || 'idle';
  act.textContent = ACT_LABEL[a] || a;
  act.className = 'act a-' + a + ((a==='thinking'||a==='streaming'||a==='running_tool'||a==='awaiting_confirmation') ? ' pulse' : '');
  if (a === 'running_tool' && s.activity_detail) act.textContent = '⚙ ' + s.activity_detail;
  if (a === 'awaiting_confirmation' && s.activity_detail) act.title = s.activity_detail;

  const u = data.usage || {};
  document.getElementById('usage').innerHTML =
    `<span><b>${(u.prompt_tokens||0).toLocaleString()}</b> in</span>` +
    `<span><b>${(u.completion_tokens||0).toLocaleString()}</b> out</span>` +
    `<span><b>${u.prompt_tokens ? Math.round(100*u.cached_tokens/u.prompt_tokens) : 0}%</b> cache</span>` +
    `<span><b>$${(u.cost_usd||0).toFixed(4)}</b></span>`;

  renderScope(data.scope_assets || []);
  renderFindings(data.findings || []);
  renderTodos(data.todos || []);
  renderEvents(data.events || []);
  if (tab === 'chat') renderChat();
}

function setConn(ok, data) {
  const dot = document.querySelector('#conn .dot');
  const txt = document.getElementById('connText');
  if (!ok) { dot.className = 'dot stale'; txt.textContent = 'sin conexión'; return; }
  const s = (data && data.session) || {};
  const srv = (data && data.server_time) || Date.now()/1000;
  const age = s.last_activity_at ? srv - s.last_activity_at : null;
  const working = ['thinking','streaming','running_tool','compacting'].includes(s.activity);
  if (working && age != null && age > 90) {
    dot.className = 'dot stale'; txt.textContent = 'sin respuesta ' + rel(s.last_activity_at);
  } else {
    dot.className = 'dot live'; txt.textContent = 'en vivo';
  }
}

function renderScope(assets) {
  const inc = assets.filter(a => a.status === 'included');
  const pend = assets.filter(a => a.status === 'pending');
  document.getElementById('scopeCount').textContent = assets.length ? assets.length : '';
  const el = document.getElementById('scope');
  if (!assets.length) { el.innerHTML = '<div class="empty">Solo el target inicial (sin ampliaciones todavía).</div>'; return; }
  let h = '';
  if (inc.length) h += '<table><tbody>' + inc.map(a =>
    `<tr><td>✓ <b>${escapeHtml(a.asset)}</b></td><td class="tag">${escapeHtml(a.relation||'')}</td></tr>`).join('') + '</tbody></table>';
  if (pend.length) h += '<div class="tag" style="margin-top:6px;color:#ffbe5c">Pendientes de aprobación:</div><table><tbody>' +
    pend.map(a => `<tr><td>◷ <b>${escapeHtml(a.asset)}</b></td><td class="tag">${escapeHtml(a.evidence||'')}</td></tr>`).join('') + '</tbody></table>';
  el.innerHTML = h;
}

function renderFindings(findings) {
  lastFindings = findings;
  findings = findings.slice().sort((a,b)=>(sevOrder[a.severity]??9)-(sevOrder[b.severity]??9));
  document.getElementById('findingCount').textContent = findings.length ? findings.length : '';

  // distribución
  const counts = {critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
  const total = findings.length || 1;
  document.getElementById('dist').innerHTML = Object.keys(sevColor).map(k =>
    counts[k] ? `<span style="width:${100*counts[k]/total}%;background:${sevColor[k]}" title="${k}: ${counts[k]}"></span>` : '').join('');

  // filtros
  const fEl = document.getElementById('sevFilters');
  fEl.innerHTML = ['all','critical','high','medium','low','info'].map(k => {
    const n = k==='all' ? findings.length : (counts[k]||0);
    const on = (sevFilter===null && k==='all') || sevFilter===k;
    return `<button class="${on?'on':''}" onclick="setSev('${k}')">${k}${k!=='all'?' '+n:''}</button>`;
  }).join('');

  const shown = sevFilter ? findings.filter(f=>f.severity===sevFilter) : findings;
  const tb = document.querySelector('#findings tbody');
  tb.innerHTML = shown.length ? shown.map(f => `
    <tr class="finding" onclick="openFinding(${f.id})">
      <td><span class="sev sev-${f.severity}">${f.severity}</span>
          <span class="badge ${f.status}">${f.status==='potential'?'pot.':f.status==='confirmed'?'conf.':escapeHtml(f.status||'')}</span></td>
      <td><b>${escapeHtml(f.title)}</b>${f.cvss_score!=null?` <span class="tag">CVSS ${f.cvss_score}</span>`:''}
          ${f.chains_from?` <span class="tag">↳ de #${f.chains_from}</span>`:''}
          <br><span class="tag">${escapeHtml(f.endpoint||'')} · ${rel(f.created_at)}</span></td>
    </tr>`).join('') : '<tr><td class="empty">Sin hallazgos' + (sevFilter?' de esa severidad':' todavía') + '.</td></tr>';
}
function setSev(k){ sevFilter = (k==='all') ? null : k; renderFindings(lastFindings); }

function renderTodos(todos) {
  const tb = document.querySelector('#todos tbody');
  tb.innerHTML = todos.length ? todos.map(t=>`<tr><td>#${t.id}</td><td>${escapeHtml(t.content)}</td></tr>`).join('')
    : '<tr><td class="empty">Sin pendientes.</td></tr>';
}

function renderEvents(events) {
  document.getElementById('events').innerHTML = events.length ? events.map(e=>`
    <div class="event"><span class="t">${rel(e.created_at)}</span>
      <span class="k">${escapeHtml(e.kind)}</span> <span class="l">${escapeHtml(e.label||'')}</span>
      ${e.detail?`<span class="d">${escapeHtml(e.detail)}</span>`:''}
    </div>`).join('') : '<div class="empty">Sin actividad todavía.</div>';
}

async function renderChat() {
  let msgs;
  try { msgs = await (await fetch('/api/messages'+(sid?'?sid='+encodeURIComponent(sid):''))).json(); }
  catch (e) { return; }
  const el = document.getElementById('chat');
  const wasBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  el.innerHTML = msgs.length ? msgs.map(m => {
    const tools = (m.tools||[]).map(t=>`<div class="tc">⏺ ${escapeHtml(t.name)}(${escapeHtml((t.arguments||'').slice(0,200))})</div>`).join('');
    const body = m.text ? `<div class="body">${escapeHtml(m.text)}</div>` : '';
    return `<div class="msg ${m.role}"><span class="role">${escapeHtml(m.role)}</span>${body}${tools}</div>`;
  }).join('') : '<div class="empty">Sin conversación todavía.</div>';
  if (wasBottom) el.scrollTop = el.scrollHeight;
}

function openFinding(id) {
  const f = lastFindings.find(x=>x.id===id); if (!f) return;
  const field = (lbl,val,pre)=> val ? `<div class="field"><div class="lbl">${lbl}</div>${pre?`<pre>${escapeHtml(val)}</pre>`:`<div>${escapeHtml(val)}</div>`}</div>` : '';
  const chained = lastFindings.filter(x=>x.chains_from===id).map(x=>'#'+x.id).join(', ');
  document.getElementById('modalBody').innerHTML =
    `<h3><span class="sev sev-${f.severity}">${f.severity}</span> ${escapeHtml(f.title)}</h3>
     <div class="meta">#${f.id} · ${f.status}${f.cvss_score!=null?` · CVSS ${f.cvss_score}`:''}
       ${f.cwe?` · ${escapeHtml(f.cwe)}`:''}${f.wstg?` · ${escapeHtml(f.wstg)}`:''}${f.owasp?` · ${escapeHtml(f.owasp)}`:''}
       ${f.cvss_vector?`<br>${escapeHtml(f.cvss_vector)}`:''}
       ${f.chains_from?`<br>↳ deriva del hallazgo #${f.chains_from}`:''}${chained?`<br>↳ habilita: ${chained}`:''}</div>`
    + field('Endpoint / activo', f.endpoint)
    + field('Descripción', f.description)
    + field('Evidencia', f.evidence, true)
    + field('PoC / pasos', f.poc, true)
    + field('Remediación', f.remediation);
  document.getElementById('modal').classList.add('open');
  document.getElementById('modalBg').classList.add('open');
}
function closeModal(){ document.getElementById('modal').classList.remove('open'); document.getElementById('modalBg').classList.remove('open'); }
document.getElementById('modalBg').onclick = closeModal;
document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeModal(); });

document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{
  tab = b.dataset.tab;
  document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on', x===b));
  document.getElementById('tab-activity').style.display = tab==='activity'?'':'none';
  document.getElementById('tab-chat').style.display = tab==='chat'?'':'none';
  if (tab==='chat') renderChat();
});

document.getElementById('reportBtn').onclick = async () => {
  const btn = document.getElementById('reportBtn'); btn.textContent = 'generando…';
  try {
    const r = await (await fetch('/api/report'+(sid?'?sid='+encodeURIComponent(sid):''))).json();
    btn.textContent = 'reporte ✓'; btn.title = r.path || '';
  } catch (e) { btn.textContent = 'error'; }
  setTimeout(()=>{ btn.textContent='reporte'; }, 2500);
};

(async function(){ await loadSessions(); tick(); setInterval(tick, 1500); })();
</script>
</body>
</html>
"""


class _Registry:
    """Resuelve sid → Store. Implementaciones: una sola sesión o multi (runs/*)."""

    def sessions(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def store(self, sid: str | None) -> Store | None:
        raise NotImplementedError


def _summary(store: Store) -> dict[str, Any]:
    s = store.session()
    usage = store.get_usage()
    return {
        "id": s.get("id", ""),
        "target": s.get("target", ""),
        "status": s.get("status", ""),
        "activity": s.get("activity", ""),
        "last_activity_at": s.get("last_activity_at"),
        "findings": len(store.findings()),
        "cost_usd": usage.get("cost_usd", 0.0),
    }


class _SingleRegistry(_Registry):
    def __init__(self, store: Store):
        self._store = store
        self._sid = store.session().get("id", "")

    def sessions(self) -> list[dict[str, Any]]:
        return [_summary(self._store)]

    def store(self, sid: str | None) -> Store | None:
        return self._store


class _MultiRegistry(_Registry):
    def __init__(self, runs_dir: Path):
        self._runs = Path(runs_dir)
        self._cache: dict[str, Store] = {}
        self._lock = threading.Lock()

    def _open(self, sid: str) -> Store | None:
        db = self._runs / sid / "state.db"
        if not db.exists():
            return None
        with self._lock:
            st = self._cache.get(sid)
            if st is None:
                st = Store(db)
                self._cache[sid] = st
            return st

    def sessions(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not self._runs.exists():
            return rows
        for d in sorted(self._runs.iterdir()):
            if not (d / "state.db").exists():
                continue
            st = self._open(d.name)
            if st is not None:
                rows.append(_summary(st))
        rows.sort(key=lambda r: r.get("last_activity_at") or 0, reverse=True)
        return rows

    def store(self, sid: str | None) -> Store | None:
        if not sid:
            rows = self.sessions()
            sid = rows[0]["id"] if rows else None
        return self._open(sid) if sid else None


def _make_handler(registry: _Registry) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def _json(self, obj: Any, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

        def _store(self, qs: dict[str, list[str]]) -> Store | None:
            sid = (qs.get("sid") or [None])[0]
            return registry.store(sid)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            if path in ("/", ""):
                self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
                return
            if path == "/api/sessions":
                self._json(registry.sessions())
                return

            store = self._store(qs)
            if store is None:
                self._json({"error": "sesión no encontrada"}, 404)
                return

            if path == "/api/state":
                self._json({
                    "session": store.session(),
                    "findings": store.findings(),
                    "todos": store.open_todos(),
                    "scope_assets": store.scope_assets(),
                    "events": store.recent_events(limit=80),
                    "usage": store.get_usage(),
                    "server_time": time.time(),
                })
            elif path == "/api/messages":
                self._json(store.conversation())
            elif path.startswith("/api/output/"):
                try:
                    out_id = int(path.rsplit("/", 1)[-1])
                except ValueError:
                    self._json({"error": "id inválido"}, 400)
                    return
                self._json({"output": store.get_output(out_id) or ""})
            elif path == "/api/report":
                out = store.db_path.parent / "report.md"
                write_report(store, out)
                self._json({"path": str(out)})
            else:
                self._send(404, b"not found", "text/plain")

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _serve(registry: _Registry, port: int, open_browser: bool) -> tuple[str, ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(registry))
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    return url, server


def start_dashboard(
    store: Store, port: int = 0, open_browser: bool = True
) -> tuple[str, ThreadingHTTPServer]:
    """Dashboard de UNA sesión (lo abre ``glaive run``). Devuelve (url, server);
    llamar ``server.shutdown()`` al terminar."""
    return _serve(_SingleRegistry(store), port, open_browser)


def start_multi_dashboard(
    runs_dir: Path, port: int = 0, open_browser: bool = True
) -> tuple[str, ThreadingHTTPServer]:
    """Dashboard MULTI-sesión (lo abre ``glaive dashboard``): escanea ``runs/*``
    y muestra todas las sesiones con un selector."""
    return _serve(_MultiRegistry(runs_dir), port, open_browser)
