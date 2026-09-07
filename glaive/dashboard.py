"""Dashboard local en tiempo real — sin gastar un solo token de LLM.

Es una vista de SOLO LECTURA sobre el mismo Store (SQLite) que ya usa el
agente (findings con drill-down completo, superficie de alcance descubierta,
conversación, feed de actividad, uso/costo). No hay nada nuevo que calcular ni
ningún LLM involucrado: por eso es gratis agregarlo. El browser hace polling
liviano a /api/state cada 1.5s.

Dos modos, mismo handler:
- ``start_dashboard(store, ...)``: atado a UNA sesión — lo que abre `glaive run`
  automáticamente.
- ``start_multi_dashboard(runs_dir, ...)``: escanea `runs/*/state.db` y sirve un
  selector de sesiones — lo que abre `glaive dashboard` (sin --session-id).

Servidor stdlib (http.server) a propósito — cero dependencias nuevas.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from glaive.state import Store

_PAGE = """<!doctype html>
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
  a { color: #4fd1c5; }
  header {
    padding: 14px 20px; border-bottom: 1px solid #1c2530;
    display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  }
  header h1 { font-size: 15px; margin: 0; color: #4fd1c5; letter-spacing: .5px; }
  .pill { padding: 2px 8px; border-radius: 999px; font-size: 12px; background: #1c2530; }
  .pill.status-running { background: #1c3a2e; color: #4ade80; }
  .pill.status-finished { background: #1c2f3a; color: #38bdf8; }
  .pill.status-stopped { background: #3a1c1c; color: #f87171; }
  .pill.live-ok { background: #1c3a2e; color: #4ade80; }
  .pill.live-dead { background: #3a1c1c; color: #f87171; }
  main {
    display: grid; grid-template-columns: 1.3fr 1fr; gap: 0;
    height: calc(100vh - 58px);
  }
  main.picker { grid-template-columns: 1fr; }
  section { padding: 16px 20px; overflow-y: auto; }
  section + section { border-left: 1px solid #1c2530; }
  h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #7c8a99; margin: 18px 0 8px; }
  h2:first-child { margin-top: 0; }
  table { width: 100%; border-collapse: collapse; }
  td, th { text-align: left; padding: 6px 6px; border-bottom: 1px solid #16202b; vertical-align: top; }
  tr.finding-row { cursor: pointer; }
  tr.finding-row:hover td { background: #101720; }
  tr.detail-row td { background: #0e141b; padding: 10px 12px; }
  .detail dt { color: #7c8a99; font-size: 11px; text-transform: uppercase; margin-top: 8px; }
  .detail dd { margin: 2px 0 0; white-space: pre-wrap; word-break: break-word; }
  .detail code { background: #16202b; padding: 1px 5px; border-radius: 3px; }
  .sev { font-weight: 600; padding: 1px 7px; border-radius: 4px; font-size: 11px; display: inline-block; }
  .sev-critical { background: #4a1414; color: #ff8080; }
  .sev-high { background: #4a2c14; color: #ffb366; }
  .sev-medium { background: #4a4614; color: #f0e070; }
  .sev-low { background: #14304a; color: #7ec8ff; }
  .sev-info { background: #1c2530; color: #9fb0c0; }
  .empty { color: #55606c; font-style: italic; }
  .muted { color: #55606c; font-size: 11.5px; }
  .event { padding: 5px 0; border-bottom: 1px solid #131b24; font-size: 12.5px; }
  .event .k { color: #4fd1c5; }
  .event .l { color: #d8e0e8; font-weight: 600; }
  .event .d { color: #8b98a6; display: block; white-space: pre-wrap; word-break: break-word; }
  .event .t { float: right; color: #55606c; }
  .usage { display: flex; gap: 18px; flex-wrap: wrap; font-size: 12.5px; color: #9fb0c0; }
  .usage b { color: #d8e0e8; }
  .tabs { display: flex; gap: 4px; margin-bottom: 10px; }
  .tab { padding: 4px 10px; border-radius: 5px; cursor: pointer; color: #7c8a99; font-size: 12px; }
  .tab.active { background: #1c2530; color: #d8e0e8; }
  .msg { padding: 8px 0; border-bottom: 1px solid #131b24; font-size: 12.5px; }
  .msg .role { font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
  .msg.role-user .role { color: #4ade80; }
  .msg.role-assistant .role { color: #4fd1c5; }
  .msg.role-tool .role { color: #f0e070; }
  .msg .content { white-space: pre-wrap; word-break: break-word; margin-top: 3px; }
  .msg .tc { color: #ffb366; margin-top: 3px; }
  .bars { display: flex; flex-direction: column; gap: 4px; margin-bottom: 4px; }
  .bar-row { display: flex; align-items: center; gap: 8px; font-size: 11.5px; }
  .bar-row .lbl { width: 60px; color: #9fb0c0; }
  .bar-track { flex: 1; background: #16202b; border-radius: 3px; height: 10px; overflow: hidden; }
  .bar-fill { height: 100%; }
  .bar-row .cnt { width: 20px; text-align: right; color: #9fb0c0; }
  .session-card { display: block; padding: 12px 14px; margin-bottom: 8px; border: 1px solid #1c2530; border-radius: 6px; text-decoration: none; color: inherit; }
  .session-card:hover { background: #101720; }
  .session-card .row1 { display: flex; justify-content: space-between; align-items: center; }
  footer { padding: 8px 20px; color: #55606c; font-size: 11px; border-top: 1px solid #1c2530; }
</style>
</head>
<body>
<header id="header">
  <h1>glaive</h1>
</header>
<main id="main"></main>
<footer>actualiza cada 1.5s · solo lectura · no consume tokens</footer>
<script>
const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
const sevColor = {critical:'#ff8080', high:'#ffb366', medium:'#f0e070', low:'#7ec8ff', info:'#9fb0c0'};
const params = new URLSearchParams(location.search);
let sessionId = params.get('session');
let multiMode = false;
let lastOkTick = 0;
let activeTab = 'actividad';
let expandedFinding = null;
let cachedFindings = [];

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function relTime(ts) {
  if (!ts) return '';
  const diff = Date.now()/1000 - ts;
  if (diff < 5) return 'ahora';
  if (diff < 60) return `hace ${Math.floor(diff)}s`;
  if (diff < 3600) return `hace ${Math.floor(diff/60)}m`;
  if (diff < 86400) return `hace ${Math.floor(diff/3600)}h`;
  return `hace ${Math.floor(diff/86400)}d`;
}
function apiUrl(path) {
  return sessionId ? `${path}?session=${encodeURIComponent(sessionId)}` : path;
}

async function init() {
  try {
    const r = await fetch('/api/sessions');
    if (r.ok) {
      multiMode = true;
      if (!sessionId) { renderPicker(); return; }
    }
  } catch (e) { /* modo single-session, sigue abajo */ }
  renderDetailShell();
  tick();
  setInterval(tick, 1500);
  setInterval(updateLiveBadge, 1000);
}

async function renderPicker() {
  document.getElementById('header').innerHTML = '<h1>glaive</h1><span class="muted">elegí una sesión</span>';
  const main = document.getElementById('main');
  main.className = 'picker';
  main.innerHTML = '<section id="sessions"></section>';
  await refreshPicker();
  setInterval(refreshPicker, 3000);
}
async function refreshPicker() {
  let sessions;
  try { sessions = await (await fetch('/api/sessions')).json(); } catch (e) { return; }
  const el = document.getElementById('sessions');
  if (!sessions.length) { el.innerHTML = '<p class="empty">Todavía no hay sesiones en runs/.</p>'; return; }
  el.innerHTML = sessions.map(s => `
    <a class="session-card" href="?session=${encodeURIComponent(s.id)}">
      <div class="row1">
        <b>${escapeHtml(s.target || s.id)}</b>
        <span class="pill status-${s.status}">${s.status}</span>
      </div>
      <div class="muted">${s.findings} hallazgo(s) · $${(s.cost_usd||0).toFixed(4)} · ${relTime(s.last_activity)}</div>
    </a>`).join('');
}

function renderDetailShell() {
  document.getElementById('header').innerHTML = `
    ${multiMode ? '<a href="?">&larr; sesiones</a>' : ''}
    <h1>glaive</h1>
    <span id="target" class="pill"></span>
    <span id="status" class="pill"></span>
    <span id="live" class="pill live-dead">sin datos</span>
    <span id="usage" class="usage"></span>`;
  const main = document.getElementById('main');
  main.className = '';
  main.innerHTML = `
    <section>
      <h2>Superficie de alcance</h2>
      <div id="scope"></div>
      <h2>Hallazgos</h2>
      <div id="sevbars" class="bars"></div>
      <table id="findings"><tbody></tbody></table>
      <h2>Pendientes</h2>
      <table id="todos"><tbody></tbody></table>
    </section>
    <section>
      <div class="tabs">
        <span class="tab active" data-tab="actividad">Actividad</span>
        <span class="tab" data-tab="conversacion">Conversación</span>
      </div>
      <div id="actividad"></div>
      <div id="conversacion" style="display:none"></div>
    </section>`;
  for (const t of document.querySelectorAll('.tab')) {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  }
  document.getElementById('findings').addEventListener('click', onFindingClick);
}

function switchTab(name) {
  activeTab = name;
  for (const t of document.querySelectorAll('.tab')) t.classList.toggle('active', t.dataset.tab === name);
  document.getElementById('actividad').style.display = name === 'actividad' ? '' : 'none';
  document.getElementById('conversacion').style.display = name === 'conversacion' ? '' : 'none';
  if (name === 'conversacion') loadConversation();
}

function updateLiveBadge() {
  const el = document.getElementById('live');
  if (!el) return;
  const age = (Date.now() - lastOkTick) / 1000;
  if (lastOkTick && age < 5) { el.textContent = 'en vivo'; el.className = 'pill live-ok'; }
  else if (lastOkTick) { el.textContent = `sin respuesta hace ${Math.floor(age)}s`; el.className = 'pill live-dead'; }
}

async function tick() {
  let data;
  try {
    const r = await fetch(apiUrl('/api/state'));
    if (!r.ok) return;
    data = await r.json();
  } catch (e) { return; }
  lastOkTick = Date.now();
  updateLiveBadge();

  const s = data.session || {};
  document.getElementById('target').textContent = s.target || '—';
  const st = document.getElementById('status');
  st.textContent = s.status || '—';
  st.className = 'pill status-' + (s.status || '');

  const u = data.usage || {};
  document.getElementById('usage').innerHTML =
    `<span><b>${(u.prompt_tokens||0).toLocaleString()}</b> in</span>` +
    `<span><b>${(u.completion_tokens||0).toLocaleString()}</b> out</span>` +
    `<span><b>${u.prompt_tokens ? Math.round(100*u.cached_tokens/u.prompt_tokens) : 0}%</b> cacheado</span>` +
    `<span><b>$${(u.cost_usd||0).toFixed(4)}</b></span>`;

  const scope = data.scope_assets || [];
  const included = scope.filter(x => x.status === 'included');
  const pending = scope.filter(x => x.status === 'pending');
  document.getElementById('scope').innerHTML = (included.length || pending.length) ? (
    (included.length ? `<div class="muted">Incluidos:</div>` + included.map(a =>
      `<div>${escapeHtml(a.asset)} <span class="muted">(${escapeHtml(a.relation)})</span></div>`).join('') : '') +
    (pending.length ? `<div class="muted" style="margin-top:6px">Pendientes de aprobación:</div>` + pending.map(a =>
      `<div>${escapeHtml(a.asset)} <span class="muted">— ${escapeHtml(a.evidence||'')}</span></div>`).join('') : '')
  ) : '<div class="empty">Sin ampliaciones de alcance todavía.</div>';

  cachedFindings = (data.findings || []).slice().sort((a,b) => (sevOrder[a.severity]??9) - (sevOrder[b.severity]??9));
  renderSeverityBars(cachedFindings);
  renderFindings(cachedFindings);

  const todos = data.todos || [];
  const ttbody = document.querySelector('#todos tbody');
  ttbody.innerHTML = todos.length ? todos.map(t => `<tr><td>#${t.id}</td><td>${escapeHtml(t.content)}</td></tr>`).join('')
    : '<tr><td class="empty">Sin pendientes.</td></tr>';

  const events = data.events || [];
  document.getElementById('actividad').innerHTML = events.length ? events.map(e => `
    <div class="event">
      <span class="t">${relTime(e.created_at)}</span>
      <span class="k">${escapeHtml(e.kind)}</span> <span class="l">${escapeHtml(e.label||'')}</span>
      ${e.detail ? `<span class="d">${escapeHtml(e.detail)}</span>` : ''}
    </div>`).join('') : '<div class="empty">Sin actividad todavía.</div>';
}

function renderSeverityBars(findings) {
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  let confirmed = 0, potential = 0;
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity]||0) + 1;
    if (f.status === 'confirmed') confirmed++; else if (f.status === 'potential') potential++;
  }
  const max = Math.max(1, ...Object.values(counts));
  const el = document.getElementById('sevbars');
  if (!findings.length) { el.innerHTML = ''; return; }
  el.innerHTML = Object.entries(counts).map(([sev, n]) => `
    <div class="bar-row">
      <span class="lbl">${sev}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${100*n/max}%;background:${sevColor[sev]}"></span></span>
      <span class="cnt">${n}</span>
    </div>`).join('') + `<div class="muted" style="margin-top:2px">${confirmed} confirmado(s) · ${potential} potencial(es)</div>`;
}

function renderFindings(findings) {
  const tbody = document.querySelector('#findings tbody');
  if (!findings.length) { tbody.innerHTML = '<tr><td class="empty">Sin hallazgos todavía.</td></tr>'; return; }
  tbody.innerHTML = findings.map(f => {
    const row = `
      <tr class="finding-row" data-id="${f.id}">
        <td><span class="sev sev-${f.severity}">${f.severity}</span>${f.status === 'potential' ? ' <span class="d" style="color:#f0e070">(potencial)</span>' : ''}</td>
        <td><b>${escapeHtml(f.title)}</b>${f.cvss_score != null ? ` <span class="d">CVSS ${f.cvss_score}</span>` : ''}<br><span class="d" style="color:#8b98a6">${escapeHtml(f.endpoint||'')}</span></td>
      </tr>`;
    if (expandedFinding !== f.id) return row;
    const enabledBy = f.chains_from ? findings.find(x => x.id === f.chains_from) : null;
    const enables = findings.filter(x => x.chains_from === f.id);
    return row + `
      <tr class="detail-row"><td colspan="2"><dl class="detail">
        ${f.description ? `<dt>Descripción</dt><dd>${escapeHtml(f.description)}</dd>` : ''}
        ${f.evidence ? `<dt>Evidencia</dt><dd>${escapeHtml(f.evidence)}</dd>` : ''}
        ${f.poc ? `<dt>PoC</dt><dd>${escapeHtml(f.poc)}</dd>` : ''}
        ${f.remediation ? `<dt>Remediación</dt><dd>${escapeHtml(f.remediation)}</dd>` : ''}
        ${(f.cwe || f.wstg || f.owasp) ? `<dt>Referencias</dt><dd>${[f.cwe,f.wstg,f.owasp].filter(Boolean).map(escapeHtml).join(' · ')}</dd>` : ''}
        ${f.cvss_vector ? `<dt>CVSS 3.1</dt><dd><code>${escapeHtml(f.cvss_vector)}</code></dd>` : ''}
        ${enabledBy ? `<dt>Habilitado por</dt><dd>#${enabledBy.id} ${escapeHtml(enabledBy.title)}</dd>` : ''}
        ${enables.length ? `<dt>Habilita</dt><dd>${enables.map(x => `#${x.id} ${escapeHtml(x.title)}`).join(', ')}</dd>` : ''}
      </dl></td></tr>`;
  }).join('');
}

function onFindingClick(ev) {
  const row = ev.target.closest('tr.finding-row');
  if (!row) return;
  const id = Number(row.dataset.id);
  expandedFinding = expandedFinding === id ? null : id;
  renderFindings(cachedFindings);
}

async function loadConversation() {
  const el = document.getElementById('conversacion');
  el.innerHTML = '<div class="empty">Cargando…</div>';
  let data;
  try { data = await (await fetch(apiUrl('/api/messages'))).json(); } catch (e) { el.innerHTML = '<div class="empty">No se pudo cargar.</div>'; return; }
  const msgs = (data.messages || []).filter(m => m.role !== 'system');
  el.innerHTML = msgs.length ? msgs.map(m => `
    <div class="msg role-${m.role}">
      <span class="role">${m.role}</span>
      ${m.content ? `<div class="content">${escapeHtml(m.content)}</div>` : ''}
      ${(m.tool_calls||[]).map(tc => `<div class="tc">⏺ ${escapeHtml(tc.name)}(${escapeHtml(tc.arguments)})</div>`).join('')}
    </div>`).join('') : '<div class="empty">Sin conversación todavía.</div>';
}

init();
</script>
</body>
</html>
"""


def _format_messages(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for m in msgs:
        role = m.get("role", "")
        content = m.get("content") or ""
        if isinstance(content, list):
            content = " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
        entry: dict[str, Any] = {"role": role, "content": content}
        tool_calls = m.get("tool_calls") or []
        if tool_calls:
            entry["tool_calls"] = [
                {
                    "name": tc.get("function", {}).get("name", ""),
                    "arguments": tc.get("function", {}).get("arguments", ""),
                }
                for tc in tool_calls
            ]
        out.append(entry)
    return out


def _list_sessions(runs_dir: Path) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    if not runs_dir.exists():
        return sessions
    for d in sorted(runs_dir.iterdir()):
        db_path = d / "state.db"
        if not db_path.is_file():
            continue
        try:
            s = Store(db_path)
            sess = s.session()
            findings = s.findings()
            usage = s.get_usage()
            recent = s.recent_events(limit=1)
            s.close()
        except Exception:  # noqa: BLE001 - una sesión corrupta no debe tirar abajo el listado
            continue
        sessions.append(
            {
                "id": d.name,
                "target": sess.get("target", ""),
                "status": sess.get("status", "?"),
                "findings": len(findings),
                "cost_usd": usage.get("cost_usd", 0.0),
                "last_activity": (recent[0]["created_at"] if recent else sess.get("created_at")),
            }
        )
    sessions.sort(key=lambda x: x.get("last_activity") or 0, reverse=True)
    return sessions


def _make_handler(
    *, store: Store | None = None, runs_dir: Path | None = None
) -> type[BaseHTTPRequestHandler]:
    store_cache: dict[str, Store] = {}

    def resolve_store(session_id: str | None) -> Store | None:
        if store is not None:
            return store
        if runs_dir is None or not session_id:
            return None
        if session_id in store_cache:
            return store_cache[session_id]
        db_path = runs_dir / session_id / "state.db"
        if not db_path.is_file():
            return None
        opened = Store(db_path)
        store_cache[session_id] = opened
        return opened

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:  # silencia el access log en la consola
            pass

        def do_GET(self) -> None:  # noqa: N802 (nombre impuesto por BaseHTTPRequestHandler)
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            session_id = (qs.get("session") or [None])[0]

            if parsed.path in ("/", ""):
                self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
                return

            if parsed.path == "/api/sessions":
                if runs_dir is None:
                    self._send(404, b'{"error":"not in multi-session mode"}', "application/json")
                    return
                self._send(200, json.dumps(_list_sessions(runs_dir)).encode("utf-8"), "application/json")
                return

            if parsed.path == "/api/state":
                s = resolve_store(session_id)
                if s is None:
                    self._send(404, b'{"error":"session not found"}', "application/json")
                    return
                snapshot = {
                    "session": s.session(),
                    "findings": s.findings(),
                    "todos": s.open_todos(),
                    "events": s.recent_events(limit=60),
                    "usage": s.get_usage(),
                    "scope_assets": s.scope_assets(),
                }
                self._send(200, json.dumps(snapshot).encode("utf-8"), "application/json")
                return

            if parsed.path == "/api/messages":
                s = resolve_store(session_id)
                if s is None:
                    self._send(404, b'{"error":"session not found"}', "application/json")
                    return
                body = {"messages": _format_messages(s.load_messages())}
                self._send(200, json.dumps(body).encode("utf-8"), "application/json")
                return

            self._send(404, b"not found", "text/plain")

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def start_dashboard(
    store: Store, port: int = 0, open_browser: bool = True
) -> tuple[str, ThreadingHTTPServer]:
    """Levanta el dashboard de UNA sesión en un hilo daemon. Devuelve (url, server)
    — llamar server.shutdown() al terminar la sesión."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(store=store))
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - abrir el navegador es best-effort
            pass
    return url, server


def start_multi_dashboard(
    runs_dir: Path, port: int = 0, open_browser: bool = True
) -> tuple[str, ThreadingHTTPServer]:
    """Levanta el dashboard multi-sesión (``glaive dashboard``): escanea
    ``runs_dir/*/state.db`` y sirve un selector — cada sesión se abre on-demand."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(runs_dir=runs_dir))
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - abrir el navegador es best-effort
            pass
    return url, server
