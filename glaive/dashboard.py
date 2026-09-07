"""Dashboard local en tiempo real — sin gastar un solo token de LLM.

Es una vista de SOLO LECTURA sobre el mismo Store (SQLite) que ya usa el
agente (findings, todos, feed de actividad, uso/costo). No hay nada nuevo que
calcular ni ningún LLM involucrado: por eso es gratis agregarlo. El browser
hace polling liviano a /api/state cada 1.5s.

Servidor stdlib (http.server) a propósito — cero dependencias nuevas.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

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
  header {
    padding: 14px 20px; border-bottom: 1px solid #1c2530;
    display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
  }
  header h1 { font-size: 15px; margin: 0; color: #4fd1c5; letter-spacing: .5px; }
  .pill { padding: 2px 8px; border-radius: 999px; font-size: 12px; background: #1c2530; }
  .pill.status-running { background: #1c3a2e; color: #4ade80; }
  .pill.status-finished { background: #1c2f3a; color: #38bdf8; }
  .pill.status-stopped { background: #3a1c1c; color: #f87171; }
  main {
    display: grid; grid-template-columns: 1.3fr 1fr; gap: 0;
    height: calc(100vh - 58px);
  }
  section { padding: 16px 20px; overflow-y: auto; }
  section + section { border-left: 1px solid #1c2530; }
  h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #7c8a99; margin: 18px 0 8px; }
  h2:first-child { margin-top: 0; }
  table { width: 100%; border-collapse: collapse; }
  td, th { text-align: left; padding: 6px 6px; border-bottom: 1px solid #16202b; vertical-align: top; }
  .sev { font-weight: 600; padding: 1px 7px; border-radius: 4px; font-size: 11px; display: inline-block; }
  .sev-critical { background: #4a1414; color: #ff8080; }
  .sev-high { background: #4a2c14; color: #ffb366; }
  .sev-medium { background: #4a4614; color: #f0e070; }
  .sev-low { background: #14304a; color: #7ec8ff; }
  .sev-info { background: #1c2530; color: #9fb0c0; }
  .empty { color: #55606c; font-style: italic; }
  .event { padding: 5px 0; border-bottom: 1px solid #131b24; font-size: 12.5px; }
  .event .k { color: #4fd1c5; }
  .event .l { color: #d8e0e8; font-weight: 600; }
  .event .d { color: #8b98a6; display: block; white-space: pre-wrap; word-break: break-word; }
  .usage { display: flex; gap: 18px; flex-wrap: wrap; font-size: 12.5px; color: #9fb0c0; }
  .usage b { color: #d8e0e8; }
  footer { padding: 8px 20px; color: #55606c; font-size: 11px; border-top: 1px solid #1c2530; }
</style>
</head>
<body>
<header>
  <h1>glaive</h1>
  <span id="target" class="pill"></span>
  <span id="status" class="pill"></span>
  <span id="usage" class="usage"></span>
</header>
<main>
  <section>
    <h2>Hallazgos</h2>
    <table id="findings"><tbody></tbody></table>
    <h2>Pendientes</h2>
    <table id="todos"><tbody></tbody></table>
  </section>
  <section>
    <h2>Actividad en vivo</h2>
    <div id="events"></div>
  </section>
</main>
<footer>actualiza cada 1.5s · solo lectura · no consume tokens</footer>
<script>
const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
async function tick() {
  let data;
  try { data = await (await fetch('/api/state')).json(); } catch (e) { return; }

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

  const findings = (data.findings || []).slice().sort((a,b) => (sevOrder[a.severity]??9) - (sevOrder[b.severity]??9));
  const ftbody = document.querySelector('#findings tbody');
  ftbody.innerHTML = findings.length ? findings.map(f => `
    <tr>
      <td><span class="sev sev-${f.severity}">${f.severity}</span>${f.status === 'potential' ? ' <span class="d" style="color:#f0e070">(potencial)</span>' : ''}</td>
      <td><b>${escapeHtml(f.title)}</b>${f.cvss_score != null ? ` <span class="d">CVSS ${f.cvss_score}</span>` : ''}<br><span class="d" style="color:#8b98a6">${escapeHtml(f.endpoint||'')}</span></td>
    </tr>`).join('') : '<tr><td class="empty">Sin hallazgos todavía.</td></tr>';

  const todos = data.todos || [];
  const ttbody = document.querySelector('#todos tbody');
  ttbody.innerHTML = todos.length ? todos.map(t => `<tr><td>#${t.id}</td><td>${escapeHtml(t.content)}</td></tr>`).join('')
    : '<tr><td class="empty">Sin pendientes.</td></tr>';

  const events = data.events || [];
  document.getElementById('events').innerHTML = events.length ? events.map(e => `
    <div class="event">
      <span class="k">${e.kind}</span> <span class="l">${escapeHtml(e.label||'')}</span>
      ${e.detail ? `<span class="d">${escapeHtml(e.detail)}</span>` : ''}
    </div>`).join('') : '<div class="empty">Sin actividad todavía.</div>';
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
tick();
setInterval(tick, 1500);
</script>
</body>
</html>
"""


def _make_handler(store: Store) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:  # silencia el access log en la consola
            pass

        def do_GET(self) -> None:  # noqa: N802 (nombre impuesto por BaseHTTPRequestHandler)
            if self.path in ("/", "") or self.path.startswith("/?"):
                self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path.startswith("/api/state"):
                snapshot = {
                    "session": store.session(),
                    "findings": store.findings(),
                    "todos": store.open_todos(),
                    "events": store.recent_events(limit=60),
                    "usage": store.get_usage(),
                }
                self._send(200, json.dumps(snapshot).encode("utf-8"), "application/json")
            else:
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
    """Levanta el dashboard en un hilo daemon. Devuelve (url, server) — llamar
    server.shutdown() al terminar la sesión."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(store))
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - abrir el navegador es best-effort
            pass
    return url, server
