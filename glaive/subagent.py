"""Subagentes — delegación acotada, NO un enjambre por defecto.

A diferencia de Strix (donde un "root agent" está OBLIGADO a delegar todo y
reenvía su prompt de sistema completo, ~47KB, a cada subagente — ver
ANALISIS-Y-DISENO.md) acá:

- El agente principal decide cuándo delegar vía la tool `spawn_subagents`; por
  defecto sigue trabajando él mismo. Delegar solo vale la pena cuando hay
  trabajo genuinamente paralelo o una subtarea autocontenida.
- Cada subagente arranca con un prompt MÍNIMO (la tarea puntual, no toda la
  metodología) — si necesita el detalle de una vulnerabilidad, lo pide con
  `load_playbook` igual que el agente principal.
- Comparten el mismo Store (SQLite): sus findings/notas/eventos van directo
  al estado compartido, no viajan por el contexto del padre.
- Al padre solo le vuelve un resumen de 1-3 líneas por subagente — nunca su
  transcript completo.
- Corren en paralelo de verdad (hilos + su propio LLMClient/conexión HTTP)
  cuando el modelo pide varias tareas en un mismo tool call.
- Profundidad 1: no pueden a su vez spawnear subagentes ni llamar `finish`
  (eso le corresponde al engagement completo, no a una subtarea).
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from glaive.llm import LLMClient
from glaive.tools import TOOL_SCHEMAS, make_executor

if TYPE_CHECKING:
    from glaive.config import Config
    from glaive.sandbox import Sandbox
    from glaive.state import Store

_MAX_HOPS = 12
_MAX_SUMMARY_CHARS = 600
_EXCLUDED_TOOLS = {"spawn_subagents", "finish", "propose_scope_expansion"}

_PROMPT = """Sos un pentester especializado ejecutando UNA subtarea acotada, delegada por \
el agente principal de este engagement. No coordinás nada más allá de esto ni delegás a nadie.

<tarea>
{task}
</tarea>

<alcance>
{scope}
</alcance>

Reglas: confirmá con evidencia reproducible antes de `add_finding` (nunca reportes \
sospechas como confirmadas). Sé económico: no repitas escaneos, no releas salidas \
completas si un resumen alcanza. Metodología detallada por vulnerabilidad: cargala \
con `load_playbook` si la necesitás — no está precargada acá.

Cuando termines la subtarea, respondé en texto plano con un resumen de 1 a 3 líneas \
de lo que hiciste/encontraste. Esa respuesta es tu entrega final — no sigas \
haciendo tool calls después de darla."""


def _subagent_tools() -> list[dict[str, Any]]:
    return [t for t in TOOL_SCHEMAS if t["function"]["name"] not in _EXCLUDED_TOOLS]


@dataclass
class _Result:
    label: str
    summary: str


def _log_usage(store: "Store", raw_usage: dict[str, Any]) -> None:
    details = raw_usage.get("prompt_tokens_details") or {}
    store.add_usage(
        int(raw_usage.get("prompt_tokens") or 0),
        int(raw_usage.get("completion_tokens") or 0),
        int(details.get("cached_tokens") or 0),
        float(raw_usage.get("cost") or 0.0),
        1,
    )


def _run_one(
    cfg: "Config",
    store: "Store",
    sandbox: "Sandbox",
    label: str,
    task: str,
    scope: str,
    on_event: Callable[[str, str], None] | None,
) -> _Result:
    if on_event:
        on_event(label, "iniciado")
    store.log_event("subagent_start", label, task[:300])

    llm = LLMClient(cfg.api_key, cfg.base_url, cfg.model, cfg.model_fallback or None)
    execute_tool = make_executor(store, sandbox, cfg.tool_output_chars, cfg, on_subagent_event=None)
    tools = _subagent_tools()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": _PROMPT.format(task=task, scope=scope)},
        {"role": "user", "content": "Empezá."},
    ]
    summary = "(sin resumen — alcanzó el límite de pasos de la subtarea)"

    try:
        for _ in range(_MAX_HOPS):
            state_msg = {"role": "user", "content": store.compact_state()}
            payload = [*messages, state_msg]
            resp = llm.complete(
                payload, tools=tools, model=cfg.model, stable_len=len(payload) - 1, max_tokens=2048
            )
            _log_usage(store, resp.raw_usage)
            messages.append(resp.message)

            if not resp.tool_calls:
                summary = (resp.text or summary).strip()[:_MAX_SUMMARY_CHARS]
                break

            for call in resp.tool_calls:
                fn = call["function"]
                name = fn["name"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                store.log_event("tool_call", f"[{label}] {name}", json.dumps(args)[:300])
                result, _is_finish = execute_tool(name, args)
                store.log_event("tool_result", f"[{label}] {name}", result[:300])
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})
    finally:
        llm.close()

    store.log_event("subagent_done", label, summary)
    if on_event:
        on_event(label, f"listo — {summary[:120]}")
    return _Result(label=label, summary=summary)


def run_subagents(
    cfg: "Config",
    store: "Store",
    sandbox: "Sandbox",
    tasks: list[dict[str, str]],
    on_event: Callable[[str, str], None] | None = None,
) -> str:
    """Corre ``tasks=[{label, task}, ...]`` en paralelo. Devuelve un resumen agregado."""
    tasks = [t for t in tasks if t.get("task")]
    if not tasks:
        return "No se especificaron subtareas (cada una necesita 'label' y 'task')."

    scope = store.session().get("scope", "")

    def _worker(t: dict[str, str]) -> _Result:
        label = t.get("label") or "subagente"
        return _run_one(cfg, store, sandbox, label, t["task"], scope, on_event)

    with ThreadPoolExecutor(max_workers=min(4, len(tasks))) as pool:
        results = list(pool.map(_worker, tasks))

    return "\n".join(f"[{r.label}] {r.summary}" for r in results)
