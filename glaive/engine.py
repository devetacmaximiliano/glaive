"""Núcleo del agente: una sesión, un modelo, herramientas — sin enjambre de subagentes.

``Session`` es el motor que usan tanto el modo interactivo (glaive/repl.py,
la experiencia "como Claude Code") como el modo autónomo (--auto). Cada
``turn()`` es un intercambio completo: se le da una instrucción y el agente
encadena tool calls —mostrando cada una en vivo vía callbacks— hasta que
responde solo con texto (le devuelve la palabra al usuario) o llama
``finish``.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, FileSystemLoader

from glaive.compaction import maybe_compact
from glaive.config import Config
from glaive.llm import LLMClient, Usage
from glaive.sandbox import Sandbox
from glaive.state import Store
from glaive.tools import TOOL_SCHEMAS, make_executor

_PROMPTS_DIR = Path(__file__).parent / "prompts"

# Límite de tool calls encadenadas DENTRO de un mismo turno (red de seguridad
# contra loops; no confundir con --max-turns, que son turnos autónomos completos).
_MAX_TOOL_HOPS = 25

TextCallback = Callable[[str], None]
ToolCallCallback = Callable[[str, dict[str, Any]], None]
ToolResultCallback = Callable[[str], None]
SubagentEventCallback = Callable[[str, str], None]
AskUserCallback = Callable[[str], str]


def _render_system_prompt(target: str, scope: str, mode: str) -> str:
    env = Environment(loader=FileSystemLoader(_PROMPTS_DIR))
    return env.get_template("system.j2").render(target=target, scope=scope, mode=mode)


class Session:
    def __init__(
        self, cfg: Config, target: str, scope: str, mode: str, session_id: str | None = None
    ):
        self.cfg = cfg
        self.target = target
        self.scope = scope or target
        self.mode = mode
        self.session_id = session_id or uuid.uuid4().hex[:12]

        run_dir = cfg.runs_dir / self.session_id
        self.store = Store(run_dir / "state.db")
        previous = self.store.load_messages()
        self.store.init_session(self.session_id, self.target, self.scope)

        self.sandbox = Sandbox(cfg.sandbox, cfg.sandbox_image, self.session_id, run_dir / "workspace")
        self.llm = LLMClient(cfg.api_key, cfg.base_url, cfg.model, cfg.model_fallback or None)
        self.usage = Usage()
        self._on_subagent_event: SubagentEventCallback | None = None
        self._on_ask_user: AskUserCallback | None = None
        self.execute_tool = make_executor(
            self.store,
            self.sandbox,
            cfg.tool_output_chars,
            cfg,
            on_subagent_event=lambda label, msg: (
                self._on_subagent_event(label, msg) if self._on_subagent_event else None
            ),
            on_ask_user=lambda q: self._on_ask_user(q) if self._on_ask_user else None,
        )

        self.messages: list[dict[str, Any]] = previous or [
            {"role": "system", "content": _render_system_prompt(self.target, self.scope, self.mode)}
        ]

    def start(self) -> str:
        """Levanta el sandbox y devuelve una descripción corta para el banner."""
        self.cfg.require_key()
        return self.sandbox.start()

    def turn(
        self,
        user_text: str,
        *,
        on_text: TextCallback | None = None,
        on_tool_call: ToolCallCallback | None = None,
        on_tool_result: ToolResultCallback | None = None,
        on_subagent_event: SubagentEventCallback | None = None,
        on_ask_user: AskUserCallback | None = None,
    ) -> bool:
        """Ejecuta un turno completo. Devuelve True si el agente llamó `finish`."""
        self._on_subagent_event = on_subagent_event
        self._on_ask_user = on_ask_user
        self.messages.append({"role": "user", "content": user_text})
        finished = False

        for _ in range(_MAX_TOOL_HOPS):
            state_msg = {"role": "user", "content": self.store.compact_state()}
            payload = maybe_compact(
                [*self.messages, state_msg],
                self.llm,
                self.cfg.model_cheap,
                self.cfg.compact_tokens,
                self.store,
            )
            # El último mensaje del payload es siempre el resumen de estado
            # (cambia en cada hop); todo lo anterior es el prefijo cacheable.
            stable_len = len(payload) - 1

            stream = self.llm.stream(payload, tools=TOOL_SCHEMAS, stable_len=stable_len)
            for chunk in stream:
                if on_text:
                    on_text(chunk)
            if stream.used_model and stream.used_model != self.cfg.model:
                self.store.log_event(
                    "model_fallback",
                    stream.used_model,
                    f"'{self.cfg.model}' no disponible, se uso el modelo de respaldo",
                )
            self.usage.add(stream.raw_usage)
            self._log_usage(stream.raw_usage)
            self.messages.append(stream.message)
            if stream.message.get("content"):
                self.store.log_event("assistant_text", "", stream.message["content"][:300])

            tool_calls = stream.message.get("tool_calls") or []
            if not tool_calls:
                break

            for call in tool_calls:
                fn = call["function"]
                name = fn["name"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}

                self.store.log_event("tool_call", name, json.dumps(args)[:300])
                if on_tool_call:
                    on_tool_call(name, args)
                result, is_finish = self.execute_tool(name, args)
                self.store.log_event("tool_result", name, result[:300])
                if on_tool_result:
                    on_tool_result(result)
                self.messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})
                if is_finish:
                    finished = True

            if finished:
                break

        self._on_subagent_event = None
        self._on_ask_user = None
        self.store.replace_messages(self.messages)
        self.store.set_status(self.session_id, "finished" if finished else "running")
        return finished

    def _log_usage(self, raw_usage: dict[str, Any]) -> None:
        details = raw_usage.get("prompt_tokens_details") or {}
        self.store.add_usage(
            int(raw_usage.get("prompt_tokens") or 0),
            int(raw_usage.get("completion_tokens") or 0),
            int(details.get("cached_tokens") or 0),
            float(raw_usage.get("cost") or 0.0),
            1,
        )

    def shutdown(self) -> None:
        if self.store.session().get("status") == "running":
            self.store.set_status(self.session_id, "stopped")
        self.sandbox.stop()
        self.llm.close()
