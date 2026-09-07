"""Compactación de contexto — se dispara por umbral, no en cada turno.

Cuando el historial de mensajes crece demasiado, resumimos los turnos viejos en
un único checkpoint y conservamos los últimos N turnos verbatim. El resumen lo
hace el modelo barato (``model_cheap``), no el modelo principal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from glaive.llm import LLMClient

if TYPE_CHECKING:
    from glaive.state import Store

_KEEP_RECENT = 8  # últimos N mensajes que se conservan tal cual
_CHECKPOINT_ROLE = "user"
_CHECKPOINT_PREFIX = "<checkpoint-de-conversacion>"


def approx_tokens(messages: list[dict[str, Any]]) -> int:
    """Estimación barata: ~4 chars por token, sin llamar al tokenizer real."""
    total_chars = 0
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for part in content:
                total_chars += len(str(part.get("text", "")))
        for tc in m.get("tool_calls") or []:
            total_chars += len(str(tc))
    return total_chars // 4


def maybe_compact(
    messages: list[dict[str, Any]],
    llm: LLMClient,
    cheap_model: str,
    threshold_tokens: int,
    store: "Store | None" = None,
) -> list[dict[str, Any]]:
    if approx_tokens(messages) < threshold_tokens or len(messages) <= _KEEP_RECENT + 1:
        return messages

    system = messages[0]
    old = messages[1:-_KEEP_RECENT]
    recent = messages[-_KEEP_RECENT:]
    if not old:
        return messages

    transcript = "\n".join(
        f"[{m.get('role')}] {_flatten(m)}" for m in old if _flatten(m)
    )[:20_000]

    summary_resp = llm.complete(
        [
            {
                "role": "system",
                "content": (
                    "Resumí esta porción de un engagement de pentest en un párrafo denso. "
                    "Conservá: endpoints probados, técnicas ya intentadas (para no repetirlas), "
                    "credenciales/datos descubiertos, y qué falta explorar. Sin relleno."
                ),
            },
            {"role": "user", "content": transcript},
        ],
        model=cheap_model,
        cache=False,
        max_tokens=600,
        temperature=0.2,
    )
    if store is not None:
        details = summary_resp.raw_usage.get("prompt_tokens_details") or {}
        store.add_usage(
            int(summary_resp.raw_usage.get("prompt_tokens") or 0),
            int(summary_resp.raw_usage.get("completion_tokens") or 0),
            int(details.get("cached_tokens") or 0),
            float(summary_resp.raw_usage.get("cost") or 0.0),
            1,
        )

    checkpoint = {
        "role": _CHECKPOINT_ROLE,
        "content": f"{_CHECKPOINT_PREFIX}\n{summary_resp.text}",
    }
    return [system, checkpoint, *recent]


def _flatten(m: dict[str, Any]) -> str:
    content = m.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    tool_calls = m.get("tool_calls")
    if tool_calls:
        return f"tool_calls: {tool_calls}"
    return ""
