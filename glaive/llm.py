"""Cliente OpenRouter con prompt caching.

La palanca #1 de ahorro de tokens: marcamos con ``cache_control: ephemeral`` el
prefijo estable de la conversación (system + último mensaje). En modelos que lo
soportan (Claude, Gemini vía OpenRouter) los turnos siguientes solo pagan el
delta nuevo (~10% del prefijo en cache hits) en lugar de reenviar todo cada vez.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class Usage:
    """Acumulador de tokens/costo para toda la sesión."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0

    def add(self, raw: dict[str, Any]) -> None:
        self.calls += 1
        self.prompt_tokens += int(raw.get("prompt_tokens") or 0)
        self.completion_tokens += int(raw.get("completion_tokens") or 0)
        details = raw.get("prompt_tokens_details") or {}
        self.cached_tokens += int(details.get("cached_tokens") or 0)
        self.cost_usd += float(raw.get("cost") or 0.0)

    def summary(self) -> str:
        cache_rate = (
            f"{100 * self.cached_tokens / self.prompt_tokens:.0f}%"
            if self.prompt_tokens
            else "0%"
        )
        return (
            f"{self.calls} llamadas · {self.prompt_tokens:,} in "
            f"({cache_rate} cacheado) · {self.completion_tokens:,} out "
            f"· ${self.cost_usd:.4f}"
        )


def _is_model_unavailable(status_code: int, body_text: str) -> bool:
    """Detecta el 404 particular de OpenRouter cuando un modelo (gratis, típicamente)
    dejó de estar disponible — la capa free se rota sin aviso ni SLA."""
    return status_code == 404 and "unavailable" in body_text.lower()


@dataclass
class LLMResponse:
    message: dict[str, Any]
    finish_reason: str
    raw_usage: dict[str, Any] = field(default_factory=dict)
    used_model: str = ""

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        return self.message.get("tool_calls") or []

    @property
    def text(self) -> str:
        return self.message.get("content") or ""


def _mark_cacheable(content: Any) -> Any:
    """Convierte un content (str o lista de parts) en parts con cache_control."""
    if isinstance(content, str):
        if not content:
            return content
        return [{"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}]
    if isinstance(content, list) and content:
        marked = [dict(p) for p in content]
        if isinstance(marked[-1], dict):
            marked[-1]["cache_control"] = {"type": "ephemeral"}
        return marked
    return content


def _with_cache_breakpoints(
    messages: list[dict[str, Any]], stable_len: int | None = None
) -> list[dict[str, Any]]:
    """Marca el system y el último mensaje ESTABLE como límites de cache.

    Anthropic cachea el prefijo hasta cada breakpoint. El truco: ``stable_len``
    es cuántos mensajes desde el principio son parte de la conversación real
    (no cambian de un hop a otro); el resumen de estado que se apila al final
    de cada request SÍ cambia en cada llamada, así que queda fuera del segundo
    breakpoint — marcarlo pagaría el premio de escritura de caché en un bloque
    que nunca se reutiliza.
    """
    out = [dict(m) for m in messages]
    for m in out:
        if m.get("role") == "system":
            m["content"] = _mark_cacheable(m.get("content"))
            break
    boundary = (stable_len - 1) if stable_len else len(out) - 1
    boundary = max(0, min(boundary, len(out) - 1))
    out[boundary]["content"] = _mark_cacheable(out[boundary].get("content"))
    return out


class LLMClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        fallback_model: str | None = None,
        timeout: float = 300.0,
    ):
        self.model = model
        self.fallback_model = fallback_model
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                # Requeridos/recomendados por OpenRouter para ranking y soporte.
                "HTTP-Referer": "https://github.com/glaive-sec/glaive",
                "X-Title": "glaive",
            },
        )

    def _build_payload(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str | None,
        cache: bool,
        stable_len: int | None,
        max_tokens: int,
        temperature: float,
        stream: bool,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model or self.model,
            "messages": _with_cache_breakpoints(messages, stable_len) if cache else messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "usage": {"include": True},
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if stream:
            payload["stream"] = True
            payload["stream_options"] = {"include_usage": True}
        return payload

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        model: str | None = None,
        cache: bool = True,
        stable_len: int | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.4,
    ) -> LLMResponse:
        payload = self._build_payload(
            messages, tools, model, cache, stable_len, max_tokens, temperature, stream=False
        )
        resp = self._client.post("/chat/completions", json=payload)
        if self.fallback_model and _is_model_unavailable(resp.status_code, resp.text):
            payload = {**payload, "model": self.fallback_model}
            resp = self._client.post("/chat/completions", json=payload)
        if resp.status_code >= 400:
            raise RuntimeError(f"OpenRouter {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        if "choices" not in data:
            raise RuntimeError(f"Respuesta inesperada de OpenRouter: {json.dumps(data)[:500]}")
        choice = data["choices"][0]
        return LLMResponse(
            message=choice["message"],
            finish_reason=choice.get("finish_reason", ""),
            raw_usage=data.get("usage") or {},
            used_model=payload["model"],
        )

    def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        model: str | None = None,
        cache: bool = True,
        stable_len: int | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.4,
    ) -> "StreamResult":
        payload = self._build_payload(
            messages, tools, model, cache, stable_len, max_tokens, temperature, stream=True
        )
        return StreamResult(self._client, payload, self.fallback_model)

    def close(self) -> None:
        self._client.close()


class StreamResult:
    """Envoltorio iterable de una respuesta en streaming.

    Iterar sobre la instancia produce los deltas de texto a medida que llegan
    (para imprimirlos en vivo, estilo Claude Code). Una vez agotado el
    iterador, ``.message``/``.finish_reason``/``.raw_usage`` quedan poblados
    con el resultado completo, en el mismo formato que ``LLMResponse.message``.
    """

    def __init__(
        self, client: httpx.Client, payload: dict[str, Any], fallback_model: str | None = None
    ):
        self._client = client
        self._payload = payload
        self._fallback_model = fallback_model
        self.message: dict[str, Any] = {"role": "assistant", "content": ""}
        self.finish_reason: str = ""
        self.raw_usage: dict[str, Any] = {}
        self.used_model: str = payload.get("model", "")

    def __iter__(self):
        content_parts: list[str] = []
        tool_calls: dict[int, dict[str, Any]] = {}
        payload = self._payload
        tried_fallback = False

        while True:
            with self._client.stream("POST", "/chat/completions", json=payload) as resp:
                if resp.status_code >= 400:
                    resp.read()
                    if (
                        not tried_fallback
                        and self._fallback_model
                        and _is_model_unavailable(resp.status_code, resp.text)
                    ):
                        # El modelo (gratis, típicamente) dejó de estar disponible.
                        # Reabrimos la conexión con el de respaldo, una sola vez.
                        tried_fallback = True
                        payload = {**payload, "model": self._fallback_model}
                        self.used_model = self._fallback_model
                        continue
                    raise RuntimeError(f"OpenRouter {resp.status_code}: {resp.text[:500]}")

                for line in resp.iter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:") :].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if chunk.get("usage"):
                        self.raw_usage = chunk["usage"]
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    choice = choices[0]
                    if choice.get("finish_reason"):
                        self.finish_reason = choice["finish_reason"]
                    delta = choice.get("delta") or {}
                    text = delta.get("content")
                    if text:
                        content_parts.append(text)
                        yield text
                    for tc in delta.get("tool_calls") or []:
                        idx = tc.get("index", 0)
                        slot = tool_calls.setdefault(
                            idx,
                            {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                        )
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["function"]["name"] += fn["name"]
                        if fn.get("arguments"):
                            slot["function"]["arguments"] += fn["arguments"]
            break

        self.message["content"] = "".join(content_parts)
        if tool_calls:
            self.message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
