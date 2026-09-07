"""Definición de herramientas + su ejecución.

Reglas de eficiencia aplicadas acá (ver ANALISIS-Y-DISENO.md §6):
- Toda salida de herramienta se trunca a ``tool_output_chars``; si el modelo
  necesita más, usa ``read_more`` para pedir el resto por id (no se reenvía
  todo "por las dudas").
- Los playbooks de metodología (SQLi, XSS, IDOR...) NO están en el system
  prompt: se cargan on-demand con ``load_playbook`` solo cuando el agente
  decide que aplican.
- findings/notas/todos van directo al Store (estado externo), no al historial
  de mensajes.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from glaive.guard import check_destructive
from glaive.sandbox import Sandbox
from glaive.state import Store

if TYPE_CHECKING:
    from glaive.config import Config

_MAX_SUBAGENT_TASKS = 4
_CLEAR_SCOPE_RELATIONS = {
    "shared_cert",
    "same_org_confirmed",
    "explicit_backend_reference",
    "subdomain_of_scope",
}

PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"


def _available_playbooks() -> list[str]:
    if not PLAYBOOKS_DIR.exists():
        return []
    return sorted(p.stem for p in PLAYBOOKS_DIR.glob("*.md"))


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "exec_command",
            "description": (
                "Ejecuta un comando de shell en el sandbox de testing (nmap, curl, "
                "sqlmap, ffuf, python, etc). Usalo para reconocimiento, escaneo y "
                "verificación de vulnerabilidades. La salida se trunca; si necesitás "
                "más, usá read_more con el id devuelto."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Comando de shell a ejecutar."},
                    "timeout": {"type": "integer", "description": "Timeout en segundos (default 180)."},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "load_playbook",
            "description": (
                "Carga la metodología detallada para un tipo de vulnerabilidad o fase "
                f"(bajo demanda, no ocupa contexto hasta que la pedís). Disponibles: "
                f"{', '.join(_available_playbooks()) or '(ninguno instalado)'}."
            ),
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_more",
            "description": "Recupera el texto completo de una salida truncada previa por su id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "output_id": {"type": "integer"},
                    "offset": {"type": "integer", "description": "Carácter desde donde seguir leyendo (default 0)."},
                },
                "required": ["output_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": (
                "Registra o actualiza un hallazgo. status es OBLIGATORIO: 'potential' "
                "(sospecha, evidencia parcial) o 'confirmed' (≥2 señales independientes o "
                "un PoC ejecutado). Si el mismo CWE+endpoint ya tiene un finding potential/"
                "confirmed, esto NO crea uno nuevo — te devuelve el existente (pasale "
                "finding_id para actualizarlo, o chains_from si es realmente distinto). "
                "Para pasar un finding de potential a confirmed, volvé a llamar con el "
                "mismo finding_id y status='confirmed' + la evidencia nueva."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "status": {"type": "string", "enum": ["potential", "confirmed", "remediated"]},
                    "cwe": {"type": "string", "description": "Ej: CWE-89"},
                    "wstg": {"type": "string", "description": "OWASP WSTG ID, ej: WSTG-INPV-05"},
                    "owasp": {"type": "string", "description": "OWASP Top 10, ej: A03:2021-Injection"},
                    "cvss_vector": {
                        "type": "string",
                        "description": "Vector CVSS 3.1 completo, ej: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — el score se calcula solo, no lo inventes vos.",
                    },
                    "endpoint": {"type": "string", "description": "URL/host/puerto afectado."},
                    "description": {"type": "string"},
                    "evidence": {"type": "string", "description": "Petición/respuesta u output que lo prueba."},
                    "poc": {"type": "string", "description": "Pasos para reproducir."},
                    "remediation": {"type": "string"},
                    "chains_from": {
                        "type": "integer",
                        "description": "ID de otro finding que habilita este (para reconstruir la cadena de ataque). Omitir si es independiente.",
                    },
                    "finding_id": {
                        "type": "integer",
                        "description": "Si se pasa, ACTUALIZA ese finding en vez de crear uno nuevo (ej: potential -> confirmed).",
                    },
                },
                "required": ["title", "severity", "status", "endpoint", "description", "evidence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_scope_expansion",
            "description": (
                "Proponé incluir un activo nuevo (dominio/subdominio/host/IP) descubierto "
                "durante el engagement. Si la relación con el target original es CLARA "
                "(mismo certificado TLS, mismo dueño/org confirmado, es el backend/API que "
                "la app en scope consume explícitamente, o es subdominio directo del "
                "dominio en scope) se incluye automáticamente. Si es dudosa ('uncertain'), "
                "se le pregunta al usuario en sesión interactiva, o queda PENDIENTE sin "
                "tocar en modo autónomo (sin nadie a quien preguntarle) — en ambos casos "
                "NO lo ataques hasta tener respuesta."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "asset": {"type": "string", "description": "Dominio/host/IP descubierto."},
                    "relation": {
                        "type": "string",
                        "enum": [
                            "shared_cert",
                            "same_org_confirmed",
                            "explicit_backend_reference",
                            "subdomain_of_scope",
                            "uncertain",
                        ],
                    },
                    "evidence": {"type": "string", "description": "Por qué creés que está relacionado."},
                },
                "required": ["asset", "relation", "evidence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "manage_todo",
            "description": "Agrega o completa un ítem del plan de trabajo (estado externo, no ocupa el chat).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["add", "complete"]},
                    "content": {"type": "string", "description": "Requerido si action=add."},
                    "todo_id": {"type": "integer", "description": "Requerido si action=complete."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_note",
            "description": "Guarda una nota corta de contexto útil (credenciales encontradas, estructura del sitio, etc).",
            "parameters": {
                "type": "object",
                "properties": {"content": {"type": "string"}},
                "required": ["content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "spawn_subagents",
            "description": (
                "Delega 1 a 4 subtareas ACOTADAS y AUTOCONTENIDAS a subagentes que corren "
                "en paralelo de verdad (mismo estado compartido — sus hallazgos aparecen "
                "directo en tu <estado> —, pero con un prompt propio mínimo: no ven tu "
                "conversación, así que cada 'task' tiene que ser autosuficiente). "
                "Usalo SOLO cuando hay trabajo genuinamente paralelizable: varios "
                "hosts/endpoints independientes, o un playbook completo contra un target "
                "mientras vos seguís con otra cosa. Para el flujo principal del "
                "engagement seguí trabajando vos mismo — no delegues por costumbre, cada "
                "subagente tiene su propio costo de tokens. Te vuelve un resumen corto "
                "por subtarea, no el detalle completo de lo que hicieron."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tasks": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": _MAX_SUBAGENT_TASKS,
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {
                                    "type": "string",
                                    "description": "Identificador corto, ej: 'host-10.0.0.5'.",
                                },
                                "task": {
                                    "type": "string",
                                    "description": "Instrucción completa y AUTOCONTENIDA (el subagente no ve tu historial).",
                                },
                            },
                            "required": ["label", "task"],
                        },
                    }
                },
                "required": ["tasks"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Marca el engagement como terminado. Llamalo solo cuando el alcance esté cubierto.",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    },
]


def _truncate(store: Store, tool: str, text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    out_id = store.stash_output(tool, text)
    return (
        text[:limit]
        + f"\n\n[... truncado a {limit} chars · id={out_id} ·"
        f" usá read_more(output_id={out_id}, offset={limit}) para continuar ...]"
    )


def make_executor(
    store: Store,
    sandbox: Sandbox,
    tool_output_chars: int,
    cfg: "Config",
    on_subagent_event: Callable[[str, str], None] | None = None,
    on_ask_user: Callable[[str], str] | None = None,
) -> Callable[[str, dict[str, Any]], tuple[str, bool]]:
    """Devuelve execute(name, args) -> (resultado_texto, is_finish).

    ``on_ask_user`` solo lo pasa la sesión raíz en modo interactivo — nunca los
    subagentes (correrían en un hilo de fondo y no hay a quién preguntarle) ni
    el modo ``--auto``. Cuando es ``None``, ``propose_scope_expansion`` con
    relación dudosa queda directamente en estado pendiente.
    """

    def execute(name: str, args: dict[str, Any]) -> tuple[str, bool]:
        if name == "exec_command":
            command = args["command"]
            blocked_reason = check_destructive(command)
            if blocked_reason:
                store.log_event("blocked_command", blocked_reason, command[:300])
                return (
                    f"[bloqueado por el guard anti-destructivo: {blocked_reason}] "
                    "Esta acción es potencialmente destructiva o de denegación de "
                    "servicio. Reformulá a una prueba mínima y no destructiva, o "
                    "documentá el impacto teórico sin ejecutarla. Esto es defensa en "
                    "profundidad, no reemplaza tu criterio — no intentes evadirlo."
                ), False
            out = sandbox.exec(command, timeout=int(args.get("timeout") or 180))
            return _truncate(store, name, out, tool_output_chars), False

        if name == "load_playbook":
            pb = PLAYBOOKS_DIR / f"{args['name']}.md"
            if not pb.exists():
                available = ", ".join(_available_playbooks())
                return f"No existe el playbook '{args['name']}'. Disponibles: {available}", False
            return pb.read_text(encoding="utf-8"), False

        if name == "read_more":
            full = store.get_output(int(args["output_id"]))
            if full is None:
                return "output_id inválido.", False
            offset = int(args.get("offset") or 0)
            chunk = full[offset : offset + tool_output_chars]
            more = offset + tool_output_chars < len(full)
            suffix = (
                f"\n\n[... seguí con offset={offset + tool_output_chars} ...]" if more else ""
            )
            return chunk + suffix, False

        if name == "add_finding":
            _fid, message = store.upsert_finding(**args)
            return message, False

        if name == "propose_scope_expansion":
            asset = args.get("asset", "")
            relation = args.get("relation", "uncertain")
            evidence = args.get("evidence", "")

            if relation in _CLEAR_SCOPE_RELATIONS:
                store.add_scope_asset(asset, relation, evidence, status="included")
                store.log_event("scope_expanded", asset, f"relación clara: {relation}")
                return f"'{asset}' incluido en el alcance (relación: {relation}).", False

            # ``on_ask_user`` (la trampolín de Session) siempre es callable aunque no
            # haya nadie a quien preguntarle en este turno — por eso lo que importa
            # es lo que DEVUELVE, no si el callable existe. None = sin usuario
            # disponible (subagente, modo --auto, o interactivo pero sin handler).
            answer = on_ask_user(
                f"El agente descubrió '{asset}' y no está seguro si está relacionado "
                f"con el alcance actual.\nEvidencia: {evidence}\n"
                "¿Lo incluyo en el alcance? (si/no)"
            ) if on_ask_user else None

            if answer is not None:
                included = answer.strip().lower().startswith("s")
                store.add_scope_asset(
                    asset, relation, evidence, status="included" if included else "rejected"
                )
                store.log_event(
                    "scope_expanded" if included else "scope_rejected", asset, f"usuario: {answer}"
                )
                veredicto = "incluido en el alcance." if included else "NO incluido en el alcance."
                return f"Usuario respondió {answer!r}. '{asset}' {veredicto}", False

            store.add_scope_asset(asset, relation, evidence, status="pending")
            store.log_event("scope_pending", asset, evidence)
            return (
                f"Sin usuario disponible para confirmar (modo autónomo). '{asset}' quedó "
                "PENDIENTE de aprobación — todavía NO está en el alcance, no lo ataques."
            ), False

        if name == "manage_todo":
            if args["action"] == "add":
                tid = store.add_todo(args.get("content", ""))
                return f"Todo #{tid} agregado.", False
            store.complete_todo(int(args["todo_id"]))
            return f"Todo #{args['todo_id']} completado.", False

        if name == "add_note":
            store.add_note(args.get("content", ""))
            return "Nota guardada.", False

        if name == "spawn_subagents":
            from glaive.subagent import run_subagents  # import diferido: evita ciclo con tools

            tasks = (args.get("tasks") or [])[:_MAX_SUBAGENT_TASKS]
            return run_subagents(cfg, store, sandbox, tasks, on_event=on_subagent_event), False

        if name == "finish":
            return args.get("summary", "Engagement finalizado."), True

        return f"Herramienta desconocida: {name}", False

    return execute
