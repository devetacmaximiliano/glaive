"""La interfaz de terminal: la experiencia "Claude Code, pero de pentesting".

Input ASÍNCRONO (como Claude Code): el prompt sigue vivo mientras el modelo
piensa y responde. Podés:
- escribir mientras el agente trabaja → tu mensaje se ENCOLA y se manda cuando
  termina el turno en curso;
- interrumpir el turno en caliente con Ctrl-C (una vez); Ctrl-C de nuevo (o con
  la cola vacía y nada corriendo) sale;
- responder las confirmaciones del agente (ampliación de scope, etc.) desde el
  mismo prompt.

Se apoya en ``prompt_toolkit`` (input no bloqueante + ``patch_stdout`` para que
el streaming del agente no rompa el renglón de input). Si no está instalado, cae
a un REPL clásico lockstep. ``--auto`` no usa nada de esto (no hay input humano).
"""

from __future__ import annotations

import asyncio
import queue
import threading
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from glaive.config import Config
from glaive.dashboard import start_dashboard
from glaive.engine import Session
from glaive.report import write_report

_HELP = """\
[bold]Comandos[/]
  /help              esta ayuda
  /findings          lista los hallazgos (potential/confirmed, con CVSS si tiene)
  /todos             lista los pendientes
  /scope             activos incluidos/pendientes en el alcance dinámico
  /report [archivo]  genera el reporte (plantilla, no gasta tokens de LLM)
  /usage             tokens/costo consumidos en esta sesión
  /auto [n]          corre n turnos sin esperar tu input (default 10; te puede preguntar por scope)
  /stop              interrumpe el turno en curso
  /exit, /quit       termina la sesión

[dim]Mientras el agente trabaja podés seguir escribiendo: tu mensaje se encola.
Ctrl-C interrumpe el turno; de nuevo (o con todo quieto) sale.[/]\
"""

_AUTO_CONTINUE = "Continuá con el siguiente paso según tu plan y el estado actual."


def _short(value: object, limit: int = 60) -> str:
    s = str(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


class Printer:
    """Centraliza el output en pantalla para que interactivo y --auto se vean igual."""

    def __init__(self, console: Console):
        self.console = console
        self._streaming = False

    def text(self, chunk: str) -> None:
        if not self._streaming:
            self.console.print()
            self._streaming = True
        self.console.print(chunk, end="", soft_wrap=True, highlight=False, markup=False)

    def end_text(self) -> None:
        if self._streaming:
            self.console.print()
            self._streaming = False

    def tool_call(self, name: str, args: dict) -> None:
        self.end_text()
        preview = ", ".join(f"{k}={_short(v)}" for k, v in args.items())
        self.console.print(f"[bold cyan]⏺[/] [bold]{escape(name)}[/]({escape(preview)})")

    def tool_result(self, result: str) -> None:
        lines = result.splitlines() or [""]
        shown, rest = lines[:6], lines[6:]
        for line in shown:
            self.console.print(f"  [dim]⎿ {escape(line)}[/]", highlight=False)
        if rest:
            self.console.print(f"  [dim]  … (+{len(rest)} líneas más)[/]")

    def turn_header(self, n: int) -> None:
        self.console.print(f"\n[dim]── turno automático {n} ──[/]")

    def usage(self, usage) -> None:
        self.console.print(f"[bold green]Uso:[/] {usage.summary()}")

    def subagent_event(self, label: str, msg: str) -> None:
        self.end_text()
        self.console.print(f"  [dim magenta]⇢ subagente[{escape(label)}]:[/] {escape(msg)}")

    def ask_user_blocking(self, question: str) -> str:
        """Confirmación en el REPL clásico (fallback sin prompt_toolkit)."""
        self.end_text()
        self.console.print(f"\n[bold yellow]❓ El agente necesita tu confirmación:[/]\n{escape(question)}")
        try:
            return self.console.input("[bold green]tu respuesta ›[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            return "no"


class _AskBridge:
    """Puente para que ``on_ask_user`` (llamado desde el hilo del turno) obtenga
    la respuesta que el loop de input entrega desde el hilo principal, sin que
    dos lectores se peleen por stdin."""

    def __init__(self) -> None:
        self._pending = threading.Event()
        self._answer: "queue.Queue[str]" = queue.Queue(maxsize=1)
        self.question: str = ""

    def ask(self, question: str) -> str:  # hilo del turno
        self.question = question
        self._pending.set()
        try:
            return self._answer.get()
        finally:
            self._pending.clear()
            self.question = ""

    def is_pending(self) -> bool:
        return self._pending.is_set()

    def answer(self, text: str) -> None:  # hilo principal
        try:
            self._answer.put_nowait(text)
        except queue.Full:
            pass


def _banner(console: Console, session: Session, sandbox_info: str, dashboard_url: str | None) -> None:
    body = (
        f"sesión   {session.session_id}\n"
        f"target   {escape(session.target)}\n"
        f"scope    {escape(session.scope)}\n"
        f"modelo   {session.cfg.model}\n"
        f"sandbox  {escape(sandbox_info)}"
    )
    if dashboard_url:
        body += f"\ndashboard {dashboard_url}"
    console.print(Panel(body, title="glaive", border_style="cyan", expand=False))


def _run_auto_turns(
    session: Session,
    printer: Printer,
    start_text: str,
    max_turns: int,
    ask_user=None,
    should_cancel=None,
) -> None:
    text = start_text
    for i in range(1, max_turns + 1):
        printer.turn_header(i)
        finished = session.turn(
            text,
            on_text=printer.text,
            on_tool_call=printer.tool_call,
            on_tool_result=printer.tool_result,
            on_subagent_event=printer.subagent_event,
            on_ask_user=ask_user,
            should_cancel=should_cancel,
        )
        printer.end_text()
        if finished or (should_cancel and should_cancel()):
            break
        text = _AUTO_CONTINUE


def _handle_slash(cmd: str, session: Session, printer: Printer, console: Console) -> bool:
    """Comandos que NO corren turnos (solo lectura / utilidades). Devuelve True
    si hay que terminar la sesión. Los que corren turnos (/auto) se manejan afuera."""
    parts = cmd.split(maxsplit=1)
    name = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if name in ("/exit", "/quit"):
        return True
    if name == "/help":
        console.print(_HELP)
    elif name == "/findings":
        findings = session.store.findings()
        if not findings:
            console.print("Sin hallazgos todavía.")
        for f in findings:
            cvss = f" cvss={f['cvss_score']}" if f.get("cvss_score") is not None else ""
            console.print(
                f"  #{f['id']} [{escape(f['severity'])}/{escape(f['status'])}]{cvss} "
                f"{escape(f['title'])} — {escape(f['endpoint'])}"
            )
    elif name == "/scope":
        included = session.store.scope_assets(status="included")
        pending = session.store.scope_assets(status="pending")
        if not included and not pending:
            console.print("Alcance sin ampliaciones todavía (solo el target/scope inicial).")
        if included:
            console.print("[bold]Incluidos:[/]")
            for s in included:
                console.print(f"  {escape(s['asset'])} ({escape(s['relation'])})")
        if pending:
            console.print("[bold yellow]Pendientes de aprobación:[/]")
            for s in pending:
                console.print(f"  #{s['id']} {escape(s['asset'])} — {escape(s['evidence'])}")
    elif name == "/todos":
        todos = session.store.open_todos()
        if not todos:
            console.print("Sin pendientes.")
        for t in todos:
            console.print(f"  #{t['id']} {escape(t['content'])}")
    elif name == "/report":
        out_path = Path(arg) if arg else session.cfg.runs_dir / session.session_id / "report.md"
        write_report(session.store, out_path)
        console.print(f"Reporte escrito en {out_path}")
    elif name == "/usage":
        printer.usage(session.usage)
    else:
        console.print(f"Comando desconocido: {escape(name)}. /help para ver comandos.")
    return False


# --------------------------------------------------------------------------- #
#  REPL asíncrono (prompt_toolkit)                                             #
# --------------------------------------------------------------------------- #

async def _async_repl(
    console: Console,
    session: Session,
    printer: Printer,
    initial_instruction: str | None,
) -> None:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.patch_stdout import patch_stdout

    loop = asyncio.get_running_loop()
    ps: PromptSession = PromptSession()
    ask = _AskBridge()
    cancel_event = threading.Event()
    pending: list[str] = [initial_instruction] if initial_instruction else []
    turn_future: asyncio.Future | None = None
    input_future: asyncio.Future | None = None

    def run_turn(text: str) -> bool:
        cancel_event.clear()
        session.store.set_activity("thinking")
        try:
            return session.turn(
                text,
                on_text=printer.text,
                on_tool_call=printer.tool_call,
                on_tool_result=printer.tool_result,
                on_subagent_event=printer.subagent_event,
                on_ask_user=_ask_via_bridge,
                should_cancel=cancel_event.is_set,
            )
        finally:
            printer.end_text()

    def _ask_via_bridge(question: str) -> str:
        session.store.set_activity("awaiting_confirmation", question)
        printer.end_text()
        console.print(f"\n[bold yellow]❓ {escape(question)}[/]")
        return ask.ask(question)

    def run_auto(n: int) -> bool:
        _run_auto_turns(
            session, printer, _AUTO_CONTINUE, n,
            ask_user=_ask_via_bridge, should_cancel=cancel_event.is_set,
        )
        return False

    def prompt_label() -> str:
        if ask.is_pending():
            return "respuesta › "
        if turn_future is not None and not turn_future.done():
            return "(trabajando — escribí para encolar, Ctrl-C interrumpe) › "
        return "› "

    console.print("Escribí instrucciones. /help para comandos, /exit para salir.\n")

    with patch_stdout():
        while True:
            # Lanzar un turno si hay algo encolado y no hay turno corriendo.
            if turn_future is None and pending and not ask.is_pending():
                nxt = pending.pop(0)
                if nxt.startswith("/"):
                    lower = nxt.split(maxsplit=1)[0].lower()
                    if lower in ("/exit", "/quit"):
                        break
                    if lower == "/stop":
                        console.print("[dim]nada corriendo para interrumpir[/]")
                        continue
                    if lower == "/auto":
                        arg = nxt.split(maxsplit=1)[1].strip() if len(nxt.split(maxsplit=1)) > 1 else ""
                        n = int(arg) if arg.isdigit() else 10
                        turn_future = loop.run_in_executor(None, run_auto, n)
                    else:
                        _handle_slash(nxt, session, printer, console)
                    continue
                turn_future = loop.run_in_executor(None, run_turn, nxt)

            if turn_future is None and not pending:
                session.store.set_activity("awaiting_input")

            if input_future is None:
                input_future = asyncio.ensure_future(ps.prompt_async(prompt_label()))

            waitset = {input_future} | ({turn_future} if turn_future is not None else set())
            try:
                done, _ = await asyncio.wait(waitset, return_when=asyncio.FIRST_COMPLETED)
            except KeyboardInterrupt:
                # Ctrl-C fuera del prompt (raro): interrumpir o salir.
                if turn_future is not None and not turn_future.done():
                    cancel_event.set()
                    console.print("[dim][interrumpiendo…][/]")
                else:
                    break
                continue

            if turn_future is not None and turn_future in done:
                try:
                    finished = turn_future.result()
                except Exception as exc:  # noqa: BLE001
                    printer.end_text()
                    console.print(f"[bold red]Error:[/] {escape(str(exc))}")
                    finished = False
                turn_future = None
                if finished:
                    console.print("[dim][el agente dio por terminado el engagement][/]")

            if input_future in done:
                try:
                    line = input_future.result()
                except (EOFError, KeyboardInterrupt):
                    # Ctrl-C / Ctrl-D en el prompt.
                    input_future = None
                    if turn_future is not None and not turn_future.done():
                        cancel_event.set()
                        console.print("[dim][interrumpiendo turno…][/]")
                        continue
                    break
                input_future = None
                line = (line or "").strip()
                if not line:
                    continue
                if ask.is_pending():
                    ask.answer(line)
                    continue
                if line.lower() == "/stop":
                    if turn_future is not None and not turn_future.done():
                        cancel_event.set()
                        console.print("[dim][interrumpiendo turno…][/]")
                    else:
                        console.print("[dim]nada corriendo para interrumpir[/]")
                    continue
                if line.lower() in ("/exit", "/quit"):
                    if turn_future is not None and not turn_future.done():
                        cancel_event.set()
                    break
                # /help, /findings, etc. de solo lectura: correr al toque aunque
                # haya un turno en curso (no tocan el modelo).
                if line.startswith("/") and not line.lower().startswith("/auto"):
                    _handle_slash(line, session, printer, console)
                    continue
                pending.append(line)  # instrucción o /auto → cola

    # cancelar futures pendientes
    if turn_future is not None and not turn_future.done():
        cancel_event.set()
    if input_future is not None and not input_future.done():
        input_future.cancel()


def _classic_repl(
    console: Console, session: Session, printer: Printer, initial_instruction: str | None
) -> None:
    """Fallback lockstep si no está prompt_toolkit."""
    console.print("Escribí instrucciones para el agente. /help para comandos, /exit para salir.\n")
    pending: str | None = initial_instruction
    while True:
        if pending is None:
            session.store.set_activity("awaiting_input")
            try:
                pending = console.input("[bold green]›[/] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break
        if not pending:
            pending = None
            continue
        if pending.startswith("/"):
            low = pending.split(maxsplit=1)[0].lower()
            if low == "/auto":
                arg = pending.split(maxsplit=1)[1].strip() if len(pending.split(maxsplit=1)) > 1 else ""
                _run_auto_turns(session, printer, _AUTO_CONTINUE, int(arg) if arg.isdigit() else 10,
                                ask_user=printer.ask_user_blocking)
                pending = None
                continue
            if _handle_slash(pending, session, printer, console):
                break
            pending = None
            continue
        try:
            session.turn(
                pending,
                on_text=printer.text,
                on_tool_call=printer.tool_call,
                on_tool_result=printer.tool_result,
                on_subagent_event=printer.subagent_event,
                on_ask_user=printer.ask_user_blocking,
            )
            printer.end_text()
        except KeyboardInterrupt:
            printer.end_text()
            console.print("[dim][interrumpido][/]")
        except Exception as exc:  # noqa: BLE001
            printer.end_text()
            console.print(f"[bold red]Error:[/] {escape(str(exc))}")
        pending = None


def run_repl(
    cfg: Config,
    target: str,
    scope: str,
    mode: str,
    session_id: str | None,
    initial_instruction: str | None,
    dashboard: bool = True,
    dashboard_port: int = 0,
) -> None:
    console = Console()
    session = Session(cfg, target, scope, mode, session_id)
    sandbox_info = session.start()
    dash_url, dash_server = (None, None)
    if dashboard:
        dash_url, dash_server = start_dashboard(session.store, dashboard_port)
    _banner(console, session, sandbox_info, dash_url)
    _replay_history(console, session)
    printer = Printer(console)

    try:
        try:
            import prompt_toolkit  # noqa: F401
            has_ptk = True
        except ImportError:
            has_ptk = False
            console.print(
                "[dim](prompt_toolkit no instalado: input clásico. `pip install prompt_toolkit` "
                "para escribir mientras el agente trabaja.)[/]"
            )
        if has_ptk:
            asyncio.run(_async_repl(console, session, printer, initial_instruction))
        else:
            _classic_repl(console, session, printer, initial_instruction)
    finally:
        session.shutdown()
        if dash_server:
            dash_server.shutdown()
        console.print()
        printer.usage(session.usage)


def _replay_history(console: Console, session: Session) -> None:
    """Al reanudar una sesión, re-imprime un recap del historial para no arrancar
    con la pantalla en blanco (el modelo sí conserva todo el contexto)."""
    convo = session.store.conversation(limit=12)
    findings = session.store.findings()
    todos = session.store.open_todos()
    if not convo and not findings:
        return
    console.print("[dim]── recap de la sesión (reanudada) ──[/]")
    for m in convo:
        role = m.get("role")
        text = (m.get("text") or "").strip()
        if role == "user" and text:
            console.print(f"[green]› {escape(text[:200])}[/]")
        elif role == "assistant" and text:
            console.print(f"[dim]{escape(text[:200])}[/]")
        for t in m.get("tools") or []:
            console.print(f"  [dim cyan]⏺ {escape(t.get('name',''))}[/]")
    if findings:
        console.print(f"[dim]{len(findings)} hallazgo(s), {len(todos)} pendiente(s). /findings /todos para ver.[/]")
    console.print("[dim]────────────────────────────────[/]\n")


def run_auto(
    cfg: Config,
    target: str,
    scope: str,
    mode: str,
    session_id: str | None,
    instruction: str | None,
    max_turns: int,
    dashboard: bool = True,
    dashboard_port: int = 0,
) -> None:
    console = Console()
    session = Session(cfg, target, scope, mode, session_id)
    sandbox_info = session.start()
    dash_url, dash_server = (None, None)
    if dashboard:
        dash_url, dash_server = start_dashboard(session.store, dashboard_port)
    _banner(console, session, sandbox_info, dash_url)
    printer = Printer(console)
    start_text = instruction or "Empezá con reconocimiento según tu metodología."
    try:
        _run_auto_turns(session, printer, start_text, max_turns)
    finally:
        session.shutdown()
        if dash_server:
            dash_server.shutdown()
        console.print()
        printer.usage(session.usage)
