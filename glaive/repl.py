"""La interfaz de terminal: la experiencia "Claude Code, pero de pentesting".

Vos escribís una instrucción, el agente responde con texto en streaming y
muestra cada tool call en vivo (nombre + args, después un preview del
resultado) antes de devolverte el control. `/auto` (o `glaive run --auto`)
deja que encadene turnos solo, para correr un engagement hands-off.
"""

from __future__ import annotations

from pathlib import Path

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
  /exit, /quit       termina la sesión\
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

    def ask_user(self, question: str) -> str:
        self.end_text()
        self.console.print(f"\n[bold yellow]❓ El agente necesita tu confirmación:[/]\n{escape(question)}")
        try:
            return self.console.input("[bold green]tu respuesta ›[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            return "no"


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
    ask_user: bool = False,
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
            on_ask_user=printer.ask_user if ask_user else None,
        )
        printer.end_text()
        if finished:
            break
        text = _AUTO_CONTINUE


def _handle_slash(cmd: str, session: Session, printer: Printer, console: Console) -> bool:
    """Devuelve True si hay que terminar la sesión."""
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
    elif name == "/auto":
        n = int(arg) if arg.isdigit() else 10
        _run_auto_turns(session, printer, _AUTO_CONTINUE, n, ask_user=True)
    else:
        console.print(f"Comando desconocido: {escape(name)}. /help para ver comandos.")
    return False


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
    console.print("Escribí instrucciones para el agente. /help para comandos, /exit para salir.\n")
    printer = Printer(console)

    try:
        pending: str | None = initial_instruction
        while True:
            if pending is None:
                try:
                    pending = console.input("[bold green]›[/] ").strip()
                except (EOFError, KeyboardInterrupt):
                    console.print()
                    break

            if not pending:
                pending = None
                continue

            if pending.startswith("/"):
                should_exit = _handle_slash(pending, session, printer, console)
                pending = None
                if should_exit:
                    break
                continue

            try:
                session.turn(
                    pending,
                    on_text=printer.text,
                    on_tool_call=printer.tool_call,
                    on_tool_result=printer.tool_result,
                    on_subagent_event=printer.subagent_event,
                    on_ask_user=printer.ask_user,
                )
                printer.end_text()
            except KeyboardInterrupt:
                printer.end_text()
                console.print("[dim][interrumpido][/]")
            except Exception as exc:  # noqa: BLE001
                printer.end_text()
                console.print(f"[bold red]Error:[/] {escape(str(exc))}")
            pending = None
    finally:
        session.shutdown()
        if dash_server:
            dash_server.shutdown()
        console.print()
        printer.usage(session.usage)


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
