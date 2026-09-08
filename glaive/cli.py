"""CLI de glaive."""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Any

import click

from glaive import __version__
from glaive.config import Config
from glaive.dashboard import start_multi_dashboard
from glaive.engine import Session
from glaive.repl import run_auto, run_repl
from glaive.report import write_report
from glaive.state import Store

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def run_print(
    cfg: Config, target: str, scope: str, mode: str, session_id: str | None, instruction: str
) -> None:
    """Modo no interactivo (como ``claude -p``): UN turno, imprime la respuesta
    final a stdout sin nada más (sin dashboard, sin streaming en vivo, sin
    colores) — pensado para scripting/pipes, no para mirarlo en vivo."""
    session = Session(cfg, target, scope, mode, session_id)
    session.start()
    texts: list[str] = []
    try:
        session.turn(instruction, on_text=texts.append)
    finally:
        session.shutdown()
    print("".join(texts))

_PICK_SENTINEL = "__pick__"


def _list_sessions_for_cli(runs_dir: Path) -> list[dict[str, Any]]:
    """Sesiones locales, más reciente primero — para --continue y --resume."""
    rows: list[dict[str, Any]] = []
    if not runs_dir.exists():
        return rows
    for d in sorted(runs_dir.iterdir()):
        db_path = d / "state.db"
        if not db_path.is_file():
            continue
        try:
            store = Store(db_path)
            sess = store.session()
            rows.append(
                {
                    "id": d.name,
                    "target": sess.get("target", ""),
                    "scope": sess.get("scope", ""),
                    "status": sess.get("status", "?"),
                    "findings": len(store.findings()),
                    "last_activity_at": sess.get("last_activity_at") or sess.get("created_at") or 0,
                }
            )
            store.close()
        except Exception:  # noqa: BLE001 - una sesión corrupta no debe tirar abajo el listado
            continue
    rows.sort(key=lambda r: r["last_activity_at"], reverse=True)
    return rows


def _peek_session_target(cfg: Config, session_id: str) -> tuple[str, str] | None:
    """Target/scope guardados de una sesión existente, sin instanciar el motor."""
    db_path = cfg.runs_dir / session_id / "state.db"
    if not db_path.is_file():
        return None
    store = Store(db_path)
    sess = store.session()
    store.close()
    if not sess.get("target"):
        return None
    return sess["target"], sess.get("scope", "")


def _pick_session_interactively(cfg: Config) -> str:
    sessions = _list_sessions_for_cli(cfg.runs_dir)
    if not sessions:
        raise SystemExit(f"No hay sesiones todavía en {cfg.runs_dir}.")
    click.echo("Sesiones disponibles (más reciente primero):")
    for i, s in enumerate(sessions, 1):
        click.echo(f"  {i}. [{s['status']}] {s['target']}  ·  {s['findings']} hallazgo(s)  ·  id={s['id']}")
    choice = click.prompt("Elegí una", type=click.IntRange(1, len(sessions)), default=1)
    return sessions[choice - 1]["id"]


@click.group(context_settings=_CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="glaive")
def main() -> None:
    """glaive — agente de pentesting automatizado, eficiente en tokens."""


@main.command(context_settings=_CONTEXT_SETTINGS)
@click.option("--target", default=None, help="URL/host objetivo, ej: https://demo.local")
@click.option("--scope", default="", help="Descripción del alcance autorizado (default: = target)")
@click.option("--mode", default="web", type=click.Choice(["web", "recon"]), help="Modo de engagement")
@click.option("--session-id", default=None, help="Reanudar una sesión existente por ID exacto.")
@click.option(
    "--resume", "resume_id", is_flag=False, flag_value=_PICK_SENTINEL, default=None,
    help="Reanuda una sesión: sin valor abre un selector, con un ID la retoma directo.",
)
@click.option(
    "-c", "--continue", "continue_session", is_flag=True,
    help="Retoma la sesión local más reciente (la de última actividad), sin preguntar.",
)
@click.option("--model", default=None, help="Modelo a usar en esta corrida (override puntual de GLAIVE_MODEL).")
@click.option(
    "-p", "--print", "print_mode", is_flag=True,
    help="Modo no interactivo: corre UN turno con INSTRUCTION, imprime la respuesta a stdout y sale.",
)
@click.option(
    "--auto", is_flag=True, help="Modo autónomo: no espera tu input, encadena turnos solo."
)
@click.option(
    "--max-turns", default=None, type=int, help="Turnos autónomos máximos con --auto (default: GLAIVE_MAX_ITERATIONS)."
)
@click.option(
    "--dashboard/--no-dashboard", default=True, help="Levantar el dashboard local (default: sí)."
)
@click.option(
    "--dashboard-port", default=0, type=int, help="Puerto del dashboard (default: uno libre al azar)."
)
@click.argument("instruction", required=False)
def run(
    target: str | None,
    scope: str,
    mode: str,
    session_id: str | None,
    resume_id: str | None,
    continue_session: bool,
    model: str | None,
    print_mode: bool,
    auto: bool,
    max_turns: int | None,
    dashboard: bool,
    dashboard_port: int,
    instruction: str | None,
) -> None:
    """Abre una sesión — interactiva por defecto, como un chat.

    Pasá INSTRUCTION para arrancar directo con esa instrucción (o dejala vacía
    y escribila en el prompt). --target es obligatorio para una sesión NUEVA;
    para retomar una existente alcanza con --session-id/--resume/--continue,
    no hace falta re-escribir el target.

    Con --auto corre sin esperar tu input, turno a turno, hasta que el agente
    llame a `finish` o se alcance --max-turns. Con -p/--print corre UN solo
    turno y imprime la respuesta a stdout (para scripting, sin dashboard). El
    dashboard local (http://127.0.0.1:<puerto>) muestra hallazgos, pendientes,
    actividad en vivo y costo — sin gastar tokens; desactivalo con --no-dashboard.
    """
    cfg = Config.load()
    if model:
        cfg = dataclasses.replace(cfg, model=model)

    if sum(bool(x) for x in (session_id, resume_id, continue_session)) > 1:
        raise SystemExit("Usá solo uno de --session-id / --resume / --continue.")

    if continue_session:
        sessions = _list_sessions_for_cli(cfg.runs_dir)
        if not sessions:
            raise SystemExit("No hay sesiones previas para continuar (runs/ vacío).")
        session_id = sessions[0]["id"]
    elif resume_id:
        session_id = _pick_session_interactively(cfg) if resume_id == _PICK_SENTINEL else resume_id

    if session_id and not target:
        loaded = _peek_session_target(cfg, session_id)
        if not loaded:
            raise SystemExit(f"No se encontró la sesión '{session_id}' en {cfg.runs_dir}.")
        target, saved_scope = loaded
        scope = scope or saved_scope

    if not target:
        raise SystemExit(
            "Falta --target (o --session-id/--resume/--continue para retomar una sesión existente)."
        )

    if print_mode:
        if auto:
            raise SystemExit("Usá -p/--print o --auto, no los dos juntos.")
        if not instruction:
            raise SystemExit("-p/--print necesita una INSTRUCTION.")
        run_print(cfg, target, scope, mode, session_id, instruction)
        return

    if auto:
        run_auto(
            cfg, target, scope, mode, session_id, instruction, max_turns or cfg.max_iterations,
            dashboard=dashboard, dashboard_port=dashboard_port,
        )
    else:
        run_repl(
            cfg, target, scope, mode, session_id, instruction,
            dashboard=dashboard, dashboard_port=dashboard_port,
        )


@main.command(context_settings=_CONTEXT_SETTINGS)
@click.option("--session-id", required=True)
@click.option("--out", default=None, help="Archivo de salida (default: runs/<id>/report.md o .pdf con --pdf)")
@click.option("--pdf", "as_pdf", is_flag=True, help="Generar PDF (branding Devetac) en vez del Markdown.")
@click.option("--client-name", default="", help="Solo con --pdf: nombre del cliente en la portada.")
@click.option("--client-industry", default="", help="Solo con --pdf: industria del cliente.")
@click.option("--engagement-type", default="", help="Solo con --pdf (default: Black Box External Assessment).")
@click.option("--start-date", default="", help="Solo con --pdf, formato AAAA-MM-DD (default: creación de la sesión).")
@click.option("--end-date", default="", help="Solo con --pdf, formato AAAA-MM-DD (default: hoy).")
@click.option(
    "--include-potential", is_flag=True,
    help="Solo con --pdf: incluir también hallazgos potential (marcados), no solo confirmed.",
)
def report(
    session_id: str,
    out: str | None,
    as_pdf: bool,
    client_name: str,
    client_industry: str,
    engagement_type: str,
    start_date: str,
    end_date: str,
    include_potential: bool,
) -> None:
    """Genera el reporte de una sesión ya corrida — Markdown por defecto, PDF con --pdf.

    Ambos son 100% determinísticos: arman el documento a partir de los
    hallazgos ya guardados, sin ninguna llamada al LLM.
    """
    cfg = Config.load()
    db_path = cfg.runs_dir / session_id / "state.db"
    if not db_path.exists():
        raise SystemExit(f"No se encontró la sesión '{session_id}' en {cfg.runs_dir}")
    store = Store(db_path)

    if as_pdf:
        from glaive.pdf.engine import generate_report
        from glaive.pdf.mapper import build_report_data

        meta = {
            "client_name": client_name,
            "client_industry": client_industry,
            "engagement_type": engagement_type,
            "start_date": start_date,
            "end_date": end_date,
        }
        data = build_report_data(store, cfg, meta, include_potential=include_potential)
        out_path = Path(out) if out else cfg.runs_dir / session_id / "report.pdf"
        generate_report(data, str(out_path))
        click.echo(f"PDF escrito en {out_path}")
        return

    out_path = Path(out) if out else cfg.runs_dir / session_id / "report.md"
    write_report(store, out_path)
    click.echo(f"Reporte escrito en {out_path}")


@main.command(context_settings=_CONTEXT_SETTINGS)
@click.option("--port", default=0, type=int, help="Puerto (default: uno libre al azar).")
@click.option("--no-open", is_flag=True, help="No abrir el navegador automáticamente.")
def dashboard(port: int, no_open: bool) -> None:
    """Dashboard MULTI-sesión: muestra todas las sesiones de runs/ a la vez.

    A diferencia del dashboard que abre `glaive run` (una sola sesión), este
    escanea runs/*/state.db y te deja ver el trabajo de varios targets en
    simultáneo desde un solo lugar. Es solo-lectura y no gasta tokens.
    """
    cfg = Config.load()
    if not cfg.runs_dir.exists():
        raise SystemExit(f"No hay sesiones todavía en {cfg.runs_dir}.")
    url, server = start_multi_dashboard(cfg.runs_dir, port=port, open_browser=not no_open)
    click.echo(f"Dashboard multi-sesión en {url}  (Ctrl-C para salir)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
        click.echo("\nDashboard detenido.")


@main.command(context_settings=_CONTEXT_SETTINGS)
def sessions() -> None:
    """Lista las sesiones locales, más reciente primero."""
    cfg = Config.load()
    rows = _list_sessions_for_cli(cfg.runs_dir)
    if not rows:
        click.echo("No hay sesiones todavía.")
        return
    for s in rows:
        click.echo(f"{s['id']}\t{s['status']}\t{s['target']}\t{s['findings']} hallazgos")


if __name__ == "__main__":
    main()
