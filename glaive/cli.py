"""CLI de glaive."""

from __future__ import annotations

import time
from pathlib import Path

import click

from glaive.config import Config
from glaive.dashboard import start_multi_dashboard
from glaive.repl import run_auto, run_repl
from glaive.report import write_report
from glaive.state import Store


@click.group()
def main() -> None:
    """glaive — agente de pentesting automatizado, eficiente en tokens."""


@main.command()
@click.option("--target", required=True, help="URL/host objetivo, ej: https://demo.local")
@click.option("--scope", default="", help="Descripción del alcance autorizado (default: = target)")
@click.option("--mode", default="web", type=click.Choice(["web", "recon"]), help="Modo de engagement")
@click.option("--session-id", default=None, help="Reanudar una sesión existente")
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
    target: str,
    scope: str,
    mode: str,
    session_id: str | None,
    auto: bool,
    max_turns: int | None,
    dashboard: bool,
    dashboard_port: int,
    instruction: str | None,
) -> None:
    """Abre una sesión contra TARGET — interactiva por defecto, como un chat.

    Pasá INSTRUCTION para arrancar directo con esa instrucción (o dejala vacía
    y escribila en el prompt). Con --auto corre sin esperar tu input, turno a
    turno, hasta que el agente llame a `finish` o se alcance --max-turns. El
    dashboard local (http://127.0.0.1:<puerto>) muestra hallazgos, pendientes,
    actividad en vivo y costo — sin gastar tokens (lee el mismo estado del
    agente); desactivalo con --no-dashboard.
    """
    cfg = Config.load()
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


@main.command()
@click.option("--session-id", required=True)
@click.option("--out", default=None, help="Archivo de salida (default: runs/<id>/report.md)")
def report(session_id: str, out: str | None) -> None:
    """Genera el reporte Markdown de una sesión ya corrida (sin usar el LLM)."""
    cfg = Config.load()
    db_path = cfg.runs_dir / session_id / "state.db"
    if not db_path.exists():
        raise SystemExit(f"No se encontró la sesión '{session_id}' en {cfg.runs_dir}")
    store = Store(db_path)
    out_path = Path(out) if out else cfg.runs_dir / session_id / "report.md"
    write_report(store, out_path)
    click.echo(f"Reporte escrito en {out_path}")


@main.command()
@click.option("--port", default=0, type=int, help="Puerto (default: uno libre al azar).")
def dashboard(port: int) -> None:
    """Dashboard con TODAS las sesiones locales (runs/*) — no gasta tokens.

    A diferencia del que se abre solo con `glaive run`, este escanea todo
    `runs/` y deja elegir a qué sesión mirar; sirve para seguir varios
    engagements en simultáneo o revisar uno viejo sin retomarlo.
    """
    cfg = Config.load()
    url, server = start_multi_dashboard(cfg.runs_dir, port=port)
    click.echo(f"Dashboard en {url}  (Ctrl+C para cerrar)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


@main.command()
def sessions() -> None:
    """Lista las sesiones locales."""
    cfg = Config.load()
    if not cfg.runs_dir.exists():
        click.echo("No hay sesiones todavía.")
        return
    for d in sorted(cfg.runs_dir.iterdir()):
        db = d / "state.db"
        if db.exists():
            store = Store(db)
            s = store.session()
            n = len(store.findings())
            click.echo(f"{d.name}\t{s.get('status', '?')}\t{s.get('target', '?')}\t{n} hallazgos")


if __name__ == "__main__":
    main()
