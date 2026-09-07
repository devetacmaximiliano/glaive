"""Renderizado del reporte final: 100% plantilla, 0 tokens de LLM.

Los findings ya llegaron estructurados (vía la tool add_finding) durante el
engagement. Acá solo maquetamos — es la diferencia con Strix/PentAGI, que
gastan una llamada de LLM para "redactar" el reporte.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from glaive.state import Store

_TEMPLATES_DIR = Path(__file__).parent / "prompts"

_SEVERITY_LABEL = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}


def render_markdown(store: Store) -> str:
    env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR))
    tpl = env.get_template("report.md.j2")
    session = store.session()
    findings = store.findings()
    counts = {sev: 0 for sev in _SEVERITY_LABEL}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return tpl.render(
        session=session,
        findings=findings,
        severity_label=_SEVERITY_LABEL,
        counts=counts,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


def write_report(store: Store, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_markdown(store), encoding="utf-8")
    return out_path
