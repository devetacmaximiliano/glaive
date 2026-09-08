"""Arma el dict que ``glaive.pdf.engine.generate_report`` espera, a partir del
``Store`` de glaive. 100% determinístico — ningún campo sale de una llamada
al LLM; lo que no está disponible queda con un default neutro (el motor ya
sabe manejarlo, ver ``engine.load_from_yaml`` como referencia del schema).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from glaive.config import Config
from glaive.state import Store

_SEVERITY_ES = {
    "critical": "critico",
    "high": "alto",
    "medium": "medio",
    "low": "bajo",
    "info": "info",
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_PREFIX = {"critical": "CRITICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO"}


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _map_finding(f: dict[str, Any], seq: int) -> dict[str, Any]:
    sev_en = (f.get("severity") or "info").lower()
    out: dict[str, Any] = {
        "id": f"{_SEVERITY_PREFIX.get(sev_en, 'INFO')}-{seq:02d}",
        "title": f.get("title") or "Hallazgo sin título",
        "severity": _SEVERITY_ES.get(sev_en, "info"),
        "status": "Validado",
        "system": f.get("endpoint") or "N/A",
        "verified": f.get("description") or "",
        "evidence": f.get("evidence") or "",
    }
    if f.get("cvss_score") is not None:
        out["cvss_score"] = f["cvss_score"]
    if f.get("cvss_vector"):
        out["cvss_vector"] = f["cvss_vector"]
    if f.get("remediation"):
        out["remediation"] = [("Remediar", f["remediation"], "Equipo de desarrollo", "Según prioridad")]
    return out


def build_report_data(
    store: Store, cfg: Config, meta: dict[str, str] | None = None, include_potential: bool = False
) -> dict[str, Any]:
    """``meta`` son los campos que el usuario completó al pedir el PDF
    (client_name, client_industry, engagement_type, start_date, end_date) —
    todos opcionales, con default razonable si vienen vacíos."""
    meta = meta or {}
    session = store.session()
    target = session.get("target", "")

    statuses = ("confirmed", "potential") if include_potential else ("confirmed",)
    findings_raw = [f for f in store.findings() if f.get("status") in statuses]

    counters: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    counts_es = {"critico": 0, "alto": 0, "medio": 0, "bajo": 0, "info": 0}
    for f in findings_raw:
        sev_en = (f.get("severity") or "info").lower()
        counters[sev_en] = counters.get(sev_en, 0) + 1
        findings.append(_map_finding(f, counters[sev_en]))
        counts_es[_SEVERITY_ES.get(sev_en, "info")] += 1
    # Orden estable: crítico -> info (igual que la tabla resumen del motor).
    findings.sort(key=lambda f: _SEVERITY_ORDER.index(
        next(k for k, v in _SEVERITY_ES.items() if v == f["severity"])
    ))

    created = session.get("created_at")
    start_default = datetime.fromtimestamp(created).strftime("%Y-%m-%d") if created else _today()

    return {
        "client_name": meta.get("client_name") or target or "[CLIENTE]",
        "client_industry": meta.get("client_industry", ""),
        "target_scope": session.get("scope", "") or target,
        "engagement_type": meta.get("engagement_type") or "Black Box External Assessment",
        "methodology": "PTES + OWASP WSTG + CVSS v3.1",
        "start_date": meta.get("start_date") or start_default,
        "end_date": meta.get("end_date") or _today(),
        "report_date": _today(),
        "version": "1.0",
        "auditor_name": cfg.pdf_auditor_name or "Auditor de Seguridad",
        "auditor_role": cfg.pdf_auditor_role or "Security Consultant",
        "company": cfg.pdf_company,
        "company_website": "",
        "findings_count": counts_es,
        "executive_narrative": (
            f"Se evaluó {target or 'el alcance definido'} identificando "
            f"{len(findings)} hallazgo(s) confirmado(s). Ver detalle técnico "
            "por severidad en las secciones siguientes."
        ),
        "executive_metrics": [
            ["Hallazgos Críticos", str(counts_es["critico"])],
            ["Hallazgos Altos", str(counts_es["alto"])],
            ["Hallazgos Medios", str(counts_es["medio"])],
            ["Hallazgos Bajos", str(counts_es["bajo"])],
            ["Informativos", str(counts_es["info"])],
        ],
        "attacker_can_do": [],
        "immediate_actions": [],
        "legal_exposure": [],
        "attack_narrative": [],
        "detection_gaps": [],
        "defensive_gaps": [],
        "findings": findings,
        "remediation_plan": {},
        "iocs": [],
        "tools_used": [],
        "systems_tested": [[target or "N/A", "Activo evaluado", "Web"]] if target else [],
        "out_of_scope": [
            "Ingeniería social activa",
            "DoS / DDoS",
            "Infraestructura de terceros sin autorización",
            "Acciones destructivas",
        ],
        "strengths": [],
        "strategic_opportunities": [],
    }
