"""Calculadora determinística de CVSS v3.1 (Base Score).

Por qué existe: pedirle al modelo que "calcule" un score de CVSS a ojo produce
inconsistencias entre findings (el mismo vector podría puntuar distinto en dos
llamadas). El vector en sí (qué tan explotable es, qué impacto tiene) sí lo
decide el agente — pero el número sale de acá, con la fórmula oficial de FIRST.org,
igual que el reporte se renderiza con plantilla y no con el LLM.
"""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(.+)$")
_REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

_SEVERITY_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


class InvalidCvssVector(ValueError):
    pass


def _roundup(value: float) -> float:
    """Redondeo "hacia arriba a 1 decimal" tal como lo define la spec de CVSS
    (no es un round() común: 4.02 -> 4.1, no 4.0)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    match = _VECTOR_RE.match(vector.strip())
    if not match:
        raise InvalidCvssVector(f"vector no reconocido (esperado 'CVSS:3.1/...'): {vector!r}")
    metrics: dict[str, str] = {}
    for part in match.group(1).split("/"):
        if ":" not in part:
            raise InvalidCvssVector(f"segmento inválido en el vector: {part!r}")
        key, value = part.split(":", 1)
        metrics[key] = value
    missing = _REQUIRED_METRICS - metrics.keys()
    if missing:
        raise InvalidCvssVector(f"faltan métricas base obligatorias: {sorted(missing)}")
    return metrics


def base_score(vector: str) -> float:
    """Base Score de CVSS v3.1 a partir de un vector completo. Lanza
    InvalidCvssVector si el vector es inválido o le falta una métrica base."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        ui = _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise InvalidCvssVector(f"valor de métrica no reconocido: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity_from_score(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


def try_score(vector: str) -> float | None:
    """Como base_score, pero devuelve None en vez de lanzar si el vector es
    inválido — para usar en el flujo de add_finding sin cortar la sesión por
    un vector mal formado."""
    try:
        return base_score(vector)
    except InvalidCvssVector:
        return None
