"""Guard anti-destructivo — defensa en profundidad, NO una garantía completa.

Bloquea patrones de comandos OBVIAMENTE destructivos (DoS/flooding, borrado o
corrupción de datos, degradación de disponibilidad) antes de que `exec_command`
los corra. Un clasificador por patrones nunca es exhaustivo — algo semánticamente
destructivo puede venir embebido en un argumento de alto nivel que esto no lea
(ej. un payload SQL dentro de un flag de sqlmap). Por eso la instrucción de
"PoC mínimo y no destructivo" también vive en el system prompt: esto es una
capa adicional, no la única.

El scope de este proyecto es deliberadamente GENEROSO en qué se puede probar
(ver `glaive/tools.py::propose_scope_expansion`) — la única línea roja son las
acciones destructivas o de denegación de servicio, que es justo lo que este
módulo bloquea.
"""

from __future__ import annotations

import re

# (patrón, motivo, flags) — flags opcional, default 0.
_DESTRUCTIVE_PATTERNS: list[tuple[str, str, int]] = [
    (r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+/(?:\s|$)", "borrado recursivo de la raíz del filesystem", 0),
    (r"\bmkfs\.", "formateo de filesystem", 0),
    (r":\(\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;\s*:", "fork bomb", 0),
    (r"\bhping3\b[^\n]*--flood", "flood/DoS (hping3 --flood)", 0),
    (r"\bslowloris\b", "ataque de agotamiento de conexiones (slowloris)", 0),
    (r"\bgoldeneye\b", "herramienta de DoS HTTP (GoldenEye)", 0),
    (r"\b(ab|wrk|siege)\b[^\n]*-[nc]\s*[1-9]\d{4,}", "carga masiva de requests (posible DoS)", 0),
    (r"\bnmap\b[^\n]*(-T5\b|--min-rate[= ]\d{4,})", "escaneo agresivo (riesgo de degradar el target)", 0),
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b", "DROP/TRUNCATE de tabla o base de datos", re.I),
    (r"\bDELETE\s+FROM\s+\S+\s*;?\s*$", "DELETE sin WHERE (borraría toda la tabla)", re.I),
    (r"\bUPDATE\s+\S+\s+SET\b(?![\s\S]*\bWHERE\b)", "UPDATE sin WHERE (afectaría toda la tabla)", re.I),
    (r"--dump-all\b", "sqlmap --dump-all (exfiltración masiva, innecesaria para un PoC)", 0),
    (r"\bshred\b", "borrado seguro irreversible de archivos", 0),
    (r"\bdd\s+[^\n]*of=/dev/(sd|nvme|hd)", "escritura directa sobre un disco", 0),
    (r"\b(passwd|chpasswd)\b[^\n]*\S", "cambio de contraseña de una cuenta real", 0),
]


def check_destructive(command: str) -> str | None:
    """Devuelve el motivo de bloqueo si el comando matchea un patrón
    destructivo/DoS conocido; ``None`` si no matchea nada (no implica que sea
    seguro — solo que no disparó ninguna de las reglas obvias)."""
    for pattern, reason, flags in _DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command, flags):
            return reason
    return None
