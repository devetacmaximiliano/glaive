"""Estado externo en SQLite.

Principio de eficiencia: findings, notas, todos y salidas largas de herramientas
viven FUERA del contexto del modelo. Al prompt solo le inyectamos un resumen
compacto (ver ``compact_state``), no el historial completo. Así el contexto no
crece sin control y cada turno cuesta menos.

Esta misma externalización es lo que hace posible el dashboard (glaive/dashboard.py)
sin gastar tokens: es una vista de solo lectura sobre esta base. Y es lo que hace
posible los subagentes (glaive/subagent.py) sin duplicar contexto: escriben acá
directo en vez de tener que "contarle" sus hallazgos al agente padre.

``Store`` se comparte entre threads (subagentes corriendo en paralelo + el hilo
del dashboard), así que todo acceso a la conexión sqlite pasa por un lock.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from glaive.cvss import try_score

_SCHEMA = """
CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY, target TEXT, scope TEXT, status TEXT, created_at REAL,
    activity TEXT DEFAULT 'idle', activity_detail TEXT DEFAULT '', last_activity_at REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, severity TEXT, cwe TEXT,
    wstg TEXT, owasp TEXT,
    endpoint TEXT, description TEXT, evidence TEXT, poc TEXT, remediation TEXT,
    status TEXT DEFAULT 'potential',
    cvss_vector TEXT, cvss_score REAL, chains_from INTEGER,
    created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS scope_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, asset TEXT, relation TEXT, evidence TEXT,
    status TEXT DEFAULT 'included', created_at REAL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT, done INTEGER DEFAULT 0,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS tool_outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT, full_output TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT, payload TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, label TEXT, detail TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    prompt_tokens INTEGER DEFAULT 0, completion_tokens INTEGER DEFAULT 0,
    cached_tokens INTEGER DEFAULT 0, cost_usd REAL DEFAULT 0, calls INTEGER DEFAULT 0
);
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.executescript(_SCHEMA)
            self._migrate()
            self.db.commit()

    def _migrate(self) -> None:
        """Agrega columnas nuevas a DBs de sesiones viejas (idempotente)."""
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(session)").fetchall()}
        for name, ddl in (
            ("activity", "ALTER TABLE session ADD COLUMN activity TEXT DEFAULT 'idle'"),
            ("activity_detail", "ALTER TABLE session ADD COLUMN activity_detail TEXT DEFAULT ''"),
            ("last_activity_at", "ALTER TABLE session ADD COLUMN last_activity_at REAL"),
        ):
            if name not in cols:
                self.db.execute(ddl)

    # ---- sesión ----
    def init_session(self, sid: str, target: str, scope: str) -> None:
        with self._lock:
            self.db.execute(
                """INSERT OR REPLACE INTO session
                   (id,target,scope,status,created_at,activity,activity_detail,last_activity_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sid, target, scope, "running", time.time(), "idle", "", time.time()),
            )
            self.db.commit()

    def set_status(self, sid: str, status: str) -> None:
        with self._lock:
            self.db.execute("UPDATE session SET status=? WHERE id=?", (status, sid))
            self.db.commit()

    def set_activity(self, state: str, detail: str = "") -> None:
        """Estado de actividad EN VIVO (pensando / streaming / ejecutando tool /
        esperando input / esperando confirmación / compactando / pausado). Es
        distinto del ``status`` de ciclo de vida (running/finished/stopped) y es
        lo que el dashboard usa para mostrar si el agente trabaja o te espera.
        Actualiza también ``last_activity_at`` como heartbeat."""
        with self._lock:
            self.db.execute(
                "UPDATE session SET activity=?, activity_detail=?, last_activity_at=?",
                (state, (detail or "")[:300], time.time()),
            )
            self.db.commit()

    def session(self) -> dict[str, Any]:
        with self._lock:
            row = self.db.execute("SELECT * FROM session LIMIT 1").fetchone()
        return dict(row) if row else {}

    # ---- findings ----
    _DEDUP_STATUSES = ("potential", "confirmed")
    _VALID_STATUSES = ("potential", "confirmed", "remediated")

    def upsert_finding(self, **f: Any) -> tuple[int, str]:
        """Inserta o actualiza (si viene ``finding_id``) un finding.

        - El ``cvss_score`` se calcula ACÁ (glaive.cvss), nunca se confía en un
          número que haya tipeado el modelo — solo el vector es su input.
        - Dedup por causa raíz: un insert nuevo con el mismo (cwe, endpoint) que
          un finding ya potential/confirmed se rechaza (devuelve el existente),
          salvo que venga ``chains_from`` — señal explícita de que es un finding
          distinto derivado de otro, no una repetición.

        Devuelve ``(id, mensaje)`` — el mensaje es lo que ve el agente como
        resultado de la tool call.
        """
        finding_id = f.get("finding_id")
        cvss_vector = (f.get("cvss_vector") or "").strip()
        cvss_score = try_score(cvss_vector) if cvss_vector else None
        status = (f.get("status") or "potential").lower()
        if status not in self._VALID_STATUSES:
            status = "potential"
        now = time.time()

        with self._lock:
            if finding_id:
                exists = self.db.execute(
                    "SELECT id FROM findings WHERE id=?", (finding_id,)
                ).fetchone()
                if not exists:
                    return 0, f"No existe el finding #{finding_id}."
                self.db.execute(
                    """UPDATE findings SET title=?,severity=?,cwe=?,wstg=?,owasp=?,endpoint=?,
                       description=?,evidence=?,poc=?,remediation=?,status=?,cvss_vector=?,
                       cvss_score=?,chains_from=?,updated_at=? WHERE id=?""",
                    (
                        f.get("title", ""),
                        (f.get("severity", "info") or "info").lower(),
                        f.get("cwe", ""),
                        f.get("wstg", ""),
                        f.get("owasp", ""),
                        f.get("endpoint", ""),
                        f.get("description", ""),
                        f.get("evidence", ""),
                        f.get("poc", ""),
                        f.get("remediation", ""),
                        status,
                        cvss_vector or None,
                        cvss_score,
                        f.get("chains_from"),
                        now,
                        finding_id,
                    ),
                )
                self.db.commit()
                return int(finding_id), f"Finding #{finding_id} actualizado (status={status})."

            if not f.get("chains_from"):
                dup = self.db.execute(
                    "SELECT id FROM findings WHERE cwe=? AND endpoint=? AND status IN (?,?)",
                    (f.get("cwe", ""), f.get("endpoint", ""), *self._DEDUP_STATUSES),
                ).fetchone()
                if dup:
                    return int(dup["id"]), (
                        f"Ya existe el finding #{dup['id']} con la misma causa raíz "
                        "(mismo CWE+endpoint). Si esto es un IMPACTO derivado de ese "
                        "hallazgo, documentalo con add_note o actualizalo pasando "
                        f"finding_id={dup['id']}. Si es realmente un finding distinto, "
                        "volvé a llamar con chains_from para dejarlo explícito."
                    )

            cur = self.db.execute(
                """INSERT INTO findings
                   (title,severity,cwe,wstg,owasp,endpoint,description,evidence,poc,
                    remediation,status,cvss_vector,cvss_score,chains_from,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f.get("title", ""),
                    (f.get("severity", "info") or "info").lower(),
                    f.get("cwe", ""),
                    f.get("wstg", ""),
                    f.get("owasp", ""),
                    f.get("endpoint", ""),
                    f.get("description", ""),
                    f.get("evidence", ""),
                    f.get("poc", ""),
                    f.get("remediation", ""),
                    status,
                    cvss_vector or None,
                    cvss_score,
                    f.get("chains_from"),
                    now,
                    now,
                ),
            )
            self.db.commit()
            new_id = int(cur.lastrowid)
            return new_id, f"Finding #{new_id} registrado (status={status})."

    def findings(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [dict(r) for r in self.db.execute("SELECT * FROM findings").fetchall()]
        rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 9))
        return rows

    # ---- notas / todos ----
    def add_note(self, content: str) -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO notes (content,created_at) VALUES (?,?)", (content, time.time())
            )
            self.db.commit()
            return int(cur.lastrowid)

    def add_todo(self, content: str) -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO todos (content,created_at) VALUES (?,?)", (content, time.time())
            )
            self.db.commit()
            return int(cur.lastrowid)

    def complete_todo(self, todo_id: int) -> None:
        with self._lock:
            self.db.execute("UPDATE todos SET done=1 WHERE id=?", (todo_id,))
            self.db.commit()

    def open_todos(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(r) for r in self.db.execute("SELECT * FROM todos WHERE done=0").fetchall()
            ]

    # ---- salidas largas (para read_more) ----
    def stash_output(self, tool: str, full: str) -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO tool_outputs (tool,full_output,created_at) VALUES (?,?,?)",
                (tool, full, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def get_output(self, out_id: int) -> str | None:
        with self._lock:
            row = self.db.execute(
                "SELECT full_output FROM tool_outputs WHERE id=?", (out_id,)
            ).fetchone()
        return row["full_output"] if row else None

    # ---- conversación (resume + compaction) ----
    def replace_messages(self, msgs: list[dict[str, Any]]) -> None:
        with self._lock:
            self.db.execute("DELETE FROM messages")
            self.db.executemany(
                "INSERT INTO messages (role,payload,created_at) VALUES (?,?,?)",
                [(m.get("role", ""), json.dumps(m), time.time()) for m in msgs],
            )
            self.db.commit()

    def load_messages(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.db.execute("SELECT payload FROM messages ORDER BY id").fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def conversation(self, limit: int = 400) -> list[dict[str, Any]]:
        """Vista formateada de la conversación para el dashboard (read-only).

        Aplana cada mensaje a {role, text, tools, created_at}. No incluye el
        system prompt ni el resumen de <estado> (ruido para el lector humano).
        """
        with self._lock:
            rows = self.db.execute(
                "SELECT role,payload,created_at FROM messages ORDER BY id"
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            m = json.loads(r["payload"])
            role = m.get("role", "")
            if role == "system":
                continue
            content = m.get("content")
            text = content if isinstance(content, str) else self._flatten_parts(content)
            if role == "user" and text.startswith("<estado>"):
                continue
            tools = []
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                tools.append({"name": fn.get("name", ""), "arguments": fn.get("arguments", "")})
            out.append(
                {"role": role, "text": text, "tools": tools, "created_at": r["created_at"]}
            )
        return out[-limit:]

    @staticmethod
    def _flatten_parts(content: Any) -> str:
        if isinstance(content, list):
            return " ".join(
                str(p.get("text", "")) for p in content if isinstance(p, dict)
            )
        return "" if content is None else str(content)

    def compact_state(self) -> str:
        """Resumen compacto del estado que se inyecta al prompt cada turno."""
        findings = self.findings()
        todos = self.open_todos()
        included_scope = self.scope_assets(status="included")
        pending_scope = self.scope_assets(status="pending")
        lines = ["<estado>"]
        if findings:
            lines.append(f"  Hallazgos ({len(findings)}):")
            for f in findings:
                cvss = f" cvss={f['cvss_score']}" if f.get("cvss_score") is not None else ""
                lines.append(
                    f"    #{f['id']} [{f['severity']}/{f['status']}]{cvss} "
                    f"{f['title']} — {f['endpoint']}"
                )
        else:
            lines.append("  Hallazgos: ninguno todavía.")
        if todos:
            lines.append("  Pendientes:")
            for t in todos:
                lines.append(f"    #{t['id']} {t['content']}")
        if included_scope:
            lines.append("  Alcance ampliado (activos incluidos durante el engagement):")
            for s in included_scope:
                lines.append(f"    {s['asset']} ({s['relation']})")
        if pending_scope:
            lines.append("  Activos PENDIENTES de aprobación (NO están en scope, no los ataques):")
            for s in pending_scope:
                lines.append(f"    #{s['id']} {s['asset']} — {s['evidence'][:80]}")
        lines.append("</estado>")
        return "\n".join(lines)

    # ---- alcance dinámico (activos descubiertos durante el engagement) ----
    def add_scope_asset(self, asset: str, relation: str, evidence: str, status: str = "included") -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO scope_assets (asset,relation,evidence,status,created_at) VALUES (?,?,?,?,?)",
                (asset, relation, evidence, status, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def scope_assets(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if status:
                rows = self.db.execute(
                    "SELECT * FROM scope_assets WHERE status=?", (status,)
                ).fetchall()
            else:
                rows = self.db.execute("SELECT * FROM scope_assets").fetchall()
        return [dict(r) for r in rows]

    # ---- eventos (feed de actividad para el dashboard) ----
    def log_event(self, kind: str, label: str, detail: str = "") -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO events (kind,label,detail,created_at) VALUES (?,?,?,?)",
                (kind, label, (detail or "")[:500], time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- uso de tokens/costo (acumulado, incluye subagentes) ----
    def add_usage(
        self, prompt_tokens: int, completion_tokens: int, cached_tokens: int, cost_usd: float, calls: int
    ) -> None:
        with self._lock:
            self.db.execute(
                """INSERT INTO usage (id,prompt_tokens,completion_tokens,cached_tokens,cost_usd,calls)
                   VALUES (1,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     prompt_tokens=prompt_tokens+excluded.prompt_tokens,
                     completion_tokens=completion_tokens+excluded.completion_tokens,
                     cached_tokens=cached_tokens+excluded.cached_tokens,
                     cost_usd=cost_usd+excluded.cost_usd,
                     calls=calls+excluded.calls""",
                (prompt_tokens, completion_tokens, cached_tokens, cost_usd, calls),
            )
            self.db.commit()

    def get_usage(self) -> dict[str, Any]:
        with self._lock:
            row = self.db.execute("SELECT * FROM usage WHERE id=1").fetchone()
        return dict(row) if row else {
            "prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0, "cost_usd": 0.0, "calls": 0,
        }

    def close(self) -> None:
        self.db.close()
