"""Configuración cargada desde entorno / .env. Un único punto de verdad."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    api_key: str
    base_url: str
    model: str
    model_cheap: str
    model_fallback: str
    sandbox: str            # auto | docker | local
    sandbox_image: str
    max_iterations: int
    tool_output_chars: int
    compact_tokens: int
    runs_dir: Path
    pdf_auditor_name: str
    pdf_auditor_role: str
    pdf_company: str

    @classmethod
    def load(cls) -> "Config":
        model = os.environ.get("GLAIVE_MODEL", "anthropic/claude-sonnet-4").strip()
        return cls(
            api_key=os.environ.get("OPENROUTER_API_KEY", "").strip(),
            base_url=os.environ.get(
                "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
            ).strip(),
            model=model,
            model_cheap=os.environ.get("GLAIVE_MODEL_CHEAP", "").strip() or model,
            model_fallback=os.environ.get("GLAIVE_MODEL_FALLBACK", "").strip(),
            sandbox=os.environ.get("GLAIVE_SANDBOX", "auto").strip().lower(),
            sandbox_image=os.environ.get(
                "GLAIVE_SANDBOX_IMAGE", "glaive-sandbox:latest"
            ).strip(),
            max_iterations=_int("GLAIVE_MAX_ITERATIONS", 60),
            tool_output_chars=_int("GLAIVE_TOOL_OUTPUT_CHARS", 2000),
            compact_tokens=_int("GLAIVE_CONTEXT_COMPACT_TOKENS", 120_000),
            runs_dir=Path(os.environ.get("GLAIVE_RUNS_DIR", "runs")).resolve(),
            pdf_auditor_name=os.environ.get("GLAIVE_AUDITOR_NAME", "").strip(),
            pdf_auditor_role=os.environ.get("GLAIVE_AUDITOR_ROLE", "").strip(),
            pdf_company=os.environ.get("GLAIVE_PDF_COMPANY", "Devetac").strip(),
        )

    def require_key(self) -> None:
        if not self.api_key:
            raise SystemExit(
                "Falta OPENROUTER_API_KEY. Copiá .env.example a .env y completá tu key."
            )
