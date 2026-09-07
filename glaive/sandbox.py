"""Sandbox de ejecución de comandos.

- ``docker``: levanta un contenedor con herramientas de pentest y ejecuta ahí
  (aislado del host; recomendado). El agente puede usar nmap, curl, sqlmap, etc.
- ``local``: ejecuta en el host, en un workspace dedicado (rápido para arrancar,
  pero sin aislamiento — usalo solo en una VM o entorno de laboratorio).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

DEFAULT_IMAGE = "glaive-sandbox:latest"
_DOCKERFILE_DIR = Path(__file__).parent / "docker"


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _image_exists(image: str) -> bool:
    proc = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, text=True
    )
    return proc.returncode == 0


def _build_default_image() -> None:
    """Construye la imagen curada de glaive (una sola vez; Docker cachea las capas)."""
    print(
        f"[glaive] Construyendo imagen de sandbox '{DEFAULT_IMAGE}' "
        "(una sola vez, ~1-2 min)...",
        flush=True,
    )
    subprocess.run(
        ["docker", "build", "-t", DEFAULT_IMAGE, str(_DOCKERFILE_DIR)], check=True
    )


class Sandbox:
    def __init__(self, mode: str, image: str, session_id: str, workspace: Path):
        self.image = image
        self.session_id = session_id
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.container = f"glaive_{session_id}"

        if mode == "auto":
            mode = "docker" if _docker_available() else "local"
        if mode == "docker" and not _docker_available():
            raise SystemExit("GLAIVE_SANDBOX=docker pero 'docker' no está en el PATH.")
        self.mode = mode

    # ---- ciclo de vida ----
    def start(self) -> str:
        if self.mode != "docker":
            return f"sandbox local en {self.workspace}"

        if self.image == DEFAULT_IMAGE and not _image_exists(self.image):
            _build_default_image()

        # Reutiliza el contenedor si ya existe; si no, lo crea.
        exists = subprocess.run(
            ["docker", "ps", "-aq", "-f", f"name=^{self.container}$"],
            capture_output=True, text=True,
        ).stdout.strip()
        if not exists:
            subprocess.run(
                [
                    "docker", "run", "-d", "--name", self.container,
                    "-v", f"{self.workspace}:/workspace", "-w", "/workspace",
                    self.image, "sleep", "infinity",
                ],
                check=True, capture_output=True, text=True,
            )
        else:
            subprocess.run(["docker", "start", self.container], capture_output=True, text=True)
        return f"sandbox docker '{self.container}' ({self.image})"

    def exec(self, command: str, timeout: int = 180) -> str:
        try:
            if self.mode == "docker":
                argv = ["docker", "exec", self.container, "bash", "-lc", command]
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            else:
                proc = subprocess.run(
                    command, shell=True, cwd=str(self.workspace),
                    capture_output=True, text=True, timeout=timeout,
                )
        except subprocess.TimeoutExpired:
            return f"[timeout tras {timeout}s]"
        except Exception as exc:  # noqa: BLE001
            return f"[error ejecutando: {exc}]"

        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            out = f"[exit {proc.returncode}]\n{out}"
        return out.strip() or "[sin salida]"

    def stop(self) -> None:
        if self.mode == "docker":
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, text=True)
