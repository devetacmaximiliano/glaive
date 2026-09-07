"""glaive — agente de pentesting automatizado, eficiente en tokens.

Diseño: un solo agente + herramientas + prompt caching + estado externo.
Ver ANALISIS-Y-DISENO.md en la raiz del repo para el porqué de cada decisión.
"""

import sys as _sys

# Windows puede darle a stdout/stderr el codepage legacy (cp1252) cuando la
# salida no es una consola moderna (redirigida, pipeada, cmd.exe viejo sin
# UTF-8) — y ahí revienta con UnicodeEncodeError apenas imprimimos un
# carácter como "⏺" o "─". Forzamos UTF-8 acá, antes de que nada más se
# importe, para no depender de la config de consola del usuario.
if _sys.platform == "win32":
    for _stream in (_sys.stdout, _sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - best-effort, seguimos igual si falla
            pass

__version__ = "0.1.0"
