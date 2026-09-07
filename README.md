# glaive

Agente de pentesting automatizado, con generación de reportes, diseñado para gastar
**una fracción** de los tokens que consumen herramientas como [Strix](https://github.com/usestrix/strix)
o [PentAGI](https://github.com/vxcontrol/pentagi).

Ver [`ANALISIS-Y-DISENO.md`](ANALISIS-Y-DISENO.md) para la ingeniería inversa de esas
dos herramientas (por qué son caras) y el razonamiento detrás de cada decisión de
diseño de acá abajo.

## Por qué es más barato

- **Un solo agente con herramientas**, no un enjambre de subagentes ni un pipeline de
  "routing → ejecución → reflexión → resumen" por cada paso.
- **System prompt chico (~1.5 KB)** en vez de decenas de KB, y **marcado para prompt
  caching** (`cache_control`) en cada llamada — los turnos siguientes casi no pagan
  el prefijo repetido.
- **Conocimiento bajo demanda**: la metodología detallada por vulnerabilidad
  (`glaive/playbooks/*.md`) se carga solo si el agente decide que aplica, vía la tool
  `load_playbook` — no viaja en el prompt base.
- **Estado fuera del contexto**: hallazgos, notas y pendientes viven en SQLite
  (`glaive/state.py`), no en el historial de mensajes; a cada turno se inyecta un
  resumen compacto, no el chat completo.
- **Salidas de herramientas truncadas** con `read_more` para pedir el resto solo si
  hace falta.
- **Compactación por umbral**, no por turno, y con el modelo barato.
- **Reporte por plantilla determinística** (`glaive/report.py` + Jinja): 0 tokens de
  LLM para maquetar el informe final; los findings ya llegaron estructurados durante
  el engagement.
- **Subagentes solo cuando valen la pena** (`glaive/subagent.py`): a diferencia de
  Strix (que fuerza a un "root agent" a delegar TODO y reenvía su prompt de sistema
  completo a cada subagente), acá el agente principal decide caso por caso vía
  `spawn_subagents`, y cada subagente arranca con un **prompt mínimo** (la tarea
  puntual, no toda la metodología), comparte el mismo estado (sus hallazgos van
  directo al Store, no viajan por el contexto del padre), corre en **paralelo real**
  (hilos) y le devuelve al padre solo un resumen de 1-3 líneas — nunca su transcript.
- **Dashboard local** (`glaive/dashboard.py`): vista de solo lectura sobre el mismo
  SQLite, servida con la librería estándar de Python (sin dependencias nuevas). Como
  no calcula nada ni llama a ningún LLM, **agregarlo no cuesta tokens**.

## Instalación

```bash
python -m venv .venv
source .venv/Scripts/activate   # Windows (Git Bash) — o .venv\Scripts\activate en cmd/PowerShell
pip install -e .
cp .env.example .env
# completá OPENROUTER_API_KEY en .env
```

## Uso

`glaive run` abre una **sesión interactiva** contra el target — la idea es que se sienta
como Claude Code, pero para pentesting: vos das instrucciones, el agente responde en
streaming y muestra cada tool call en vivo antes de devolverte el control.

```bash
# Sesión interactiva (requiere autorización explícita del target)
glaive run --target https://demo.local --scope "https://demo.local/*" --mode web

› Empezá con reconocimiento
⏺ exec_command(command=curl -sI https://demo.local)
  ⎿ HTTP/1.1 200 OK
  ⎿ Server: nginx/1.24
...
Encontré 3 endpoints con parámetros. ¿Querés que empiece por /api/search?

› dale, probá SQLi ahí
⏺ load_playbook(name=sqli)
...
```

Dentro de la sesión:

```
/findings          hallazgos confirmados hasta el momento
/todos              pendientes del plan del agente
/report [archivo]   genera el reporte (plantilla, no gasta tokens de LLM)
/usage               tokens/costo consumidos en esta sesión
/auto [n]            n turnos sin esperar tu input (hands-off puntual)
/exit, /quit          termina la sesión
```

Al arrancar se abre automáticamente el **dashboard local** (`http://127.0.0.1:<puerto>`)
con hallazgos, pendientes, actividad en vivo y costo acumulado — se actualiza solo,
sin gastar tokens. Desactivalo con `--no-dashboard` o fijá el puerto con
`--dashboard-port`.

```bash
# Modo autónomo de punta a punta (sin interacción, hasta que el agente termine)
glaive run --target https://demo.local --auto --max-turns 20

# Reanudar una sesión anterior (retoma el historial guardado)
glaive run --target https://demo.local --session-id <id>

# Generar el reporte de una sesión ya corrida (no llama al LLM)
glaive report --session-id <id>

# Listar sesiones locales
glaive sessions
```

El sandbox de ejecución es Docker por defecto (`GLAIVE_SANDBOX=auto` usa Docker si
está disponible, si no cae a ejecución local — usá `local` solo en un entorno de
laboratorio aislado, nunca contra targets reales sin sandbox). La primera vez que
corrés `glaive run` con Docker, se construye sola una imagen propia y liviana
(`glaive-sandbox:latest`, ~600MB, `glaive/docker/Dockerfile`) con un toolkit curado
(nmap, sqlmap, nikto, gobuster, ffuf, curl, dnsutils, whois, python3-cloudscraper,
jq, git) — no el metapaquete completo de Kali, que pesa varios GB. Las corridas
siguientes reusan la imagen cacheada, arranca al instante.

## Estructura

```
glaive/
  cli.py            comandos: run (interactivo/--auto), report, sessions
  repl.py           la terminal interactiva: streaming, tool calls en vivo, /comandos
  engine.py         Session — un modelo, un turno, tool calls, delega a subagentes
  subagent.py       subagentes acotados: prompt mínimo, paralelos, estado compartido
  dashboard.py      dashboard local (http.server, sin dependencias nuevas)
  llm.py            cliente OpenRouter + streaming + prompt caching
  compaction.py     resumen de contexto por umbral
  state.py          estado externo (SQLite): findings, notas, todos, eventos, uso
  sandbox.py        ejecución de comandos (docker/local)
  tools.py          definición de herramientas del agente (incl. spawn_subagents)
  prompts/
    system.j2       system prompt (~1.5 KB)
    report.md.j2    plantilla del reporte final
  playbooks/        metodología por vulnerabilidad, cargada bajo demanda
    recon.md
    sqli.md
    xss.md
    idor_authz.md
```

## Estado del proyecto

v0.1 — motor funcional end-to-end para pentest web (recon → prueba de vulns
comunes → hallazgos → reporte). Cobertura de playbooks y hardening de sandbox en
progreso. Uso previsto: **solo contra targets con autorización explícita por escrito**.

## Licencia

MIT.
