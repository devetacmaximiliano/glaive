# Ingeniería inversa (Strix + PentAGI) y diseño de una alternativa eficiente en tokens

> Objetivo: un framework open source que automatice pentesting **con reportes**, que
> actúe como un pentester profesional, pero que gaste **una fracción** de los tokens
> que gastan Strix y PentAGI. Documento de análisis y arquitectura propuesta.

---

## 1. Resumen ejecutivo

Analicé el código de ambos proyectos (clonados de GitHub). Los dos son capaces, pero
**derrochan tokens por diseño**, cada uno de una forma distinta:

- **Strix** (Python, OpenAI Agents SDK + LiteLLM): un **prompt de sistema gigante
  (~47 KB / 545 líneas)** al que además se le **concatenan varios archivos de "skills"
  en markdown en cada render**. Ese bloque se reenvía en **cada turno** y se **replica
  en cada subagente** que el root agent crea. El coste crece con `turnos × subagentes`.
- **PentAGI** (Go, microservicios, "equipo de especialistas"): un **enjambre de ~13
  agentes especializados**, cada uno con su propio prompt (el de `pentester` mide
  **26 KB**), **más** un set paralelo de prompts `question_*` que hacen una llamada de
  routing/decisión *antes* de invocar a cada especialista, **más** llamadas separadas de
  `summarizer`, `enricher`, `reflector`, `memorist`. Una sola acción real puede disparar
  **4–8 llamadas al LLM**.

La conclusión práctica: no hace falta un enjambre de agentes ni un prompt de 47 KB para
actuar como pentester profesional. Con **un solo agente con herramientas**, **prompt
caching**, **carga bajo demanda de conocimiento** y **salida estructurada para el
reporte**, se consigue el mismo comportamiento a **~10–20% del coste**.

---

## 2. Ingeniería inversa — Strix

**Repo:** `github.com/usestrix/strix` · Python · construido sobre **OpenAI Agents SDK**
(`agents.create_agent`, `Session`, `ModelResponse`) + **LiteLLM** (multi-proveedor).

### Arquitectura
- **1 metodología, prompt Jinja** (`strix/agents/prompts/system_prompt.jinja`, 545 líneas)
  que describe todo el flujo hands-on (recon → mapping → scanning → PoC → fix).
- **Skills en markdown** cargadas y **concatenadas dentro del prompt** en tiempo de render
  (`agents/prompt.py`). Siempre se cargan varias aunque no apliquen:
  `scan_modes/<modo>`, `tooling/agent_browser`, `tooling/python`,
  `analysis/counterevidence`, `analysis/severity_calibration`, y `coordination/root_agent`
  para el root. → el prompt efectivo es **bastante más grande que 47 KB**.
- **Root agent = orquestador**. `<root_agent_directive>` le prohíbe testear a mano: debe
  **delegar** todo vía `create_agent` a subagentes. **Cada subagente recibe el prompt
  completo otra vez.**
- **Gestión de contexto** (lo que sí hacen bien):
  - `llm/context_budget.py`: budget de tokens por modelo vía metadata de LiteLLM.
  - `llm/compaction.py`: cuando el contexto se desborda, resume los turnos viejos en un
    `<conversation-checkpoint>` y conserva los recientes, preservando el emparejamiento
    tool-call/tool-result.
  - **Cap de salida de herramientas a 2.000 chars** (`_TOOL_OUTPUT_MAX_CHARS`).
- **Herramientas**: shell, `agent_browser`, `apply_patch`, `notes`, `todo`, `thinking`,
  `threat_model`, `agents_graph`, `reporting`, `web_search`, `mcp`, `finish`, etc.

### Dónde quema tokens
1. **Prompt de sistema enorme reenviado en cada turno** (y no hay evidencia de prompt
   caching de proveedor; se apoya en compaction, que actúa *después* de inflar).
2. **Fan-out de subagentes**: cada subagente arranca con el prompt completo (~47 KB+).
   N subagentes = N × prompt base.
3. **Skills siempre cargadas** aunque la tarea no las use (todo va al prompt, no bajo
   demanda por herramienta).

---

## 3. Ingeniería inversa — PentAGI

**Repo:** `github.com/vxcontrol/pentagi` · Go · microservicios (cola de mensajes, Postgres,
grafo de conocimiento **Graphiti**, observabilidad **Langfuse**).

### Arquitectura — "equipo de especialistas"
39 plantillas de prompt (`backend/pkg/templates/prompts/`, ~4.400 líneas en total). Roles:
`primary_agent` (15 KB), `pentester` (26 KB), `adviser`, `coder`, `enricher`, `installer`,
`memorist`, `searcher`, `generator`, `refiner`, `reflector`, `summarizer`, `reporter`.

El patrón caro es el **doble juego de prompts**:
- Por cada especialista `X` existe un `question_X` (`question_pentester`, `question_coder`,
  `question_execution_monitor`, …). Es una **llamada de routing/decisión** — con modelo más
  chico — para decidir *si* y *cómo* invocar a `X` (el README lo vende como "optimal
  performance with smaller models").
- Además, llamadas **independientes** de `summarizer` (comprime contexto), `enricher` /
  `memorist` (reinyectan contexto desde el grafo), `reflector` (auto-crítica).

→ Una única acción real ("probar SQLi en este endpoint") puede encadenar:
`primary_agent → question_pentester → pentester → question_execution_monitor →
reflector → summarizer`. Son **4–8 llamadas al LLM por paso**, varias con prompts de
decenas de KB.

### Dónde quema tokens
1. **Multiplicación de llamadas por paso** (routing + ejecución + reflexión + resumen).
2. **Prompts por especialista enormes** (`pentester` 26 KB) reenviados en cada invocación.
3. **Reinyección de contexto** vía enricher/memorist (grafo Graphiti) en cada ciclo.
4. Overhead de infraestructura (colas, microservicios) — no es token pero sí complejidad.

---

## 4. Comparativa de coste (por qué son caros)

| Palanca de coste            | Strix                              | PentAGI                              |
|-----------------------------|------------------------------------|--------------------------------------|
| Tamaño del prompt base      | ~47 KB + skills concatenadas       | 15–26 KB por especialista            |
| ¿Prompt caching?            | No evidente                        | No evidente                          |
| Llamadas LLM por acción     | 1 (pero prompt gigante) × subagentes | 4–8 (routing+exec+reflex+resumen)  |
| Multiplicador principal     | nº de subagentes                   | nº de especialistas por paso         |
| Compresión de contexto      | Sí (compaction)                    | Sí (summarizer, dedicado)            |
| Cap de salida de tools      | Sí (2 KB)                          | Parcial                              |

**Insight clave:** el problema #1 de ambos (reenviar prompts enormes) **se neutraliza con
prompt caching de proveedor** (Anthropic `cache_control` / caching automático de OpenAI):
un prompt estable de 47 KB cacheado cuesta ~**10%** en los hits. El problema #2 de PentAGI
(muchas llamadas por paso) **se neutraliza con un solo agente con herramientas** en vez de
un enjambre con routing.

---

## 5. Diseño propuesto — arquitectura eficiente

### Principios
1. **Un agente, un loop, muchas herramientas** (no enjambre). El modelo es el pentester;
   las herramientas son sus manos. Subagentes **solo** para paralelismo real y acotado
   (p. ej. escanear 3 hosts a la vez), no para "pensar por capas".
2. **Prompt de sistema pequeño y estable** (~2–4 KB): rol, reglas de alcance/ética,
   metodología en bullets, contrato de herramientas. Todo lo demás **bajo demanda**.
3. **Prompt caching agresivo**: prefijo estable (system + definición de tools) marcado para
   cache. Coste marginal por turno ≈ solo el delta nuevo.
4. **Conocimiento bajo demanda (RAG ligero)**: playbooks por vulnerabilidad (SQLi, XSS,
   SSRF, IDOR, authz…) en archivos markdown; se cargan con una tool `load_playbook(name)`
   **solo cuando el agente los pide**, no en el prompt base.
5. **Herramientas con salida acotada y "vista → detalle"**: toda salida de tool se
   trunca (p. ej. 1.5–2 KB) con opción de pedir más. El modelo pide detalle solo si lo
   necesita.
6. **Estado externo, no en el contexto**: hallazgos, todos y notas viven en un store
   (SQLite/JSON), no en la conversación. Se inyecta un **resumen compacto** del estado,
   no el historial completo.
7. **Reporte por salida estructurada**: los hallazgos se emiten como JSON estructurado
   (tool `add_finding`), y el reporte final se **renderiza con plantilla determinística**
   (sin LLM) → 0 tokens para maquetar el reporte.
8. **Modelo por tarea (tiering)**: modelo grande para razonar/planear; modelo chico para
   tareas mecánicas (parsear salida de nmap, clasificar, deduplicar). Opt-in, no un
   `question_*` obligatorio por paso.

### Componentes
```
┌─────────────────────────────────────────────────────────────┐
│  CLI / entrypoint  (scope, target, modo)                     │
└──────────────┬──────────────────────────────────────────────┘
               │
        ┌──────▼───────┐   prompt base estable (cacheado)
        │  Agent loop  │◄──────────────────────────────┐
        │ (1 modelo)   │                                │
        └──┬────────┬──┘                                │
           │        │ tool calls                        │
     ┌─────▼──┐  ┌──▼───────────┐  ┌──────────────┐     │
     │ shell/ │  │ load_playbook│  │ add_finding  │     │
     │ recon  │  │ (RAG demanda)│  │ (structured) │     │
     └─────┬──┘  └──────────────┘  └──────┬───────┘     │
           │                              │             │
     ┌─────▼─────────┐            ┌────────▼─────────┐   │
     │ Sandbox Docker│            │ Findings store   │   │
     │ (kali tools)  │            │ (SQLite/JSON)    │───┘  resumen compacto
     └───────────────┘            └────────┬─────────┘
                                           │
                                  ┌────────▼─────────┐
                                  │ Report renderer  │  plantilla determinística
                                  │ (Markdown/PDF)   │  (sin LLM)
                                  └──────────────────┘
```

### Bucle del agente (pseudo)
```
estado = cargar_estado(target, scope)
while not estado.done and turnos < max:
    msgs = [system(cacheado), tools(cacheado), resumen(estado), ultimos_turnos]
    resp = llm(msgs)                     # 1 sola llamada
    for call in resp.tool_calls:
        out = ejecutar(call)             # salida truncada
        estado.registrar(call, out)      # persiste fuera del contexto
    if contexto_grande(): estado.compactar()   # resumen barato, ocasional
render_report(estado.findings)           # 0 tokens
```

---

## 6. Palancas de eficiencia (checklist concreto)

- [ ] **Prompt caching** del prefijo estable (system + tools). *Mayor ahorro individual.*
- [ ] **System prompt ≤ 4 KB**; metodología en bullets, no en prosa.
- [ ] **Playbooks bajo demanda** vía tool, no en el prompt base.
- [ ] **Cap de salida de tools** (~1.5–2 KB) + tool `read_more(id, offset)`.
- [ ] **Estado externo** (findings/todos/notas en SQLite) + resumen compacto inyectado.
- [ ] **Compaction ocasional**, disparada por umbral, no en cada turno.
- [ ] **Reporte por plantilla determinística** desde findings estructurados (sin LLM).
- [ ] **Un agente por defecto**; subagentes solo para paralelismo real y con presupuesto.
- [ ] **Tiering de modelos** para tareas mecánicas (opcional).
- [ ] **`max_tokens` de salida ajustado** por tipo de turno (no 8K siempre).
- [ ] **Deduplicación de findings** antes de gastar tokens re-analizando.

---

## 7. Stack recomendado (a confirmar)

- **Lenguaje:** Python (ecosistema IA maduro, rápido de iterar; igual que Strix pero sin
  su peso). Alternativa: Go si querés binario único y performance (como PentAGI, más
  trabajo).
- **Acceso a modelos:** Anthropic directo con `cache_control` (prompt caching de primera
  clase y modelos fuertes en razonamiento de seguridad). Multi-proveedor vía LiteLLM como
  capa opcional.
- **Sandbox:** contenedor Docker tipo Kali con las tools (nmap, sqlmap, ffuf, nuclei…),
  igual filosofía que ambos proyectos.
- **Persistencia:** SQLite (findings, todos, notas, sesiones).
- **Reporte:** plantilla Jinja → Markdown → PDF (WeasyPrint), reusando tus skills
  existentes (`rewrite-report`, `new-finding`, `review-severity`).

---

## 8. Próximos pasos sugeridos

1. Confirmar decisiones abiertas (lenguaje, proveedor, alcance de la v1).
2. Escribir el **system prompt mínimo** (≤4 KB) + contrato de tools.
3. Scaffolding del **agent loop** con caching + estado externo.
4. 3–4 **playbooks** de arranque (SQLi, XSS, IDOR/authz, recon) cargables bajo demanda.
5. **Report renderer** determinístico enganchado a tus skills.
6. Benchmark de tokens vs. una corrida equivalente de Strix para validar el ahorro.
