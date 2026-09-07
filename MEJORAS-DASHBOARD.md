# Mejoras del dashboard de glaive

> Análisis del dashboard actual (`glaive/dashboard.py`) y del REPL que lo alimenta
> (`glaive/repl.py`), con plan de mejoras. Todo lo del dashboard es **read-only sobre el
> SQLite que ya persiste el agente → 0 tokens de LLM y 0 dependencias nuevas**. Las dos
> mejoras de UX marcadas (estado de actividad y CLI asíncrono) sí tocan `repl.py`/motor y
> se detallan en §3 y §4.

---

## 1. Diagnóstico: qué muestra hoy vs. qué datos ya están guardados

El dashboard es una vista de solo-lectura sobre el mismo `Store` (SQLite) del agente —
eso está bien. El problema es que **hoy expone ~40% de lo que ya persistís**.

**Muestra hoy:** findings (title / severidad / cvss_score / status / endpoint), todos,
feed de eventos (últimos 60) y usage (tokens/costo/cacheo).

**Ya está en SQLite pero el dashboard NO lo usa:**

| Dato ya persistido | Tabla / método | ¿En el dashboard? |
|---|---|---|
| Superficie descubierta (dominios/hosts/activos) | `scope_assets` · `store.scope_assets(status)` | ❌ no aparece |
| Detalle del finding: `description`, `evidence`, `poc`, `remediation`, `cwe`, `wstg`, `owasp`, `cvss_vector` | `findings` · `store.findings()` | ❌ solo el título |
| Cadena de ataque entre findings | `findings.chains_from` | ❌ no |
| Conversación completa | `messages` · `store.load_messages()` | ❌ no (solo feed truncado a 300 chars) |
| Evidencia cruda de comandos | `tool_outputs` · `store.get_output(id)` | ❌ no |
| Timestamps (`created_at` / `updated_at`) | varias tablas | ❌ no se muestran |
| **Estado de actividad** (pensando / esperando tu input / pausado / pidiendo confirmación) | **no existe todavía** | ❌ ver §3 |

---

## 2. Problemas de robustez del dashboard / REPL actual

1. **No distingue "trabajando" de "esperándote" de "pausado".** *(Marcado por el usuario.)*
   El `status` de sesión solo toma `running` / `finished` / `stopped`. Cuando el REPL está
   bloqueado en `console.input("› ")` esperando que escribas, el status sigue en `running`
   — igual que cuando el modelo está pensando o ejecutando tools. El dashboard muestra
   "running" en los tres casos. Tampoco refleja cuando el agente pide confirmación
   (`on_ask_user`, p. ej. ampliación de scope). → **§3.**
2. **El CLI no funciona como Claude Code.** *(Marcado por el usuario.)* No podés escribir
   mientras el modelo piensa/responde: el REPL es lockstep (leer input → correr turno
   completo → recién ahí volver a leer input). No hay cola de mensajes ni interrupción en
   caliente. → **§4.**
3. **Sin indicador de conexión perdida.** Si el proceso del agente muere, el
   `catch(e){return}` del `tick()` hace que el navegador siga mostrando datos viejos como
   si estuviera vivo. No te enterás de que se cortó.
4. **Cada tick re-baja todo** (findings + todos + 60 eventos + usage) cada 1.5s. Funciona,
   pero no escala: en engagements largos el feed se re-serializa entero cada vez. Falta un
   `?since=<event_id>` para traer solo lo nuevo.
5. **Una sola sesión.** Sigue atado a un único `Store`; no hay `glaive dashboard`
   multi-target. Con dos targets tenés dos dashboards sueltos en puertos distintos.
6. **No se puede revisar un finding.** Ves el título pero no la evidencia / PoC /
   remediación → hoy no sirve como herramienta de review.
7. **Sin timestamps** en eventos/findings ni **filtros** (por severidad, potential vs
   confirmed).

---

## 3. Estado de actividad de la sesión — P0  *(issue marcado)*

**Problema:** cuando el chat se frena (esperando que escribas, o pausado) el dashboard no
lo muestra como tal — sigue diciendo "running". Falta un **estado de actividad** separado
del **status de ciclo de vida**.

Hay que separar dos ejes:

- **Lifecycle** (ya existe, campo `session.status`): `running` / `finished` / `stopped`.
- **Activity** (nuevo): en qué está el agente *ahora mismo*.

### 3.1 Modelo propuesto
Nuevo estado de actividad con valores tipo:

| activity | cuándo | color sugerido |
|---|---|---|
| `thinking` | el modelo está generando (antes/entre tokens) | ámbar, pulsante |
| `streaming` | está escribiendo la respuesta | ámbar |
| `running_tool` | ejecutando un `exec_command` u otra tool | cian |
| `awaiting_input` | terminó el turno, **esperando que vos escribas** | azul “en espera” |
| `awaiting_confirmation` | el agente pidió confirmación (`on_ask_user`) | amarillo, destacado |
| `compacting` | corriendo compactación de contexto | gris |
| `paused` / `idle` | sesión abierta pero sin actividad (o `stopped`) | gris apagado |

### 3.2 Backend (cómo persistirlo — 0 tokens)
- Agregar a la tabla `session` dos columnas: `activity TEXT` y `last_activity_at REAL`
  (heartbeat). O una tabla `activity(state, detail, updated_at)` de una sola fila.
- Un método `store.set_activity(state, detail="")` que actualice ambas.
- **Instrumentar los puntos donde cambia** (en `engine.py` y `repl.py`):
  - `repl.py`, antes de `console.input(...)` → `set_activity("awaiting_input")`.
  - `engine.py::turn`, al empezar el hop → `set_activity("thinking")`; al primer chunk de
    texto → `streaming`; en cada tool call → `running_tool` (con el nombre en `detail`).
  - `Printer.ask_user` / `on_ask_user` → `awaiting_confirmation` (con la pregunta en
    `detail`).
  - `compaction.maybe_compact` cuando dispara → `compacting`.
  - `session.shutdown()` → `paused`/`stopped`.
- **Heartbeat:** actualizar `last_activity_at` en cada cambio (y opcionalmente un latido
  cada N s durante `thinking` largo) para poder detectar proceso muerto (§3.4).

### 3.3 Frontend
- Badge de actividad en el header, separado del pill de status. Texto claro:
  “⏳ esperando tu respuesta”, “🤖 pensando…”, “⚙ ejecutando nmap…”, “❓ esperando
  confirmación”, “⏸ pausado”.
- Cuando `awaiting_confirmation`, mostrar la pregunta (`detail`) destacada — así desde el
  dashboard ves *qué* está preguntando el agente aunque estés mirando la web y no la
  terminal.

### 3.4 Indicador vivo / desconectado (relacionado)
Con `last_activity_at` + el timestamp del último `tick()` OK en el cliente: si el fetch
falla o el heartbeat quedó viejo, mostrar “⚠ sin respuesta hace Ns / proceso caído” en
vez de datos stale. Resuelve el punto 3 de §2.

---

## 4. CLI interactivo estilo Claude Code (input asíncrono) — P1  *(issue marcado)*

**Problema:** en `run_repl` el flujo es estrictamente lockstep:
1. `console.input("› ")` **bloquea** hasta que apretás Enter.
2. `session.turn(...)` corre hasta terminar (streaming de texto + tool calls).
3. Recién ahí se vuelve a leer stdin.

Durante el paso 2 **no se lee el teclado**: no podés escribir, encolar un mensaje, ni
interrumpir mientras el modelo piensa/responde. Claude Code, en cambio, **desacopla el
input del turno**: seguís teniendo el prompt vivo, podés tipear mientras responde, encolar
el próximo mensaje, e interrumpir en caliente.

### 4.1 Qué se necesita (arquitectura)
1. **Lector de input desacoplado del turno.** Un hilo (o loop async) que lee stdin de
   forma continua y **encola** lo que escribís en una `queue.Queue`, sin bloquear el turno
   en curso.
2. **Prompt que convive con el output en streaming.** Mientras el agente imprime, el
   renglón de input tiene que quedar “abajo” sin romperse. Esto no se resuelve con
   `input()`/`console.input()` a secas.
3. **Turno cancelable (interrupción en caliente).** `session.turn()` tiene que poder
   abortar entre hops (y idealmente cortar el stream del LLM). Hoy corre `_MAX_TOOL_HOPS`
   sin chequear cancelación.
4. **Política de mensajes encolados.** Definir qué pasa con lo que escribís durante un
   turno: (a) se **encola** y se manda como próximo turno (simple), o (b) **interrumpe** el
   turno actual e inyecta tu mensaje como steering (avanzado, estilo Claude Code:
   Esc/Ctrl-C corta y tu texto entra).

### 4.2 Opción recomendada: `prompt_toolkit`
Es la librería estándar para REPLs interactivos en Python y **la forma limpia de lograrlo
en Windows** (win32), donde no se puede hacer `select()` sobre stdin ni trucos de
`termios`.

- `PromptSession.prompt_async()` para leer sin bloquear el loop.
- **`patch_stdout()`**: context manager que permite imprimir (el streaming del agente)
  mientras hay un prompt activo, sin corromper el renglón de input — resuelve el punto 4.2
  de arriba directamente.
- Barra inferior (`bottom_toolbar`) para mostrar el estado de actividad (§3) y “› ” de
  input fijo abajo.
- Keybindings para interrumpir (Ctrl-C / Esc) el turno en curso.
- **Costo:** una dependencia nueva (`prompt_toolkit`, pura-Python, cross-platform). Es la
  única mejora del doc que agrega dependencia; el resto es 0.

**Alternativa sin dependencia** (más frágil en Windows): hilo lector con `input()` en loop
+ `queue.Queue`, y el turno consume de la cola entre hops. Problema: imprimir el streaming
mientras un `input()` está bloqueado interleava feo en Windows. Sirve para “encolar
próximo mensaje” pero no para tipear-mientras-responde prolijo. Por eso se recomienda
`prompt_toolkit`.

### 4.3 Cambios concretos
- `engine.py::turn(...)`: aceptar `should_cancel: Callable[[], bool]` (o un
  `threading.Event`) y chequearlo entre hops y dentro del `for chunk in stream` para poder
  abortar; cerrar el stream httpx al cancelar.
- `repl.py`: reescribir `run_repl` con `prompt_toolkit` — hilo/loop de input → `Queue`;
  loop principal: si hay turno en curso, encolar; si está `awaiting_input`, tomar de la
  cola; Ctrl-C/Esc setea el `cancel_event`.
- Integrar con §3: el estado de actividad alimenta la `bottom_toolbar` **y** el dashboard,
  de una sola fuente de verdad (`store.set_activity`).
- El modo `--auto` no cambia (no tiene input humano); solo mejora el interactivo.

### 4.4 Alcance / cuidado
Es la mejora más grande del doc (toca REPL + firma de `turn` + threading). Conviene
hacerla **después** del estado de actividad (§3), porque §3 es la fuente de verdad que
tanto la barra inferior del CLI como el dashboard van a consumir. Sugerido: §3 primero
(chico, alto valor), §4 después.

---

## 5. Resto de mejoras del dashboard (priorizadas)

### P0 — máximo valor, sobre datos que YA tenés

#### 5.1 Panel de superficie de ataque (`scope_assets`)
Dado el enfoque de **scope generoso**, un panel que muestre los dominios/hosts/activos que
el agente va **descubriendo en vivo** (`included` vs `pending`), con relación y evidencia.
Es lo que querés “ver crecer” durante el engagement.
- **Backend:** sumar `"scope_assets": store.scope_assets()` al snapshot de `/api/state`.
- **Frontend:** panel con dos grupos (incluidos / pendientes) + contador en el header.

#### 5.2 Drill-down de finding
Click en un finding → detalle con `description`, `evidence`, `poc`, `remediation`,
`cwe`/`wstg`/`owasp`, `cvss_vector` y `chains_from`. Lo vuelve herramienta de review real.
- **Backend:** `store.findings()` ya trae todos los campos — no recortarlos en `/api/state`.
- **Frontend:** fila clickeable → detalle expandible o modal.

### P1

#### 5.3 Panel de conversación
Endpoint `/api/messages` (lee tabla `messages`), tab que renderice el chat real
(user/assistant/tool) con polling — no el feed truncado a 300 chars.

#### 5.4 Dashboard multi-sesión (`glaive dashboard`)
Comando en `cli.py` que escanee `runs/*/state.db`, liste todas las sesiones (target,
status, activity, nº findings, costo, última actividad) y sirva una vista índice; click →
detalle. Un solo puerto, N sesiones, cada `Store` abierto on-demand (WAL permite leer
mientras otro proceso escribe). El dashboard por-sesión actual se mantiene.

#### 5.5 Distribución de severidad + confirmed/potential
Mini-barras (crítico/alto/medio/bajo/info) + conteo confirmed vs potential. Cálculo en el
cliente sobre `findings`.

#### 5.6 Timestamps
`created_at` / `updated_at` en findings y eventos, en hora relativa (“hace 2m”).

#### 5.7 Attack chain visual
Con `chains_from`: en el drill-down, “habilitado por #N” / “habilita a #M”; luego un árbol.

### P2 — pulido
- **Delta updates:** `/api/events?since=<id>` (rendimiento en sesiones largas).
- **Filtros:** por severidad y estado (confirmed/potential) + búsqueda.
- **Evidencia cruda:** `/api/output/<id>` que sirva `store.get_output(id)`.
- **Botón “generar reporte”:** dispara `report.py` (0 tokens) y ofrece el `.md`/PDF.
- **Auto-scroll / marca de actividad nueva** en el feed.

---

## 6. Recomendación de orden de arranque

1. **§3 Estado de actividad** (P0, chico) — resuelve el “no figura como pausado/esperando”
   y es la fuente de verdad para el CLI y el dashboard.
2. **§5.1 Panel de `scope_assets`** + **§5.2 Drill-down de finding** (P0) — superficie en
   vivo + review real, 100% sobre datos existentes.
3. **§3.4 Indicador vivo/desconectado** (P0, trivial una vez está el heartbeat).
4. **§4 CLI asíncrono estilo Claude Code** (P1, la más grande — hacerla después de §3).
5. Resto de P1/P2 según ganas.

---

## 7. Checklist de implementación

- [ ] **P0** Estado de actividad: columnas/tabla + `set_activity()` + instrumentar engine/repl (§3)
- [ ] **P0** Badge de actividad en el dashboard (pensando/esperando/confirmación/pausado)
- [ ] **P0** Indicador vivo/desconectado (heartbeat `last_activity_at` + último tick OK)
- [ ] **P0** Panel superficie de ataque (`scope_assets` en `/api/state` + UI)
- [ ] **P0** Drill-down de finding (evidencia/PoC/CVSS/CWE/WSTG/OWASP/chains)
- [ ] **P1** CLI asíncrono con `prompt_toolkit`: input desacoplado + cola + interrupción (§4)
- [ ] **P1** `turn()` cancelable (`should_cancel`/`Event`, cortar stream) (§4.3)
- [ ] **P1** Panel de conversación (`/api/messages` + tab)
- [ ] **P1** Dashboard multi-sesión (`glaive dashboard`, escanea `runs/*`)
- [ ] **P1** Distribución de severidad + confirmed/potential
- [ ] **P1** Timestamps (hora relativa) en findings y eventos
- [ ] **P1** Attack chain (habilitado por / habilita a, vía `chains_from`)
- [ ] **P2** Delta updates (`?since=`) en el feed
- [ ] **P2** Filtros por severidad/estado + búsqueda
- [ ] **P2** Link a evidencia cruda (`/api/output/<id>`)
- [ ] **P2** Botón “generar reporte” desde el dashboard

---

## 8. Archivos a tocar (referencia)

```
glaive/
  dashboard.py   panel scope_assets, drill-down finding, /api/messages,
                 badge de actividad + indicador de conexión, modo multi-sesión
  cli.py         comando `glaive dashboard` (multi-sesión, escanea runs/*)
  state.py       set_activity()/last_activity_at (§3); resto sin cambios de datos
  engine.py      instrumentar activity en turn(); turn() cancelable (§4.3)
  repl.py        CLI asíncrono con prompt_toolkit: input + cola + interrupción (§4)
  compaction.py  set_activity("compacting") al disparar
pyproject.toml   agregar dependencia prompt_toolkit (única dep nueva del doc, §4.2)
```

El resto del stack (tokens, sandbox, playbooks) queda intacto. El dashboard sigue siendo
una capa de solo-lectura; la única mejora que agrega dependencia y toca el motor es el CLI
asíncrono (§4).

---

*Documento de mejoras del dashboard + REPL — no modifica código. Para adaptar sobre
`dashboard.py` / `repl.py` / `engine.py`.*
