# Playbook: Cross-Site Scripting (XSS)

1. **Ubicar reflejos**: parámetros que se reflejan en el HTML de respuesta (búsqueda,
   mensajes de error, nombre de usuario, parámetros de URL mostrados en la página).
2. **Marcador único primero**: probá con una cadena única no-ejecutable
   (`glvXSS12345`) para confirmar DÓNDE se refleja (HTML body, atributo, JS string,
   URL) antes de elegir el payload — el contexto define el vector correcto.
3. **Payload según contexto**:
   - HTML body: `<script>alert(document.domain)</script>` o `<img src=x onerror=...>`
   - Atributo HTML: `" onmouseover=alert(1) x="`
   - Contexto JS: `';alert(1);//`
4. **Revisar sanitización/encoding**: si el marcador vuelve escapado (`&lt;script&gt;`),
   probá bypasses de encoding o filtros conocidos antes de descartar.
5. **Stored vs Reflected vs DOM**: confirmá el tipo — stored (persiste y afecta a otros
   usuarios) es más severo que reflected.
Evitá spamear decenas de payloads genéricos contra el mismo campo — con el contexto
identificado en el paso 2, un payload dirigido alcanza.

**Evidencia mínima para `add_finding`:** captura de la ejecución real (alert, o
exfiltración simulada de cookie/token si el scope lo permite), URL/parámetro, y
contexto de reflejo.

**Criterio de severidad:** high/critical si stored y afecta a otros usuarios o permite
session hijacking; medium si reflected y requiere interacción significativa de la
víctima.
