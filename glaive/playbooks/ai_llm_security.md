# Playbook: Seguridad de features con LLM/IA

Solo aplica si el target tiene una funcionalidad con LLM integrado (chatbot,
asistente, resumen de documentos, agente que ejecuta acciones). Categoría en
fuerte crecimiento — reportes de prompt injection subieron ~540% en 2025 según
HackerOne, y el patrón se repite: el input de un usuario (o de un documento que
el LLM procesa) termina teniendo más poder del que el diseño asumía.

1. **Prompt injection directo**: mandar instrucciones al chat que intenten
   sobreescribir el system prompt — "ignorá las instrucciones anteriores y...",
   pedirle que revele su system prompt o sus herramientas disponibles, o que
   actúe fuera de su rol declarado. Confirmar con algo verificable (que
   realmente cambie de comportamiento o filtre info que no debería).
2. **Prompt injection indirecto** (el vector de mayor impacto real): si el LLM
   procesa contenido de terceros (un documento subido, el resultado de una
   búsqueda web, un email, una página que resume) — insertar instrucciones
   ocultas en ESE contenido (texto blanco sobre blanco, comentarios HTML,
   metadata) para que el LLM las ejecute cuando lo procese. Esto es "stored
   prompt injection" — mucho más peligroso que el directo porque la víctima ni
   sabe que está pasando.
3. **Manejo inseguro del output** (Insecure Output Handling): si la respuesta
   del LLM se renderiza directo en HTML sin sanitizar → XSS clásico con el LLM
   como vector (pedirle que incluya `<script>` en su respuesta y ver si se
   ejecuta). Si el output del LLM se usa para construir queries/comandos sin
   sanitizar → injection clásico con el LLM en el medio.
4. **Excessive agency** (el más crítico si aplica): si el LLM puede ejecutar
   acciones (llamar herramientas/APIs, no solo generar texto) — ¿puede un
   usuario, vía prompt injection, hacer que ejecute una acción no autorizada
   (borrar datos, enviar un email en nombre de otro, hacer una transacción)?
   ¿las herramientas que el LLM puede invocar tienen los mismos controles de
   autorización que si el usuario las llamara directo, o el LLM tiene más
   privilegios de los que debería?
5. **Filtración de contexto/system prompt**: pedirle al LLM que repita todo lo
   que tiene "arriba" en la conversación, o usar técnicas de "role play" para
   que revele instrucciones internas, credenciales embebidas en el prompt, o
   el contenido de otros usuarios si el contexto se comparte indebidamente
   entre sesiones.
6. **Denegación de servicio de costo** (si aplica y el guard lo permite): inputs
   diseñados para maximizar el uso de tokens/tiempo de respuesta — documentar
   como hallazgo si no hay límites, pero NO ejecutar un ataque de volumen real
   (ver guard anti-destructivo).
7. **Multi-tenant / cross-session leakage**: si hay memoria/contexto persistente
   entre sesiones, ¿puede un usuario acceder al historial o contexto de otro
   (fuga de aislamiento entre tenants)?

**Evidencia mínima para `add_finding`:** el prompt/input exacto usado, la
respuesta del LLM que confirma el comportamiento no deseado, y si aplica
excessive agency, la acción real ejecutada (con impacto mínimo, no destructivo).

**Criterio de severidad:** critical si excessive agency permite una acción
dañina real, o si hay fuga de datos de otro usuario/tenant; high para prompt
injection indirecto confirmado con impacto claro (filtración de datos,
comportamiento no autorizado) o XSS vía output no sanitizado; medium para
prompt injection directo sin impacto más allá de cambiar el tono/rol del
asistente, o filtración de system prompt sin datos sensibles en él.
