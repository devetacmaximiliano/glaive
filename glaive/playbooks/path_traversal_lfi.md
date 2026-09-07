# Playbook: Path Traversal / LFI / RFI

1. **Puntos de entrada**: parámetros de descarga de archivo (`?file=`, `?doc=`,
   `?template=`, `?lang=` para archivos de idioma, `?page=include`), cualquier
   funcionalidad que arme una ruta de filesystem a partir de input.
2. **Traversal básico**: `../../../../etc/passwd`, variantes de encoding
   (`%2e%2e%2f`, doble encoding `%252e%252e%252f`), null byte en stacks viejos.
3. **Wrappers PHP** (si el stack es PHP):
   - `php://filter/convert.base64-encode/resource=config.php` — para leer
     código fuente sin que se ejecute (evita que el include lo interprete).
   - `data://text/plain;base64,<payload en base64>` — para RFI si `allow_url_include`
     está activo (raro hoy, pero probar).
   - `php://filter` con múltiples filtros encadenados si el primero no alcanza.
4. **Log poisoning → RCE**: si conseguís LFI pero no un wrapper directo, y hay
   un log accesible por traversal (`../../../var/log/apache2/access.log`),
   inyectar PHP en el `User-Agent` de una request propia y luego incluir el log
   — el server lo interpreta como código al incluirlo.
5. **RFI** (poco común hoy, pero verificar): si el parámetro acepta una URL
   completa en vez de solo un path local, apuntarlo a un archivo PHP propio en
   un server que controlás.
6. **Confirmar impacto real, no solo la lectura**: si llegaste a leer
   `/etc/passwd`, intentá escalar a un archivo de config con credenciales
   (`.env`, `wp-config.php`, `config/database.yml`) — eso es lo que le importa
   al reporte, no el `/etc/passwd` genérico.

**Evidencia mínima para `add_finding`:** el payload exacto y el contenido leído
(mostrando lo suficiente para probar acceso, sin necesidad de volcar archivos
completos innecesariamente).

**Criterio de severidad:** critical si escala a RCE (log poisoning exitoso) o
expone credenciales que dan acceso a otro sistema; high si permite leer
archivos de config/código fuente sensibles; medium si solo se confirma lectura
de archivos de bajo valor (ej: `/etc/passwd` sin nada más).
