# Playbook: Reconocimiento activo (web)

Objetivo: mapear superficie de ataque tocando el target directamente. Esto es
recon **activo** — si todavía no corriste `osint.md` (pasivo), hacelo antes.

1. **Resolución y alcance**: confirmá que el target resuelve y está dentro del scope
   autorizado. `curl -sI` al host base para ver headers, servidor, redirecciones.
2. **Descubrimiento de puertos/servicios** (si el scope incluye IP/host, no solo una URL):
   `nmap -sV -T4 --top-ports 200 <host>`. Ampliá con `-p-` solo si hace falta.
3. **Fingerprinting real de tecnología**:
   - `whatweb <url>` (o headers manuales si no está: `Server`, `X-Powered-By`, cookies,
     `robots.txt`, `sitemap.xml`, favicon hash).
   - Detección de WAF: `wafw00f <url>` — si hay WAF, ajustá el ritmo de requests y
     esperá bloqueos/429 (evitá parecer un scanner ruidoso).
4. **Content discovery dirigido, no a ciegas**: con la tecnología detectada en el paso 3,
   elegí wordlist específica (ej: rutas típicas de WordPress si es WP, no `common.txt`
   genérico). `ffuf`/`gobuster` con wordlist corta primero, ampliar solo si aparecen
   indicios (paths parciales, 403s que sugieren algo protegido).
5. **Mapeo de superficie autenticada**: si hay credenciales de prueba, iniciá sesión y
   listá los endpoints/funcionalidades reales (mejor que fuzzear a ciegas).
6. **Screenshotting** (si el scope tiene varios subdominios/hosts vivos): capturas
   rápidas para priorizar visualmente qué mirar primero (paneles de admin, apps
   desactualizadas, páginas de error con stack traces).
7. **Priorización**: anotá con `add_note` los endpoints que manejan datos sensibles,
   IDs en URL (candidatos a IDOR — `load_playbook idor_authz`), uploads (`load_playbook
   file_upload`), búsquedas/formularios (candidatos a injection), auth (`load_playbook
   auth_session`), parámetros con URLs (candidatos a SSRF — `load_playbook ssrf`).

Salí de este playbook con una lista priorizada de endpoints/objetivos, no con un dump
completo de output — guardá el detalle bruto solo si lo vas a necesitar como evidencia.

Si aparece un host/subdominio que no estaba en el scope original, `propose_scope_expansion`
antes de seguir con él.
