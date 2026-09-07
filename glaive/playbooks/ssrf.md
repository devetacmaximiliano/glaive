# Playbook: SSRF (Server-Side Request Forgery)

Puerta de entrada frecuente a infraestructura cloud — hoy es de las vulns de
mayor impacto real por lo que habilita después (metadata de cloud → credenciales
IAM → pivot).

1. **Identificar puntos de entrada**: cualquier parámetro/campo que el server usa
   para hacer una request saliente — webhooks, importadores de URL, generadores
   de PDF/thumbnail que reciben una URL, "fetch preview" de links, integraciones
   con servicios externos, SSO/SAML con URL de metadata configurable.
2. **Marcador OOB primero**: apuntá el parámetro a un host que controlás (tu
   propio listener con `nc -lvnp <puerto>`, o un servicio tipo interactsh si
   está disponible) — un callback confirma la SSRF sin ambigüedad, incluso blind.
3. **Si hay respuesta reflejada** (no blind): comparar contra un host interno
   conocido (`http://127.0.0.1:<puerto-de-servicio-probable>`) y ver diffs de
   respuesta/timing respecto a un host que no existe.
4. **Escalada a metadata de cloud** (el paso de mayor impacto — probar si el
   entorno parece cloud):
   - AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - GCP: `http://metadata.google.internal/computeMetadata/v1/` con header
     `Metadata-Flavor: Google`
   - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
     con header `Metadata: true`
   - Si responde con credenciales/token → confirmado y crítico. Ver `cloud_misconfig.md`
     para qué hacer con las credenciales robadas (siempre de forma no destructiva).
5. **Bypasses si hay filtro de IP/dominio**: IP en decimal/octal/hex
   (`http://2130706433/` = 127.0.0.1), `http://[::1]/`, redirects (`http://tuservidor/
   redirige-a-interno`), DNS rebinding, `@` en la URL (`http://esperado@interno`),
   IPv6-mapped IPv4.

**Evidencia mínima para `add_finding`:** el callback OOB recibido (con timestamp), o
el diff de respuesta que prueba acceso a un recurso interno, o el contenido de
metadata devuelto (redactando el secreto real en el reporte, mostrando solo que
se pudo leer).

**Criterio de severidad:** critical si llega a credenciales cloud o a un recurso
interno sensible; high si confirmado pero el impacto queda acotado a leer un
servicio interno sin credenciales explotables; medium si es blind sin poder
demostrar impacto más allá del callback.
