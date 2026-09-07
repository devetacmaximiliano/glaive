# Playbook: Misceláneos web (detección rápida, alto ROI)

Vulnerabilidades de bajo esfuerzo/alta frecuencia — revisar temprano en el
engagement, no dejar para el final.

1. **CORS mal configurado**: enviar `Origin: https://atacante.com` y ver si el
   response refleja ese origin en `Access-Control-Allow-Origin` (en vez de una
   allowlist real), especialmente combinado con
   `Access-Control-Allow-Credentials: true` — eso permite a cualquier sitio leer
   respuestas autenticadas de la víctima. `null` como origin también es un
   patrón peligroso si se acepta.
2. **Open Redirect**: parámetros tipo `?redirect=`, `?next=`, `?url=`,
   `?returnUrl=` — probar si aceptan un dominio externo completo. Impacto real
   depende de qué habilite (phishing con dominio de confianza, o robo de token
   OAuth si se usa como `redirect_uri` — ver `oauth_sso.md`).
3. **HTTP Request Smuggling** (`CL.TE`/`TE.CL`): requiere un proxy/balanceador
   delante del origin — mandar requests con `Content-Length` y
   `Transfer-Encoding: chunked` inconsistentes entre sí y observar si el
   backend y el proxy los parsean distinto (síntoma: response desincronizada
   respecto al request, o contenido de otro usuario mezclado). Alto impacto
   pero requiere cuidado — no generar tráfico masivo, un par de requests bien
   armadas alcanzan para confirmar.
4. **Host Header Injection**: cambiar el header `Host` a un valor propio y ver
   si aparece reflejado en links generados (reset de password, emails) o si
   cambia el comportamiento del routing interno.
5. **Clickjacking**: revisar si falta `X-Frame-Options`/`frame-ancestors` en
   páginas sensibles (login, cambio de configuración) — confirmar con un iframe
   de prueba simple, no hace falta nada destructivo.
6. **Deserialización insegura**: si el stack es Java (buscar cookies/params en
   formato serializado, típicamente empiezan con `rO0` en base64), .NET
   (`ViewState`), PHP (`O:` al inicio de un valor serializado) o Python
   (`pickle` en cookies/cache) — señal fuerte de riesgo de RCE vía gadget
   chains. Confirmar con herramientas específicas (`ysoserial` para Java) solo
   si el scope y el tiempo lo justifican; si no, reportar como `potential` alto
   con la evidencia del formato serializado detectado.

**Evidencia mínima para `add_finding`:** la request/response cruda que muestra
el comportamiento (header CORS reflejado, redirect aceptado, smuggling
confirmado, etc).

**Criterio de severidad:** critical para smuggling confirmado o deserialización
con RCE demostrado; high para CORS con credentials + origin reflejado, o
deserialización detectada sin RCE confirmado; medium para open redirect,
clickjacking o host header injection sin cadena de explotación adicional.
