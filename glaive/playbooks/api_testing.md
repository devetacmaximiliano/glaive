# Playbook: API Testing (OWASP API Top 10)

APIs concentran hoy una porción creciente de los findings de alto impacto —
menos superficie visual que probar a ojo, más lógica que romper con requests
directas.

1. **Descubrir la superficie completa**:
   - Swagger/OpenAPI: `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`.
   - GraphQL: `/graphql` — probar introspection (`{__schema{types{name,fields{name}}}}`)
     si está habilitada, expone el schema completo.
   - Colecciones Postman filtradas/expuestas por error (buscar en `osint.md`).
   - Versionado: probar `/v1/` si solo ves `/v2/` documentado — las versiones
     viejas suelen tener menos controles y seguir activas.
2. **BOLA (Broken Object Level Authorization)** — extiende `idor_authz.md` a
   nivel API: cambiar el ID del recurso en el path/body (`/api/orders/123` →
   `/api/orders/124`) con tu propio token y ver si accedés a datos ajenos.
3. **BFLA (Broken Function Level Authorization)**: probar endpoints
   administrativos/de escritura con un token de usuario normal — no solo GET,
   también POST/PUT/DELETE. Muchas APIs solo protegen la UI, no el endpoint.
4. **Mass assignment**: enviar campos extra en el body que no están en el form
   de la UI (`"role":"admin"`, `"is_verified":true`, `"price":0`) — si el
   backend bindea el objeto completo sin whitelist de campos, puede aceptarlos.
5. **Exceso de datos expuestos**: comparar qué campos devuelve la API vs qué
   muestra la UI — a veces el response trae campos internos/sensibles que el
   frontend simplemente no renderiza (pero siguen ahí en el JSON).
6. **Rate limiting**: ¿hay límite real por usuario/IP en endpoints sensibles
   (login, reset, creación de recursos, búsqueda cara)? Probar con un burst
   moderado (no masivo — ver guard anti-destructivo) y medir si corta.
7. **GraphQL específico**:
   - Batching/aliasing para brute-force disfrazado de una sola request (varias
     queries de login con distinta contraseña en un solo POST).
   - Queries anidadas profundas (posible DoS de recursos — no explotar
     agresivamente, solo confirmar que no hay límite de profundidad).
   - Mutaciones sin autorización que sí están protegidas en las queries.

**Evidencia mínima para `add_finding`:** la request/response exacta que
demuestra el acceso indebido (BOLA/BFLA), el body enviado con campos extra que
fueron aceptados (mass assignment), o el schema de introspection si aplica.

**Criterio de severidad:** critical/high para BOLA/BFLA con datos sensibles o
funciones administrativas expuestas (igual criterio que `idor_authz.md`); high
para mass assignment que permite escalar rol/privilegios; medium para exceso
de datos expuestos o falta de rate-limiting sin explotación directa demostrada.
