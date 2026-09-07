# Playbook: OAuth 2.0 / SSO

Distinto de `jwt.md` (que ataca el token en sí) — esto ataca el **flujo** de
autorización. En 2025-2026 la mayoría de los incidentes reales de OAuth no
explotan un bug de implementación sino que **abusan de features legítimas del
protocolo** (redirects, device code flow, consentimiento) — el brecha de
Salesloft/Drift (tokens OAuth robados vía integración comprometida, usados
contra 700+ organizaciones) es el ejemplo de referencia de 2025.

1. **Validación de `redirect_uri`**: el paso de mayor ROI. Probar:
   - Subdominio no registrado (`https://attacker.legit-app.com` si el dominio
     base matchea pero el subdominio no está en la allowlist).
   - Path traversal en el redirect (`https://legit-app.com/callback/../../attacker`).
   - Parámetro abierto (`?redirect_uri=https://legit-app.com&next=https://attacker.com`
     si el server solo valida el host antes del `&`).
   - Wildcard mal configurado en el registro de la app OAuth (si podés verlo).
   - Si conseguís que acepte un `redirect_uri` de atacante → el `code`/`token` se
     filtra ahí. PoC: armar la URL de autorización completa con tu redirect y
     mostrar que el code llega a tu endpoint.
2. **`state` parameter (CSRF de OAuth)**: ¿el flujo valida que el `state` que
   vuelve coincide con el que se envió? Si no hay `state` o no se valida, es
   CSRF — se puede forzar a una víctima a autenticarse con la cuenta del
   atacante (login CSRF) o vincular cuentas sin su consentimiento.
3. **PKCE ausente o no validado** (apps públicas/mobile/SPA): sin PKCE, un code
   interceptado (ej: vía el bug de redirect_uri de arriba) es directamente
   canjeable por un atacante sin necesitar el `code_verifier`.
4. **Device code flow**: si la app lo soporta, ¿hay rate-limit en los intentos de
   código de 8 dígitos? ¿el código tiene tiempo de vida razonable? Un atacante
   que fuerza el device code puede secuestrar la sesión de la víctima.
5. **Scope/consent**: ¿la pantalla de consentimiento muestra claramente qué
   permisos pide la app de terceros? ¿se puede pedir un scope excesivo sin que
   el usuario lo note (consent phishing)? ¿los tokens emitidos tienen alcance
   más amplio del que la app declaró necesitar?
6. **IdP confusion / mix-up attack**: en setups con múltiples proveedores de
   identidad, ¿el cliente valida DE QUÉ IdP vino la respuesta, o confía en
   cualquier respuesta bien firmada sin verificar el `iss`?
7. **Revocación**: al desconectar la integración de terceros desde la app,
   ¿el token OAuth se revoca server-side, o sigue siendo válido indefinidamente?

**Evidencia mínima para `add_finding`:** la URL de autorización completa usada,
la respuesta que confirma el `redirect_uri`/`state`/`code` mal validado, y si se
llegó a canjear un code robado, el token obtenido (redactado en el reporte).

**Criterio de severidad:** critical si permite robar un token/code utilizable
contra la cuenta de otro usuario (redirect_uri abierto confirmado, o PKCE
ausente + code interceptable); high para CSRF de `state` ausente con impacto de
account linking; medium para consentimiento excesivo o falta de revocación sin
un camino directo a takeover.
