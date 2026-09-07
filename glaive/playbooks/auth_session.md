# Playbook: Autenticación y gestión de sesión

1. **Enumeración de usuarios**: comparar respuestas de login/registro/reset con
   usuario válido vs inválido — diferencias de mensaje ("usuario no existe" vs
   "contraseña incorrecta"), de status code, o de tiempo de respuesta.
2. **Password spraying / brute force con conciencia de rate-limit**: NO fuerza
   bruta masiva por defecto (riesgo de lockout/DoS de cuentas reales — ver el
   guard anti-destructivo). Probar un set acotado de contraseñas comunes contra
   varios usuarios (spray) en vez de muchas contraseñas contra un usuario,
   espaciando requests. Si hay rate-limiting, documentarlo como control presente
   (positivo) en vez de forzarlo.
3. **MFA**: ¿se puede saltear yendo directo al endpoint post-login? ¿el código
   se puede reusar? ¿hay rate-limit en el intento de código (brute-force de un
   OTP de 6 dígitos es viable sin límite)? ¿hay "recordar este dispositivo" que
   se pueda falsificar con solo la cookie?
4. **Password reset roto**: ¿el token es predecible (secuencial, timestamp,
   poco entropía)? ¿expira? ¿el link de reset filtra el token en el `Referer`
   al cargar recursos de terceros? ¿acepta un host header manipulado
   (`Host: atacante.com`) y genera el link de reset apuntando ahí?
5. **Gestión de sesión**:
   - Cookies: ¿tienen `HttpOnly`, `Secure`, `SameSite`? ¿el session ID cambia
     tras login (fixation) o se reusa el de antes de autenticar?
   - Logout: ¿invalida la sesión server-side, o solo borra la cookie del cliente
     (la sesión sigue viva si se reusa el token capturado)?
   - Expiración: ¿hay timeout de sesión razonable, o dura indefinidamente?
6. **Confusión de roles al cambiar de cuenta**: cambiar de usuario sin cerrar
   sesión primero — ¿queda algún dato/permiso de la sesión anterior?

**Evidencia mínima para `add_finding`:** la comparación de respuestas (para
enumeración), el token de reset con su patrón (para predictibilidad), o los
atributos de cookie observados en la respuesta HTTP cruda.

**Criterio de severidad:** critical si permite bypass completo de auth o MFA;
high si permite account takeover con esfuerzo moderado (reset roto, session
fixation); medium para enumeración de usuarios o cookies mal configuradas sin
un camino directo a takeover.
