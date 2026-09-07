# Playbook: JWT (JSON Web Tokens)

1. **Decodificar primero** (`header.payload.signature`, base64url cada parte) —
   mirá el algoritmo declarado (`alg`) y los claims antes de tocar nada.
2. **`alg:none`**: cambiar el header a `{"alg":"none"}`, dejar el payload
   modificado, quitar la firma (dejar el punto final vacío). Algunas
   implementaciones viejas lo aceptan igual.
3. **Confusión RS256 → HS256**: si el server usa RS256 (asimétrico) pero podés
   conseguir la clave pública, resigná el token como HS256 usando la clave
   pública como secreto HMAC — si la librería del server no valida que el
   algoritmo esperado coincida, lo acepta.
4. **Secreto débil (si es HS256)**: `hashcat -m 16500 token.txt wordlist.txt` o
   `jwt_tool` con un diccionario — muchos JWT en producción usan secretos
   default o cortos.
5. **`kid` (Key ID) injection**: si el header trae `kid` apuntando a un archivo/
   ruta, probar path traversal (`kid: "../../../../dev/null"` con secreto vacío)
   o SQL injection si `kid` se usa en una query para buscar la clave.
6. **`jku`/`x5u` apuntando a atacante**: si el header permite especificar la URL
   de donde sacar la clave de verificación, apuntarla a un servidor propio con
   una clave que vos generaste y firmar el token con esa clave.
7. **Claims sin validar**: `exp` ausente o no verificado (token nunca expira),
   `aud` no validado (token de otro servicio aceptado acá), escalada cambiando
   `role`/`is_admin`/`scope` en el payload y reenviando con la firma rota (probar
   igual — algunos servers solo decodifican sin verificar firma en ciertos paths).

**Evidencia mínima para `add_finding`:** el token original vs el modificado
(ambos, en base64), y la respuesta del server que confirma que aceptó el token
manipulado (ej: acceso a un endpoint protegido, cambio de rol efectivo).

**Criterio de severidad:** critical si permite escalar a admin o bypassear auth
completamente (alg:none aceptado, confusión de algoritmo exitosa); high si
permite impersonar otro usuario sin escalar privilegios; medium para claims mal
validados sin un camino directo a impacto (ej: `exp` ausente pero sin forma de
obtener un token válido de otra forma).
