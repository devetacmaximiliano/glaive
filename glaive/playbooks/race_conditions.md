# Playbook: Race Conditions

Categoría en crecimiento (bug bounty 2025-2026) — el bug existe en la ventana
de tiempo entre "verificar" y "actuar" (TOCTOU: time-of-check to time-of-use).
Requiere mandar requests EN PARALELO, no una tras otra — secuencial casi nunca
lo dispara.

1. **Candidatos típicos**: cualquier acción que primero verifica un estado y
   después lo actualiza — canje de cupón/código de invitación, transferencia de
   saldo, "me gusta"/voto único, creación de un recurso con nombre único,
   límite de intentos (login, OTP), reserva de stock limitado, uso de un token
   de un solo uso (reset de password, confirmación de email).
2. **Técnica: single-packet attack / requests simultáneas**: mandar N copias
   idénticas de la misma request lo más simultáneas posible (mismo instante de
   red, no en loop secuencial con delay). Con `curl` puro es difícil lograr
   verdadero paralelismo; si hay `python3` con `httpx`/`asyncio` o `curl` con
   `&` de shell disparados juntos, usarlo:
   ```
   for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -X POST <url> -d "<body>" & done; wait
   ```
   (ajustar N según el límite que se está probando — 10-20 copias alcanza para
   la mayoría de los casos, no hace falta más).
3. **Qué mirar en el resultado**: ¿el cupón se canjeó más de una vez? ¿el saldo
   quedó negativo o se duplicó una transferencia? ¿se crearon N recursos con el
   mismo nombre "único"? ¿el límite de intentos se saltó (más intentos
   exitosos que el máximo permitido)?
4. **Multi-endpoint race**: a veces la ventana no está en el mismo endpoint sino
   entre dos relacionados — ej: cambiar el email de la cuenta y verificar el
   código de confirmación viejo en simultáneo, o iniciar un pago y cancelarlo
   mientras el webhook de confirmación todavía está en vuelo.
5. **Confirmar con evidencia reproducible**: correr el ataque 2-3 veces
   consecutivas — una race condition explotada una sola vez podría ser
   casualidad; que se repita de forma consistente confirma que es real.

**Evidencia mínima para `add_finding`:** el comando/script usado para disparar
las requests en paralelo, y el estado resultante que prueba el impacto (más
usos de los permitidos, saldo inconsistente, recursos duplicados) — idealmente
reproducido más de una vez.

**Criterio de severidad:** critical/high si hay impacto financiero (doble
gasto, transferencia duplicada) o bypass de un control de seguridad (límite de
intentos de login/OTP saltado); medium para duplicación de recursos sin
impacto financiero directo.
