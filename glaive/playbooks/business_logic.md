# Playbook: Business Logic Flaws

Esto es lo que separa a un pentester de un scanner. Los reportes de HackerOne
2025 lo dicen explícito: la mayoría de los investigadores creen que las
herramientas automatizadas/IA se pierden los flaws de lógica de negocio y los
encadenamientos — es exactamente el tipo de razonamiento en el que este agente
tiene que invertir tiempo real, no solo correr payloads conocidos.

**Metodología**: entendé el flujo/workflow que la app espera (ej: carrito →
checkout → pago → confirmación), y probá romper las **asunciones** de ese flujo:
reordenar pasos, saltear pasos, repetir pasos, y manipular cantidades/precios/
estados en cada uno.

1. **Salteo de pasos**: si el flujo es A→B→C, ¿se puede llegar directo a C sin
   pasar por A y B? (ej: acceder directo a la página de "pedido confirmado" sin
   haber pagado, o completar un onboarding multi-paso llamando solo al último
   endpoint).
2. **Repetición/replay**: reenviar la misma request de una acción que debería
   ser única — ¿se puede canjear un cupón dos veces? ¿se puede aplicar un
   descuento repetidas veces? ¿se puede confirmar la misma orden múltiples
   veces generando múltiples envíos por un solo pago?
3. **Manipulación de cantidades/precios en el cliente**: si el precio/cantidad
   se calcula en el frontend y se envía al backend como parámetro (en vez de
   recalcularse server-side), probar: precio negativo, cantidad negativa
   (¿suma saldo en vez de restar?), precio en 0 o en centavos por error de
   redondeo, moneda distinta si la app es multi-moneda (arbitraje de tipo de
   cambio no validado).
4. **Límites de negocio no aplicados server-side**: límites de uso (cupón "una
   vez por usuario" validado solo en el frontend), límites de cantidad
   (stock negativo permitido), límites de tiempo (acción que debería expirar
   pero se puede seguir ejecutando).
5. **Estados inconsistentes**: cambiar el estado de un recurso a algo que la UI
   no permite pero la API sí acepta (ej: mover un pedido de "cancelado" a
   "enviado" directo, saltando "pagado"). Probar transiciones de estado que
   la UI no expone pero el endpoint no valida.
6. **Abuso de funcionalidad legítima**: features pensadas para un uso normal
   pero abusables a escala o en combinación — invitaciones/referidos sin
   límite (farming de recompensas), funciones de "probar gratis" reutilizables
   cambiando un identificador, exportación de datos sin paginación real
   (extracción masiva vía una feature de "exportar mi info").
7. **Condiciones de carrera relacionadas** (ver también `race_conditions.md`
   para la técnica específica): muchos bugs de lógica de negocio (doble
   canje, doble gasto) en realidad son condiciones de carrera — si un ataque
   secuencial no funciona, probar la misma acción en paralelo.

**Evidencia mínima para `add_finding`:** la secuencia exacta de requests (orden,
parámetros modificados) y el estado resultante que prueba el impacto (saldo
cambiado, descuento aplicado de más, pedido en estado inconsistente).

**Criterio de severidad:** critical/high si hay impacto financiero directo
(descuentos/saldo/precio manipulable, doble canje) o bypass de un control de
negocio central (pago saltado); medium para abuso de features sin impacto
financiero directo pero con costo operacional real para el negocio (farming,
extracción masiva).
