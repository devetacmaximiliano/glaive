# Playbook: IDOR y fallas de autorización (BOLA/BFLA)

1. **Identificar objetos referenciados por ID**: URLs/params con IDs numéricos, UUIDs,
   o slugs que representan un recurso de otro usuario (`/api/orders/123`,
   `/users/45/invoices`).
2. **Baseline con tu propia sesión**: confirmá el comportamiento normal (accedés a tus
   propios recursos) antes de probar cross-user.
3. **Horizontal (mismo rol, otro usuario)**: con tu sesión autenticada, cambiá el ID a
   uno que no te pertenece. Si obtenés 200 con datos ajenos → IDOR confirmado.
4. **Vertical (escalada de rol/función)**: probá endpoints de admin/función privilegiada
   con una sesión de usuario normal (BFLA) — no solo GET, también métodos de escritura.
5. **IDs no adivinables (UUID)**: no asumas que no hay IDOR — revisá si el UUID se filtra
   en otra respuesta (listados, referencias cruzadas, emails).
6. **Confirmar impacto real**: leer datos ajenos es un finding; poder modificar/borrar
   datos ajenos (IDOR de escritura) es más severo — probá ambos si el scope lo permite.
Priorizá los endpoints que tocan datos financieros, PII o documentos antes que los de
bajo valor — el mismo esfuerzo de prueba, mayor impacto si se confirma.

**Evidencia mínima para `add_finding`:** dos requests lado a lado (tu sesión → recurso
ajeno) y la respuesta mostrando los datos/acción no autorizados.

**Criterio de severidad:** critical si permite modificar/borrar datos ajenos o escalar
privilegios; high si expone datos sensibles de lectura; medium si expone datos de bajo
impacto.
