# Playbook: SQL Injection

1. **Identificar puntos de entrada**: parámetros de query, body (JSON/form), headers
   custom, cookies. Priorizá los que tocan búsquedas, filtros, login, IDs.
2. **Prueba de error-based rápida**: agregá `'` o `"` al valor y compará la respuesta
   (error de DB, cambio de status, diff de tamaño de respuesta) contra el baseline.
3. **Confirmación booleana**: `id=1 AND 1=1` vs `id=1 AND 1=2` — si difieren, hay
   inyección. Esto ya es evidencia reproducible.
4. **Time-based (si boolean no es concluyente)**: `AND SLEEP(5)` / `pg_sleep(5)` /
   `WAITFOR DELAY '0:0:5'` según motor sospechado, midiendo el delta de tiempo real.
5. **Confirmar con sqlmap solo después de tener un candidato claro**:
   `sqlmap -u "<url>" --batch --level=2 --risk=1 -p <param>` — no lo corras a ciegas
   contra todos los parámetros, es caro en tiempo y ruido.
No reportes basado solo en un mensaje de error genérico de la app — confirmá con al
menos dos señales (booleana o time-based) antes de `add_finding`.

**Evidencia mínima para `add_finding`:** la request exacta, la respuesta que prueba la
inyección (error, diff booleano, o delay medido), y motor de DB si se identificó.

**Criterio de severidad:** critical si permite extracción de datos o bypass de auth;
high si confirmado pero de impacto acotado (ej. blind sin data extraíble fácil).
