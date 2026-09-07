# Playbook: Exposición de secretos

1. **JS del frontend**: descargar y revisar los bundles (`curl` + `grep` por
   patrones de API key, o buscar strings largas base64/hex sospechosas). Los
   secretos hardcodeados en frontend son visibles para cualquiera, no hace
   falta explotar nada más para reportarlos.
2. **Source maps expuestos** (`.map` junto al `.js` minificado): si están
   accesibles, revierten el código a algo legible — a veces exponen lógica
   interna o comentarios con credenciales de desarrollo.
3. **Comentarios y respuestas de error**: HTML comentado con URLs internas o
   credenciales de prueba, stack traces que filtran rutas del filesystem,
   versión de librerías, o incluso queries SQL completas en el error.
4. **Archivos de config/backup expuestos**: `.env`, `config.php.bak`,
   `backup.zip`, `.DS_Store`, `web.config`, `docker-compose.yml` en la raíz o
   en rutas predecibles.
5. **Verificar el scope REAL de cada secreto encontrado** (regla importante —
   evita sobre-reportar): una API key encontrada no es automáticamente un
   "sistema comprometido". Probar:
   - ¿La key tiene permisos reales? (ej: `aws sts get-caller-identity` con
     credenciales AWS encontradas, o un request de prueba de bajo impacto con
     una API key de terceros).
   - Si la key no tiene permisos o está revocada, documentar como "credenciales
     expuestas" (hallazgo real, de todos modos — mala práctica) pero NO como
     "acceso obtenido" — son cosas distintas en el reporte.
6. **Repos y CI/CD** (si están en scope): buscar historial de git con
   credenciales que se borraron pero quedaron en commits viejos
   (`git log -p | grep -i "key\|secret\|password"` sobre un repo clonado del
   `.git/` expuesto, ver `osint.md`).

**Evidencia mínima para `add_finding`:** dónde se encontró el secreto (URL/
archivo/commit), el tipo de secreto (sin necesidad de pegar la key completa en
texto plano si el reporte va a circular — redactar parcialmente), y el
resultado de la verificación de scope (paso 5).

**Criterio de severidad:** critical si la credencial da acceso verificado a
datos/sistemas sensibles; high si la credencial es válida pero de alcance
limitado, o si permite acceso a otro sistema sin verificar aún el impacto
completo; medium/low para secretos expuestos pero sin permisos reales
confirmados (documentar igual — es mala práctica aunque no sea explotable hoy).
