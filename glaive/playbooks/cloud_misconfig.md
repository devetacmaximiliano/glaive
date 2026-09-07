# Playbook: Misconfiguración de Cloud

A menudo el destino final de una cadena que empezó con SSRF (`ssrf.md`) o con
credenciales filtradas (`secrets_exposure.md`) — pero también se busca
directamente si el scope lo permite.

1. **Object storage público**: buckets S3/GCS/Azure Blob con nombres derivados
   del dominio/empresa (`empresa-backups`, `empresa-assets`, `empresa-prod`).
   - Listado: `curl -s https://<bucket>.s3.amazonaws.com/` (si devuelve XML con
     objetos, está listable públicamente).
   - Si el scope lo permite, probar si además de leer se puede **escribir**
     (mucho más grave) — pero solo con un archivo de prueba inocuo y
     documentando/borrando después, nunca sobreescribiendo contenido real.
2. **Credenciales en variables de entorno / Secrets Manager expuestas**: si
   conseguiste RCE o LFI en algún punto, revisar variables de entorno
   (`env`, `/proc/self/environ`) antes de asumir que no hay nada más que
   explotar ahí.
3. **CI/CD con credenciales hardcodeadas**: pipelines expuestos
   (`.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile`) que a veces
   quedan accesibles por error — revisar si tienen secretos en texto plano en
   vez de usar el vault del CI.
4. **Post-SSRF: enumerar el alcance real de credenciales robadas** (si llegaste
   acá vía `ssrf.md`):
   - AWS: `aws sts get-caller-identity` con las credenciales obtenidas, después
     `aws iam list-attached-user-policies` (o `enumerate-iam`/`pacu` si están
     disponibles) para ver el alcance real — no asumas que son admin sin
     verificar.
   - GCP/Azure: equivalente con `gcloud auth` / `az account show`.
   - **Documentar el alcance real, no ejecutar acciones destructivas ni
     movimiento lateral agresivo** — el objetivo es demostrar el impacto
     potencial, no explotarlo a fondo.

**Evidencia mínima para `add_finding`:** el listado del bucket (o el objeto
leído como muestra, no un dump completo), el output de la verificación de
identidad/permisos de las credenciales (`get-caller-identity` o equivalente),
y de dónde salieron las credenciales (cadena de ataque, usar `chains_from` si
vino de un SSRF u otro finding).

**Criterio de severidad:** critical si el bucket es de escritura pública o si
las credenciales tienen permisos amplios (admin, acceso a otros recursos
sensibles); high si es lectura pública de datos sensibles o credenciales con
permisos acotados pero reales; medium para exposición sin datos sensibles
confirmados dentro.
