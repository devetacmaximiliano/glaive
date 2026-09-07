# Playbook: OSINT / Reconocimiento pasivo

Regla de oro: **agotá lo pasivo antes de generar ruido activo.** Acá a menudo está
el hallazgo más gordo (un `.env` en un repo, un subdominio olvidado, un bucket
abierto) y es gratis en términos de riesgo — no tocás el target todavía.

1. **Superficie de dominio/subdominios**
   - `subfinder -d <dominio> -all -silent`
   - Certificados: `curl -s "https://crt.sh/?q=%25.<dominio>&output=json" | jq -r '.[].name_value' | sort -u`
   - Permutaciones sobre lo encontrado + resolución (`dnsx` si está disponible).
2. **Infra / rangos**
   - WHOIS del dominio y de la IP; ASN si es relevante.
   - DNS: `dig ANY <dominio>`, `dig TXT <dominio>` (SPF/DMARC/verificaciones),
     intento de zone transfer: `dig AXFR @<ns> <dominio>` (raro que funcione, pero
     cuando pega es oro).
3. **Exposición pública / superficie histórica**
   - Endpoints históricos que alimentan fuzzing dirigido: `gau <dominio>` /
     `waybackurls <dominio>` (si no están instalados, `curl` directo a la API de
     Wayback: `http://web.archive.org/cdx/search/cdx?url=<dominio>/*&output=json`).
   - Búsqueda de menciones del dominio en GitHub/paste sites si el scope lo permite.
4. **Secretos y leaks** (altísimo impacto, priorizar)
   - `.git/` expuesto en el sitio web (`curl -s https://target/.git/HEAD`) — si
     responde, hay repo completo para extraer.
   - Buckets de storage con nombre derivado del dominio/empresa
     (`curl -s https://<nombre>.s3.amazonaws.com`).
   - Archivos de config/backup expuestos: `.env`, `config.php.bak`, `backup.zip`,
     `.DS_Store` en la raíz.
5. **Personas** (solo si el scope incluye phishing/spraying — si no, saltear)
   - Patrón de email corporativo + nombres de empleados públicos → lista de
     usuarios candidatos para password spraying (ver `auth_session.md`).

**Salida de este playbook:** una lista priorizada de activos + "leads" (secretos
potenciales, subdominios vivos, endpoints históricos) anotados con `add_note`. No
vuelques el output crudo al contexto — guardá solo lo accionable.

Si encontrás un subdominio o host que parece relacionado pero no estaba en el
scope original, usá `propose_scope_expansion` antes de tocarlo.
