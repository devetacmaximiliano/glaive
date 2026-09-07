# Playbook: Subdomain Takeover

Un CNAME apuntando a un servicio de terceros (GitHub Pages, S3, Heroku, Azure,
Fastly, etc.) que ya no está reclamado permite que un atacante registre ese
servicio y sirva contenido bajo el subdominio de la víctima. Frecuente, alto
impacto (phishing con dominio legítimo, robo de cookies si comparten dominio
padre), y hoy nadie lo busca por defecto.

1. **Enumerar CNAMEs de todos los subdominios conocidos** (los que salieron de
   `osint.md`): `dig CNAME <subdominio>` para cada uno.
2. **Buscar servicios "colgados"**: si el CNAME apunta a un dominio de un
   proveedor conocido (`*.github.io`, `*.s3.amazonaws.com`, `*.herokuapp.com`,
   `*.azurewebsites.net`, `*.fastly.net`, `*.pantheonsite.io`, etc.) pero al
   visitarlo da un error tipo "no such app"/"bucket does not exist"/404 de
   GitHub Pages → candidato fuerte.
3. **Confirmar con `nuclei -t http/takeovers/` si está disponible**, o manual:
   intentar registrar el recurso en el servicio de terceros (solo si el scope
   y los términos del proveedor lo permiten — si no, documentar como
   `potential` sin reclamarlo).
4. **PoC no destructivo**: si podés reclamarlo, servir una página inocua
   (no phishing real) y mostrar que el subdominio de la víctima ahora la sirve.
   Si no podés/no corresponde reclamarlo, el candidato queda como `potential`
   con la evidencia del error del proveedor.

**Evidencia mínima para `add_finding`:** el CNAME, la respuesta de error del
proveedor que confirma que el recurso no existe, y (si se reclamó) la captura
del subdominio sirviendo contenido controlado.

**Criterio de severidad:** high si se confirma que el recurso puede reclamarse
(aunque no lo reclames por alcance); medium como `potential` si el patrón
aparece pero no se confirmó la disponibilidad del recurso en el proveedor.
