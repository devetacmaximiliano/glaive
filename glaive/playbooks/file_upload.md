# Playbook: File Upload

1. **Mapear la validación existente**: subir un archivo legítimo primero para
   ver dónde queda (ruta expuesta, nombre generado o preservado) y qué
   extensiones acepta la UI.
2. **Bypass de extensión**:
   - Doble extensión: `shell.php.jpg` (si el server solo mira la última
     extensión al servir, pero un `.htaccess`/config mal hecho ejecuta por la
     del medio).
   - Null byte (en stacks viejos): `shell.php%00.jpg`.
   - Case/variantes: `shell.PHP`, `shell.pHp`, `shell.php5`, `shell.phtml`.
3. **Bypass de `Content-Type`**: cambiar el header a `image/jpeg` mientras el
   contenido real es un script — muchas validaciones solo miran el header, no
   el contenido.
4. **Bypass de magic bytes**: anteponer los bytes mágicos de un formato válido
   (ej. `GIF89a;` antes del código PHP) si la validación revisa la firma del
   archivo pero no lo parsea completo después.
5. **Path traversal en el nombre**: `../../var/www/html/shell.php` como nombre
   de archivo, si el server lo usa sin sanitizar para construir la ruta destino.
6. **Camino a impacto**:
   - RCE directo: si el archivo subido queda en un directorio ejecutable y es
     accesible vía HTTP → confirmar con un webshell mínimo (`<?php echo
     shell_exec($_GET['c']); ?>`, ejecutar solo `id`).
   - Stored XSS: subir un `.svg` o `.html` que el server sirve con
     `Content-Type` que el browser ejecuta (no como descarga forzada).
   - DoS por tamaño/tipo: fuera de scope salvo que el guard lo permita — no
     subir archivos masivos para tirar el servicio.

**Evidencia mínima para `add_finding`:** el archivo subido (contenido y
extensión/Content-Type usados), la URL donde quedó accesible, y el output del
webshell (`id`) o la ejecución del XSS almacenado.

**Criterio de severidad:** critical si lleva a RCE; high si lleva a stored XSS
persistente afectando a otros usuarios; medium si el bypass de validación se
confirma pero sin poder demostrar impacto más allá de subir un archivo
inesperado (ej: tipo no permitido pero sin ejecución ni persistencia visible).
