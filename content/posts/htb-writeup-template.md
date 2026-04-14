---
title: "HTB Walkthrough: [Nombre de la Máquina]"
date: 2026-01-01
draft: true
description: "Walkthrough completo de la máquina [Nombre] de Hack The Box. Dificultad [Easy/Medium/Hard], OS [Linux/Windows]. [Resumen de 1 línea con los vectores principales]."
tags: ["HackTheBox", "[Linux/Windows]", "[Easy/Medium/Hard]", "[técnica1]", "[técnica2]", "[nombre-maquina]", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución paso a paso de **[Nombre de la Máquina]** en Hack The Box. Máquina de dificultad **[Easy/Medium/Hard]** con sistema operativo **[Linux/Windows]**. [Descripción breve del vector de entrada y la escalada — 1-2 frases que cuenten la historia sin spoilear los detalles].
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}[Linux/Windows]{{< /badge >}}
{{< badge >}}[Easy/Medium/Hard]{{< /badge >}}

> ⚠️ **Esta máquina está retirada.** Los writeups públicos solo están permitidos sobre máquinas retiradas según las [normas de la comunidad HTB](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines).

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                          |
|----------------|----------------------------------|
| **Nombre**     | [Nombre]                         |
| **OS**         | [Linux / Windows] ([Distro/Ver]) |
| **Dificultad** | [Easy / Medium / Hard]           |
| **IP**         | 10.10.11.X                       |
| **Técnicas**   | [Técnica 1] · [Técnica 2] · [Técnica 3] |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.X
```

```
PORT   STATE SERVICE
[X]/tcp open  [servicio]
```

Escaneo de versiones sobre los puertos abiertos:

```bash
nmap -sC -sV -p[PUERTOS] 10.10.11.X
```

```
PORT   STATE SERVICE  VERSION
[X]/tcp open  [servicio] [versión]
```

*Puertos abiertos:*
- `[PUERTO]` → `[SERVICIO/VERSIÓN]` ([nota relevante])

> **💡 Dato clave:** [Observación importante del escaneo — cabeceras, versiones con CVE, servicios inusuales, etc.]

### 1.2 Enumeración Web (si aplica)

[Descripción de lo que encontramos al navegar al servicio web.]

```bash
# Fuzzing de directorios si aplica
gobuster dir -u http://10.10.11.X -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt
```

[Hallazgos relevantes: endpoints, archivos JS, rutas interesantes, tecnologías identificadas.]

> **💡 Conclusiones:** [Qué información tenemos ya y qué vector vamos a seguir.]

---

## 2. Explotación — [Nombre del Vector / CVE]

### 2.1 Análisis de la Vulnerabilidad

[Explicación clara de qué es la vulnerabilidad y por qué existe. Incluir diagrama de flujo si aplica.]

```
Flujo normal:    [cómo debería funcionar]
Flujo malicioso: [cómo lo explotamos]
```

### 2.2 [Desarrollo del Exploit / Enumeración adicional]

[Si usamos un exploit externo, linkearlo:]
Exploit disponible en: [Nombre del exploit](https://URL)

```bash
# Instalación de dependencias si aplica
```

```bash
# Exploit o comandos usados
```

### 2.3 Ejecución

```bash
[comando de ejecución]
```

```
[output relevante]
```

[Análisis de la respuesta — qué información nos da para el siguiente paso.]

### 2.4 [Pasos adicionales hasta el foothold — renombrar o eliminar si no aplica]

[Pasos intermedios: inyección de tokens, acceso a dashboards, extracción de credenciales, etc.]

> **🔑 [Resumen del dato clave obtenido que permite el acceso inicial].**

---

## 3. User Flag

```bash
[comando de acceso — ssh, reverse shell, etc.]
```

```
[banner de bienvenida / prompt obtenido]
```

```bash
[usuario]@[maquina]:~$ cat user.txt
```

> 🔑 Flag de usuario obtenida.

---

## 4. Escalada de Privilegios

### 4.1 Enumeración del Sistema

```bash
sudo -l
id
find / -group [grupo-interesante] 2>/dev/null
find / -perm -4000 2>/dev/null   # SUID binaries
```

```
[output relevante]
```

[Qué encontramos y por qué es interesante.]

### 4.2 Análisis del Vector de Escalada

[Explicación de la misconfiguration o vulnerabilidad encontrada. Si es compleja, incluir contexto teórico.]

```bash
# Lectura de configuraciones relevantes
cat /ruta/al/archivo/de/configuracion
```

```
[output]
```

[Análisis de la configuración: qué está mal y por qué es explotable.]

> **💡 [Insight sobre el vector — conexión con el foothold, patrón de vulnerabilidad, etc.]**

### 4.3 Explotación

[Pasos numerados si son múltiples:]

**Paso 1 — [Descripción]:**

```bash
[comando]
```

**Paso 2 — [Descripción]:**

```bash
[comando]
```

**Paso 3 — [Verificación / conexión final]:**

```bash
[comando]
```

```
[output — prompt de root u otro usuario privilegiado]
```

✅ **[Descripción de lo conseguido].**

---

## 5. Root Flag

```bash
[usuario-root]@[maquina]:~# cat /root/root.txt
```

> 🏁 Flag de root obtenida.

---

## 6. Resumen y Lecciones Aprendidas

**Ruta de compromiso:**

1. **Recon** → [hallazgo clave del escaneo]
2. **Enumeración** → [información obtenida sin autenticación]
3. **[Vector de explotación]** → [qué se hizo y qué se consiguió]
4. **Foothold** → [cómo se obtuvo el acceso inicial] → `user.txt`
5. **PrivEsc** → [técnica usada] → `root.txt`

**Lo que aprendí con esta máquina:**

- **[Lección 1 — título corto].** [Explicación de la lección.]

- **[Lección 2 — título corto].** [Explicación de la lección.]

- **[Lección 3 — título corto].** [Explicación de la lección.]

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| [Vector 1] | [Mitigación 1] |
| [Vector 2] | [Mitigación 2] |
| [Vector 3] | [Mitigación 3] |