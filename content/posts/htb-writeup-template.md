---
title: "HTB Walkthrough: [Nombre de la Máquina]"
date: 2026-03-24
draft: true
description: "Walkthrough completo de la máquina [Nombre] de Hack The Box. Dificultad [Easy/Medium/Hard], OS [Linux/Windows]."
tags: ["HackTheBox", "Linux", "Medium"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Resolución paso a paso de **[Nombre de la Máquina]** en Hack The Box. Máquina de dificultad **[Easy/Medium/Hard]** con sistema operativo **[Linux/Windows]**. Cubrimos recon, explotación y escalada de privilegios hasta root.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}[Linux/Windows]{{< /badge >}}
{{< badge >}}[Easy/Medium/Hard]{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo        | Detalle                     |
|--------------|-----------------------------|
| **Nombre**   | [Nombre]                    |
| **OS**       | [Linux / Windows]           |
| **Dificultad** | [Easy / Medium / Hard]   |
| **IP**       | 10.10.11.X                  |
| **Técnicas** | [ej. SQLi, RCE, PrivEsc]    |

---

## 🔎 Reconocimiento

### Escaneo de puertos (Nmap)

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.X -oG allPorts
```

```bash
# Escaneo de versiones y scripts sobre puertos abiertos
nmap -sCV -p[PUERTOS] 10.10.11.X -oN targeted
```

*Puertos abiertos:*
- `[PUERTO]` → `[SERVICIO/VERSIÓN]`

### Enumeración Web (si aplica)

```bash
# Fuzzing de directorios
gobuster dir -u http://10.10.11.X -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt
```

---

## 🚪 Foothold / Explotación

Descripción del vector de ataque encontrado...

```bash
# Comando / exploit utilizado
```

---

## 🔑 User Flag

{{< spoiler text="user.txt" >}}
`HTB{f4k3_us3r_fl4g_h3r3}`
{{< /spoiler >}}

---

## 👑 Escalada de Privilegios (PrivEsc)

### Enumeración del sistema

```bash
# Qué enumeré para buscar el vector de escalada
id
sudo -l
find / -perm -4000 2>/dev/null   # SUID binaries
```

Descripción de la vulnerabilidad o misconfiguration encontrada...

```bash
# Exploit de escalada
```

---

## 🏁 Root Flag

{{< spoiler text="root.txt" >}}
`HTB{f4k3_r00t_fl4g_h3r3}`
{{< /spoiler >}}

---

## 📝 Resumen y Lecciones Aprendidas

**Ruta de compromiso:**
1. Recon → [hall of fame del escaneo]
2. Foothold → [vector inicial]
3. PrivEsc → [técnica usada]

**Lo que aprendí con esta máquina:**

- [Lección 1]
- [Lección 2]
