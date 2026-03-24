---
title: "HTB Writeup Template: [Nombre de la Máquina]"
date: 2026-03-24
draft: false
description: "Resolución detallada de la máquina [Nombre] de Hack The Box."
tags: ["HackTheBox", "Windows", "Active Directory", "Medium"]
categories: ["Writeups"]
series: ["HackTheBox CPTS"]
feature: "https://www.hackthebox.com/images/htb_logo/HTB%20Logo.png"
thumbnail: "https://www.hackthebox.com/images/htb_logo/HTB%20Logo.png"
---

{{< lead >}}
En este artículo detallo la resolución completa de **[Nombre]**, una máquina de dificultad [Dificultad] en la plataforma Hack The Box. Exploraremos vulnerabilidades en [Servicio] y escalaremos privilegios mediante [Técnica].
{{< /lead >}}

{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}
{{< badge >}}Active Directory{{< /badge >}}

---

## 🔎 Reconocimiento (Recon)

Comenzamos con un escaneo inicial de puertos usando `nmap` para descubrir los servicios expuestos en la máquina objetivo.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.X -oG allPorts
```

Analizamos los puertos encontrados...

## 🚪 Explotación (Foothold)

Aprovechamos la vulnerabilidad encontrada en **[Servicio/Aplicación]** para obtener nuestro acceso inicial.

```python
# Exploit de ejemplo
import requests
url = "http://10.10.11.X/vulnerable"
```

Obtenemos la flag de usuario:
{{< spoiler text="user.txt" >}}
`HTB{f4k3_us3r_fl4g_h3r3}`
{{< /spoiler >}}

## 👑 Escalada de Privilegios (PrivEsc)

Una vez obtenida la shell como usuario no privilegiado, procedemos a enumerar el sistema y descubrimos...

Obtenemos la flag de root:
{{< spoiler text="root.txt" >}}
`HTB{f4k3_r00t_fl4g_h3r3}`
{{< /spoiler >}}

## 🛠️ Conclusiones y Resumen

Esta máquina me permitió consolidar mis conocimientos sobre Active Directory y la explotación de malas configuraciones en servicios web.
