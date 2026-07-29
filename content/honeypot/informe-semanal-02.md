---
title: "Informe Semanal de Threat Intelligence — Honeypot T-Pot (12–18 julio 2026)"
date: 2026-07-19
draft: false
description: "Segundo informe semanal del honeypot T-Pot: volumen x3,2 respecto a la semana anterior (~3.213.000 eventos). RDPHoneypot se dispara x20,7 con Flyservers S.A. como origen dominante, Sentrypeer x9,3 con cambio de objetivo a numeración UK, nuevo loader para loongarch64 y m68k en Cowrie, y confirmación de actores recurrentes en múltiples sensores."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "VoIP", "TollFraud", "Malware", "IoT", "Botnet", "Redtail", "ICS", "SCADA", "IEC104", "IPMI"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Segundo informe semanal del honeypot T-Pot, período **12–18 de julio de 2026**. El volumen total se dispara a **~3.213.000 eventos** (x3,2 respecto a la semana anterior), pero el crecimiento no es homogéneo: está casi enteramente explicado por dos sensores — **RDPHoneypot x20,7** con Flyservers S.A. como origen dominante, y **Sentrypeer x9,3** con un cambio de objetivo hacia numeración del Reino Unido. Se confirman además actores recurrentes en múltiples sensores y un nuevo loader compilado para arquitecturas poco habituales (`loongarch64`, `m68k`).
{{< /lead >}}

---

**Período analizado:** 12 – 18 de julio de 2026
**Fuente:** T-Pot (multi-honeypot + ELK Stack) — instancia expuesta públicamente en internet
**Clasificación:** Uso en portfolio / TLP:CLEAR
**Informe anterior:** [semana del 7–11 de julio de 2026](/honeypot/informe-semanal-01/)

---

## 1. Resumen Ejecutivo

Esta semana el volumen total se **dispara a ~3.213.000 eventos**, frente a ~1.011.000 la semana anterior (x3,2). El salto no es homogéneo: está casi enteramente concentrado en dos sensores muy concretos, mientras otros incluso bajan.

Los cambios más significativos respecto a la semana anterior:

- **RDPHoneypot pasa de 111.818 a 2.312.634 ataques (x20,7)**, con foco geográfico desplazado a Mónaco, Alemania, Panamá y Bulgaria. El origen se concentra en dos ASN con el mismo nombre comercial (**Flyservers S.A.**) que juntos suman más de un millón de eventos.
- **Sentrypeer pasa de 36.522 a 340.759 ataques (x9,3)**, con cambio de objetivo: la semana anterior era numeración francesa/norteamericana, **esta semana es un bloque del Reino Unido** probado de forma sistemática y secuencial.
- **Honeytrap cae de 678.792 a 218.202 ataques**, pero las IPs únicas **suben de 6.119 a 10.015** — el tráfico pasó de pocos orígenes generando mucho volumen a un patrón más distribuido.
- **Confirmación de actor recurrente:** las subredes `62.84.80.240-243` (Dionaea) y `217.154.196-197.x` / `31.70.86.6x` (Sentrypeer) vuelven a aparecer con las mismas IPs exactas. Ya no es coincidencia puntual, es presencia sostenida.
- **Nuevo loader multi-arquitectura en Cowrie:** binarios para `aarch64`, `i386`, `loongarch64` y `m68k`. La inclusión de `loongarch64` (arquitectura china de nicho) y `m68k` (hardware de los años 80, hoy en sistemas embebidos/routers muy antiguos) es inusual.
- **El mismo payload de Adbhoney de la semana pasada reaparece con 228 descargas** (frente a 110), confirmando que la campaña de minería Android (`UFO Miner`) sigue activa.
- **IEC-104** (protocolo de subestaciones eléctricas) sigue presente en ConPot por segunda semana consecutiva.

---

## 2. Volumetría Comparativa

| Honeypot | Semana 7–11 jul | Semana 12–18 jul | Variación |
|---|---:|---:|---:|
| RDPHoneypot | 111.818 | 2.312.634 | **x20,7** ⬆️⬆️ |
| Sentrypeer | 36.522 | 340.759 | **x9,3** ⬆️⬆️ |
| Cowrie | 116.390 | 229.182 | x1,97 ⬆️ |
| Honeytrap | 678.792 | 218.202 | x0,32 ⬇️⬇️ |
| Dionaea | 61.123 | 91.957 | x1,50 ⬆️ |
| ConPot | 1.594 | 4.461 | x2,80 ⬆️ |
| Adbhoney | 2.618 | 2.012 | x0,77 ≈ |
| Tanner | ~2.000 | ~6.000 | ⬆️ |
| Mailoney | 906 | ~6.000 | ⬆️ fuerte |
| **Total aprox.** | **~1.011.000** | **~3.213.000** | **x3,18** |

El crecimiento total está explicado casi en su totalidad por RDPHoneypot y Sentrypeer — entre los dos aportan **más de 2,6 millones** de los ~3,2 millones de eventos. Honeytrap, dominante la semana pasada, pasa a un rol secundario en volumen, aunque su base de IPs únicas casi se duplica (6.119 → 10.015): tráfico más disperso, no menos interés en el servicio.

---

## 3. RDPHoneypot — El Sensor Dominante de la Semana

**2.312.634 ataques, 470 IPs únicas.** La media de eventos por IP pasa de ~447 la semana pasada a **~4.920** — no solo hay más IPs atacando, cada una es mucho más agresiva.

### Distribución temporal

Actividad sostenida y creciente durante toda la semana, con un pico documentado el **18 de julio (56.293 ataques en un solo intervalo)**. A diferencia del pico aislado del 9-10 de julio, aquí el patrón es de **crecimiento sostenido**, no un pico y caída.

### Origen geográfico e infraestructura

Los países dominantes son **Mónaco, Alemania, Bulgaria y Panamá** — cambio notable respecto a Bulgaria/Azerbaiyán/Ucrania de la semana anterior.

| ASN | Organización | Eventos |
|---|---|---:|
| 48721 | Flyservers S.A. | 736.290 |
| 201814 | MEVSPACE sp. z o.o. | 424.077 |
| 35042 | Layer7 Networks GmbH | 343.918 |
| 267784 | Flyservers S.A. (2º AS) | 320.582 |
| 211736 | FOP Dmytro Nedilskyi | 149.293 |
| 49434 | Fbw Networks SAS | 109.146 |

**Flyservers S.A.** aparece con **dos números de ASN distintos** (48721 y 267784) sumando **más de 1.056.000 eventos** — casi la mitad de todo el tráfico RDP de la semana. Mismo proveedor de hosting con presencia en Panamá, posiblemente el mismo actor operando bloques de IP en dos rangos de ASN distintos del mismo proveedor.

---

## 4. Sentrypeer — Escalada del Fraude VoIP y Cambio de Objetivo

**340.759 ataques, 198 IPs únicas** (x9,3). El histograma muestra **dos oleadas distintas**: actividad alta el 12-13 de julio, caída pronunciada del 13 al 16, y nuevo pico fuerte el 17-18.

### Cambio de objetivo de fraude

La semana pasada: numeración francesa y norteamericana. **Esta semana: bloque del Reino Unido** (prefijo `+44 1292 379...`), probado con variaciones de prefijo consecutivas (`0014`, `0021`, `0024`, `0031`, `0041`...) — barrido metódico de un rango específico, consistente con reconocimiento previo a toll fraud dirigido, no escaneo genérico.

### Infraestructura

La IP `108.181.56.189` acumula **200.379 eventos** — la IP individual más activa de todo el dataset de la semana. Los ASN dominantes son **Psychz Networks (202.591)** e **IONOS SE (122.465)**.

**Confirmación de actor recurrente:** `217.154.196.179`, `217.154.197.64`, `217.154.196.247` y `31.70.86.62` / `31.70.86.68` — ya señaladas la semana pasada — **vuelven a aparecer esta semana en el top 10**, algunas con las mismas IPs exactas. Es un operador con presencia sostenida y repetida contra este servicio concreto.

---

## 5. Honeytrap — Menos Volumen, Más Dispersión y Cambio de Foco

**218.202 ataques, 10.015 IPs únicas.** Pico inicial fuerte el día 12 (~57.000 eventos) y luego actividad baja y estable el resto de la semana.

### Cambio de puertos objetivo

| Semana anterior | Esta semana |
|---|---|
| 11434 — Ollama | 2763 |
| 7860 — Gradio | **5038 — Asterisk Manager Interface** |
| 8501 — Streamlit | **8728 — API MikroTik** |

El escaneo de infraestructura de IA desaparece del top 5. El giro hacia **puerto 5038 (AMI, Asterisk Manager Interface)** es relevante: es el puerto de gestión de centralitas Asterisk, lo que conecta temáticamente con el repunte de fraude VoIP en Sentrypeer esta misma semana — posible coordinación o reflejo de una campaña más amplia de reconocimiento de infraestructura de telefonía IP.

**LANTEC COMUNICACAO MULTIMIDIA LTDA (Brasil)** domina con 71.274 eventos. Modat B.V. (el escáner de investigación identificado la semana pasada) reaparece con 11.086 eventos — presente, pero en proporción mucho menor.

---

## 6. Cowrie — Crecimiento Sostenido y Nuevo Loader Multi-Arquitectura

**229.182 ataques, 1.798 IPs únicas, 65 HASSH únicos** (x1,97). Repunte marcado el 17-18 de julio.

### Credenciales (datos exactos vía CSV)

| Usuario | Intentos | | Contraseña | Intentos |
|---|---:|---|---|---:|
| Administrator | 273.098 | | 123456 | 1.629 |
| Administrador | 52.633 | | 123 | 788 |
| root | 14.292 | | 1234 | 732 |
| admin | 2.500 | | password | 630 |
| sa | 679 | | admin | 614 |

**Dato llamativo:** `Administrador` (en español, 52.633 intentos) aparece como segundo usuario más probado — diccionarios localizados para hispanohablantes, algo ausente la semana pasada.

### Post-explotación

El patrón de comandos se repite casi idéntico: `uname -a`, `chattr -ia .ssh; lockr -ia .ssh`, `cat /proc/cpuinfo`, `whoami` — mismo script de fingerprinting/bloqueo de `.ssh` de la semana anterior. Mismo tipo de loader, misma operación.

### Nuevo loader: arquitecturas inusuales

Descargas capturadas desde `41.216.189.157` con patrón de nombre ofuscado `xnxnxnxnxnxn[arquitectura]xnxn`:

| Arquitectura | Contexto |
|---|---|
| `aarch64` | ARM 64-bit — servidores y móviles modernos |
| `i386` | x86 32-bit |
| `loongarch64` | Arquitectura china de propósito general, muy poco habitual en malware |
| `m68k` | Arquitectura de los años 80, hoy solo en sistemas embebidos/routers legacy |

Compilar para `loongarch64` y `m68k` junto a las arquitecturas habituales indica un intento deliberado de **maximizar la superficie de dispositivos comprometibles**, incluyendo hardware legacy que normalmente no recibe atención de este tipo de malware. **Redtail** (identificado la semana pasada) también sigue presente.

TechTies Inc. (37.526) y Net Access Internet India (24.150) encabezan el origen por ASN. La IP `103.149.197.34` acumula 24.150 eventos — prácticamente todo el tráfico de Net Access Internet India viene de esa única IP.

---

## 7. Dionaea — El Mismo Actor, Segunda Semana

**91.957 ataques, 1.474 IPs únicas** (x1,50).

Las IPs `62.84.80.240`, `.241`, `.242` y `.243` — marcadas la semana pasada con ~5.600-5.700 eventos cada una — **vuelven a aparecer esta semana con conteos similares (3.796-3.874 cada una)**. Segunda semana consecutiva. Ya no es ruido: es un operador con infraestructura fija y presencia continuada contra este honeypot.

Aparece con fuerza el protocolo **`ftpdatalisten`** (nuevo en el top de esta semana), ganando peso el puerto 21 (FTP) frente al dominio casi exclusivo de SMB/RPC de la semana anterior.

Líbano y Vietnam repiten como países de origen; se suman **Japón y Armenia**, ausentes la semana pasada. Broadband Plus S.a.l. (Líbano) sigue siendo el ASN más activo (15.316).

---

## 8. ConPot — IEC-104 por Segunda Semana Consecutiva

**4.461 ataques, 257 IPs únicas** (x2,8). El protocolo **IEC-104** (puerto 2404, telecontrol de subestaciones eléctricas) sigue presente — ya no es un evento puntual, hay sondeo recurrente.

Aparece también actividad en el **puerto 623 (IPMI)**, gestión remota fuera de banda de servidores — vector distinto al resto de protocolos ICS vistos hasta ahora, relevante porque IPMI mal asegurado es una vía de compromiso real y documentada en entornos de datacenter.

**Censys, Inc.** aparece en el top de ASN (110 eventos) — al igual que Modat B.V. y ONYPHE SAS, es una empresa de escaneo de investigación de internet, no un actor malicioso. Confirma el patrón ya visto: parte del tráfico "de ataque" hacia honeypots ICS es catalogación pasiva de internet.

---

## 9. Adbhoney — Misma Campaña, Más Actividad

**2.012 ataques, 106 IPs únicas.** El **mismo hash de payload de la semana pasada** reaparece con **228 descargas** (frente a 110 la semana anterior). La cadena Rebirth → `com.ufo.miner` → Trinity sigue activa con la misma muestra, confirmando una campaña persistente, no un evento aislado.

---

## 10. Conclusiones

1. **El crecimiento de esta semana es una redistribución del foco, no "más de lo mismo"**: RDP y VoIP se disparan mientras Honeytrap se modera. Un entorno real con RDP o centralita SIP expuestos debería considerar esta semana como una ventana de riesgo elevado específica para esos dos servicios.

2. **Los mismos actores/subredes reaparecen semana tras semana** (`62.84.80.240-243` en Dionaea; `217.154.196-197.x` y `31.70.86.6x` en Sentrypeer). Ya justifica una regla de bloqueo permanente a nivel de subred para estos rangos en un entorno real, en lugar de bloqueos puntuales por IP.

3. **El giro hacia AMI (5038) en Honeytrap coincidiendo con el pico de Sentrypeer** sugiere interés más amplio en infraestructura VoIP/PBX esta semana — merece seguimiento la semana siguiente para confirmar si es tendencia o coincidencia puntual.

4. **El loader con soporte para `loongarch64` y `m68k`** es un dato técnico distintivo: pocos análisis de honeypot mencionan malware dirigido a estas arquitecturas. Merece un post independiente.

5. **La reaparición y crecimiento del hash de Adbhoney** confirma el valor del seguimiento longitudinal: permite diferenciar entre "ruido nuevo cada semana" y "campañas persistentes" — exactamente lo que distingue un informe de threat intel con perspectiva temporal real de una foto aislada.

6. **IEC-104 e IPMI en ConPot, dos semanas seguidas**, consolidan la recomendación anterior: cualquier repunte en estos puertos merece revisión prioritaria por el tipo de infraestructura que simulan.

---

*Informe elaborado a partir de datos propios recogidos en una instancia T-Pot expuesta públicamente a internet. Metodología: exportación de paneles agregados de Kibana (rango 12–18 julio 2026) más tagclouds de credenciales en CSV. Comparativa realizada frente al [informe de la semana anterior (7–11 julio 2026)](/honeypot/informe-semanal-01/).*
