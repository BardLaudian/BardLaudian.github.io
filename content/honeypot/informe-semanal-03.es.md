---
title: "Informe Semanal de Threat Intelligence — Honeypot T-Pot (19–25 julio 2026)"
date: 2026-07-26
draft: false
description: "Tercer informe semanal del honeypot T-Pot: volumen baja a ~1.820.000 eventos pero la composición cambia radicalmente. ConPot se dispara x27 con ISPs residenciales (Comcast, AT&T, Virgin Media) atacando SNMP — firma de botnet IoT. Flyservers S.A. colapsa en RDP, Adbhoney confirma campaña activa por tercera semana y Dionaea detecta fuerza bruta dirigida a software de contabilidad turco (LOGO, Mikro)."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "SNMP", "VoIP", "Malware", "IoT", "Botnet", "Redtail", "ICS", "SCADA", "IEC104", "MSSQL", "ERP"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Tercer informe semanal del honeypot T-Pot, período **19–25 de julio de 2026**. El volumen total baja a **~1.820.000 eventos** (la mitad que la semana anterior), pero el dato relevante no es el total sino la composición: **ConPot se dispara x27** con origen en ISPs residenciales (Comcast, AT&T, Virgin Media, Free SAS) — la firma de un botnet de routers domésticos atacando SNMP, un actor cualitativamente distinto a todo lo visto hasta ahora. Mientras tanto, Flyservers S.A. colapsa en RDP, el mismo payload de Adbhoney lleva tres semanas creciendo, y Dionaea detecta fuerza bruta dirigida específicamente a software de contabilidad turco sobre MSSQL.
{{< /lead >}}

---

**Período analizado:** 19 – 25 de julio de 2026
**Fuente:** T-Pot (multi-honeypot + ELK Stack) — instancia expuesta públicamente en internet
**Clasificación:** Uso en portfolio / TLP:CLEAR
**Informes anteriores:** [semana 7–11 jul](/honeypot/informe-semanal-01/) · [semana 12–18 jul](/honeypot/informe-semanal-02/)

---

## 1. Resumen Ejecutivo

El volumen total baja a **~1.820.000 eventos**, prácticamente la mitad que la semana anterior (~3.213.000). Pero el dato relevante no es el volumen total — es que **la composición cambia radicalmente sensor a sensor**:

- **ConPot se dispara x27** (4.461 → 122.376 ataques) con un cambio de origen sin precedentes: ya no son VPS de hosting ni escáneres de investigación, sino **ISPs residenciales** — Comcast, Charter, AT&T, Virgin Media, Free SAS, TIM. Todo concentrado en el puerto **161 (SNMP)**. La firma de un **botnet compuesto por routers domésticos/IoT comprometidos**.
- **RDPHoneypot se desploma a un tercio** (2.312.634 → 843.181). **Flyservers S.A.**, que la semana pasada generaba más de un millón de eventos, cae a apenas ~40.800 — su campaña se detuvo o migró casi por completo.
- **Sentrypeer también cae a un tercio** (340.759 → 119.651), pero la IP `108.181.56.189` — la más activa del dataset la semana pasada — **vuelve a aparecer como la más activa**, ahora destacada también en el top 10 global. Tercera semana con presencia relevante.
- **Honeytrap vuelve a crecer** (218.202 → 372.001), impulsado en un 40% por una sola IP de la **red académica alemana DFN** — casi con toda seguridad tráfico de investigación, no un ataque real.
- **Cowrie confirma por tercera semana consecutiva** la subred `45.153.34.x` y el malware Redtail. Mismo actor, misma infraestructura, mismo payload.
- **El hash de Adbhoney sigue creciendo semana a semana**: 110 → 228 → **287 descargas**. Tres semanas de datos confirman una campaña activa y en expansión.
- **Nuevo hallazgo en Dionaea**: términos en turco en el tagcloud de usuarios (`KASA`, `DEPO`, `FATURA`, `LOGO`, `MIKRO`) — nombres de software ERP/contable real turco — junto al repunte de `mssqld` y un ISP turco en el top de ASN. Fuerza bruta vertical dirigida a un sector y geografía específicos.

---

## 2. Volumetría Comparativa (tres semanas)

| Honeypot | 7–11 jul | 12–18 jul | 19–25 jul | Tendencia |
|---|---:|---:|---:|---|
| RDPHoneypot | 111.818 | 2.312.634 | 843.181 | 📈📉 pico y caída |
| Honeytrap | 678.792 | 218.202 | 372.001 | 📉📈 en forma de V |
| Cowrie | 116.390 | 229.182 | 249.057 | 📈 crecimiento sostenido |
| ConPot | 1.594 | 4.461 | 122.376 | 📈📈📈 explosión |
| Sentrypeer | 36.522 | 340.759 | 119.651 | 📈📉 pico y caída |
| Dionaea | 61.123 | 91.957 | 92.722 | ➡️ estable |
| Adbhoney | 2.618 | 2.012 | 1.737 | ➡️ (payload +161%) |
| **Total aprox.** | **~1.011.000** | **~3.213.000** | **~1.820.000** | |

Ningún sensor mantiene un comportamiento estable salvo Dionaea y Cowrie. Esta variabilidad extrema semana a semana es en sí misma un dato: un snapshot de una sola semana sin comparación histórica daría una foto muy distorsionada del riesgo real de este honeypot.

---

## 3. ConPot — El Hallazgo Más Relevante de la Semana

**122.376 ataques, 1.009 IPs únicas** (x27 en volumen, x4 en IPs respecto a la semana anterior). Varios picos abruptos a lo largo de la semana (~20.000 eventos en un solo intervalo), no un crecimiento gradual.

### Cambio radical de infraestructura de origen

La semana pasada, los orígenes de ConPot eran proveedores de hosting/VPS típicos. **Esta semana, el top de ASN está copado por ISPs residenciales**:

| ASN | Organización | País | Eventos |
|---|---|---|---:|
| 7922 | Comcast Cable Communications | EE. UU. | 12.053 |
| 33363 | Charter Communications | EE. UU. | 11.644 |
| 12322 | Free SAS | Francia | 10.889 |
| 11426 / 20001 | Charter Communications | EE. UU. | 9.872 / 7.923 |
| 3269 | TIM | Italia | 6.337 |
| 7018 | AT&T Enterprises | EE. UU. | 5.489 |
| 5089 | Virgin Media | Reino Unido | 4.765 |

**Comcast, Charter, AT&T, Virgin Media, Free SAS y TIM** son operadores de banda ancha residencial. Ninguno es un proveedor de hosting/VPS. Este perfil de origen, combinado con el hecho de que el **99% del tráfico apunta al puerto 161 (SNMP)**, es la firma característica de un **botnet formado por routers domésticos o dispositivos IoT comprometidos** escaneando SNMP a gran escala — no de un actor con su propia infraestructura de ataque.

> **¿Por qué SNMP?** SNMP (Simple Network Management Protocol) es el protocolo de gestión remota más extendido en routers, switches y dispositivos de red. Escanearlo masivamente sirve para identificar dispositivos con SNMP habilitado y credenciales por defecto (community string `public`/`private`), el primer paso para comprometer nuevos nodos que incorporar al botnet.

El protocolo **IEC-104** (telecontrol de subestaciones eléctricas, puerto 2404) sigue presente por **cuarta semana consecutiva**, aunque en proporción mínima frente al aluvión de SNMP de esta semana.

---

## 4. RDPHoneypot — El Gran Actor de la Semana Pasada Desaparece

**843.181 ataques, 453 IPs únicas** (frente a 2.312.634 la semana pasada). Dos picos concretos el 22 y 23 de julio (~85-90k cada uno) y caída sostenida el resto de la semana.

### Colapso de Flyservers S.A.

La semana pasada, **Flyservers S.A.** (dos ASN distintos) generaba más de 1.056.000 eventos — casi la mitad de todo el tráfico RDP. Esta semana, ambos ASN suman apenas **~40.800 eventos combinados**: una caída del 96% en siete días. Este tipo de colapso abrupto es típico de: (a) el operador fue detectado y su infraestructura dada de baja por el proveedor, (b) migró a otro proveedor, o (c) simplemente pausó la campaña.

### Nuevos protagonistas

| ASN | Organización | Eventos |
|---|---|---:|
| 201814 | MEVSPACE sp. z o.o. | 260.270 |
| 205997 | Vlad Cojuhari | 224.226 |

**"Vlad Cojuhari"** (ASN 205997, 224.226 eventos) es un ASN registrado a nombre de una persona física en lugar de una empresa — inusual, y habitual en operaciones de hosting más pequeñas o menos reguladas. Mónaco y Panamá, dominantes la semana pasada (ligados a Flyservers), prácticamente desaparecen del top. Los países de origen son ahora Estados Unidos, Polonia, Francia y Azerbaiyán.

---

## 5. Honeytrap — Recuperación Impulsada por Tráfico de Investigación

**372.001 ataques, 9.974 IPs únicas** (x1,7 respecto a la semana anterior). Pico marcado el 22-23 de julio.

### El actor dominante no es malicioso

La IP `141.76.94.28`, perteneciente al ASN **Verein zur Förderung eines Deutschen Forschungsnetzes e.V. (DFN)** — la red académica y de investigación de Alemania — genera **146.980 eventos, casi el 40% de todo el tráfico de Honeytrap esta semana**. Es, con alta probabilidad, un proyecto de medición/escaneo de internet con fines de investigación académica. **No debe contabilizarse con el mismo peso que tráfico de un actor malicioso** al valorar el nivel de amenaza real de la semana.

Los puertos más atacados mantienen el perfil de la semana pasada (8728/MikroTik, 5038/Asterisk AMI, 7070), sumando ahora **8081 y 2222** (puerto SSH alternativo, común en configuraciones no estándar).

---

## 6. Cowrie — Tercera Semana Confirmando el Mismo Actor

**249.057 ataques, 1.623 IPs únicas, 57 HASSH únicos.** Crecimiento sostenido y moderado, coherente con las dos semanas anteriores.

### Confirmación longitudinal a tres semanas

| Indicador | Sem 1 (7-11 jul) | Sem 2 (12-18 jul) | Sem 3 (19-25 jul) |
|---|---|---|---|
| Subred `45.153.34.x` | ✅ ~3.817/IP | ✅ ~3.817/IP | ✅ ~3.815/IP |
| Malware Redtail | ✅ | ✅ | ✅ |
| Script `chattr -ia .ssh` | ✅ | ✅ | ✅ |
| Loader `xnxnxnxn` (loongarch64/m68k) | ❌ | ✅ | ❌ (puntual) |

La subred `45.153.34.x`, Redtail y el script de bloqueo de `.ssh` son ya actores/TTPs permanentes de este honeypot. El loader con arquitecturas inusuales de la semana pasada no reaparece — fue una campaña puntual, no persistente.

El comando `uname -a` casi duplica su frecuencia (384 → 711 ejecuciones) — mayor actividad del mismo loader. TechTies Inc. e India Net Access Internet lideran por tercer semana consecutiva; la IP `103.149.197.34` sigue siendo la más activa.

---

## 7. Sentrypeer — Actor Recurrente, Tercera Semana

**119.651 ataques, 192 IPs únicas.** Pico inicial el 19 de julio y caída sostenida el resto de la semana.

`108.181.56.189` acumula **59.769 eventos** y vuelve a ser la IP más activa del sensor, y una de las más destacadas en el dashboard global. Con presencia en al menos dos semanas consecutivas y visibilidad a nivel de dashboard, es ya un actor confirmado con actividad prolongada contra esta instancia.

### Detalle técnico curioso

En el panel de user-agents SIP aparece la cadena **`'or"='`** — literalmente una carga de inyección SQL/comando clásica, usada aquí como valor de cabecera SIP. No es un ataque dirigido contra la base de datos del honeypot, sino una prueba automatizada genérica para comprobar si el servidor procesa cabeceras sin sanitizar. Ilustrativo del nivel de ruido que lanza cualquier escáner masivo: ensaya técnicas de inyección independientemente de que el protocolo objetivo sea SQL, SIP o cualquier otra cosa.

---

## 8. Dionaea — Fuerza Bruta Dirigida a Software ERP Turco

**92.722 ataques, 1.799 IPs únicas** — volumen estable respecto a la semana anterior.

### Hallazgo del tagcloud

Junto a las credenciales genéricas habituales (`admin`, `root`, `sa`), aparece un conjunto de términos que no encajan con fuerza bruta genérica:

| Término | Significado | Contexto |
|---|---|---|
| `KASA` | Caja/efectivo | Módulo de caja en ERP turco |
| `DEPO` | Almacén | Módulo de stock/almacén |
| `FATURA` | Factura | Módulo de facturación |
| `MUHASEBE` | Contabilidad | Módulo contable |
| `LOGO` | — | Marca real de software ERP turco |
| `MIKRO` | — | Marca real de software contable turco |
| `BARKOD` | Código de barras | Módulo de inventario |

**LOGO y MIKRO son marcas reales de software ERP/contable muy usadas en Turquía**, con bases de datos MSSQL como backend habitual. Combinado con el protocolo `mssqld` ganando peso en Dionaea y **TurkNet İletişim Hizmetleri A.Ş.** en el top de ASN (3.410 eventos), esto sugiere un ataque *vertical*: fuerza bruta dirigida específicamente contra instalaciones de MSSQL usadas por software de gestión empresarial turco, en lugar del ruido genérico habitual.

**México** aparece como primer país de origen (nuevo, no visto en semanas anteriores), con la IP `187.235.152.60` (11.055 eventos, ASN **UNINET** — el mayor operador de telecomunicaciones de México). Arabia Saudí y Uruguay también son nuevos en el top.

---

## 9. Adbhoney — Tres Semanas de Crecimiento Confirmado

**1.737 ataques, 102 IPs únicas.** El volumen del sensor se mantiene bajo y estable, pero el dato relevante es la progresión del payload:

| Semana | Descargas del hash |
|---|---:|
| 7–11 jul | 110 |
| 12–18 jul | 228 |
| 19–25 jul | **287** |

El hash `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d53839b5.raw` (cadena Rebirth → `com.ufo.miner` → Trinity) lleva **tres semanas creciendo de forma consecutiva con el mismo payload**. Es el indicador más claro de inteligencia longitudinal de todo el seguimiento: una campaña real, activa y en expansión, no un evento puntual.

---

## 10. Conclusiones

1. **El hallazgo de la semana es ConPot**: ISPs residenciales + puerto 161 SNMP es la firma de un botnet IoT/router doméstico — un tipo de actor cualitativamente distinto a la infraestructura VPS/hosting vista en semanas anteriores. Merece seguimiento la semana que viene para confirmar si el patrón se consolida o fue puntual.

2. **No todo pico de volumen es una amenaza**: el 40% del tráfico de Honeytrap esta semana viene de la red académica alemana DFN. La separación entre escaneo de investigación y tráfico malicioso real sigue siendo crítica para no distorsionar el nivel de amenaza percibido.

3. **Redtail, la subred `45.153.34.x` y el payload de Adbhoney llevan tres semanas activos** — son ya candidatos sólidos para reglas de bloqueo permanente a nivel de subred y hash si se gestionara un entorno real.

4. **El colapso de Flyservers S.A. en RDP** ilustra lo rápido que cambia la infraestructura de un actor — de dominar casi la mitad del tráfico de un sensor a prácticamente desaparecer en siete días. Cualquier lista de bloqueo basada en ASN necesita revisión frecuente.

5. **La fuerza bruta contra software ERP turco (LOGO/Mikro) en Dionaea** es un buen candidato para un post independiente sobre ataques verticales dirigidos a sectores y geografías específicos.

6. Con tres semanas de datos acumulados, el informe empieza a tener valor real de **inteligencia longitudinal**. La próxima entrega debería incluir una sección fija de "actores persistentes" (IPs, hashes y subredes vistas en 2+ semanas) — ya hay suficiente histórico para sostenerla.

---

*Informe elaborado a partir de datos propios recogidos en una instancia T-Pot expuesta públicamente a internet. Metodología: exportación de paneles agregados de Kibana (rango 19–25 julio 2026) más tagclouds de credenciales en CSV. Comparativa realizada frente a los informes de las semanas anteriores ([7–11 jul](/honeypot/informe-semanal-01/) y [12–18 jul](/honeypot/informe-semanal-02/)).*
