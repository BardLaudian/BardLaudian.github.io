---
title: "Informe Semanal de Threat Intelligence — Honeypot T-Pot (2–9 agosto 2026)"
date: 2026-08-10
draft: false
description: "Quinto informe semanal del honeypot T-Pot: ~2.814.000 eventos. El botnet residencial de ConPot se confirma por tercera semana con alcance global (NTT DOCOMO, Wind Tre, Bouygues). RDPHoneypot regresa al máximo histórico impulsado por Datacamp Limited. Nueva oleada de credenciales cripto en Cowrie y familia de malware 'iran'. La campaña de Adbhoney seguida desde el primer informe se cierra definitivamente."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "SNMP", "Botnet", "Redtail", "IoT", "ICS", "SCADA", "IEC104", "IPMI", "VoIP", "Cripto", "Bitcoin", "Malware"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Quinto informe semanal del honeypot T-Pot, período **2–9 de agosto de 2026**. El volumen sube a **~2.814.000 eventos**. El botnet residencial de ConPot alcanza su **tercera semana consecutiva con alcance ya global** (NTT DOCOMO, Wind Tre, Bouygues Telecom suman a los ya conocidos Comcast, AT&T, Charter). RDPHoneypot casi iguala su máximo histórico impulsado por un nuevo actor: **Datacamp Limited**. En Cowrie aparece por primera vez una oleada de credenciales temáticas de criptomonedas y una nueva familia de malware nombrada `iran`. Y la campaña de Adbhoney que seguimos desde el primer informe —110→228→287→102 descargas— **se cierra definitivamente**.
{{< /lead >}}

---

**Período analizado:** 2 – 9 de agosto de 2026
**Fuente:** T-Pot (multi-honeypot + ELK Stack) — instancia expuesta públicamente a internet
**Clasificación:** Uso en portfolio / TLP:CLEAR
**Informes anteriores:** [7–11 jul](/honeypot/informe-semanal-01/) · [12–18 jul](/honeypot/informe-semanal-02/) · [19–25 jul](/honeypot/informe-semanal-03/) · [26 jul–2 ago](/honeypot/informe-semanal-04/)

---

## 1. Resumen Ejecutivo

El volumen total sube a **~2.814.000 eventos** (frente a ~2.023.000 la semana anterior). Con cinco semanas acumuladas, esta entrega confirma el hallazgo más sólido del proyecto y añade dos nuevos:

- **El botnet residencial/móvil de ConPot se confirma por tercera semana consecutiva, y ahora es global**: al bloque estadounidense (Comcast, AT&T, Charter, tercera semana) se suman **NTT DOCOMO (Japón), Wind Tre (Italia) y Bouygues Telecom (Francia)**. Botnet distribuido en al menos cuatro países, sostenido tres semanas, siempre en SNMP.
- **RDPHoneypot revierte su tendencia a la baja** (2,3M→843k→657k) y se dispara a **1.894.467 ataques (x2,9)**, casi igualando el pico histórico. El motor es un actor nuevo: **Datacamp Limited**, con 479.496 eventos sin presencia previa en ningún informe.
- **Giro temático en Cowrie**: primera vez en cinco semanas que los tagclouds de usuario incluyen credenciales de criptomonedas (`wallet`, `bitcoin`, `blockchain`, `chainlink`, `polkadot`, `solana`, `btcuser`, `exchange0`) — campaña de fuerza bruta dirigida a nodos/wallets/exchanges SSH expuestos.
- **Nueva familia de malware**: binarios `iran.x86_64`, `iran.aarch64`, `iran.m68k`, `iran.mips` desde `165.22.69.214`, en paralelo con Redtail que sigue presente.
- **La campaña de Adbhoney seguida desde el informe #1 se cierra**: el hash `849840d92c44ed...` (110→228→287→102→**0**) desaparece del top 10, sustituido por uno nuevo de menor escala.
- **Los actores persistentes más estables (`108.181.56.189`, `103.149.197.34`) prácticamente desaparecen del top 10 general** esta semana, mientras `45.153.34.x` en Cowrie cumple **cinco semanas consecutivas**.

---

## 2. Volumetría — Cinco Semanas de Contexto

| Honeypot | 7–11 jul | 12–18 jul | 19–25 jul | 26 jul–2 ago | 2–9 ago |
|---|---:|---:|---:|---:|---:|
| RDPHoneypot | 111.818 | 2.312.634 | 843.181 | 657.393 | **1.894.467** |
| Honeytrap | 678.792 | 218.202 | 372.001 | 545.549 | 321.830 |
| Cowrie | 116.390 | 229.182 | 249.057 | 318.800 | 251.659 |
| ConPot | 1.594 | 4.461 | 122.376 | 100.475 | **118.762** |
| Sentrypeer | 36.522 | 340.759 | 119.651 | 279.730 | 89.607 |
| Dionaea | 61.123 | 91.957 | 92.722 | 74.429 | 78.268 |
| Adbhoney | 2.618 | 2.012 | 1.737 | 1.292 | 652 |
| **Total aprox.** | **~1.011.000** | **~3.213.000** | **~1.820.000** | **~2.023.000** | **~2.814.000** |

**Patrones a cinco semanas:**

- **RDPHoneypot** es el sensor más volátil: depende casi enteramente de si hay una campaña activa esa semana. Esta semana hay.
- **ConPot** pasó de ser anecdótico (1.594 eventos, semana 1) a estabilizarse en 100.000-122.000 durante las últimas tres semanas — la evolución más significativa del proyecto.
- **Adbhoney** cae un 75% acumulado en cinco semanas (2.618→652), confirmando el fin de la campaña específica que veníamos siguiendo.
- **Cowrie es el único con crecimiento monótono** las primeras cuatro semanas; esta semana baja levemente, probablemente por rotación del pool de atacantes hacia otras infraestructuras.

---

## 3. ConPot — Botnet Residencial Confirmado: Tres Semanas, Cuatro Países

**118.762 ataques, 1.232 IPs únicas.** Tercera semana en el rango de 100.000-122.000, y la composición del origen **amplía el patrón a escala internacional**.

### Tercera semana: de EE. UU. al mundo

| ASN | Organización | Tipo | País | Semanas |
|---|---|---|---|---:|
| 4713 | NTT DOCOMO BUSINESS | Móvil | Japón | 1ª vez |
| 7922 | Comcast Cable Communications | Residencial | EE. UU. | 3ª |
| 7018 | AT&T Enterprises | Residencial | EE. UU. | 3ª |
| 33363 / 20115 | Charter Communications | Residencial | EE. UU. | 3ª |
| 1267 | Wind Tre S.p.A. | Móvil | Italia | 1ª vez |
| 15557 | SFR | Residencial | Francia | 2ª |
| 6327 | Shaw Communications | Residencial | Canadá | 1ª vez |
| 5410 | Bouygues Telecom | Móvil | Francia | 1ª vez |

**Este es el hallazgo más sólido del proyecto.** Cero proveedores de hosting/VPS en el top 10 durante tres semanas consecutivas, con presencia confirmada ahora en EE. UU., Canadá, Francia, Italia y Japón. La conclusión ya no admite duda razonable: **botnet de dispositivos domésticos y/o móviles comprometidos, distribuido internacionalmente, escaneando SNMP de forma sostenida**.

> ¿Por qué SNMP? Es el protocolo de gestión más extendido en routers domésticos y dispositivos IoT, habitualmente con credenciales por defecto (`public`/`private`) que nunca se cambian. Escanearlo masivamente sirve para identificar nuevos nodos comprometibles — el botnet se auto-replica.

### IEC-104: sexta semana consecutiva

El protocolo de telecontrol eléctrico (puerto 2404) continúa presente. Esta semana sin interacción capturada en los paneles de input/response — sondeo puro de puerto, sin intentos de hablar el protocolo.

---

## 4. RDPHoneypot — Casi Máximo Histórico, Nuevo Actor

**1.894.467 ataques, 828 IPs únicas** (x2,9 respecto a la semana anterior).

### Datacamp Limited: de cero a protagonista

| ASN | Organización | Eventos |
|---|---|---:|
| — | Datacamp Limited | 479.496 |
| 47447 | IONOS SE | 351.489 |
| 201814 | MEVSPACE sp. z o.o. | 200.267 |
| 205997 | Vlad Cojuhari | 186.326 |

**Datacamp Limited** pasa de no aparecer en ningún informe anterior a liderar el origen con casi la cuarta parte de todo el tráfico del sensor. Coincide con la entrada de **España como segundo país de origen** (nuevo esta semana), sugiriendo que la infraestructura de este actor está ubicada o enrutada a través de España. **MEVSPACE** sigue siendo el actor más constante de las últimas semanas — ya lleva cuatro apariciones en el top.

Por primera vez, la proporción de tráfico catalogado como **"bot/crawler"** se acerca al 45%, casi igualando a "known attacker" — un cambio de perfil respecto a semanas anteriores donde "known attacker" dominaba por encima del 90%.

---

## 5. Cowrie — Credenciales Cripto y Nueva Familia de Malware

**251.659 ataques, 2.868 IPs únicas** (salto notable en IPs únicas), **60 HASSH únicos**.

### Oleada de credenciales cripto

El tagcloud de usuarios rompe por primera vez con el patrón de las cuatro semanas anteriores. Junto a los habituales `Administrator`/`root`, aparece un diccionario completo de criptomonedas:

`wallet` · `bitcoin` · `blockchain` · `chainlink` · `polkadot` · `solana` · `cardano` · `metaverse` · `binance` · `ethuser` · `btcuser` · `cryptoadmin` · `exchange0` · `xrp`

Ninguno de estos términos había aparecido en los cuatro informes anteriores. Es un diccionario construido específicamente para probar cuentas de administración de **nodos de blockchain, wallets autoalojadas o paneles de exchanges** expuestos por SSH — vector de ataque completamente distinto al de fuerza bruta genérica de servidores.

### Nueva familia: "iran"

Descargas capturadas desde `165.22.69.214` con binarios nombrados:

- `iran.x86_64`
- `iran.aarch64`
- `iran.m68k`
- `iran.mips`

Cuatro arquitecturas bajo un mismo nombre de campaña, en paralelo con Redtail (que sigue apareciendo). El uso de un nombre de país como identificador no permite concluir nada sobre origen real sin análisis del binario — podría ser una elección arbitraria del operador — pero es un dato distintivo que merece registro y seguimiento si reaparece.

### Persistencia a cinco semanas

La subred `45.153.34.x` (esta vez la IP `.167`) vuelve a aparecer — **quinta semana consecutiva**, la racha de persistencia más larga confirmada de todo el proyecto.

### Cambio de cliente SSH dominante

Por primera vez, `SSH-2.0-Go` (dominante las cuatro semanas anteriores) **pierde el primer puesto** frente a una variante `libssh`, que pasa a representar más del 80% del tráfico — coherente con el cambio de herramienta que típicamente acompaña a una nueva campaña entrando con su propio tooling.

---

## 6. Honeytrap — Nuevo Actor Dominante de Ciclo Corto

**321.830 ataques, 9.280 IPs únicas.**

La IP `193.46.255.112` (ASN **Unmanaged Ltd**) lidera con **118.453 eventos** en Honeytrap, y aparece también en el top general (122.767) y en Adbhoney (38). Mientras tanto, `45.95.147.229` —dominante la semana pasada con 188.529 eventos— **cae a solo 15.455 esta semana**. Este patrón (actor nuevo aparece con fuerza, domina una semana, cae drásticamente la siguiente) es ya recurrente: Flyservers S.A., `45.95.147.229`, ahora `193.46.255.112`. **Los actores dominantes de Honeytrap tienen ciclos de vida de aproximadamente una semana.**

Aparece el puerto **5901 (VNC)** en el top de destinos por primera vez, junto a los ya habituales 5038/AMI, 7070, 8728/MikroTik y 2222.

---

## 7. Sentrypeer — Nuevo Bloque, Nuevo País

**89.607 ataques, 188 IPs únicas** — otra caída (de 279.730), confirmando el patrón errático del sensor a lo largo de las cinco semanas (36k→340k→119k→280k→90k).

**Polonia** pasa a ser el primer país de origen, con **MEVSPACE sp. z o.o.** concentrando 68.436 eventos en un bloque de cinco IPs consecutivas (`149.50.107.43`, `.47`, `.48`, `.49`, `.53`) — el mismo patrón de rotación dentro de subred ya visto repetidamente en otros sensores.

`108.181.56.189` y `108.181.64.154` —presentes las últimas semanas— no aparecen en el top 10 esta semana. Su racha de presencia continuada parece haberse cortado.

---

## 8. Dionaea — El Objetivo Turco se Diluye

**78.268 ataques, 1.348 IPs únicas.**

Los términos de ERP turco (`KASA`, `LOGO`, `MIKRO`, `MUHASEBE`) que dominaron los tagclouds las dos semanas anteriores **desaparecen esta semana**. Sin embargo, dos ISPs turcos (`Superonline İletişim Hizmetleri A.Ş.` y `Netonline Bilişim`) siguen en el top de ASN con volúmenes moderados — el tráfico de fondo con origen turco continúa, aunque la campaña dirigida específica parece haber pausado o concluido.

Aparecen nuevos países de origen: **Georgia, Nepal y Albania** — mayor dispersión geográfica que en semanas anteriores.

---

## 9. Adbhoney — Cierre Confirmado de la Campaña Original

**652 ataques, 99 IPs únicas** — mínimo histórico del sensor.

| Semana | Descargas del hash `849840...` |
|---|---:|
| 7–11 jul | 110 |
| 12–18 jul | 228 |
| 19–25 jul | 287 |
| 26 jul–2 ago | 102 |
| **2–9 ago** | **0** |

El hash desaparece completamente del top 10. En su lugar aparece `f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679be3f46d.raw` con solo 16 descargas — campaña distinta, de mucho menor escala. La campaña original de minería (`com.ufo.miner` vía `rebirth.arm7`) ha terminado o su infraestructura fue neutralizada. Cinco semanas de seguimiento de un único hash, desde su aparición hasta su cierre, es exactamente el tipo de inteligencia longitudinal que distingue un informe de threat intel con perspectiva temporal real.

---

## 10. Actores Persistentes — Semana 5

| Indicador | S1 | S2 | S3 | S4 | S5 |
|---|:---:|:---:|:---:|:---:|:---:|
| `45.153.34.x` (Cowrie) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Redtail (Cowrie) | ✅ | ✅ | ✅ | ✅ (+RISC-V) | ✅ (+iran paralelo) |
| IEC-104 en ConPot | ✅ | ✅ | ✅ | ✅ | ✅ |
| Botnet SNMP residencial (ConPot) | ❌ | ❌ | ✅ | ✅ | ✅ |
| `108.181.56.189` (Sentrypeer) | ❌ | ✅ | ✅ | ✅ | ⚠️ ausente |
| `103.149.197.34` (Cowrie) | ✅ | ✅ | ✅ | ✅ | ⚠️ menor rol |
| Hash Adbhoney `849840...` | ✅ 110 | ✅ 228 | ✅ 287 | ⚠️ 102 | ❌ fin |
| Objetivo ERP turco (Dionaea) | ❌ | ❌ | ✅ | ✅ | ⚠️ diluido |

---

## 11. Conclusiones

1. **El botnet residencial/móvil de ConPot es el hallazgo más sólido de las cinco semanas**: tres semanas consecutivas con el mismo perfil de origen (ISPs domésticos/móviles, sin un solo VPS) y ahora con alcance en cuatro países. Es el mejor candidato para un artículo técnico independiente centrado en la dinámica "el atacante no tiene su propia infraestructura, son los dispositivos de tus vecinos".

2. **Los actores dominantes en Honeytrap y RDPHoneypot tienen ciclos de vida de aproximadamente una semana**: Flyservers S.A., `45.95.147.229`, Datacamp Limited, `193.46.255.112` — todos dominan una semana y se desinflán drásticamente la siguiente. Tratarlos como actores distintos semana a semana es más correcto que intentar construir un perfil de actor persistente para estos sensores.

3. **La oleada de credenciales cripto en Cowrie merece seguimiento específico**: si se repite la semana que viene, es una campaña dirigida real y un hallazgo de nivel de post independiente; si no reaparece, fue un evento puntual como el malware `iran` o las arquitecturas raras de semanas anteriores.

4. **El ciclo completo del hash de Adbhoney** (aparición → crecimiento → caída → desaparición en cinco semanas) es el mejor ejemplo del valor del seguimiento longitudinal de IOCs. Sin el contexto acumulado, la caída de la semana 4 no habría tenido interpretación clara.

5. **`45.153.34.x` en Cowrie es el actor más persistente del proyecto** (cinco semanas) y el candidato más sólido a regla de bloqueo permanente a nivel de subred en un entorno de producción real.

---

*Informe elaborado a partir de datos propios recogidos en una instancia T-Pot expuesta públicamente a internet. Metodología: exportación de paneles agregados de Kibana (rango 2–9 agosto 2026) más tagclouds de credenciales en CSV. Comparativa frente a los cuatro informes anteriores ([7–11 jul](/honeypot/informe-semanal-01/), [12–18 jul](/honeypot/informe-semanal-02/), [19–25 jul](/honeypot/informe-semanal-03/), [26 jul–2 ago](/honeypot/informe-semanal-04/)).*
