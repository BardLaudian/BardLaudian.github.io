---
title: "Informe Semanal de Threat Intelligence — Honeypot T-Pot (26 jul – 2 ago 2026)"
date: 2026-08-03
draft: false
description: "Cuarto informe semanal del honeypot T-Pot: ~2.023.000 eventos. El botnet SNMP residencial de ConPot se confirma por segunda semana consecutiva (Comcast, AT&T, Verizon, Charter). La IP 91.199.133.133 —catalogada en ThreatFox como C2 de Mirai Katana— reaparece sirviendo payloads en Cowrie. Redtail añade soporte RISC-V y el objetivo ERP turco en Dionaea se confirma como campaña activa."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "SNMP", "Botnet", "Redtail", "Mirai", "Katana", "IoT", "ICS", "SCADA", "IEC104", "IPMI", "MSSQL", "ERP", "RISCV", "VoIP"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Cuarto informe semanal del honeypot T-Pot, período **26 de julio – 2 de agosto de 2026**. Con cuatro semanas de datos acumuladas, los patrones dejan de ser anecdóticos y se convierten en tendencias: el **botnet SNMP residencial de ConPot se confirma por segunda semana consecutiva** (Comcast, AT&T, Verizon, Charter sin un solo VPS en el top 10), la IP **`91.199.133.133` catalogada en ThreatFox como C2 de Mirai Katana reaparece** sirviendo payloads en Cowrie, **Redtail añade arquitectura RISC-V**, y la campaña de fuerza bruta contra software ERP turco en Dionaea se confirma con una segunda semana de datos consistentes.
{{< /lead >}}

---

**Período analizado:** 26 de julio – 2 de agosto de 2026
**Fuente:** T-Pot (multi-honeypot + ELK Stack) — instancia expuesta públicamente en internet
**Clasificación:** Uso en portfolio / TLP:CLEAR
**Informes anteriores:** [7–11 jul](/honeypot/informe-semanal-01/) · [12–18 jul](/honeypot/informe-semanal-02/) · [19–25 jul](/honeypot/informe-semanal-03/)

---

## 1. Resumen Ejecutivo

El volumen total sube a **~2.023.000 eventos** (frente a ~1.820.000 la semana anterior). Con cuatro semanas de datos, los patrones dejan de ser anecdóticos:

- **El botnet residencial de ConPot no fue un evento puntual**: top 10 de ASN copado de nuevo por ISPs domésticos (Comcast, AT&T, Verizon, Charter ×3, Cox, CenturyLink, Videotron, SFR), sin un solo proveedor de hosting/VPS. Segunda semana idéntica en composición.
- **Cierre de círculo con la primera investigación del proyecto**: la IP `91.199.133.133` —catalogada en ThreatFox como C2 activo de la variante Mirai "Katana"— **reaparece sirviendo `deploy.sh` a Cowrie**, semanas después de su primera detección. Sigue operativa.
- **Nuevo actor dominante**: `45.95.147.229` (Alsycon B.V.) se convierte en la **IP más activa de todo el dashboard** (194.606 eventos), concentrada en Honeytrap. Sin presencia relevante en semanas anteriores.
- **Persistencia a cuatro semanas**: `108.181.56.189` (Sentrypeer) y `103.149.197.34` (Cowrie) llevan cuatro semanas consecutivas en el top 10 de sus respectivos sensores.
- **Primera caída del hash de Adbhoney tras tres semanas de crecimiento**: 110→228→287→**102 descargas**. ¿Pausa o takedown del servidor origen? El dato clave será la semana que viene.
- **Redtail amplía arquitecturas**: primera aparición de `redtail.riscv`, sumando RISC-V a ARM7/ARM8/i686/x86_64.
- **El objetivo turco en Dionaea se confirma**: segunda semana con terminología ERP turca en el tagcloud (`POS`, `ERCYONETICI` como términos nuevos) y Turk Telekom repitiendo en el top de ASN.

---

## 2. Volumetría — Cuatro Semanas de Contexto

| Honeypot | 7–11 jul | 12–18 jul | 19–25 jul | 26 jul–2 ago |
|---|---:|---:|---:|---:|
| RDPHoneypot | 111.818 | 2.312.634 | 843.181 | 657.393 |
| Honeytrap | 678.792 | 218.202 | 372.001 | 545.549 |
| Cowrie | 116.390 | 229.182 | 249.057 | 318.800 |
| Sentrypeer | 36.522 | 340.759 | 119.651 | 279.730 |
| ConPot | 1.594 | 4.461 | 122.376 | 100.475 |
| Dionaea | 61.123 | 91.957 | 92.722 | 74.429 |
| Adbhoney | 2.618 | 2.012 | 1.737 | 1.292 |
| **Total aprox.** | **~1.011.000** | **~3.213.000** | **~1.820.000** | **~2.023.000** |

**Patrones que emergen a cuatro semanas:**

- **Cowrie es el único sensor con crecimiento monótono** las cuatro semanas (116k→229k→249k→319k) — actividad orgánica, sin picos artificiales.
- **RDPHoneypot lleva tres semanas de caída consecutiva** tras el pico de la semana 2 (2,3M→843k→657k) — la campaña se está desinflando gradualmente.
- **Sentrypeer es el más errático** (36k→340k→119k→280k) — sugiere varios actores independientes entrando y saliendo, no una única campaña predecible.
- **Adbhoney es el único con declive sostenido** en volumen de sensor las cuatro semanas, aunque el hash específico creció tres semanas antes de caer esta semana — son señales distintas.

---

## 3. ConPot — Segunda Semana del Botnet Residencial: ya es Patrón

**100.475 ataques, 1.077 IPs únicas.** Volumen algo menor que la semana pasada (122.376) pero **el hallazgo importante es que se repite exactamente la composición del origen**.

### Top ASN: segunda semana sin un solo proveedor de hosting

| ASN | Organización | País | Eventos |
|---|---|---|---:|
| 7922 | Comcast Cable Communications | EE. UU. | 29.940 |
| 7018 | AT&T Enterprises | EE. UU. | 8.303 |
| 701 | Verizon Business | EE. UU. | 7.434 |
| 20001 / 11426 / 10796 | Charter Communications | EE. UU. | 3.799 / 2.339 / 2.155 |
| 22773 | Cox Communications | EE. UU. | 2.809 |
| 15557 | SFR | Francia | 2.547 |
| 209 | CenturyLink | EE. UU. | 2.271 |
| 5769 | Videotron Ltée | Canadá | 2.188 |

Con dos semanas idénticas en composición (ISPs residenciales puros, sin VPS/hosting), la hipótesis del **botnet de routers domésticos/IoT comprometidos escaneando SNMP** pasa de ser una hipótesis razonable a ser la explicación más probable respaldada por datos repetidos. El perfil es clásico: Comcast, AT&T, Charter y Verizon son los cuatro mayores operadores de banda ancha de EE. UU., con decenas de millones de routers domésticos — exactamente el tipo de infraestructura que un botnet IoT comprometería de forma masiva.

### IPMI sube posiciones

El puerto **623 (IPMI)** pasa a ser el segundo más atacado del sensor, solo por detrás del 161 (SNMP). IPMI mal asegurado es una vía de compromiso real de servidores en datacenters — su crecimiento sostenido merece seguimiento si continúa.

### IEC-104: quinta semana consecutiva

El protocolo de telecontrol de subestaciones eléctricas sigue presente. El "Conpot Response - Top 10" muestra la respuesta *"? Command not found. Send 'H' for help."* repetida **53 veces** esta semana, frente a 2-3 veces en semanas anteriores — más intentos de interacción exploratoria con el servicio simulado, no solo escaneo automático de puertos.

---

## 4. El Nuevo Actor Dominante: `45.95.147.229` (Alsycon B.V.)

La **IP individual más activa de todo el dashboard esta semana: 194.606 eventos**. Sin presencia destacable en ninguna semana anterior.

| Sensor | Eventos |
|---|---:|
| Honeytrap | 188.529 |
| Adbhoney | 266 |

El ASN Alsycon B.V. había aparecido en semanas anteriores con volúmenes menores repartidos entre varios sensores, pero nunca con una sola IP concentrando casi 200.000 eventos en una semana. Perfil típico de una IP recién puesta en producción para una campaña de escaneo agresiva. El dato clave será la semana que viene: ¿se consolida como actor recurrente o sigue el camino de Flyservers S.A. y desaparece casi por completo?

---

## 5. Cowrie — Cierre de Círculo con ThreatFox y RISC-V en Redtail

**318.800 ataques, 1.821 IPs únicas, 63 HASSH.** Cuarto incremento semanal consecutivo.

### La IP de ThreatFox reaparece

En el panel de descargas aparece la URL **`http://91.199.133.133:8080/deploy.sh`** con 10 descargas. **`91.199.133.133` es la misma IP que identificamos en ThreatFox al inicio de este proyecto**, catalogada como C2 activo de la variante Mirai **"Katana"** con confianza del 100%. Ahora sirve un script de despliegue por HTTP en el puerto 8080, confirmando que la infraestructura **sigue operativa semanas después** de su primera detección. Sin el registro de IOCs de semanas anteriores, esta reaparición habría pasado desapercibida como "una URL más" en el top de descargas.

### Redtail añade RISC-V

Primera aparición de `redtail.riscv` junto a los ya habituales `.arm7`, `.arm8`, `.i686`. RISC-V es una arquitectura de conjunto de instrucciones abierta con presencia creciente en microcontroladores y hardware IoT de bajo coste. Su inclusión confirma que el operador de Redtail sigue ampliando activamente su cobertura de dispositivos objetivo.

### Actores persistentes

| Indicador | Sem 1 | Sem 2 | Sem 3 | Sem 4 |
|---|:---:|:---:|:---:|:---:|
| Subred `45.153.34.x` | ✅ | ✅ | ✅ | ✅ |
| Malware Redtail | ✅ | ✅ | ✅ | ✅ |
| Script `chattr -ia .ssh` | ✅ | ✅ | ✅ | ✅ |
| `103.149.197.34` en top 10 | ✅ | ✅ | ✅ | ✅ |

### Curiosidad técnica: cabeceras HTTP como "credenciales"

En los tagclouds de usuario y contraseña aparecen literalmente fragmentos de peticiones HTTP: `User-Agent: python-requests/2.27.1`, `Accept: */*`, `Host: 62.84.184.111:23`. Esto ocurre cuando un cliente HTTP automatizado (escáner mal configurado, dado el user-agent `python-requests`) envía una petición HTTP completa contra el puerto SSH de Cowrie — el honeypot intenta interpretar las primeras líneas como intento de login y las registra tal cual. No es un ataque en sí, pero es un buen ejemplo de ruido de escáneres mal construidos que puede distorsionar las estadísticas de credenciales si no se filtra con criterio.

---

## 6. Sentrypeer — Repunte con Nuevos Protagonistas del Mismo Bloque

**279.730 ataques, 178 IPs únicas** (x2,3 respecto a la semana anterior). Dos fases: meseta alta el 26-27 de julio, pico aún mayor el 30-31.

### Persistencia a cuatro semanas

`108.181.56.189` vuelve con **96.541 eventos** — cuarta semana consecutiva con presencia relevante en este sensor y en el dashboard general.

### Nuevo protagonista del mismo bloque

`108.181.64.154` —del mismo rango `108.181.6x.x`— se convierte en la IP más activa del sensor con **103.695 eventos**. Dos IPs del mismo bloque /16 siendo las más activas en semanas consecutivas apunta a que no opera una única IP, sino **un bloque de direcciones bajo el mismo control**, rotando de forma similar a lo ya visto con la subred `45.153.34.x` en Cowrie.

Los user-agents SIP más frecuentes cambian a `Cisco-SIPGateway/IOS` y `FreeSWITCH-mod_sofia` — variación en las herramientas, mismo objetivo de fraude/enumeración VoIP.

---

## 7. RDPHoneypot — Tercera Semana de Declive Sostenido

**657.393 ataques, 551 IPs únicas.** Tendencia confirmada: 2.312.634 → 843.181 → 657.393.

MEVSPACE sp. z o.o. se mantiene como el ASN más constante de las últimas semanas (190.392 esta semana). **Flyservers S.A.**, que casi desapareció en la semana 3, reaparece con un volumen modesto (22.783) — ni vuelve a dominar ni desaparece del todo. Se consolida como actor secundario recurrente.

---

## 8. Dionaea — Segunda Semana del Objetivo ERP Turco: ya es Campaña

**74.429 ataques, 1.660 IPs únicas** — a la baja en volumen, pero con el hallazgo cualitativo más importante del sensor.

### El tagcloud se amplía

| Término | Significado / Contexto |
|---|---|
| `KASA` | Caja/efectivo |
| `MIKRO`, `LOGO` | Marcas reales de ERP turco |
| `MUHASEBE` | Contabilidad |
| `BARKOD` | Código de barras |
| `ENTEGRA` | Integración (módulo ERP) |
| `POS` *(nuevo)* | Punto de venta |
| `ERCYONETICI` *(nuevo)* | Probable "ERP yöneticisi" — administrador de ERP en turco |

**Turk Telekom repite en el top de ASN** (3.670 eventos, frente a 3.410 la semana pasada). Con dos semanas de datos consistentes en terminología, protocolo (MSSQL) y origen geográfico, la clasificación de campaña dirigida es ya sólida, no una hipótesis.

**India** se convierte en el primer país de origen (nuevo en Dionaea), con Alliance Broadband Services Pvt. Ltd. (11.070 eventos) y la IP `144.48.227.75` como principal origen.

---

## 9. Adbhoney — Primera Caída: ¿Pausa o Takedown?

**1.292 ataques, 108 IPs únicas.** El dato que rompe la racha:

| Semana | Descargas del hash |
|---|---:|
| 7–11 jul | 110 |
| 12–18 jul | 228 |
| 19–25 jul | 287 |
| 26 jul–2 ago | **102** |

El hash `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d53839b5` cae de 287 a 102 descargas. El comando `busybox wget` contra `94.154.43.48` también cae de forma proporcional (218 → 80 ejecuciones). Las causas posibles son la baja de la infraestructura de origen, una pausa deliberada de la campaña, o variabilidad puntual. **El dato decisivo será la semana que viene**: si se recupera, fue una pausa; si sigue cayendo o desaparece, es indicio de takedown o abandono de la campaña.

---

## 10. Actores Persistentes — Primera Tabla Consolidada

Con cuatro semanas de datos ya disponibles, se inaugura esta sección de seguimiento longitudinal:

| Indicador | S1 (7-11 jul) | S2 (12-18 jul) | S3 (19-25 jul) | S4 (26 jul-2 ago) |
|---|:---:|:---:|:---:|:---:|
| `45.153.34.x` (Cowrie) | ✅ | ✅ | ✅ | ✅ |
| Redtail (Cowrie) | ✅ | ✅ | ✅ | ✅ (+RISC-V) |
| `103.149.197.34` (Cowrie) | ✅ | ✅ | ✅ | ✅ |
| `108.181.56.189` (Sentrypeer) | ❌ | ✅ | ✅ | ✅ |
| Hash Adbhoney `849840...` | ✅ 110 | ✅ 228 | ✅ 287 | ⚠️ 102 |
| IEC-104 en ConPot | ✅ | ✅ | ✅ | ✅ |
| Botnet SNMP residencial (ConPot) | ❌ | ❌ | ✅ | ✅ |
| Objetivo ERP turco (Dionaea) | ❌ | ❌ | ✅ | ✅ |
| `91.199.133.133` (C2 Katana) | 🔍 IOC | ❌ | ❌ | ✅ reaparece |

---

## 11. Conclusiones

1. **El botnet SNMP residencial es ya el hallazgo más sólido del proyecto**: dos semanas con composición de origen idéntica (ISPs domésticos puros) eliminan la posibilidad de anomalía puntual. Es el mejor candidato para un post técnico independiente.

2. **La reaparición de `91.199.133.133` demuestra el valor del registro longitudinal de IOCs**: sin el contexto de semanas anteriores, habría sido "una URL más". Con el contexto, es la confirmación de que una infraestructura C2 investigada explícitamente sigue operativa semanas después.

3. **Vigilar `45.95.147.229` la semana que viene**: ¿actor recurrente o flash-in-the-pan como Flyservers S.A.? Una sola semana no permite clasificarlo.

4. **El objetivo ERP turco en Dionaea es ya campaña confirmada**: dos semanas con el mismo perfil (terminología, protocolo, ASN de origen) justifican tratarlo como ataque dirigido, no ruido genérico.

5. **La caída del hash de Adbhoney es la señal más incierta de la semana**: el seguimiento de la semana que viene resolverá si fue pausa o fin de campaña.

6. **La tabla de actores persistentes está ya en condiciones de ser una sección fija** del informe — con cuatro semanas de histórico, tiene valor real para distinguir comportamiento orgánico de campañas estructuradas.

---

*Informe elaborado a partir de datos propios recogidos en una instancia T-Pot expuesta públicamente a internet. Metodología: exportación de paneles agregados de Kibana (rango 26 julio – 2 agosto 2026) más tagclouds de credenciales en CSV. Comparativa realizada frente a los tres informes anteriores ([7–11 jul](/honeypot/informe-semanal-01/), [12–18 jul](/honeypot/informe-semanal-02/), [19–25 jul](/honeypot/informe-semanal-03/)).*
