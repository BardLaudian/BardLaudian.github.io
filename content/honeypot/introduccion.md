---
title: "Monté un honeypot y voy a contar cada semana lo que veo"
date: 2026-07-08
draft: false
description: "Presentación del proyecto: un honeypot basado en T-Pot expuesto a internet real, con resúmenes semanales de actividad maliciosa y análisis en profundidad cuando algo lo merece."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "Mirai", "Botnet", "BlueTeam"]
---

{{< lead >}}
Voy a exponer un servidor a internet a propósito para que lo ataquen — y luego contarlo aquí, cada semana. Sin simulaciones ni datos de laboratorio: tráfico malicioso real, de internet real, contra un servidor que no hace nada más que esperar a que alguien intente entrar.
{{< /lead >}}

---

## Qué es esto

Este blog documenta lo que un **honeypot** — un sistema señuelo diseñado para parecer vulnerable y atraer ataques — detecta en tiempo real, semana a semana.

La mayoría de lo que se lee sobre ciberseguridad son informes trimestrales de grandes empresas o análisis retrospectivos de incidentes ya resueltos. Aquí va a ser lo contrario — un vistazo pequeño pero continuo y sin filtrar a lo que está pasando *ahora mismo* en el ruido de fondo de internet.

> Qué credenciales prueban los bots. Qué vulnerabilidades de hace años se siguen explotando. Qué botnets siguen activas reclutando dispositivos.

---

## La Infraestructura

El honeypot corre sobre **[T-Pot](https://github.com/telekom-security/tpotce)**, una plataforma que despliega más de 20 honeypots distintos en paralelo junto con Elasticsearch y Kibana para analizar y visualizar todo lo que entra.

| Honeypot | Qué simula |
|----------|------------|
| Cowrie | SSH/Telnet vulnerable |
| Dionaea | SMB, FTP, HTTP, bases de datos |
| ADBHoney | Dispositivos Android con ADB expuesto |
| Conpot | Sistemas de control industrial (ICS/SCADA) |
| Mailoney | Servidor SMTP trampa |
| +15 más | Servicios web, RDP, SIP, Redis… |

Está alojado en un VPS dedicado exclusivamente a esto, completamente aislado de cualquier otro sistema o dato personal.

---

## Qué vas a encontrar aquí

Dos tipos de contenido, con ritmos distintos:

**📅 Resúmenes semanales** — cada domingo. Cuántos ataques hubo, qué honeypot recibió más tráfico, de dónde vino, y el hallazgo más interesante de la semana: un patrón de credenciales, un comando ejecutado, o un CVE siendo explotado activamente.

**🔬 Análisis en profundidad** — sin calendario fijo. Cuando algo capturado merece más que un párrafo — una muestra de malware real, una técnica de evasión, una campaña identificable — le dedico un post propio. El primero ya está publicado: una muestra del botnet **Rebirth** (variante de Mirai/Gafgyt) capturada disfrazada como una app de Clash Royale.

---

## Por qué lo hago

Vengo de un perfil ofensivo — CJCA, máquinas de HackTheBox — y ahora mismo estoy preparando la Security+. Este proyecto es mi forma de meterle horas al otro lado del tablero: detección, análisis de amenazas, y la disciplina de convertir datos crudos en algo legible y útil — que es al fin y al cabo el trabajo de un analista SOC.

No pretendo que cada semana traiga un hallazgo espectacular. Muchas van a ser simplemente "más de lo mismo: fuerza bruta SSH, escaneo SMB, credenciales genéricas". Y está bien así. El valor no está en que cada entrada sea impactante, sino en la **constancia**: mirar la misma superficie de ataque semana tras semana hasta que los patrones — y las anomalías — se vuelven visibles.

---

## Una nota sobre honestidad técnica

Me marco un compromiso desde el primer post: no voy a inflar la gravedad de lo que encuentro. Si algo es simplemente ruido de escaneo automatizado, lo digo así. Si un hallazgo requiere matizar, lo matizo.

Prefiero que esto sea **útil y creíble** antes que vistoso.

---

*Nos vemos el domingo con el primer resumen semanal.*
