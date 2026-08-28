---
title: "Monté un honeypot y voy a contar cada semana lo que veo"
date: 2026-07-08
draft: false
description: "Presentación del proyecto: un honeypot basado en T-Pot expuesto a internet real, con resúmenes semanales de actividad maliciosa y análisis en profundidad cuando algo lo merece."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "Mirai", "Botnet", "BlueTeam"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Voy a exponer un servidor a internet a propósito para que lo ataquen — y luego contarlo aquí, cada semana. Sin simulaciones ni datos de laboratorio: tráfico malicioso real, de internet real, contra un servidor que no hace nada más que esperar a que alguien intente entrar.
{{< /lead >}}

---

## Qué es esto

Este blog documenta lo que un **honeypot** — un sistema señuelo diseñado para parecer vulnerable y atraer ataques — detecta en tiempo real, semana a semana.

La idea es sencilla: la mayoría de lo que se lee sobre ciberseguridad son informes trimestrales de grandes empresas o análisis retrospectivos de incidentes ya resueltos. Aquí va a ser lo contrario — un vistazo pequeño pero continuo y sin filtrar a lo que está pasando *ahora mismo* en el ruido de fondo de internet: qué credenciales prueban los bots, qué vulnerabilidades de hace años se siguen explotando, qué botnets siguen activas reclutando dispositivos.

---

## La Infraestructura

El honeypot corre sobre **T-Pot**, una plataforma que despliega más de 20 honeypots distintos en paralelo (SSH, ADB de Android, SMB, bases de datos expuestas, sistemas industriales, servidores web vulnerables, entre otros), junto con Elasticsearch y Kibana para poder analizar y visualizar todo lo que entra. Está alojado en un VPS dedicado exclusivamente a esto, aislado de cualquier otro sistema o dato personal.

---

## Qué vas a encontrar aquí

Dos tipos de contenido, con ritmos distintos:

**Resúmenes semanales**, cada domingo. Formato corto y consistente: cuántos ataques hubo, qué honeypot recibió más tráfico, de dónde vino, y el hallazgo más interesante de la semana — ya sea un patrón curioso de credenciales, un comando ejecutado, o una alerta de un CVE concreto siendo explotado activamente.

**Análisis en profundidad**, sin calendario fijo. Cuando algo capturado merece más que un párrafo — una muestra de malware real, una técnica de evasión, una campaña identificable — le dedico un post propio. El primero de estos ya está publicado: un análisis de una muestra del botnet **Rebirth** (variante de Mirai/Gafgyt) que capturé intentando infectar el honeypot disfrazada como una app de Clash Royale.

---

## Por qué lo hago

Vengo de un perfil más orientado a lo ofensivo — CJCA, un puñado de máquinas de HackTheBox resueltas y documentadas — y ahora mismo estoy preparando la Security+. Este proyecto es mi forma de meterle horas al otro lado del tablero: detección, análisis de amenazas, y la disciplina de convertir datos crudos en algo legible y útil, que es al fin y al cabo el trabajo diario de un analista SOC o de threat intelligence.

No pretendo que cada semana traiga un hallazgo espectacular — muchas van a ser simplemente "más de lo mismo: fuerza bruta SSH, escaneo SMB, credenciales genéricas". Y está bien así. El valor de esto no es que cada entrada sea impactante, sino la constancia: mirar la misma superficie de ataque semana tras semana hasta que los patrones — y las anomalías — se vuelven visibles.

---

## Una nota sobre honestidad técnica

Un compromiso que me marco desde el primer post: no voy a inflar la gravedad de lo que encuentro. Si algo es simplemente ruido de escaneo automatizado sin mayor interés, lo digo así. Si un hallazgo requiere matizar ("esto parece X, pero no lo he confirmado del todo"), lo matizo. Prefiero que este blog sea útil y creíble a que sea vistoso.

Nos vemos el domingo con el primer resumen semanal.
