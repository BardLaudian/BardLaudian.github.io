---
title: "Weekly Threat Intelligence Report — T-Pot Honeypot (Jul 12–18, 2026)"
date: 2026-07-19
draft: false
description: "Second weekly report from the T-Pot honeypot: volume x3.2 compared to the previous week (~3,213,000 events). RDPHoneypot spikes x20.7 with Flyservers S.A. as the dominant source, Sentrypeer x9.3 with a target shift to UK numbering, new loongarch64 and m68k loader in Cowrie, and confirmation of recurring actors across multiple sensors."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "VoIP", "TollFraud", "Malware", "IoT", "Botnet", "Redtail", "ICS", "SCADA", "IEC104", "IPMI"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Second weekly report from the T-Pot honeypot, period **July 12–18, 2026**. Total volume spikes to **~3,213,000 events** (x3.2 compared to the previous week), but growth is not uniform: it's almost entirely explained by two sensors — **RDPHoneypot x20.7** with Flyservers S.A. as the dominant source, and **Sentrypeer x9.3** with a target shift toward UK numbering. Recurring actors are confirmed across multiple sensors, and a new loader compiled for unusual architectures (`loongarch64`, `m68k`) is identified.
{{< /lead >}}

---

**Period analyzed:** July 12–18, 2026
**Source:** T-Pot (multi-honeypot + ELK Stack) — publicly internet-exposed instance
**Classification:** Portfolio use / TLP:CLEAR
**Previous report:** [week of July 7–11, 2026](/honeypot/informe-semanal-01/)

---

## 1. Executive Summary

This week total volume **spikes to ~3,213,000 events**, compared to ~1,011,000 the previous week (x3.2). The jump is not uniform: it's almost entirely concentrated in two very specific sensors, while others actually decrease.

Most significant changes from the previous week:

- **RDPHoneypot goes from 111,818 to 2,312,634 attacks (x20.7)**, with geographic focus shifted to Monaco, Germany, Panama, and Bulgaria. The source is concentrated in two ASNs sharing the same commercial name (**Flyservers S.A.**) that together account for over a million events.
- **Sentrypeer goes from 36,522 to 340,759 attacks (x9.3)**, with a target change: last week it was French/North American numbering, **this week it's a UK block** tested systematically and sequentially.
- **Honeytrap drops from 678,792 to 218,202 attacks**, but unique IPs **increase from 6,119 to 10,015** — traffic shifted from few origins generating high volume to a more distributed pattern.
- **Recurring actor confirmed:** subnets `62.84.80.240-243` (Dionaea) and `217.154.196-197.x` / `31.70.86.6x` (Sentrypeer) reappear with the exact same IPs. No longer a one-off coincidence — it's sustained presence.
- **New multi-architecture loader in Cowrie:** binaries for `aarch64`, `i386`, `loongarch64`, and `m68k`. The inclusion of `loongarch64` (a niche Chinese architecture) and `m68k` (1980s hardware, today only in embedded systems/very old routers) is unusual.
- **The same Adbhoney payload from last week reappears with 228 downloads** (compared to 110), confirming the Android mining campaign (`UFO Miner`) is still active.
- **IEC-104** (electrical substation protocol) remains present in ConPot for a second consecutive week.

---

## 2. Comparative Volume

| Honeypot | Week Jul 7–11 | Week Jul 12–18 | Change |
|---|---:|---:|---:|
| RDPHoneypot | 111,818 | 2,312,634 | **x20.7** ⬆️⬆️ |
| Sentrypeer | 36,522 | 340,759 | **x9.3** ⬆️⬆️ |
| Cowrie | 116,390 | 229,182 | x1.97 ⬆️ |
| Honeytrap | 678,792 | 218,202 | x0.32 ⬇️⬇️ |
| Dionaea | 61,123 | 91,957 | x1.50 ⬆️ |
| ConPot | 1,594 | 4,461 | x2.80 ⬆️ |
| Adbhoney | 2,618 | 2,012 | x0.77 ≈ |
| Tanner | ~2,000 | ~6,000 | ⬆️ |
| Mailoney | 906 | ~6,000 | ⬆️ strong |
| **Approx. total** | **~1,011,000** | **~3,213,000** | **x3.18** |

Total growth is almost entirely explained by RDPHoneypot and Sentrypeer — between them they contribute **over 2.6 million** of the ~3.2 million events. Honeytrap, dominant last week, drops to a secondary role in volume, though its unique IP base nearly doubles (6,119 → 10,015): more dispersed traffic, not less interest in the service.

---

## 3. RDPHoneypot — The Week's Dominant Sensor

**2,312,634 attacks, 470 unique IPs.** The average events per IP goes from ~447 last week to **~4,920** — not only are more IPs attacking, each one is far more aggressive.

### Temporal distribution

Sustained and growing activity throughout the week, with a documented peak on **July 18 (56,293 attacks in a single interval)**. Unlike the isolated spike of July 9–10, here the pattern is **sustained growth**, not a spike and drop.

### Geographic origin and infrastructure

Dominant countries are **Monaco, Germany, Bulgaria, and Panama** — a notable shift from Bulgaria/Azerbaijan/Ukraine the previous week.

| ASN | Organization | Events |
|---|---|---:|
| 48721 | Flyservers S.A. | 736,290 |
| 201814 | MEVSPACE sp. z o.o. | 424,077 |
| 35042 | Layer7 Networks GmbH | 343,918 |
| 267784 | Flyservers S.A. (2nd AS) | 320,582 |
| 211736 | FOP Dmytro Nedilskyi | 149,293 |
| 49434 | Fbw Networks SAS | 109,146 |

**Flyservers S.A.** appears with **two different ASN numbers** (48721 and 267784) totaling **over 1,056,000 events** — nearly half of all RDP traffic this week. Same hosting provider with presence in Panama, possibly the same actor operating IP blocks in two different ASN ranges of the same provider.

---

## 4. Sentrypeer — VoIP Fraud Escalation and Target Shift

**340,759 attacks, 198 unique IPs** (x9.3). The histogram shows **two distinct waves**: high activity July 12–13, sharp drop July 13–16, and another strong peak July 17–18.

### Fraud target change

Last week: French and North American numbering. **This week: UK block** (prefix `+44 1292 379...`), tested with consecutive prefix variations (`0014`, `0021`, `0024`, `0031`, `0041`...) — methodical sweep of a specific range, consistent with reconnaissance prior to targeted toll fraud, not generic scanning.

### Infrastructure

IP `108.181.56.189` accumulates **200,379 events** — the most active individual IP in the entire dataset this week. Dominant ASNs are **Psychz Networks (202,591)** and **IONOS SE (122,465)**.

**Recurring actor confirmed:** `217.154.196.179`, `217.154.197.64`, `217.154.196.247`, and `31.70.86.62` / `31.70.86.68` — flagged last week — **reappear this week in the top 10**, some with the exact same IPs. This is an operator with sustained, repeated presence against this specific service.

---

## 5. Honeytrap — Less Volume, More Dispersion and Focus Shift

**218,202 attacks, 10,015 unique IPs.** Strong initial peak on day 12 (~57,000 events) then low, stable activity for the rest of the week.

### Target port change

| Previous week | This week |
|---|---|
| 11434 — Ollama | 2763 |
| 7860 — Gradio | **5038 — Asterisk Manager Interface** |
| 8501 — Streamlit | **8728 — MikroTik API** |

AI infrastructure scanning disappears from the top 5. The shift to **port 5038 (AMI, Asterisk Manager Interface)** is relevant: it's the management port for Asterisk PBX systems, which thematically connects to the VoIP fraud surge in Sentrypeer this same week — possibly coordination or a reflection of a broader IP telephony infrastructure reconnaissance campaign.

**LANTEC COMUNICACAO MULTIMIDIA LTDA (Brazil)** dominates with 71,274 events. Modat B.V. (the research scanner identified last week) reappears with 11,086 events — present but in a much smaller proportion.

---

## 6. Cowrie — Sustained Growth and New Multi-Architecture Loader

**229,182 attacks, 1,798 unique IPs, 65 unique HASSH** (x1.97). Marked uptick July 17–18.

### Credentials (exact data via CSV)

| Username | Attempts | | Password | Attempts |
|---|---:|---|---|---:|
| Administrator | 273,098 | | 123456 | 1,629 |
| Administrador | 52,633 | | 123 | 788 |
| root | 14,292 | | 1234 | 732 |
| admin | 2,500 | | password | 630 |
| sa | 679 | | admin | 614 |

**Notable data:** `Administrador` (in Spanish, 52,633 attempts) appears as the second most tested username — localized dictionaries for Spanish speakers, absent last week.

### Post-exploitation

The command pattern repeats almost identically: `uname -a`, `chattr -ia .ssh; lockr -ia .ssh`, `cat /proc/cpuinfo`, `whoami` — same fingerprinting/`.ssh` blocking script from the previous week. Same loader type, same operation.

### New loader: unusual architectures

Downloads captured from `41.216.189.157` with obfuscated name pattern `xnxnxnxnxnxn[architecture]xnxn`:

| Architecture | Context |
|---|---|
| `aarch64` | ARM 64-bit — modern servers and mobile devices |
| `i386` | x86 32-bit |
| `loongarch64` | Chinese general-purpose architecture, very unusual in malware |
| `m68k` | 1980s architecture, today only in embedded systems/legacy routers |

Compiling for `loongarch64` and `m68k` alongside the usual architectures indicates a deliberate attempt to **maximize the compromisable device surface**, including legacy hardware that normally doesn't receive this type of malware attention. **Redtail** (identified last week) also remains present.

TechTies Inc. (37,526) and Net Access Internet India (24,150) lead by ASN origin. IP `103.149.197.34` accumulates 24,150 events — virtually all Net Access Internet India traffic comes from that single IP.

---

## 7. Dionaea — The Same Actor, Second Week

**91,957 attacks, 1,474 unique IPs** (x1.50).

IPs `62.84.80.240`, `.241`, `.242`, and `.243` — flagged last week with ~5,600–5,700 events each — **reappear this week with similar counts (3,796–3,874 each)**. Second consecutive week. This is no longer noise: it's an operator with fixed infrastructure and continued presence against this honeypot.

The **`ftpdatalisten`** protocol appears strongly (new in this week's top), with port 21 (FTP) gaining weight compared to the near-exclusive SMB/RPC dominance last week.

Lebanon and Vietnam repeat as source countries; **Japan and Armenia** are added, absent last week. Broadband Plus S.a.l. (Lebanon) remains the most active ASN (15,316).

---

## 8. ConPot — IEC-104 for a Second Consecutive Week

**4,461 attacks, 257 unique IPs** (x2.8). The **IEC-104** protocol (port 2404, electrical substation telecontrol) remains present — this is no longer a one-off event, there's recurring probing.

**Port 623 (IPMI)** activity also appears, out-of-band remote management of servers — a different vector from the ICS protocols seen so far, relevant because insecure IPMI is a real, documented compromise path in datacenter environments.

**Censys, Inc.** appears in the top ASNs (110 events) — like Modat B.V. and ONYPHE SAS, it's an internet research scanning company, not a malicious actor. Confirms the already-observed pattern: some "attack" traffic toward ICS honeypots is passive internet cataloguing.

---

## 9. Adbhoney — Same Campaign, More Activity

**2,012 attacks, 106 unique IPs.** The **same payload hash from last week** reappears with **228 downloads** (compared to 110 the previous week). The Rebirth → `com.ufo.miner` → Trinity chain remains active with the same sample, confirming a persistent campaign, not an isolated event.

---

## 10. Conclusions

1. **This week's growth is a redistribution of focus, not "more of the same"**: RDP and VoIP spike while Honeytrap moderates. A real environment with exposed RDP or SIP PBX should consider this week a specific elevated-risk window for those two services.

2. **The same actors/subnets reappear week after week** (`62.84.80.240-243` in Dionaea; `217.154.196-197.x` and `31.70.86.6x` in Sentrypeer). This now justifies a permanent subnet-level blocking rule for these ranges in a real environment, rather than one-off per-IP blocks.

3. **The shift to AMI (5038) in Honeytrap coinciding with the Sentrypeer peak** suggests broader interest in VoIP/PBX infrastructure this week — worth tracking next week to confirm whether it's a trend or a one-off.

4. **The loader with `loongarch64` and `m68k` support** is a distinctive technical data point: few honeypot analyses mention malware targeting these architectures. It warrants a separate post.

5. **The reappearance and growth of the Adbhoney hash** confirms the value of longitudinal tracking: it allows distinguishing between "new noise each week" and "persistent campaigns" — exactly what separates a threat intel report with real temporal perspective from an isolated snapshot.

6. **IEC-104 and IPMI in ConPot, two weeks in a row**, consolidates the previous recommendation: any uptick on these ports warrants priority review given the type of infrastructure they simulate.

---

*Report compiled from data collected in a publicly internet-exposed T-Pot instance. Methodology: export of aggregated Kibana dashboards (range July 12–18, 2026) plus credential tag clouds in CSV. Comparison made against the [previous week's report (July 7–11, 2026)](/honeypot/informe-semanal-01/).*
