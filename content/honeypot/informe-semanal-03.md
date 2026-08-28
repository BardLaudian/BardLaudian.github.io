---
title: "Weekly Threat Intelligence Report — T-Pot Honeypot (Jul 19–25, 2026)"
date: 2026-07-26
draft: false
description: "Third weekly report from the T-Pot honeypot: volume drops to ~1,820,000 events but composition changes radically. ConPot spikes x27 with residential ISPs (Comcast, AT&T, Virgin Media) attacking SNMP — the signature of an IoT botnet. Flyservers S.A. collapses on RDP, Adbhoney confirms an active campaign for a third week, and Dionaea detects brute force targeting Turkish accounting software (LOGO, Mikro)."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "SNMP", "VoIP", "Malware", "IoT", "Botnet", "Redtail", "ICS", "SCADA", "IEC104", "MSSQL", "ERP"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Third weekly report from the T-Pot honeypot, period **July 19–25, 2026**. Total volume drops to **~1,820,000 events** (half of last week), but the relevant data isn't the total — it's the composition: **ConPot spikes x27** with origin in residential ISPs (Comcast, AT&T, Virgin Media, Free SAS) — the signature of a domestic router botnet attacking SNMP, a qualitatively different actor from anything seen so far. Meanwhile, Flyservers S.A. collapses on RDP, the same Adbhoney payload is in its third week of growth, and Dionaea detects brute force specifically targeting Turkish accounting software over MSSQL.
{{< /lead >}}

---

**Period analyzed:** July 19–25, 2026
**Source:** T-Pot (multi-honeypot + ELK Stack) — publicly internet-exposed instance
**Classification:** Portfolio use / TLP:CLEAR
**Previous reports:** [Jul 7–11](/honeypot/informe-semanal-01/) · [Jul 12–18](/honeypot/informe-semanal-02/)

---

## 1. Executive Summary

Total volume drops to **~1,820,000 events**, roughly half of last week (~3,213,000). But the relevant data isn't the total volume — it's that **composition changes radically sensor by sensor**:

- **ConPot spikes x27** (4,461 → 122,376 attacks) with an unprecedented origin shift: no longer VPS hosting or research scanners, but **residential ISPs** — Comcast, Charter, AT&T, Virgin Media, Free SAS, TIM. All concentrated on **port 161 (SNMP)**. The signature of a **botnet of compromised home routers/IoT devices**.
- **RDPHoneypot drops to a third** (2,312,634 → 843,181). **Flyservers S.A.**, which generated over a million events last week, falls to barely ~40,800 — its campaign stopped or migrated almost entirely.
- **Sentrypeer also drops to a third** (340,759 → 119,651), but the IP `108.181.56.189` — the most active in the dataset last week — **reappears as the most active again**, also highlighted in the global top 10. Third week with relevant presence.
- **Honeytrap grows again** (218,202 → 372,001), driven 40% by a single IP from the **German academic network DFN** — almost certainly research traffic, not a real attack.
- **Cowrie confirms for a third consecutive week** the subnet `45.153.34.x` and the Redtail malware. Same actor, same infrastructure, same payload.
- **The Adbhoney hash keeps growing week over week**: 110 → 228 → **287 downloads**. Three weeks of data confirm an active, expanding campaign.
- **New Dionaea finding**: Turkish terms in the username tagcloud (`KASA`, `DEPO`, `FATURA`, `LOGO`, `MIKRO`) — names of real Turkish ERP/accounting software — alongside an uptick of `mssqld` and a Turkish ISP in the top ASN. Vertical brute force targeting a specific sector and geography.

---

## 2. Comparative Volume (three weeks)

| Honeypot | Jul 7–11 | Jul 12–18 | Jul 19–25 | Trend |
|---|---:|---:|---:|---|
| RDPHoneypot | 111,818 | 2,312,634 | 843,181 | 📈📉 spike and drop |
| Honeytrap | 678,792 | 218,202 | 372,001 | 📉📈 V-shaped |
| Cowrie | 116,390 | 229,182 | 249,057 | 📈 sustained growth |
| ConPot | 1,594 | 4,461 | 122,376 | 📈📈📈 explosion |
| Sentrypeer | 36,522 | 340,759 | 119,651 | 📈📉 spike and drop |
| Dionaea | 61,123 | 91,957 | 92,722 | ➡️ stable |
| Adbhoney | 2,618 | 2,012 | 1,737 | ➡️ (payload +161%) |
| **Approx. total** | **~1,011,000** | **~3,213,000** | **~1,820,000** | |

No sensor maintains stable behavior except Dionaea and Cowrie. This extreme week-to-week variability is itself a data point: a single-week snapshot without historical comparison would give a very distorted picture of this honeypot's real risk level.

---

## 3. ConPot — The Week's Most Relevant Finding

**122,376 attacks, 1,009 unique IPs** (x27 in volume, x4 in IPs compared to last week). Several abrupt peaks throughout the week (~20,000 events in a single interval), not gradual growth.

### Radical origin infrastructure shift

Last week ConPot's origins were typical hosting/VPS providers. **This week, the top ASN is dominated by residential ISPs**:

| ASN | Organization | Country | Events |
|---|---|---|---:|
| 7922 | Comcast Cable Communications | USA | 12,053 |
| 33363 | Charter Communications | USA | 11,644 |
| 12322 | Free SAS | France | 10,889 |
| 11426 / 20001 | Charter Communications | USA | 9,872 / 7,923 |
| 3269 | TIM | Italy | 6,337 |
| 7018 | AT&T Enterprises | USA | 5,489 |
| 5089 | Virgin Media | UK | 4,765 |

**Comcast, Charter, AT&T, Virgin Media, Free SAS, and TIM** are residential broadband operators. None is a hosting/VPS provider. This origin profile, combined with the fact that **99% of traffic targets port 161 (SNMP)**, is the characteristic signature of a **botnet formed by compromised home routers or IoT devices** scanning SNMP at scale — not an actor with their own attack infrastructure.

> **Why SNMP?** SNMP (Simple Network Management Protocol) is the most widespread remote management protocol in routers, switches, and network devices. Scanning it massively serves to identify devices with SNMP enabled and default credentials (community string `public`/`private`), the first step to compromising new nodes to add to the botnet.

The **IEC-104** protocol (electrical substation telecontrol, port 2404) remains present for a **fourth consecutive week**, though in minimal proportion compared to this week's SNMP deluge.

---

## 4. RDPHoneypot — Last Week's Major Actor Disappears

**843,181 attacks, 453 unique IPs** (compared to 2,312,634 last week). Two concrete peaks on July 22 and 23 (~85-90k each) and sustained decline the rest of the week.

### Flyservers S.A. collapse

Last week, **Flyservers S.A.** (two different ASNs) generated over 1,056,000 events — nearly half of all RDP traffic. This week, both ASNs combined total barely **~40,800 events**: a 96% drop in seven days. This type of abrupt collapse is typical of: (a) the operator was detected and their infrastructure taken down by the provider, (b) they migrated to another provider, or (c) they simply paused the campaign.

### New protagonists

| ASN | Organization | Events |
|---|---|---:|
| 201814 | MEVSPACE sp. z o.o. | 260,270 |
| 205997 | Vlad Cojuhari | 224,226 |

**"Vlad Cojuhari"** (ASN 205997, 224,226 events) is an ASN registered in an individual's name rather than a company — unusual, and common in smaller or less regulated hosting operations. Monaco and Panama, dominant last week (linked to Flyservers), virtually disappear from the top. Origin countries are now United States, Poland, France, and Azerbaijan.

---

## 5. Honeytrap — Recovery Driven by Research Traffic

**372,001 attacks, 9,974 unique IPs** (x1.7 compared to last week). Marked peak on July 22–23.

### The dominant actor is not malicious

IP `141.76.94.28`, belonging to ASN **Verein zur Förderung eines Deutschen Forschungsnetzes e.V. (DFN)** — Germany's academic and research network — generates **146,980 events, nearly 40% of all Honeytrap traffic this week**. It is, with high probability, an internet measurement/scanning project for academic research purposes. **It should not be weighted the same as traffic from a malicious actor** when assessing the real threat level for the week.

The most attacked ports maintain last week's profile (8728/MikroTik, 5038/Asterisk AMI, 7070), now adding **8081 and 2222** (alternative SSH port, common in non-standard configurations).

---

## 6. Cowrie — Third Week Confirming the Same Actor

**249,057 attacks, 1,623 unique IPs, 57 unique HASSH.** Sustained and moderate growth, consistent with the two previous weeks.

### Three-week longitudinal confirmation

| Indicator | Week 1 (Jul 7–11) | Week 2 (Jul 12–18) | Week 3 (Jul 19–25) |
|---|---|---|---|
| Subnet `45.153.34.x` | ✅ ~3,817/IP | ✅ ~3,817/IP | ✅ ~3,815/IP |
| Redtail malware | ✅ | ✅ | ✅ |
| `chattr -ia .ssh` script | ✅ | ✅ | ✅ |
| `xnxnxnxn` loader (loongarch64/m68k) | ❌ | ✅ | ❌ (one-off) |

The subnet `45.153.34.x`, Redtail, and the `.ssh` blocking script are already permanent actors/TTPs of this honeypot. Last week's loader with unusual architectures doesn't reappear — it was a one-off campaign, not persistent.

The `uname -a` command nearly doubles in frequency (384 → 711 executions) — more activity from the same loader. TechTies Inc. and India Net Access Internet lead by ASN for a third consecutive week; IP `103.149.197.34` remains the most active.

---

## 7. Sentrypeer — Recurring Actor, Third Week

**119,651 attacks, 192 unique IPs.** Initial peak on July 19 and sustained decline the rest of the week.

`108.181.56.189` accumulates **59,769 events** and is again the most active IP on the sensor, and one of the most visible in the global dashboard. With presence in at least two consecutive weeks and dashboard-level visibility, it is now a confirmed actor with prolonged activity against this instance.

### Curious technical detail

In the SIP user-agents panel, the string **`'or"='`** appears — literally a classic SQL/command injection payload, used here as a SIP header value. This is not a directed attack against the honeypot's database, but a generic automated test to check whether the server processes headers without sanitizing. Illustrative of the noise level any mass scanner generates: it tries injection techniques regardless of whether the target protocol is SQL, SIP, or anything else.

---

## 8. Dionaea — Brute Force Targeting Turkish ERP Software

**92,722 attacks, 1,799 unique IPs** — stable volume compared to last week.

### Tagcloud finding

Alongside the usual generic credentials (`admin`, `root`, `sa`), a set of terms appears that doesn't fit generic brute force:

| Term | Meaning | Context |
|---|---|---|
| `KASA` | Cash/register | Cash module in Turkish ERP |
| `DEPO` | Warehouse | Stock/warehouse module |
| `FATURA` | Invoice | Billing module |
| `MUHASEBE` | Accounting | Accounting module |
| `LOGO` | — | Real brand of Turkish ERP software |
| `MIKRO` | — | Real brand of Turkish accounting software |
| `BARKOD` | Barcode | Inventory module |

**LOGO and MIKRO are real brands of ERP/accounting software widely used in Turkey**, with MSSQL databases as their typical backend. Combined with the `mssqld` protocol gaining weight in Dionaea and **TurkNet İletişim Hizmetleri A.Ş.** in the top ASN (3,410 events), this suggests a *vertical* attack: brute force targeting specifically MSSQL installations used by Turkish business management software, rather than the usual generic noise.

**Mexico** appears as the top origin country (new, not seen in previous weeks), with IP `187.235.152.60` (11,055 events, ASN **UNINET** — Mexico's largest telecom operator). Saudi Arabia and Uruguay are also new in the top.

---

## 9. Adbhoney — Three Weeks of Confirmed Growth

**1,737 attacks, 102 unique IPs.** Sensor volume remains low and stable, but the relevant data is the payload progression:

| Week | Hash downloads |
|---|---:|
| Jul 7–11 | 110 |
| Jul 12–18 | 228 |
| Jul 19–25 | **287** |

The hash `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d53839b5.raw` (Rebirth → `com.ufo.miner` → Trinity chain) has been **growing consecutively for three weeks with the same payload**. It's the clearest indicator of longitudinal intelligence in the entire tracking: a real, active, expanding campaign — not a one-off event.

---

## 10. Conclusions

1. **The week's finding is ConPot**: residential ISPs + SNMP port 161 is the signature of an IoT/domestic router botnet — a qualitatively different actor type from the VPS/hosting infrastructure seen in previous weeks. Worth tracking next week to confirm whether the pattern consolidates or was a one-off.

2. **Not every volume spike is a threat**: 40% of Honeytrap traffic this week comes from the German academic network DFN. Separating research scanning from real malicious traffic remains critical to avoid distorting perceived threat level.

3. **Redtail, subnet `45.153.34.x`, and the Adbhoney payload have been active for three weeks** — they are already solid candidates for permanent subnet-level and hash blocking rules in a real environment.

4. **The Flyservers S.A. collapse on RDP** illustrates how quickly an actor's infrastructure changes — from dominating nearly half of a sensor's traffic to virtually disappearing in seven days. Any ASN-based block list needs frequent revision.

5. **The brute force against Turkish ERP software (LOGO/Mikro) in Dionaea** is a good candidate for an independent post on vertical attacks targeting specific sectors and geographies.

6. With three weeks of accumulated data, the report is starting to have real **longitudinal intelligence value**. The next edition should include a fixed "persistent actors" section (IPs, hashes, and subnets seen in 2+ weeks) — there's already enough history to sustain it.

---

*Report compiled from data collected in a publicly internet-exposed T-Pot instance. Methodology: export of aggregated Kibana dashboards (range July 19–25, 2026) plus credential tag clouds in CSV. Comparison made against the previous week reports ([Jul 7–11](/honeypot/informe-semanal-01/) and [Jul 12–18](/honeypot/informe-semanal-02/)).*
