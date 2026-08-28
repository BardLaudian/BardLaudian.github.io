---
title: "Weekly Threat Intelligence Report — T-Pot Honeypot (Jul 26 – Aug 2, 2026)"
date: 2026-08-03
draft: false
description: "Fourth weekly report from the T-Pot honeypot: ~2,023,000 events. The residential SNMP botnet on ConPot is confirmed for a second consecutive week (Comcast, AT&T, Verizon, Charter). IP 91.199.133.133 — catalogued in ThreatFox as a Mirai Katana C2 — reappears serving payloads in Cowrie. Redtail adds RISC-V support and the Turkish ERP target in Dionaea is confirmed as an active campaign."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "SNMP", "Botnet", "Redtail", "Mirai", "Katana", "IoT", "ICS", "SCADA", "IEC104", "IPMI", "MSSQL", "ERP", "RISCV", "VoIP"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Fourth weekly report from the T-Pot honeypot, period **July 26 – August 2, 2026**. With four weeks of accumulated data, patterns stop being anecdotal and become trends: the **residential SNMP botnet on ConPot is confirmed for a second consecutive week** (Comcast, AT&T, Verizon, Charter with not a single VPS in the top 10), IP **`91.199.133.133` catalogued in ThreatFox as a Mirai Katana C2 reappears** serving payloads in Cowrie, **Redtail adds RISC-V architecture**, and the brute force campaign against Turkish ERP software in Dionaea is confirmed with a second week of consistent data.
{{< /lead >}}

---

**Period analyzed:** July 26 – August 2, 2026
**Source:** T-Pot (multi-honeypot + ELK Stack) — publicly internet-exposed instance
**Classification:** Portfolio use / TLP:CLEAR
**Previous reports:** [Jul 7–11](/honeypot/informe-semanal-01/) · [Jul 12–18](/honeypot/informe-semanal-02/) · [Jul 19–25](/honeypot/informe-semanal-03/)

---

## 1. Executive Summary

Total volume rises to **~2,023,000 events** (compared to ~1,820,000 last week). With four weeks of data, patterns stop being anecdotal:

- **The residential ConPot botnet was not a one-off event**: top 10 ASN again dominated by domestic ISPs (Comcast, AT&T, Verizon, Charter ×3, Cox, CenturyLink, Videotron, SFR), with not a single hosting/VPS provider. Second identical week in composition.
- **Full-circle with the project's first investigation**: IP `91.199.133.133` — catalogued in ThreatFox as an active C2 for the Mirai "Katana" variant — **reappears serving `deploy.sh` to Cowrie**, weeks after its first detection. Still operational.
- **New dominant actor**: `45.95.147.229` (Alsycon B.V.) becomes the **most active IP in the entire dashboard** (194,606 events), concentrated in Honeytrap. No relevant presence in previous weeks.
- **Four-week persistence**: `108.181.56.189` (Sentrypeer) and `103.149.197.34` (Cowrie) have been in the top 10 of their respective sensors for four consecutive weeks.
- **First drop in the Adbhoney hash after three weeks of growth**: 110→228→287→**102 downloads**. Pause or takedown of the origin server? The key data point will be next week.
- **Redtail expands architectures**: first appearance of `redtail.riscv`, adding RISC-V to ARM7/ARM8/i686/x86_64.
- **The Turkish target in Dionaea is confirmed**: second week with Turkish ERP terminology in the tagcloud (`POS`, `ERCYONETICI` as new terms) and Turk Telekom repeating in the top ASN.

---

## 2. Volume — Four Weeks of Context

| Honeypot | Jul 7–11 | Jul 12–18 | Jul 19–25 | Jul 26–Aug 2 |
|---|---:|---:|---:|---:|
| RDPHoneypot | 111,818 | 2,312,634 | 843,181 | 657,393 |
| Honeytrap | 678,792 | 218,202 | 372,001 | 545,549 |
| Cowrie | 116,390 | 229,182 | 249,057 | 318,800 |
| Sentrypeer | 36,522 | 340,759 | 119,651 | 279,730 |
| ConPot | 1,594 | 4,461 | 122,376 | 100,475 |
| Dionaea | 61,123 | 91,957 | 92,722 | 74,429 |
| Adbhoney | 2,618 | 2,012 | 1,737 | 1,292 |
| **Approx. total** | **~1,011,000** | **~3,213,000** | **~1,820,000** | **~2,023,000** |

**Patterns emerging at four weeks:**

- **Cowrie is the only sensor with monotonic growth** across all four weeks (116k→229k→249k→319k) — organic activity, without artificial spikes.
- **RDPHoneypot has been declining for three consecutive weeks** after the week 2 peak (2.3M→843k→657k) — the campaign is gradually deflating.
- **Sentrypeer is the most erratic** (36k→340k→119k→280k) — suggests several independent actors entering and exiting, not a single predictable campaign.
- **Adbhoney is the only one with sustained volume decline** across all four weeks, although the specific hash grew for three weeks before dropping this week — these are distinct signals.

---

## 3. ConPot — Second Week of the Residential Botnet: It's a Pattern Now

**100,475 attacks, 1,077 unique IPs.** Slightly lower volume than last week (122,376) but **the important finding is that origin composition repeats exactly**.

### Top ASN: second week with not a single hosting provider

| ASN | Organization | Country | Events |
|---|---|---|---:|
| 7922 | Comcast Cable Communications | USA | 29,940 |
| 7018 | AT&T Enterprises | USA | 8,303 |
| 701 | Verizon Business | USA | 7,434 |
| 20001 / 11426 / 10796 | Charter Communications | USA | 3,799 / 2,339 / 2,155 |
| 22773 | Cox Communications | USA | 2,809 |
| 15557 | SFR | France | 2,547 |
| 209 | CenturyLink | USA | 2,271 |
| 5769 | Videotron Ltée | Canada | 2,188 |

With two identical weeks in composition (pure residential ISPs, no VPS/hosting), the **compromised home/IoT router botnet scanning SNMP** hypothesis moves from being a reasonable hypothesis to being the most likely explanation backed by repeated data. The profile is classic: Comcast, AT&T, Charter, and Verizon are the four largest broadband operators in the USA, with tens of millions of home routers — exactly the kind of infrastructure an IoT botnet would compromise at scale.

### IPMI rises

Port **623 (IPMI)** becomes the second most attacked port on the sensor, just behind 161 (SNMP). Poorly secured IPMI is a real server compromise path in datacenter environments — its sustained growth warrants tracking if it continues.

### IEC-104: fifth consecutive week

The electrical substation telecontrol protocol remains present. The "Conpot Response - Top 10" shows the response *"? Command not found. Send 'H' for help."* repeated **53 times** this week, compared to 2–3 times in previous weeks — more exploratory interaction attempts with the simulated service, not just automatic port scanning.

---

## 4. The New Dominant Actor: `45.95.147.229` (Alsycon B.V.)

**Most active individual IP in the entire dashboard this week: 194,606 events.** No notable presence in any previous week.

| Sensor | Events |
|---|---:|
| Honeytrap | 188,529 |
| Adbhoney | 266 |

The Alsycon B.V. ASN had appeared in previous weeks with smaller volumes distributed across several sensors, but never with a single IP concentrating nearly 200,000 events in one week. Typical profile of an IP recently put into production for an aggressive scanning campaign. The key data point will be next week: does it consolidate as a recurring actor or follow Flyservers S.A.'s path and disappear almost entirely?

---

## 5. Cowrie — ThreatFox Full Circle and RISC-V in Redtail

**318,800 attacks, 1,821 unique IPs, 63 HASSH.** Fourth consecutive weekly increase.

### The ThreatFox IP reappears

In the download panel, the URL **`http://91.199.133.133:8080/deploy.sh`** appears with 10 downloads. **`91.199.133.133` is the same IP we identified in ThreatFox at the start of this project**, catalogued as an active C2 for the Mirai **"Katana"** variant with 100% confidence. It now serves a deployment script over HTTP on port 8080, confirming that the infrastructure **remains operational weeks after its first detection**. Without the IOC record from previous weeks, this reappearance would have gone unnoticed as "just another URL" in the download top.

### Redtail adds RISC-V

First appearance of `redtail.riscv` alongside the already familiar `.arm7`, `.arm8`, `.i686`. RISC-V is an open instruction set architecture with growing presence in microcontrollers and low-cost IoT hardware. Its inclusion confirms that the Redtail operator is still actively expanding their target device coverage.

### Persistent actors

| Indicator | Week 1 | Week 2 | Week 3 | Week 4 |
|---|:---:|:---:|:---:|:---:|
| Subnet `45.153.34.x` | ✅ | ✅ | ✅ | ✅ |
| Redtail malware | ✅ | ✅ | ✅ | ✅ |
| `chattr -ia .ssh` script | ✅ | ✅ | ✅ | ✅ |
| `103.149.197.34` in top 10 | ✅ | ✅ | ✅ | ✅ |

### Technical curiosity: HTTP headers as "credentials"

The username and password tagclouds literally include fragments of HTTP requests: `User-Agent: python-requests/2.27.1`, `Accept: */*`, `Host: 62.84.184.111:23`. This happens when an automated HTTP client (a misconfigured scanner, given the `python-requests` user-agent) sends a complete HTTP request against Cowrie's SSH port — the honeypot tries to interpret the first lines as a login attempt and records them verbatim. Not an attack per se, but a good example of poorly-built scanner noise that can distort credential statistics if not filtered with judgment.

---

## 6. Sentrypeer — Rebound with New Protagonists from the Same Block

**279,730 attacks, 178 unique IPs** (x2.3 compared to last week). Two phases: high plateau July 26–27, even higher peak July 30–31.

### Four-week persistence

`108.181.56.189` returns with **96,541 events** — fourth consecutive week with relevant presence on this sensor and in the general dashboard.

### New protagonist from the same block

`108.181.64.154` — from the same range `108.181.6x.x` — becomes the most active IP on the sensor with **103,695 events**. Two IPs from the same /16 block being the most active in consecutive weeks points to operating not a single IP, but **a block of addresses under the same control**, rotating similarly to what we already saw with subnet `45.153.34.x` in Cowrie.

The most frequent SIP user-agents change to `Cisco-SIPGateway/IOS` and `FreeSWITCH-mod_sofia` — variation in tools, same VoIP fraud/enumeration objective.

---

## 7. RDPHoneypot — Third Week of Sustained Decline

**657,393 attacks, 551 unique IPs.** Trend confirmed: 2,312,634 → 843,181 → 657,393.

MEVSPACE sp. z o.o. remains the most consistent ASN of recent weeks (190,392 this week). **Flyservers S.A.**, which nearly disappeared in week 3, reappears with modest volume (22,783) — neither dominating again nor disappearing entirely. It consolidates as a recurring secondary actor.

---

## 8. Dionaea — Second Week of the Turkish ERP Target: It's a Campaign Now

**74,429 attacks, 1,660 unique IPs** — declining in volume, but with the most important qualitative finding on the sensor.

### The tagcloud expands

| Term | Meaning / Context |
|---|---|
| `KASA` | Cash/register |
| `MIKRO`, `LOGO` | Real Turkish ERP brands |
| `MUHASEBE` | Accounting |
| `BARKOD` | Barcode |
| `ENTEGRA` | Integration (ERP module) |
| `POS` *(new)* | Point of sale |
| `ERCYONETICI` *(new)* | Likely "ERP yöneticisi" — ERP administrator in Turkish |

**Turk Telekom repeats in the top ASN** (3,670 events, compared to 3,410 last week). With two weeks of consistent data in terminology, protocol (MSSQL), and geographic origin, the directed campaign classification is now solid, not a hypothesis.

**India** becomes the top origin country (new in Dionaea), with Alliance Broadband Services Pvt. Ltd. (11,070 events) and IP `144.48.227.75` as the main origin.

---

## 9. Adbhoney — First Drop: Pause or Takedown?

**1,292 attacks, 108 unique IPs.** The data that breaks the streak:

| Week | Hash `849840...` downloads |
|---|---:|
| Jul 7–11 | 110 |
| Jul 12–18 | 228 |
| Jul 19–25 | 287 |
| Jul 26–Aug 2 | **102** |

The hash `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d53839b5` drops from 287 to 102 downloads. The `busybox wget` command against `94.154.43.48` also drops proportionally (218 → 80 executions). Possible causes include the origin infrastructure being taken down, a deliberate campaign pause, or one-off variability. **The decisive data point will be next week**: if it recovers, it was a pause; if it keeps dropping or disappears, it's an indicator of takedown or campaign abandonment.

---

## 10. Persistent Actors — First Consolidated Table

With four weeks of data now available, this longitudinal tracking section is inaugurated:

| Indicator | W1 (Jul 7–11) | W2 (Jul 12–18) | W3 (Jul 19–25) | W4 (Jul 26–Aug 2) |
|---|:---:|:---:|:---:|:---:|
| `45.153.34.x` (Cowrie) | ✅ | ✅ | ✅ | ✅ |
| Redtail (Cowrie) | ✅ | ✅ | ✅ | ✅ (+RISC-V) |
| `103.149.197.34` (Cowrie) | ✅ | ✅ | ✅ | ✅ |
| `108.181.56.189` (Sentrypeer) | ❌ | ✅ | ✅ | ✅ |
| Adbhoney hash `849840...` | ✅ 110 | ✅ 228 | ✅ 287 | ⚠️ 102 |
| IEC-104 on ConPot | ✅ | ✅ | ✅ | ✅ |
| Residential SNMP botnet (ConPot) | ❌ | ❌ | ✅ | ✅ |
| Turkish ERP target (Dionaea) | ❌ | ❌ | ✅ | ✅ |
| `91.199.133.133` (Katana C2) | 🔍 IOC | ❌ | ❌ | ✅ reappears |

---

## 11. Conclusions

1. **The residential SNMP botnet is the project's most solid finding so far**: two weeks with identical origin composition (pure domestic ISPs, no VPS) eliminate the possibility of a one-off anomaly. Best candidate for an independent technical post.

2. **The reappearance of `91.199.133.133` demonstrates the value of longitudinal IOC tracking**: without the context from previous weeks, it would have been "just another URL." With context, it's confirmation that an explicitly researched C2 infrastructure remains operational weeks later.

3. **Watch `45.95.147.229` next week**: recurring actor or flash-in-the-pan like Flyservers S.A.? One week doesn't allow classification.

4. **The Turkish ERP target in Dionaea is now a confirmed campaign**: two weeks with the same profile (terminology, protocol, origin ASN) justify treating it as a directed attack, not generic noise.

5. **The Adbhoney hash drop is the week's most uncertain signal**: next week's tracking will resolve whether it was a pause or campaign end.

6. **The persistent actors table is now ready to be a fixed section** of the report — with four weeks of history, it has real value for distinguishing organic behavior from structured campaigns.

---

*Report compiled from data collected in a publicly internet-exposed T-Pot instance. Methodology: export of aggregated Kibana dashboards (range July 26 – August 2, 2026) plus credential tag clouds in CSV. Comparison made against the three previous reports ([Jul 7–11](/honeypot/informe-semanal-01/), [Jul 12–18](/honeypot/informe-semanal-02/), [Jul 19–25](/honeypot/informe-semanal-03/)).*
