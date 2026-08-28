---
title: "Weekly Threat Intelligence Report — T-Pot Honeypot (Aug 2–9, 2026)"
date: 2026-08-10
draft: false
description: "Fifth weekly report from the T-Pot honeypot: ~2,814,000 events. The residential ConPot botnet is confirmed for a third week with global reach (NTT DOCOMO, Wind Tre, Bouygues). RDPHoneypot returns to its historical maximum driven by Datacamp Limited. New wave of crypto credentials in Cowrie and 'iran' malware family. The Adbhoney campaign tracked since the first report closes definitively."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "RDP", "SNMP", "Botnet", "Redtail", "IoT", "ICS", "SCADA", "IEC104", "IPMI", "VoIP", "Crypto", "Bitcoin", "Malware"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
Fifth weekly report from the T-Pot honeypot, period **August 2–9, 2026**. Volume rises to **~2,814,000 events**. The residential ConPot botnet reaches its **third consecutive week with now-global reach** (NTT DOCOMO, Wind Tre, Bouygues Telecom joining the already known Comcast, AT&T, Charter). RDPHoneypot nearly matches its historical maximum driven by a new actor: **Datacamp Limited**. Cowrie sees a cryptocurrency credential wave and a new malware family named `iran` for the first time. And the Adbhoney campaign tracked since the first report — 110→228→287→102 downloads — **closes definitively**.
{{< /lead >}}

---

**Period analyzed:** August 2–9, 2026
**Source:** T-Pot (multi-honeypot + ELK Stack) — publicly internet-exposed instance
**Classification:** Portfolio use / TLP:CLEAR
**Previous reports:** [Jul 7–11](/honeypot/informe-semanal-01/) · [Jul 12–18](/honeypot/informe-semanal-02/) · [Jul 19–25](/honeypot/informe-semanal-03/) · [Jul 26–Aug 2](/honeypot/informe-semanal-04/)

---

## 1. Executive Summary

Total volume rises to **~2,814,000 events** (compared to ~2,023,000 last week). With five accumulated weeks, this edition confirms the project's most solid finding and adds two new ones:

- **The residential/mobile ConPot botnet is confirmed for a third consecutive week, and now it's global**: the American block (Comcast, AT&T, Charter, third week) is joined by **NTT DOCOMO (Japan), Wind Tre (Italy), and Bouygues Telecom (France)**. Botnet distributed across at least four countries, sustained three weeks, always on SNMP.
- **RDPHoneypot reverses its downward trend** (2.3M→843k→657k) and spikes to **1,894,467 attacks (x2.9)**, nearly matching the historical peak. The driver is a new actor: **Datacamp Limited**, with 479,496 events and no prior presence in any report.
- **Thematic shift in Cowrie**: first time in five weeks that the username tagclouds include cryptocurrency credentials (`wallet`, `bitcoin`, `blockchain`, `chainlink`, `polkadot`, `solana`, `btcuser`, `exchange0`) — brute force campaign targeting exposed SSH nodes/wallets/exchanges.
- **New malware family**: `iran.x86_64`, `iran.aarch64`, `iran.m68k`, `iran.mips` binaries from `165.22.69.214`, in parallel with Redtail which remains present.
- **The Adbhoney campaign tracked since report #1 closes**: hash `849840d92c44ed...` (110→228→287→102→**0**) disappears from the top 10, replaced by a new one of smaller scale.
- **The most stable persistent actors (`108.181.56.189`, `103.149.197.34`) practically disappear from the global top 10** this week, while `45.153.34.x` in Cowrie completes **five consecutive weeks**.

---

## 2. Volume — Five Weeks of Context

| Honeypot | Jul 7–11 | Jul 12–18 | Jul 19–25 | Jul 26–Aug 2 | Aug 2–9 |
|---|---:|---:|---:|---:|---:|
| RDPHoneypot | 111,818 | 2,312,634 | 843,181 | 657,393 | **1,894,467** |
| Honeytrap | 678,792 | 218,202 | 372,001 | 545,549 | 321,830 |
| Cowrie | 116,390 | 229,182 | 249,057 | 318,800 | 251,659 |
| ConPot | 1,594 | 4,461 | 122,376 | 100,475 | **118,762** |
| Sentrypeer | 36,522 | 340,759 | 119,651 | 279,730 | 89,607 |
| Dionaea | 61,123 | 91,957 | 92,722 | 74,429 | 78,268 |
| Adbhoney | 2,618 | 2,012 | 1,737 | 1,292 | 652 |
| **Approx. total** | **~1,011,000** | **~3,213,000** | **~1,820,000** | **~2,023,000** | **~2,814,000** |

**Five-week patterns:**

- **RDPHoneypot** is the most volatile sensor: it depends almost entirely on whether there's an active campaign that week. This week there is.
- **ConPot** went from anecdotal (1,594 events, week 1) to stabilizing at 100,000–122,000 during the last three weeks — the most significant evolution of the project.
- **Adbhoney** drops 75% cumulatively over five weeks (2,618→652), confirming the end of the specific campaign we were tracking.
- **Cowrie was the only one with monotonic growth** for the first four weeks; this week it drops slightly, probably due to rotation of the attacker pool toward other infrastructure.

---

## 3. ConPot — Residential Botnet Confirmed: Three Weeks, Four Countries

**118,762 attacks, 1,232 unique IPs.** Third week in the 100,000–122,000 range, and the origin composition **expands the pattern to international scale**.

### Third week: from USA to global

| ASN | Organization | Type | Country | Weeks |
|---|---|---|---|---:|
| 4713 | NTT DOCOMO BUSINESS | Mobile | Japan | 1st time |
| 7922 | Comcast Cable Communications | Residential | USA | 3rd |
| 7018 | AT&T Enterprises | Residential | USA | 3rd |
| 33363 / 20115 | Charter Communications | Residential | USA | 3rd |
| 1267 | Wind Tre S.p.A. | Mobile | Italy | 1st time |
| 15557 | SFR | Residential | France | 2nd |
| 6327 | Shaw Communications | Residential | Canada | 1st time |
| 5410 | Bouygues Telecom | Mobile | France | 1st time |

**This is the project's most solid finding.** Zero hosting/VPS providers in the top 10 for three consecutive weeks, with confirmed presence now in USA, Canada, France, Italy, and Japan. The conclusion no longer admits reasonable doubt: **botnet of compromised domestic and/or mobile devices, distributed internationally, scanning SNMP in a sustained manner**.

> Why SNMP? It's the most widespread management protocol in home routers and IoT devices, typically with default credentials (`public`/`private`) that are never changed. Scanning it at scale serves to identify new compromisable nodes — the botnet self-replicates.

### IEC-104: sixth consecutive week

The electrical telecontrol protocol (port 2404) continues present. This week without captured interaction in the input/response panels — pure port probing, no attempts to speak the protocol.

---

## 4. RDPHoneypot — Near Historical Maximum, New Actor

**1,894,467 attacks, 828 unique IPs** (x2.9 compared to last week).

### Datacamp Limited: from zero to protagonist

| ASN | Organization | Events |
|---|---|---:|
| — | Datacamp Limited | 479,496 |
| 47447 | IONOS SE | 351,489 |
| 201814 | MEVSPACE sp. z o.o. | 200,267 |
| 205997 | Vlad Cojuhari | 186,326 |

**Datacamp Limited** goes from not appearing in any previous report to leading origin with nearly a quarter of all sensor traffic. It coincides with the entry of **Spain as the second origin country** (new this week), suggesting this actor's infrastructure is located or routed through Spain. **MEVSPACE** remains the most consistent actor of recent weeks — this is now its fourth appearance in the top.

For the first time, the proportion of traffic classified as **"bot/crawler"** approaches 45%, nearly equaling "known attacker" — a profile shift compared to previous weeks where "known attacker" dominated above 90%.

---

## 5. Cowrie — Crypto Credentials and New Malware Family

**251,659 attacks, 2,868 unique IPs** (notable jump in unique IPs), **60 unique HASSH**.

### Cryptocurrency credential wave

The username tagcloud breaks for the first time in five weeks with the previous pattern. Alongside the usual `Administrator`/`root`, a complete cryptocurrency dictionary appears:

`wallet` · `bitcoin` · `blockchain` · `chainlink` · `polkadot` · `solana` · `cardano` · `metaverse` · `binance` · `ethuser` · `btcuser` · `cryptoadmin` · `exchange0` · `xrp`

None of these terms had appeared in the four previous reports. It's a dictionary built specifically to test administration accounts of **blockchain nodes, self-hosted wallets, or exchange panels** exposed by SSH — a completely different attack vector from generic server brute force.

### New family: "iran"

Downloads captured from `165.22.69.214` with binaries named:

- `iran.x86_64`
- `iran.aarch64`
- `iran.m68k`
- `iran.mips`

Four architectures under the same campaign name, in parallel with Redtail (which still appears). Using a country name as an identifier doesn't allow any conclusion about real origin without binary analysis — it could be an arbitrary choice by the operator — but it's a distinctive data point that warrants registration and tracking if it reappears.

### Five-week persistence

The subnet `45.153.34.x` (this time IP `.167`) reappears — **fifth consecutive week**, the longest confirmed persistence streak in the entire project.

### Dominant SSH client shift

For the first time, `SSH-2.0-Go` (dominant across all four previous weeks) **loses first place** to a `libssh` variant, which now represents over 80% of traffic — consistent with the tool change that typically accompanies a new campaign entering with its own tooling.

---

## 6. Honeytrap — New Short-Cycle Dominant Actor

**321,830 attacks, 9,280 unique IPs.**

IP `193.46.255.112` (ASN **Unmanaged Ltd**) leads with **118,453 events** in Honeytrap, and also appears in the global top (122,767) and in Adbhoney (38). Meanwhile, `45.95.147.229` — dominant last week with 188,529 events — **drops to only 15,455 this week**. This pattern (new actor appears strongly, dominates a week, drops sharply the next) is already recurring: Flyservers S.A., `45.95.147.229`, now `193.46.255.112`. **Honeytrap's dominant actors have life cycles of approximately one week.**

Port **5901 (VNC)** appears in the top destinations for the first time, alongside the already familiar 5038/AMI, 7070, 8728/MikroTik, and 2222.

---

## 7. Sentrypeer — New Block, New Country

**89,607 attacks, 188 unique IPs** — another drop (from 279,730), confirming the sensor's erratic pattern across five weeks (36k→340k→119k→280k→90k).

**Poland** becomes the top origin country, with **MEVSPACE sp. z o.o.** concentrating 68,436 events in a block of five consecutive IPs (`149.50.107.43`, `.47`, `.48`, `.49`, `.53`) — the same subnet rotation pattern already seen repeatedly in other sensors.

`108.181.56.189` and `108.181.64.154` — present in recent weeks — don't appear in the top 10 this week. Their streak of continuous presence appears to have cut.

---

## 8. Dionaea — The Turkish Target Dilutes

**78,268 attacks, 1,348 unique IPs.**

The Turkish ERP terms (`KASA`, `LOGO`, `MIKRO`, `MUHASEBE`) that dominated the tagclouds the two previous weeks **disappear this week**. However, two Turkish ISPs (`Superonline İletişim Hizmetleri A.Ş.` and `Netonline Bilişim`) remain in the top ASN with moderate volumes — Turkish-origin background traffic continues, although the specific directed campaign appears to have paused or ended.

New origin countries appear: **Georgia, Nepal, and Albania** — greater geographic dispersion than in previous weeks.

---

## 9. Adbhoney — Original Campaign Definitively Closed

**652 attacks, 99 unique IPs** — sensor's historical minimum.

| Week | Hash `849840...` downloads |
|---|---:|
| Jul 7–11 | 110 |
| Jul 12–18 | 228 |
| Jul 19–25 | 287 |
| Jul 26–Aug 2 | 102 |
| **Aug 2–9** | **0** |

The hash disappears completely from the top 10. In its place, `f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679be3f46d.raw` appears with only 16 downloads — a different campaign, much smaller scale. The original mining campaign (`com.ufo.miner` via `rebirth.arm7`) is over or its infrastructure was neutralized. Five weeks tracking a single hash, from its appearance to its close, is exactly the kind of longitudinal intelligence that distinguishes a threat intel report with real temporal perspective from an isolated snapshot.

---

## 10. Persistent Actors — Week 5

| Indicator | W1 | W2 | W3 | W4 | W5 |
|---|:---:|:---:|:---:|:---:|:---:|
| `45.153.34.x` (Cowrie) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Redtail (Cowrie) | ✅ | ✅ | ✅ | ✅ (+RISC-V) | ✅ (+iran parallel) |
| IEC-104 on ConPot | ✅ | ✅ | ✅ | ✅ | ✅ |
| Residential SNMP botnet (ConPot) | ❌ | ❌ | ✅ | ✅ | ✅ |
| `108.181.56.189` (Sentrypeer) | ❌ | ✅ | ✅ | ✅ | ⚠️ absent |
| `103.149.197.34` (Cowrie) | ✅ | ✅ | ✅ | ✅ | ⚠️ lesser role |
| Adbhoney hash `849840...` | ✅ 110 | ✅ 228 | ✅ 287 | ⚠️ 102 | ❌ end |
| Turkish ERP target (Dionaea) | ❌ | ❌ | ✅ | ✅ | ⚠️ diluted |

---

## 11. Conclusions

1. **The residential/mobile ConPot botnet is the project's most solid finding across five weeks**: three consecutive weeks with the same origin profile (pure domestic/mobile ISPs, not a single VPS) and now with reach across four countries. Best candidate for an independent technical article focused on the dynamic "the attacker has no own infrastructure — it's your neighbors' devices."

2. **Honeytrap and RDPHoneypot dominant actors have approximately one-week life cycles**: Flyservers S.A., `45.95.147.229`, Datacamp Limited, `193.46.255.112` — all dominate one week and deflate sharply the next. Treating them as distinct actors week by week is more accurate than trying to build a persistent actor profile for these sensors.

3. **The crypto credential wave in Cowrie warrants specific tracking**: if it repeats next week, it's a real directed campaign and an independent-post level finding; if it doesn't reappear, it was a one-off event like the `iran` malware or the unusual architectures from previous weeks.

4. **The complete Adbhoney hash lifecycle** (appearance → growth → drop → disappearance in five weeks) is the best example of the value of longitudinal IOC tracking. Without accumulated context, the week 4 drop would have had no clear interpretation.

5. **`45.153.34.x` in Cowrie is the project's most persistent actor** (five weeks) and the most solid candidate for a permanent subnet-level blocking rule in a real production environment.

---

*Report compiled from data collected in a publicly internet-exposed T-Pot instance. Methodology: export of aggregated Kibana dashboards (range August 2–9, 2026) plus credential tag clouds in CSV. Comparison against the four previous reports ([Jul 7–11](/honeypot/informe-semanal-01/), [Jul 12–18](/honeypot/informe-semanal-02/), [Jul 19–25](/honeypot/informe-semanal-03/), [Jul 26–Aug 2](/honeypot/informe-semanal-04/)).*
