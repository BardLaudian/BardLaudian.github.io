---
title: "I Set Up a Honeypot and I'm Going to Report What I See Every Week"
date: 2026-07-08
draft: false
description: "Project introduction: a T-Pot based honeypot exposed to real internet, with weekly activity summaries and in-depth analysis when something warrants it."
tags: ["Honeypot", "TPot", "ThreatIntel", "SOC", "Mirai", "Botnet", "BlueTeam"]
categories: ["Honeypot Diaries"]
---

{{< lead >}}
I'm going to intentionally expose a server to the internet so it gets attacked — and then write about it here, every week. No simulations or lab data: real malicious traffic, from the real internet, against a server that does nothing but wait for someone to try to break in.
{{< /lead >}}

---

## What This Is

This blog documents what a **honeypot** — a decoy system designed to look vulnerable and attract attacks — detects in real time, week by week.

The idea is simple: most of what you read about cybersecurity consists of quarterly reports from large companies or retrospective analyses of already-resolved incidents. This is the opposite — a small but continuous, unfiltered look at what's happening *right now* in the background noise of the internet: what credentials bots test, what years-old vulnerabilities are still being exploited, what botnets are still actively recruiting devices.

---

## The Infrastructure

The honeypot runs on **T-Pot**, a platform that deploys more than 20 different honeypots in parallel (SSH, Android ADB, SMB, exposed databases, industrial systems, vulnerable web servers, among others), together with Elasticsearch and Kibana to analyze and visualize everything coming in. It's hosted on a VPS dedicated exclusively to this project, isolated from any other systems or personal data.

---

## What You'll Find Here

Two types of content, at different cadences:

**Weekly summaries**, every Sunday. Short and consistent format: how many attacks occurred, which honeypot received the most traffic, where it came from, and the most interesting finding of the week — whether it's a curious credential pattern, an executed command, or an alert about a specific CVE being actively exploited.

**In-depth analyses**, on no fixed schedule. When something captured warrants more than a paragraph — a real malware sample, an evasion technique, an identifiable campaign — I dedicate a separate post to it. The first of these is already published: an analysis of a **Rebirth** botnet sample (Mirai/Gafgyt variant) that I captured trying to infect the honeypot disguised as a Clash Royale app.

---

## Why I'm Doing This

I come from a more offensive-oriented background — CJCA certified, a handful of HackTheBox machines solved and documented — and I'm currently preparing for Security+. This project is my way of putting hours into the other side of the board: detection, threat analysis, and the discipline of turning raw data into something readable and useful, which is ultimately the daily work of a SOC analyst or threat intelligence professional.

I don't expect every week to bring a spectacular finding — many will simply be "more of the same: SSH brute force, SMB scanning, generic credentials." And that's fine. The value here isn't that each entry is impactful, but consistency: looking at the same attack surface week after week until patterns — and anomalies — become visible.

---

## A Note on Technical Honesty

A commitment I'm setting for myself from the first post: I'm not going to inflate the severity of what I find. If something is simply automated scanning noise of no particular interest, I'll say so. If a finding requires caveats ("this looks like X, but I haven't fully confirmed it"), I'll caveat it. I'd rather this blog be useful and credible than flashy.

See you Sunday with the first weekly summary.
