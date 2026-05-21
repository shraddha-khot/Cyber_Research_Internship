# 🔴 CARBANAK — APT Intelligence Report
### RedKross Unified Threat Intelligence Platform

![Threat Level](https://img.shields.io/badge/Threat%20Level-CRITICAL-red)
![Status](https://img.shields.io/badge/Status-Active%20Fragmented-orange)
![Banks](https://img.shields.io/badge/Banks%20Hit-100%2B-blue)
![Losses](https://img.shields.io/badge/Losses-%241B%2B-darkred)

---

## 📌 Overview

This report covers **Carbanak** (also known as Anunak, FIN7, Cobalt Group) —
one of the most dangerous financially motivated APT groups ever documented.

**Analyst:** Shraddha Khot
**Platform:** RedKross Unified Threat Intelligence Platform
**Date:** May 2025
**Classification:** TLP:WHITE — Educational Use Only

---

## ⚡ Key Stats

| Attribute | Value |
|-----------|-------|
| Active Since | 2013 |
| Aliases | Anunak · FIN7 · Cobalt Group · Carbon Spider |
| Banks Compromised | 100+ |
| Total Stolen | $1 Billion+ USD |
| Countries Targeted | 40+ |
| Leader Arrested | March 26, 2018 — Alicante, Spain |
| MITRE ID | G0008 (Carbanak) · G0046 (FIN7) |

---

## 📂 Files in This Folder

| File | Description |
|------|-------------|
| `README.md` | This file — full intelligence summary |
| `carbanak_iocs.txt` | Domains, IPs, hashes, mutexes |
| `carbanak.yar` | YARA detection rule |
| `Carbanak_TI_Report.pdf` | Full PDF report |

---

## 🕐 Historical Timeline

| Year | Event |
|------|-------|
| 2013 | Carbanak emerges from Carberp source code leak — testing phase begins |
| Dec 2013 | First confirmed infections at Ukrainian banks |
| Feb–Apr 2014 | First successful thefts — ATM cashouts |
| Jun 2014 | Peak infection wave — 100+ institutions compromised |
| Feb 2015 | Kaspersky + INTERPOL publicly disclose the campaign |
| 2016–2017 | Expands to retail and hospitality — FIN7 operations begin |
| Mar 2018 | Group leader arrested in Spain by Europol |
| 2020+ | Splinter groups adopt ransomware (DarkSide, REvil) |

---

## 🎯 Attack Lifecycle (Kill Chain)
PHASE 1 → Reconnaissance     Profile targets via LinkedIn; identify bank IT staff
PHASE 2 → Initial Access     Spear-phishing .doc/.cpl with CVE-2012-0158, CVE-2013-3906
PHASE 3 → Execution          Carbanak RAT installed; connects to C2 via HTTPS
PHASE 4 → Persistence        Windows service "Microsoft KB2832077"; registry keys
PHASE 5 → Lateral Movement   PsExec, RDP, Ammyy Admin; 2–4 months silent observation
PHASE 6 → Espionage          Screen video recording; keylogging; maps bank workflows
PHASE 7 → Impact             ATM cashout · SWIFT fraud · Account inflation · POS theft

---

## 🧠 MITRE ATT&CK Mapping

| Technique ID | Name | How Carbanak Used It |
|-------------|------|----------------------|
| T1566.001 | Spearphishing Attachment | .doc/.cpl files exploiting MS Office CVEs |
| T1059.001 | PowerShell | Base64 payloads executed in memory |
| T1055 | Process Injection | Injected into svchost.exe |
| T1071.001 | Web Protocols (HTTP) | C2 over HTTP with RC2+Base64 encryption |
| T1071.004 | DNS | DNS TXT queries to aaa.stage.* domains |
| T1078 | Valid Accounts | Used real bank employee credentials |
| T1543.003 | Windows Service | Fake "Microsoft KB2832077" service |
| T1113 | Screen Capture | Screenshots + video to learn bank workflows |
| T1056.001 | Keylogging | Credential harvesting from banking software |
| T1021.001 | RDP | Enabled simultaneous remote/local sessions |

---

## 🧬 Indicators of Compromise (IOCs)

### Domains
update-bank.com
carbanak.org
cobaltgroup.cc

### IP Addresses
185.86.149.125
91.220.131.65

### File Hashes (MD5)
b3a1d9f2e4c6...   Carbanak RAT sample
f9c7a8b1d2...     Anunak dropper

### Mutex
Global\CarbanakMutex

### File System Artifacts
Service name : Microsoft KB2832077
Config file  : anak.cfg
Plugin file  : kldconfig.plug
Injected into: svchost.exe

---

## 🛡️ YARA Detection Rule

```yara
rule Carbanak_RAT {
    meta:
        description = "Detects Carbanak RAT artifacts"
        author      = "RedKross TI Platform — Shraddha Khot"
        date        = "2025"
        reference   = "Kaspersky Lab Carbanak APT Report 2015"
    strings:
        $mutex = "Global\\CarbanakMutex"
        $str1  = { 43 61 72 62 61 6E 61 6B }
        $str2  = "update-bank.com"
        $cfg   = "anak.cfg"
        $svc   = "Microsoft KB2832077"
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
```

---

## 📋 Campaign Tracking

| Camp ID | Actor | Period | Region | Sector | Key TTPs | Notes |
|---------|-------|--------|--------|--------|----------|-------|
| CAMP-001 | Carbanak | 2013–2015 | Russia/Ukraine | Banking | T1059, T1566 | Initial Anunak heists — ATM cashout |
| CAMP-002 | FIN7 | 2016–2017 | Global | Finance/Retail | T1071, T1105 | SWIFT fraud, POS theft, restaurant chains |
| CAMP-003 | Cobalt Group | 2018 | EU/Asia | Banking | T1027, T1059 | Post-arrest resurgence |
| CAMP-004 | FIN7 splinter | 2020+ | Global | Mixed | Ransomware TTPs | REvil then DarkSide ransomware pivot |

---

## 🦠 Malware Family Summary

| Field | Details |
|-------|---------|
| Family Name | Carbanak RAT / Anunak |
| First Seen | August 2013 (compiled) |
| Code Origin | Derived from leaked Carberp source code |
| Platform | Windows 32/64-bit |
| Delivery | .doc, .cpl, .rtf, .exe, .scr |
| Config File | anak.cfg |
| C2 Method | HTTP RC2+Base64 · DNS TXT · Google Apps Script |
| Unique Trait | Directly manipulated banking software GUIs |
| Detection | Backdoor.Win32.Carbanak (Kaspersky) |

---

## 🔗 Ransomware & Affiliate Links

Post-2018, Carbanak infrastructure was used by ransomware affiliates:

- **BitPaymer** — Early affiliate connection
- **Early Ryuk variants** — Infrastructure overlap
- **REvil** — FIN7 splinter used in 2020
- **DarkSide** — FIN7 splinter; responsible for Colonial Pipeline (2021)

---

## 🛡️ Defensive Countermeasures

**Detection**
- YARA rules targeting Carbanak mutex, config file, and C2 strings
- Monitor DNS TXT queries to stage.* subdomains
- Alert on svchost.exe spawning unexpected child processes
- Detect Cobalt Strike beacons on the network

**Prevention**
- Patch MS Office CVE-2012-0158, CVE-2013-3906, CVE-2014-1761
- Email filtering for .cpl and macro-enabled attachments
- MFA on all administrative and banking system ac
-  Network segmentation — isolate SWIFT terminals and ATM networks

**Response**
- Build SOC capable of detecting lateral movement and fileless malware
- Integrate IOC feeds into SIEM
- Conduct regular red-team simulations using Carbanak TTPs

---

## 📚 References

| Source | Document |
|--------|----------|
| Kaspersky Lab | Carbanak APT — The Great Bank Robbery (2015) |
| Europol | Press Release — Arrest of Carbanak leader, Spain (2018) |
| MITRE ATT&CK | G0008 Carbanak — attack.mitre.org/groups/G0008 |
| FireEye / Mandiant | FIN7 Threat Intelligence Reports |
| Group-IB & Fox-IT | Anunak Report (2014) |
| FBI/USSS | Flash Alert MI-000085 |

---
*Analyst: Shraddha Khot | Cyber Research Internship 
