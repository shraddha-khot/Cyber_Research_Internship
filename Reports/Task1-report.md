# MITRE ATT&CK CTI Assessment  
**Intern ID:** 2151  
**Campaign:** Operation Ghost (C0023) – APT29  
**Threat Actor:** APT29 (The Dukes / Cozy Bear)  
**Software Range:** S0511 – S0519  
**Classification:** TLP:CLEAR  
**Submission Date:** 12 May 2026  

---

## 📌 Executive Summary
Operation Ghost (2013–2019) was a long-term espionage campaign by APT29 targeting European foreign ministries and the EU embassy in Washington D.C. The group maintained covert access for six years using modular malware families and advanced stealth techniques such as steganography-based C2.

**Key Findings:**
- **PolyglotDuke → RegDuke → FatDuke/LiteDuke** formed the core malware chain.  
- **Steganography in images** (Twitter, Reddit, Imgur) used to hide C2 addresses.  
- **WellMess & WellMail** deployed in 2020 against COVID-19 vaccine research.  
- **SoreFang** exploited Sangfor SSL VPN appliances.  
- **Pillowmint (FIN7)** and **SYNful Knock (Cisco IOS implant)** were outside APT29 attribution.

---

## 🔍 Campaign Research – Operation Ghost (C0023)
- **Active Period:** 2013–2019  
- **Targets:** European foreign ministries, diplomatic missions, EU embassy (Washington D.C.)  
- **Objective:** Long-term covert espionage and intelligence collection  
- **C2 Infrastructure:** Dead Drop Resolvers via Twitter, Reddit, Imgur, Dropbox API  
- **Discovery:** Documented by ESET in 2019 after six years of activity  

---

## 🛠️ ATT&CK Workflow (Simplified)
1. **Spearphishing Email** → Malicious attachment (T1566.001)  
2. **Execution via rundll32.exe** (T1218.011)  
3. **Dead Drop Resolution** → PolyglotDuke fetches steganographic image (T1102.001)  
4. **Payload Download** → RegDuke implant (T1105)  
5. **Persistence via WMI Event Subscription** (T1546.003)  
6. **Encrypted C2 via Dropbox API** (T1102.002)  
7. **FatDuke Backdoor Deployment** (T1106)  
8. **LiteDuke Redundant Access** (T1008)  
9. **Data Collection** (T1005)  

---

## 🛡️ Detection & Mitigation Highlights
- **Detection Priorities:**  
  - Monitor WMI subscriptions tied to Office processes.  
  - Alert on rundll32.exe loading DLLs from user paths.  
  - Watch for non-browser processes connecting to Dropbox/Twitter/Reddit/Imgur.  
  - Detect DNS TXT tunneling and suspicious TLS certificates.  

- **Mitigation Controls:**  
  - Patch VPN/firewall appliances (SoreFang vector).  
  - Verify Cisco IOS firmware integrity (SYNful Knock).  
  - Restrict LOLBin execution via AppLocker.  
  - Enforce PowerShell constrained language mode.  
  - Apply strict egress filtering and network segmentation.  

---

## 📂 Software Profiles (S0511–S0519)
- **RegDuke (S0511):** First-stage implant, WMI persistence, Dropbox C2.  
- **FatDuke (S0512):** Long-term espionage backdoor, browser impersonation.  
- **LiteDuke (S0513):** Redundant access, steganography, Kaspersky check.  
- **WellMess (S0514):** Cross-platform backdoor, mutual TLS, DNS tunneling.  
- **WellMail (S0515):** Lightweight Golang backdoor, raw TCP over port 25.  
- **SoreFang (S0516):** Downloader exploiting Sangfor SSL VPN.  
- **Pillowmint (S0517):** FIN7 malware, unrelated to APT29.  
- **PolyglotDuke (S0518):** Downloader using steganography for C2 resolution.  
- **SYNful Knock (S0519):** Cisco IOS implant, network-level persistence.  

---

## 🎯 Conclusion
APT29’s Operation Ghost demonstrates nation-state discipline: stealthy persistence, modular malware, and innovative C2 techniques. Correct attribution across software families is essential for accurate CTI analysis and effective defense.

