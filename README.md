# 🛡️ NetShield: Dynamic DNS-Leak Guard & Proxy Enforcer

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?style=for-the-badge&logo=windows)
![Security](https://img.shields.io/badge/Focus-Network%20Security%20%26%20Privacy-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**NetShield** is a lightweight, system-level Windows networking utility engineered to eliminate **Transparent ISP DNS Hijacking**, **UDP Port 53 Leaks**, and **Split-Tunnel Proxy Mismatches**. 

When using residential HTTP/SOCKS proxies or split-tunnel VPNs on Windows, the operating system frequently leaks DNS queries through the local ISP's default gateway via Smart Multi-Homed Name Resolution (SMHNR) and IPv6 fallback. **NetShield** dynamically detects the active proxy tunnel's geolocation and enforces strict, encrypted, geo-aligned DNS resolution across all system adapters.

---

## 🚨 The Problem It Solves

Standard proxy tools and residential VPNs often operate purely at the application or HTTP layer, leaving OS-level UDP traffic unprotected. This leads to:
1. **Transparent DNS Interception:** Local ISPs intercepting standard Port 53 queries and forcing local DNS resolvers, exposing the user's true country/ISP despite an active proxy.
2. **Smart Multi-Homed Name Resolution (SMHNR) Leaks:** Windows querying all available network interfaces simultaneously and accepting the fastest response (usually the local physical router).
3. **IPv6 Routing Leaks:** Unprotected IPv6 stacks bypassing IPv4 proxy tunnels entirely.

---

## ✨ Key Features

* 🔍 **Automated Tunnel & Geo-Scanning:** Actively scans the current outbound IP and ASN of the active residential proxy/VPN tunnel to verify ISP authenticity (Residential vs. Datacenter detection).
* 🔒 **Dynamic Geo-Aligned DNS Enforcement:** Automatically synchronizes system-level DNS resolvers with the target region of the active proxy tunnel, preventing country-mismatch flags on strict anti-fraud systems.
* 🔥 **Kernel/Firewall Port-53 Kill-Switch:** Programmatically configures Windows Advanced Firewall (`netsh advfirewall`) rules to block unauthorized outbound UDP/TCP Port 53 traffic to local ISP gateways.
* 🌐 **SMHNR & IPv6 Neutralization:** Disables Windows Smart Multi-Homed Name Resolution via registry policies and unbinds IPv6 leaks across active physical and virtual network adapters (`ncpa.cpl`).
* ⚡ **One-Click State Restoration:** Includes a clean rollback engine that flushes the DNS cache (`ipconfig /flushdns`) and restores original adapter configurations upon deactivation.

---

## 📊 Verification & Benchmark Results

Tested against industry-standard network fingerprinting and anti-fraud suites (`Whoer`, `IPInfo`, `Scamalytics`):

| Metric | Before NetShield (Default OS + Proxy) | After NetShield Activation |
| :--- | :--- | :--- |
| **Outbound ISP Type** | Residential (Virgin Media / TalkTalk UK) | Residential (TalkTalk UK) |
| **OS DNS Resolution** | ❌ Leaking Local ISP DNS (-30% Penalty) | ✅ 100% Geo-Matched UK DNS |
| **Anonymizer / Blacklist** | No | No (Clean Residential Footprint) |
| **Overall Disguise Score** | **70% (Moderate Risk - Location Exposed)** | **100% (Zero Leaks Detected)** |

---

## 🚀 Getting Started

### Prerequisites
* **OS:** Windows 10 or Windows 11
* **Python:** 3.9+
* **Privileges:** Requires **Administrator** privileges to modify network adapter bindings and Windows Firewall rules.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/builtbyali27/NetShield-DNS-Guard.git
   cd NetShield-DNS-Guard
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch NetShield (as Administrator):**
   Double-click `run_shield.bat` or execute from an elevated terminal:
   ```bash
   python main.py
   ```
