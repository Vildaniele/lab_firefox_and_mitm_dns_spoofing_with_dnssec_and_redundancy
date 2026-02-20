# DNS Security Evolution: From MITM Spoofing to DNSSEC & Redundancy

This repository contains a comprehensive set of network security laboratories developed using **Kathara**. The project simulates the evolutionary path of a DNS infrastructure: starting from a vulnerable network prone to DNS Spoofing and Phishing, implementing modern cryptographic defenses via **DNSSEC**, and concluding with an enterprise-grade setup featuring **Full Redundancy** and Master/Slave synchronization.

## 📌 Project Overview
The objective of these labs is to analyze the critical role of DNS security in modern networking. We simulate a realistic interaction between a client (Firefox) and a University web portal (`uniroma3.it`), demonstrating how vulnerabilities can be exploited and subsequently mitigated.

### Key Learning Objectives
- **Protocol Analysis**: Understanding standard DNS vs. DNSSEC.
- **Offensive Security**: Implementing Man-in-the-Middle (MITM) attacks using Scapy.
- **Defensive Configuration**: Establishing a complete DNSSEC Chain of Trust (Root -> IT -> Uniroma3).
- **High Availability**: Configuring BIND9 zone transfers (AXFR) and redundant backbone routing.

---

## 🌐 Network Architecture
The infrastructure is composed of several logical segments:
- **University LAN**: Legitimate servers (`uniromatre`) and Authoritative DNS (`dnsuni`).
- **Resolver LAN**: A local DNS Resolver (`pc4`) serving the end-user.
- **Backbone**: Multi-homed core network with redundant paths (LAN C and LAN G).
- **Attacker Segment**: The `evil` network used to host phishing pages and launch injection scripts.

---

## 🔬 Scenario Details

### 1. Basic DNS MITM & Phishing (The Vulnerability)
*Folder: `01-basic-mitm/`*
- **The Threat**: Lack of origin authentication in standard DNS.
- **The Attack**: Router `r2` intercepts DNS queries for `uniroma3.it`. A Scapy-based script (`r2_attack.py`) sends a forged response pointing to the `evil` server.
- **Phishing Mechanism**: The `evil` server hosts a cloned portal. Once credentials (Matricola/Password) are entered, the PHP backend logs them and performs a **Seamless Auto-POST** to the real university site, making the attack invisible to the user.

### 2. DNSSEC Defense (The Mitigation)
*Folder: `02-dnssec-defense/`*
- **The Defense**: Implementation of **DNSSEC** (Domain Name System Security Extensions).
- **Mechanism**: All zones are signed using BIND9's `dnssec-policy`. The resolver (`pc4`) is configured as a **Validating Resolver** with a static Trust Anchor for the Root.
- **Outcome**: When the attacker attempts to inject the forged DNS record, the signature verification fails. The resolver returns a `SERVFAIL` to the client, preventing access to the malicious site.

### 3. Enterprise Redundancy (High Availability)
*Folder: `03-full-redundancy/`*
- **The Goal**: Service resilience and reliability.
- **Configuration**:
    - **Master/Slave DNS**: `dnsuni` (Master) and `dnsuni2` (Slave) use `NOTIFY` and `AXFR` for zone synchronization.
    - **Redundant Root**: Multiple root hints configured on the resolver.
    - **Backbone Failover**: Integration of router `r3` and a secondary backbone path (LAN G) to ensure connectivity even during link failure.
- **Outcome**: A robust infrastructure that maintains both high security (DNSSEC) and high availability.

---

## 🚀 How to Run

### Prerequisites
- [Kathara Framework](https://www.kathara.org/)
- [Docker](https://www.docker.com/)

### Deployment
1. Navigate to the desired scenario directory:
   ```bash
   cd 03-full-redundancy
Start the laboratory:
code
Bash
kathara lstart
Access the nodes:
Firefox (Client): Open your browser at http://localhost:3001
Wireshark: Open http://localhost:3000 to monitor traffic on the bridged interfaces.
🛠 Technical Stack
DNS Suite: BIND9 (ver. 9.16)
Web Stack: Apache2 + PHP 7.4
Attack Scripting: Python 3 + Scapy
Traffic Capture: Wireshark (containerized)
Client: Linuxserver/Firefox (Web-based VNC)
📝 Implementation Notes
DNSSEC Signing: Zones are signed dynamically. The parent-child relationship (DS records) is established during the .startup phase using dnssec-dsfromkey.
Phishing Logic: The evil/index.php is designed to be a "wrapper" that captures data before forwarding the user to the legitimate destination.
Routing: Static routing is implemented across all routers to simulate a multi-autonomous system environment.
⚖️ License & Credits
This lab is for educational purposes only.
Style inspired by: RicGobs
Author: [Your Name/Handle]
