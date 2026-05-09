# 🛡️ SentinelShield IDS/WAF

> **A highly robust, heuristic-based Intrusion Detection System (IDS) and Web Application Firewall (WAF) featuring real-time telemetry, advanced threat parsing, and an active IPS blocklist.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://www.python.org/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/sarandeeps1ngh/SentinelShield-Advanced-Intrusion-Detection-Web-Protection-System)

---

## 📖 Overview

Modern web layers face a constant barrage of automated reconnaissance, brute-force floods, and sophisticated injection payloads. This project provides a lightweight, highly configurable security middleware that actively traps malicious traffic before it reaches your core application logic. 

Coupled with a **Unified SOC Dashboard**, it provides blue teamers and security analysts with absolute visibility into live attack distributions, raw payload metrics, and immediate mitigation controls.

---

## ✨ Key Features

* **🧠 Advanced Heuristic Engine:** Parses multi-part inputs to detect syntax anomalies, high symbol densities, and exact signature markers for `SQLi`, `XSS`, `CMDi`, `LFI`, and automated `DDoS` floods.
* **🛑 Active IPS Blocklist (Jail):** Automatically identifies aggressive scanning behavior (such as missing `User-Agent` headers or unauthorized directory enumeration) and drops malicious origins into a customizable time-locked penalty box.
* **🍯 Dynamic Honeypot Routing:** Employs decoy endpoints (`/.env`, `/wp-admin`, `/backup.sql`) to safely string automated scanners along while gathering comprehensive attacker profiling metrics.
* **📊 Unified SOC Dashboard:** A responsive, live-updating monitoring console featuring anti-caching polling sockets, visual attack distribution charts, and direct one-click IP release controls.
* **📥 Standardized CSV Reporting:** Seamlessly export live incident telemetry for offline forensic auditing or external SIEM compliance.

---

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.8 or newer installed.

# Clone the repository
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name

# Create a clean virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
Running the Engine
Launch the primary WSGI/Flask security engine:

Bash
python app.py
Target Application Portal: http://127.0.0.1:5000/

Live SOC Dashboard: http://127.0.0.1:5000/dashboard

🧪 Verifying Defenses (Test Flights)
You can verify the active detection capabilities using standard penetration testing tools directly from your terminal.

1. Triggering the Reconnaissance Alarm
Run a standard Nmap service version scan against the portal:

Bash
nmap -sV -p 5000 127.0.0.1
Result: The engine traps the raw socket probe (identifying the missing User-Agent signature typical of automated scanners), registers a SCAN alert, and drops the origin IP into the Active IPS Blocklist.

2. Testing Injection Payloads
Submit malicious syntax via URL parameters or direct form entries:

Plaintext
admin' OR 1=1 --
Result: The heuristic math catches the short-string bypass attempt, logs the exact parameter risk score, and immediately serves a 403 Forbidden restriction.

📂 Repository Structure
Plaintext
├── app.py                   # Core engine, WAF middleware, and API endpoints
├── requirements.txt         # Project dependencies (Flask, Requests, etc.)
├── security.log             # Disk read/write telemetry event log
├── threat_feed.json         # Hot-patchable virtual signatures and blacklists
└── templates/
    ├── index.html           # Interactive target validation portals
    └── dashboard.html       # Anti-caching Unified SOC Dashboard interface
⚠️ Educational Disclaimer
This repository is developed strictly for educational research, defensive framework engineering, and authorized local testing environments. The author assumes no liability for unauthorized deployment or misconfiguration on production networks. Always ensure you have explicit written consent before actively probing external infrastructure.

📜 License
This project is licensed under the MIT License - see the LICENSE file for details. Feel free to fork, modify, integrate, and adapt this framework into your own defensive pipelines.

👨‍💻 Author
Sarandeep Singh Cybersecurity Researcher & Framework Developer
