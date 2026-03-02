<div align="center">
  <img src="https://img.icons8.com/nolan/256/radar.png" alt="Kharma Logo" width="120" />
  <h1>Kharma Sentinel</h1>
  <p><b>Elite Proactive Defense & Enterprise-Grade Network Intelligence</b></p>
  <p>
    <a href="https://pypi.org/project/kharma-radar/"><img src="https://img.shields.io/pypi/v/kharma-radar?label=PyPI%20Release&color=10b981&style=flat-square" alt="PyPI" /></a>
    <img src="https://img.shields.io/pypi/dm/kharma-radar?color=blue&style=flat-square" alt="Downloads" />
    <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python" alt="Python 3.8+" />
    <img src="https://img.shields.io/github/license/Mutasem-mk4/kharma-network-radar?color=purple&style=flat-square" alt="License MIT" />
  </p>
  <p><i>Kharma Sentinel is an elite, proactive network defense suite designed to eliminate 'blind spots' in system visibility. It transforms raw network data into actionable security intelligence using real-time radar mapping, behavioral analysis, and automated threat neutralization.</i></p>
</div>

---

## 🛡️ The Evolution of Defense

Kharma is not just a monitor; it's an **Active Defense System**. It acts as an all-seeing eye for your operating system, providing a stunning, high-performance radar that intercepts outbound connections, unmasks the executable initiating the socket, runs it against 70+ Anti-Virus engines in the cloud, and plots targets on a global map—all updated every 2 seconds.

---

## 🔥 Elite Features

- 🌐 **Evolution Web Dashboard:** A stunning glassmorphism interface serving real-time radar data, bandwidth charts, and security event logs.
- 📡 **Deep Packet Inspection (DPI):** Real-time protocol detection and signature matching to catch SQLi, XSS, and anomalous payloads.
- 🌍 **Elite Geo-Fencing:** Reactive nation-blocking. Automatically firewall-block entire countries from the dashboard with one click.
- 🦠 **Enterprise EDR (VirusTotal):** Natively extracts binary paths, computes SHA-256 hashes, and conducts cloud-based malware validation.
- ⚔️ **Active Defense (Auto-Kill):** Instantly terminates processes that connect to known malicious IPs or match flagged binary hashes.
- 🤖 **Guardian Bot Alerts:** Push critical breach alerts dynamically to Telegram or Discord as they happen.
- 🐝 **Multi-Node Swarm:** Federate multiple Kharma nodes into a single 'Hive' view for global enterprise oversight.
- 🛰️ **Offline Geo-IP Engine:** Powered by `MaxMind GeoLite2` for **0ms lag** resolution and 100% privacy.
- 🗄️ **Time Machine Forensics:** Persistent SQLite logging for detailed post-incident analysis and reporting.
---

## 🚀 Installation & Setup

### ⚡ One-Click Installer (Recommended)
The fastest way to get started. Automatically handles environment setup and dependencies.

**Windows (PowerShell):**
```powershell
iwr -useb https://raw.githubusercontent.com/Mutasem-mk4/kharma-network-radar/main/install_sentinel.ps1 | iex
```

**Linux/macOS (Bash):**
```bash
curl -sSL https://raw.githubusercontent.com/Mutasem-mk4/kharma-network-radar/main/install_sentinel.sh | bash
```

### 🆕 Option 2: Standalone Portable EXE
Download the zero-dependency executable. No Python installation required!
- **Download:** [kharma.exe (v11.0.1)](https://github.com/Mutasem-mk4/kharma-network-radar/releases)

### Option 3: Developer Install (via PyPI)
```bash
pip install kharma-radar
```
*If `pip` is not recognized, try:* `python -m pip install kharma-radar`

---

## 💻 Quick Start Guide

Kharma is an intelligent CLI that relies on the incredibly styled `rich-click` interface. Run `kharma --help` at any time.

| Command | Description |
|---|---|
| `kharma run` | Start the Live Network Radar Dashboard in the Terminal. |
| `kharma run --protect` | Start Dashboard + **Auto-Kill Malware** (Active Defense). |
| `kharma web` | Launch the Dark Web UI Dashboard (Localhost). |
| `kharma daemon start` | Deploy the silent Background Monitor. |
| `kharma history` | View historical connections (Time Machine). |
| `kharma config vt <KEY>` | Register a free VirusTotal API Key for advanced EDR. |

### 🌍 The Web UI Dashboard
Get the ultimate Full-Stack experience visually tracking your network:
```bash
root@linux:~# kharma web --port 8080
[*] Initializing Kharma Web Dashboard...
[*] Spawning background data scanner loop...
[*] Dashboard launched at: http://127.0.0.1:8080
```
*(Simply open your browser to the URL and watch the data flow!)*

---

## 🏗️ Architecture

Kharma is designed for maximum performance, minimal dependencies, and absolute oversight.

- **Frontend:** `rich` (Terminal TUI) & `Tailwind.css + JavaScript` (Web UI).
- **Backend Core:** `psutil` (Socket Hooks), `Flask` (REST API).
- **Persistence:** Local `SQLite` for logging and `.mmdb` for GeoIP lookups.

---

---

## 🛠️ Troubleshooting

### 1. "'pip' or 'kharma' is not recognized..." (Windows)
This means Python is not in your System PATH.
- **Fix:** Re-install Python and check **"Add Python to PATH"** in the installer.
- **Quick Workaround:** Use `python -m pip install kharma-radar` and `python -m kharma`.

### 2. "Python was not found..."
You might have the "Windows App Execution Aliases" enabled.
- **Fix:** Go to **Manage App Execution Aliases** in Windows settings and turn **OFF** the aliases for `python.exe` and `python3.exe`.

---

## 🛡️ Disclaimer
*Kharma is developed strictly for educational purposes, system administration, and defensive cybersecurity operations. The author is not responsible for any misuse or damage caused by terminating critical system processes via the Auto-Kill features.*

<div align="center">
  <b>Developed by Mutasem</b><br>
  <i>Cybersecurity & Software Engineer</i>
</div>
