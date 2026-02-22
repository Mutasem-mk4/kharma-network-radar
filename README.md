<div align="center">
  <img src="https://img.icons8.com/nolan/256/radar.png" alt="Kharma Logo" width="120" />
  <h1>Kharma_Radar</h1>
  <p><b>The Over-Watch Network Monitor</b></p>
  <p>
    <a href="https://pypi.org/project/kharma-radar/"><img src="https://img.shields.io/pypi/v/kharma-radar?label=PyPI%20Release&color=10b981&style=flat-square" alt="PyPI" /></a>
    <img src="https://img.shields.io/pypi/dm/kharma-radar?color=blue&style=flat-square" alt="Downloads" />
    <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python" alt="Python 3.8+" />
    <img src="https://img.shields.io/github/license/Mutasem-mk4/kharma-network-radar?color=purple&style=flat-square" alt="License MIT" />
    <img src="https://img.shields.io/github/actions/workflow/status/Mutasem-mk4/kharma-network-radar/publish.yml?style=flat-square&label=Security%20Publish" alt="Security Publish" />
  </p>
  <p><i>An elite cybersecurity CLI & Full-Stack Web tool that maps active connections to process IDs, geographical locations, and global threat intelligence feeds in real-time.</i></p>
</div>

---

## 👁️ What is Kharma?

Traditional network monitoring on Linux/Windows requires manually chaining `netstat`, `grep`, `lsof`, and external IP checkers. This is slow and tedious during an incident response.

**Kharma** acts as an all-seeing eye for your operating system. It provides a stunning, high-performance radar that intercepts outbound connections, unmasks the executable initiating the socket, runs the file against 70+ Anti-Virus engines in the cloud, and plots the destination IP on a map—all updated every 2 seconds.

---

## 🔥 Elite Features

- 🌐 **Web UI Dashboard (New in v5.0):** Spawns a hidden Flask backend serving a beautiful, dark-themed HTML/JS Dashboard. View live connections, Geo-locations, and kill malware right from your browser.
- 📡 **Real-Time Visualizer (v10.1):** Live bandwidth tracking per-process and dynamic Chart.js throughput visualization.
- 🌍 **Elite Geo-Fencing (v10.2):** Reactive nation-blocking. Automatically firewall-block entire countries from the dashboard.
- 🔍 **Threat Hunting Mode:** Deep forensic process deep-dives. Extract binary strings, file handles, and metadata with one click.
- 🤖 **AI Behavioral Profiling:** Learning-based anomaly detection. Flags volume spikes and unusual geographic connections using the new `BehaviorEngine`.
- 🐝 **Multi-Node Swarm (v10.5):** Federate multiple Kharma nodes into a single 'Hive' view for global network oversight.
- 🦠 **Enterprise EDR (VirusTotal):** Natively extracts the physical binary path of connected processes (`.exe` / ELF), computes its SHA-256 hash locally, and verifies it against VirusTotal limits.
- ⚔️ **Active Defense (Auto-Kill IPS):** Instantly terminates any process the millisecond it initiates a connection to a known malicious IP (Firehol blocklist) or a flagged binary hash.
- 📄 **Forensic Snapshots:** Generate professional, printable incident reports for any suspicious process activity.
- 🛰️ **Offline Geo-IP Engine:** Built-in `MaxMind GeoLite2` database ensures **0ms lag** when resolving IP coordinates. No external rate limits, 100% privacy.
- 🗄️ **Time Machine Logger:** Silently records all established connections to a local SQLite database (`~/.kharma/kharma_history.db`) for post-incident forensics.
- 🤖 **Background Daemon & Telegram Alerts:** Run `kharma daemon start` to deploy a headless background worker that watches traffic quietly and pushes critical breach alerts dynamically to Telegram. 

---

## 🚀 Installation & Setup

### 🆕 Option 1: Standalone Portable EXE (Easiest)
Download the zero-dependency executable. No Python installation required!
- **Download:** [kharma.exe (v10.1.9)](https://github.com/Mutasem-mk4/kharma-network-radar/releases)
- **Usage:** Just double-click to run or use it from the command line.

### 🆕 Option 2: Smart Windows Installer (Automated)
Don't have Python? Our script will set it up for you using `winget`.
1. Download [setup_windows.bat](file:///c:/Users/User/.gemini/antigravity/scratch/kharma/setup_windows.bat).
2. Right-click and **Run as Administrator**.
3. It will automatically install Python (if missing) and all dependencies.

### Option 3: Standard PyPI Install (For Developers)
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
