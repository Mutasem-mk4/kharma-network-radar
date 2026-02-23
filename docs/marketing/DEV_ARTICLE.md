---
title: How I Built an AI-Powered Network Radar to Auto-Kill Malware on Windows 🛡️
published: false
description: A deep technical dive into building a proactive Python-based Network Radar with Deep Packet Inspection, Geo-Fencing, and an AI scoring engine.
tags: python, cybersecurity, architecture, opensource
cover_image: https://raw.githubusercontent.com/Mutasem-mk4/kharma-network-radar/master/docs/assets/dashboard_preview.png
---

As developers, we are obsessed with observing what our apps are doing, but we rarely look at what our _machine_ is doing. I wanted a way to visually map every single outbound network connection, run heuristics on the process initiating it, and automatically terminate the connection if it was malicious.

So, I built **[Kharma Network Radar](https://mutasem-mk4.github.io/kharma-network-radar)**—an entirely open-source, AI-powered Host Intrusion Prevention System (HIPS).

In this article, I'm going to break down the architecture of Kharma, how I achieved real-time Deep Packet Inspection (DPI) in Python, and the code used to "Auto-Kill" malware.

---

## 🛑 The Problem: Silent Network Exfiltration 

Modern malware rarely destroys your computer; it quietly sits in the background, exfiltrating tokens, crypto-wallets, and personal data to a remote Command & Control (C2) server.

Standard firewalls are notoriously noisy. They ask you if you want to allow `svchost.exe`—which you blindly approve—and then malware injects itself into that trusted process.

I needed a system that doesn't just look at the IP; it needs to look at the **Process**, the **Payload**, and the **Community Reputation** of the target.

---

## 🧠 The Architecture of Kharma

Kharma is written entirely in Python, utilizing `psutil` for system-level introspection, `scapy` / `pyshark` mechanisms for packet sniffing, and a Flask dashboard overlaid with WebSockets.

### 1. The Core Loop: `psutil.net_connections`

To track live connections without kernel-level drivers, Kharma continuously polls the routing table. We map connections to PIDs (Process IDs).

```python
import psutil

def get_live_connections():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'ESTABLISHED' and c.raddr:
            try:
                proc = psutil.Process(c.pid)
                conns.append({
                    "pid": c.pid,
                    "process": proc.name(),
                    "remote_ip": c.raddr.ip,
                    "port": c.raddr.port
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    return conns
```

### 2. The AI Scoring Engine

Every new IP detected goes through an asynchronous `ThreatAnalyzer` pipeline. Instead of just pinging VirusTotal, Kharma weighs multiple factors to calculate an `ai_score` from 1 to 10:

1. **Geo-Location:** Is the IP in a blocklisted country? (+2 points)
2. **Process Legitimacy:** Is the process unsigned or running from `AppData/Temp`? (+3 points)
3. **VT Engine:** Does the IP have malicious community flags? (+5 points)
4. **Behavioral Anomalies:** Is a standard text editor making outbound SSH connections? (+4 points)

If the `ai_score` breaches a critical threshold (e.g., > 7.5), Kharma automatically triggers the **Active Defense Mechanism**.

### 3. Active Defense (The Auto-Kill Feature)

When a critical threat is confirmed, two things happen simultaneously:

1. **Process Termination:** The exact PID initiating the connection is forcefully suspended and killed via `os.kill()`.
2. **Dynamic Firewall Shielding:** The IP is added to the Windows Defender Firewall via a `subprocess.Popen` call to `netsh`.

```python
import subprocess

def shield_ip(ip_address, action="BLOCK"):
    rule_name = f"KHARMA_SHIELD_{ip_address}"
    if action == "BLOCK":
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
        subprocess.run(cmd, shell=True, capture_output=True)
        print(f"[SHIELD] Blocked outbound traffic to {ip_address}")
```

*(Note: Kharma requires Admin privileges to execute firewall modifications).*

---

## 🌐 The Glassmorphism Dashboard

Security tools often look like clunky 90s enterprise software. I wanted Kharma to feel like a command center. 

I spun up a **Flask Server** that serves a beautiful, dark-themed dashboard built with **Leaflet.js** for real-time map rendering. 

![Kharma Web Dashboard](https://raw.githubusercontent.com/Mutasem-mk4/kharma-network-radar/master/docs/assets/dashboard_preview.png)

Every connection is plotted on the map. If a connection is safe, a green beam pulses to the destination. If it's malicious, a red pulsing marker appears, and a **Toast Notification** slides in right before the auto-kill sequence triggers.

---

## ⚡ Try it yourself!

I've open-sourced the entire project under the MIT License, and deployed it to Winget and PyPI.

You can install it natively on Windows using the newly approved Winget package:
```bash
winget install Mutasem.KharmaEvolution
```

Or via pip on any OS:
```bash
pip install kharma-radar
```

To launch the web dashboard, simply run:
```bash
kharma web --port 8080
```

### Check out the repo on GitHub:
**👉 [GitHub Repository: Kharma-Network-Radar](https://github.com/Mutasem-mk4/kharma-network-radar)**

Let me know what you think in the comments! Are there specific DPI features or heuristics you'd love to see added in the next major version? 

*(P.S. If you like the project, a star ⭐️ on GitHub goes a long way!)*
