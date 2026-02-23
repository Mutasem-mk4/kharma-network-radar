# Launch Kit: Hacker News & Product Hunt

---

## 1. Hacker News (`Show HN`)

**Title:** `Show HN: Kharma – An open-source, AI-powered network radar that auto-kills malware`

**Body:**
Hey HN,

I built Kharma as a lightweight HIPS (Host Intrusion Prevention System) because I was tired of silent data exfiltration bypassing prompt-based firewalls. 

Standard firewalls trigger when a new executable binds a port, but malware often injects into trusted binaries or uses known ports. Kharma takes a different approach: it continuously polls `psutil.net_connections()`, cross-references originating processes with heuristics (e.g., unsigned binaries, temp folder execution, suspicious parent PIDs), and scores the remote IP via VirusTotal combined with a Geo-Fencing engine.

If a threshold is breached, it actively intervenes: terminating the PID via `os.kill` and invoking `netsh` to isolate the IP.

It comes with a Flask-served web UI (Leaflet.js) to visually map connections in real-time.

It's entirely open-source in Python, deployed via Winget and PyPI. Have a look at the repo and the active defense mechanism code—I'd appreciate feedback from anyone with experience building local IDS/IPS systems.

GitHub: https://github.com/Mutasem-mk4/kharma-network-radar
Website: https://Mutasem-mk4.github.io/kharma-network-radar

Looking forward to your thoughts.

---

## 2. Product Hunt Launch

**Product Name:** Kharma Network Radar
**Tagline:** AI-powered network radar to map, hunt, and kill malware.
**Link:** https://github.com/Mutasem-mk4/kharma-network-radar
**Topics:** Cybersecurity, Developer Tools, Open Source

### Overview Description (First Comment/Maker Comment)

Hey Product Hunt! 👋

I'm Mutasem. I built Kharma because observing network traffic shouldn't require reading endless terminal logs or trusting annoying firewall prompts. I wanted a highly visual, proactive defense system.

Kharma is an open-source, real-time network radar and active defense suite.

**Core Features:**
🔍 **Deep Packet Inspection:** Scans outbound packets for unencrypted credentials or malicious signatures.
🦾 **Auto-Kill Defense:** Detects hostile connections and instantly terminates the underlying process while firewalling the IP.
🌍 **Live Geo-Telemetry:** A stunning glassmorphism dashboard mapping all your system's connections globally.
🛡️ **Terminal & Web UI:** Fast console mode for servers, web dashboard for the desktop.

It's completely free and open source. If you're using Windows, you can install it via: `winget install Mutasem.KharmaEvolution` (or `pip install kharma-radar` for Linux/Mac).

Thanks for checking it out! Let me know if you have any feature requests or questions about the architecture! 🚀

**(Assets Required for PH):**
- **Logo:** High-res Kharma Icon (e.g. your avatar or radar icon)
- **Gallery Images:** 
  1. The Web Dashboard Map (with Toast notifications)
  2. The Terminal UI (showing an Auto-Kill block)
  3. The Forensics Hunt Panel from the web UI.
