# Kharma Reddit Launch Strategy

Here are 3 tailor-made Reddit posts. **Do not spam them all at the same time.** Post one, wait a day, then post to the next. Tailoring the message to the subreddit ensures it won't get removed.

---

## 1. Subreddit: `r/Python`
**Title:** I built an AI-powered Network Radar in Python that auto-kills malware via DPI and psutil
**Body:**
Hey Pythonistas,

I wanted a way to visually map every outbound connection on my machine without constantly staring at standard clunky firewalls. More importantly, I wanted something that actively hunts bad processes. 

So I wrote **Kharma Network Radar**—an entirely open-source Host Intrusion Prevention System written in Python.

**How it works under the hood:**
- It uses `psutil` to map `net_connections` to their originating `pid`.
- It performs asynchronous VirusTotal hash checks and Geo-IP lookups.
- And then scores the connection using an AI heuristic engine (flags processes running from `Temp`, unsigned binaries, bad countries).
- If the score breaches `7.5/10`, it uses `os.kill` and a `subprocess` to `netsh advfirewall` to isolate the IP.

The web dashboard is spun up using Flask and WebSockets for real-time `Leaflet.js` mapping and Toast Notifications.

It's completely free and open-source. Just ran my first major release on PyPI and Winget, so you can install it easily.

`pip install kharma-radar`

Would love some code review from the community on the `psutil` polling logic or the DPI setup!
👉 Repo is here: **[Mutasem-mk4/kharma-network-radar](https://github.com/Mutasem-mk4/kharma-network-radar)**

---

## 2. Subreddit: `r/cybersecurity`
**Title:** Why rely on prompt-based firewalls? I built an open-source Network Radar that auto-kills malicious C2 connections in real-time.
**Body:**
Hello r/cybersecurity,

Standard Windows Defender and firewalls are often incredibly noisy. They ask the user if they want to allow an executable, the user blindly clicks "Yes," and then malware gets a free pass to export tokens to a remote C2. 

I was tired of this, so I built **Kharma Network Radar** to proactively stop this.

Kharma is an AI-powered Active Defense Suite. It continuously polls network sockets and performs Deep Packet Inspection to catch data exfiltration.

It scores the remote connection on 4 pillars:
1. Location (Is it a known hostile ASN?)
2. Community reputation (VirusTotal / flags)
3. Process heuristics (Is it a script running in memory without an executable path?)
4. DPI signatures

If a connection is determined hostile, Kharma instantly terminates the PID and adds an outbound block rule to the firewall. 

You can launch a live UI map of all your connections (`kharma web --port 8080`).

We just got approved on Winget: `winget install Mutasem.KharmaEvolution`.

I'm looking for feedback from blue teamers. What other heuristic flags should an IDS/IPS look for locally?
👉 GitHub: **[Mutasem-mk4/kharma-network-radar](https://github.com/Mutasem-mk4/kharma-network-radar)**

---

## 3. Subreddit: `r/SideProject`
**Title:** I got tired of silent malware, so I built a beautiful Desktop App that maps and kills malicious network connections.
**Body:**
Hey r/SideProject,

I wanted to know exactly which apps on my computer were "phoning home", and to where. So I built an open-source cybersecurity suite called **Kharma Network Radar**.

It's a terminal tool with a beautiful Glassmorphism Web Dashboard that gives you a "god view" of your network.

**Tech Stack:**
- Python (`psutil`, `scapy`) for the backend core
- Flask for the web server
- Vanilla JS, Leaflet.js, and Lucide Icons for the frontend.

It auto-kills malicious processes and isolates the IP via firewall instantly.

Just launched V10.2! Would love to hear what you guys think about the UI and the concept.
👉 GitHub: **[Mutasem-mk4/kharma-network-radar](https://github.com/Mutasem-mk4/kharma-network-radar)**
👉 Live Preview: **[Website](https://Mutasem-mk4.github.io/kharma-network-radar)**
