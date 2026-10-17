# CyberRange: Multi-Attack Simulated Cyber Range (CC6-IC05)

Run: `cd backend && pip install -r requirements.txt && python main.py`, then open http://localhost:8000
(3D runs in any desktop or mobile browser via WebGL; no headset needed. Internet needed once for the Three.js CDN script.)

**New here?** Read [LAYMANS_GUIDE.md](LAYMANS_GUIDE.md) — everything explained in plain English. Inside the app, jargon that appears in the event log also pops up as a small definition cloud over the 3D range.

## Sections of the app
- **Left sidebar — Scenarios by category**: attacks grouped Email / Identity / Network / Data / Endpoint. When a jargon term shows up in the event log, a mini definition floats in as a cloud at the top-right corner of the 3D range — no toggles needed.
- **During a run — session controls (top bar)**: **⏸ Pause / ▶ Resume** (freezes the clock and holds every packet in place, so you can orbit around and inspect each device), **↻ Restart** (same scenario from the top), **✕** (end the session).
- **Centre — 3D range**: drag to orbit, scroll to zoom, click a device to see its role, status, load, traffic and latest activity — then isolate or reconnect it. The device inspector sits in the bottom-right corner of the range and never moves when you orbit the scene.
- **Right — Live view**: traffic graph with a plain-English guide to its three lines, live meters, and the SIEM/event log (a mini security control room).
- **End screen — Score report**: per-action feedback, mistakes, and every missed defence with the reason it mattered.
- **Trainer view (bottom left)** — instructor controls: pause/resume, restart, inject attack surge, skip to the next phase, +15s bonus time, inject a critical SIEM alert, grade & finish now, end session.

## Training (start here)
- **Email training: Genuine / Phishing / Spam** — a 9-email quiz. Classify each mail, get the tell explained (spoofed sender, urgency, look-alike link). Scored out of 300 like the scenarios; **✕** in the corner closes the quiz early and returns you to the range.

## Scenarios (5 + the email game)
- **DDoS** (Network): recon, botnet probe, SYN flood, DNS amplification, sustained peak. Defend a web service; goal is to keep real users served. Trap: "drop ALL inbound traffic".
- **Brute force** (Identity): low-and-slow password spraying on a login portal. Trap: shared passwords.
- **SQL injection** (Data): error-based probing → UNION extraction → blind extraction → destructive `DROP TABLE`. Trap: blanket input blocking.
- **Ransomware** (Endpoint): phishing click → lateral movement → encryption → backup targeting. Trap: pay the ransom.
- **Man-in-the-middle** (Network): ARP poisoning → SSL stripping → credential capture → session hijack. Trap: disable certificate warnings.

## What the backend records
- `logs/siem_events.log` — wall-clock audit trail of every detection, action, isolation and outcome.
- `logs/blocked_traffic.csv` — per-tick arriving/passed/blocked traffic for every run.
- Session log export button in the app downloads your run as text.

## Testing
`tools/run_range_tests.py` plays a scripted full run of every scenario (plus unknown/duplicate actions, isolate/reconnect, trainer surge) and asserts the outcomes:
`test_log_before.txt` (79/79, original 2 scenarios) vs `test_log_after.txt` (205/205, current build).

## Brief coverage
CC6-IC05 — detect, resist and respond to attacks; log and review incidents.

## Target audience and learning outcomes
Security trainees and students. Outcomes: recognise phishing, choose the right
defence for each attack category, understand the router → firewall → IDS/IPS → DMZ →
SIEM chain, and read an incident timeline.
