# CyberRange explained — in plain English

This guide follows the same shape as the hand sketch: **Training** first (the email
game), then **attacks grouped by category**, then the **defensive chain** every packet
travels through. No jargon without a translation.

---

## 1. Training — the email game

Open the app, click **"Email training: Genuine / Phishing or Spam"** in the left
sidebar. The 3D map disappears and you get a sequence of emails. For each one you pick:

| Your choice | What it means in real life |
|---|---|
| ✅ **Genuine** | A real message from your company or a trusted partner. Safe to act on. |
| 🎣 **Phishing** | A con: someone pretends to be someone you trust to trick you into clicking, paying, or handing over passwords. One carefully aimed email. |
| 🗑 **Spam** | Junk. Annoying, usually harmless bulk mail — ads, scams sent to millions. Delete and move on. |

**The tricky part** is that phishing often *looks* genuine, and spam can look urgent.
After every answer the app tells you the tell: the display name that doesn't match the
real address, the deadline pressure, the "your account closes today" fear, the link
that says one thing but goes somewhere else. Get it wrong and you learn exactly why.

The other four categories on that sketch — **spear phishing** (phishing aimed at one
specific person), **malicious attachments**, **credential harvesting** (fake login
pages that steal your password) — are all variations of the same con, and each of
them shows up inside the game or the scenarios below.

---

## 2. Category-based attacks (the scenarios)

Every scenario is grouped by **where the attack lands** — the same categories as the
sketch. Each button shows a short description — and whenever a jargon term appears
in the event log on the right, a **mini definition pops up in the bottom-right
corner**, so you learn the vocabulary exactly when it matters. No toggles to find.

**Running a session:** while a scenario plays, the top bar has **⏸ Pause / ▶ Resume**
(freeze the clock to discuss), **↻ Restart** (replay the same scenario from the top)
and **✕** (end the session). Trainers get more under **Trainer view** (bottom left):
skip to the next phase, add +15s bonus time, inject an attack surge, inject a
critical alert to triage, or grade and finish early.

### 📧 Email
| Scenario | In lame-man terms |
|---|---|
| **Email training game** | Sort real-looking mail into Genuine / Phishing / Spam (section 1). |


### 🪪 Identity
| Scenario | In lame-man terms |
|---|---|
| **Brute-force attack** | A robot tries thousands of passwords on the login page — one common password against many accounts, slow enough to dodge simple alarms. Defend with lockouts, MFA (a second proof: an app code or fingerprint), and watching for the slow drip. |

### 🌐 Network
| Scenario | In lame-man terms |
|---|---|
| **DDoS attack** | Attackers hijack thousands of machines (a "botnet") and point them all at your website at once, like a million people jamming your shop's doorway so real customers can't get in. You defend with traffic scrubbing (a bouncer filtering the mob), rate limits, and upstream help from your internet provider. Includes a **"drop ALL inbound traffic" trap** — it stops the attack but takes your own service offline too. |
| **Man-in-the-middle** | A hacker secretly sits between two conversations (e.g. your laptop and the Wi-Fi router), reading and altering traffic by pretending to be the router. Defend with 802.1X (only known devices get on the network), dynamic ARP inspection (don't trust "I am the router" claims), and forced HTTPS so even if they listen, the traffic is scrambled. Includes a **"disable certificate warnings" trap**. |

### 💾 Data
| Scenario | In lame-man terms |
|---|---|
| **SQL injection** | Hackers type database commands into a website's search/login boxes. If the site blindly passes them to the database, attackers can read the customer table and even delete it. Defend with input validation, parameterised queries (the site treats typed text as *text*, never as instructions) and firewall virtual patching. |

### 🖥 Endpoint
| Scenario | In lame-man terms |
|---|---|
| **Ransomware** | A booby-trapped email attachment locks everyone's files and demands payment. In the 3D map you watch the infection hop from workstation to workstation, then hit the file server and the backups. Defend with **EPP/EDR** (the bodyguard software on each laptop that can spot and quarantine the infection), **segmentation** (separate "islands" so the worm can't stroll across), and prove your backups still work — because backups are the only guaranteed way to get files back without paying. Includes a **"pay the ransom" trap**: paying teaches attackers your company pays, and there is no guarantee you get your files back. |

**Scoring:** every scenario rewards you for acting *early* and *correctly*, punishes
you for the trap actions, and ends with a report telling you what you missed — every
missed defence comes with the one-line reason it mattered.

---

## 3. The defensive chain (Router → Firewall → IDS/IPS → DMZ → SIEM)

Every packet your company receives travels through these gates **in this order**.
The full list with plain-English definitions is below — the app also floats a mini
definition over the 3D range whenever one of these terms shows up in the event
log:

1. **Router** — the receptionist. Decides which packets are even allowed to enter
   your network from the internet.
2. **Firewall** — the security guard at the door. Reads the address on every packet
   and blocks anything on the banned list, or anything arriving from a suspicious
   place.
3. **IDS / IPS** — the CCTV. An *Intrusion Detection System* watches for burglar-like
   behaviour and raises the alarm (detect); an *Intrusion Prevention System is the
   same camera wired to a lock — it can slam the door shut automatically (prevent).
4. **DMZ** — the shopfront. A separate, locked-down zone where things the public must
   reach (your website) live — so if hackers break in there, they're still far from
   your customer database.
5. **SIEM** — the security control room. Collects every log from every device,
   spots patterns no single device can see ("this login failed 400 times, then
   succeeded from another country"), and pages a human. The red event feed on the
   right of the app *is* a mini SIEM in action.

And below everything: **EPP/EDR** on each laptop or phone — the personal bodyguard
for the endpoint, catching what got past the gates.

---

## 4. Glossary (the app's built-in jargon buster)

The same jargon buster lives inside the app: whenever a technical term appears in
the event log, its plain-English definition floats in as a small cloud at the
**top-right of the 3D range**. Highlights:

- **botnet** — thousands of hijacked computers an attacker rents out
- **zero-day** — a hole in software nobody has fixed yet
- **SIEM** — the log-correlation control room (see chain above)
- **MFA / 2FA** — the "second proof" beyond your password
- **VPN / TLS / HSTS** — ways of wrapping traffic in a lock so eavesdroppers see noise
- **SOC** — the team of humans watching the alerts
- **incident response** — the fire-drill plan for when something actually happens
- **air gap / immutable backup** — physical distance and write-once copies: the two
  things ransomware can't reach

---

## 5. Where the records go

- **Right-hand panel in the app** — the live event log: detections, your actions, points.
- **"Export session log" button** — downloads everything from your session as text.
- **`logs/siem_events.log`** (on the server) — every event from every run, with real
  timestamps: the audit trail a real SOC would review after an incident.
- **`logs/blocked_traffic.csv`** — per-second traffic accounting for every run.
- **`logs/test_log_after.txt`** — the automated proof that all 5 scenarios + the email
  game behave as designed (205 assertions).

Everything in CyberRange is simulated. No real systems are ever contacted.
