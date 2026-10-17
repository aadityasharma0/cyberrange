"""CyberRange: simulated cyber-attack range. Nothing real is attacked; all traffic is modelled.

Scenarios: DDoS, brute force, SQL injection, ransomware, man-in-the-middle.
The backend also keeps two audit logs under logs/ (appended, never truncated):
  * siem_events.log      - every detection / action / milestone, wall-clock stamped
  * blocked_traffic.csv  - per-tick attack traffic vs what the defences blocked
"""
import asyncio, csv, io, os, random, re
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

DT, DUR, MAXS = 0.5, 70, 300
N = lambda i, l, t, x, y, z, r="": dict(id=i, label=l, type=t, x=x, y=y, z=z, role=r)
E = lambda *p: [dict(s=a, t=b) for a, b in p]

# --- server-side audit logging ------------------------------------------------
# CYBERRANGE_LOGDIR is set by the packaged (exe/app) launcher so the audit
# trail lands in a writable per-user folder; plain `python main.py` still
# writes to the project's logs/ directory.
LOGDIR = Path(os.environ.get("CYBERRANGE_LOGDIR") or Path(__file__).resolve().parent.parent / "logs")
LOGDIR.mkdir(parents=True, exist_ok=True)
SIEM_LOG = LOGDIR / "siem_events.log"
BLOCK_LOG = LOGDIR / "blocked_traffic.csv"
_wall = lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _line(path, text):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass

def _csv_row(vals):
    buf = io.StringIO()
    csv.writer(buf).writerow(vals)
    return buf.getvalue().rstrip("\r\n")

def _level(msg):
    if re.search(r"BREACH|SLA |CRITICAL|DROP TABLE|encryption started|recovery points|hijack", msg, re.I):
        return "CRITICAL"
    if re.search(r"^SIEM|possible|in progress|attempt|spike|anomal|mismatch|downgrade|beacon", msg, re.I):
        return "WARNING"
    return "INFO"

def siem(kind, t, msg):
    _line(SIEM_LOG, f"{_wall()} [{_level(msg)}] scenario={kind} t={t:5.1f}s {msg}")

if not BLOCK_LOG.exists() or BLOCK_LOG.stat().st_size == 0:
    _line(BLOCK_LOG, _csv_row(["wall_time", "scenario", "t", "phase", "legit_users",
                               "attack_arriving", "attack_passed", "attack_blocked",
                               "blocked_pct", "score", "isolated_nodes"]))

KINDS = {
 "ddos": dict(name="DDoS: SYN flood + DNS amplification", desc="SYN flood + DNS amplification on a web service", start=6,
  nodes=[N("botnet","Botnet (C2)","attacker",-8,0,0,"Controls zombie hosts"), N("dns","Open DNS resolver","server",-5,2.5,0,"Misconfigured recursion"),
         N("users","Real users","users",-6,-3,1,"Legitimate customers"), N("firewall","Firewall","firewall",-2.5,0,0,"SYN backlog"),
         N("lb","Load balancer","router",0.5,0,0,"Edge link"), N("web1","Web 1","server",3.5,1.6,0), N("web2","Web 2","server",3.5,-1.6,0),
         N("db","Database","database",6.5,0,0), N("scrub","Scrubbing CDN","monitor",0.5,3.2,-1,"Upstream scrubbing")],
  edges=E(("botnet","firewall"),("dns","firewall"),("users","firewall"),("firewall","lb"),("lb","web1"),("lb","web2"),("web1","db"),("web2","db"),("lb","scrub")),
  phases=[(0,"Reconnaissance"),(6,"Botnet probe"),(14,"SYN flood"),(30,"DNS amplification"),(45,"Sustained peak")],
  actions={"block_ip":("Block C2 IP","Null-route the controller (botnet/spoofed traffic still arrives)",10,"One IP block barely helps: botnet and spoofed sources are distributed."),
   "syn_cookies":("SYN cookies + rate limit","Strong vs SYN flood, drops ~5% of real users",25,"SYN cookies avoid storing half-open connections, so the backlog cannot be exhausted."),
   "close_resolver":("Close open DNS recursion","Removes the amplification vector",30,"Open resolvers make reflection attacks possible; closing recursion removes ~60% of peak volume."),
   "scrubbing":("Enable scrubbing CDN","Ramps up over ~6s, ~2% collateral",35,"Scrubbing absorbs volumetric floods upstream of your own links."),
   "isp_filter":("Ask ISP to filter upstream","Slow (~10s), some collateral",20,"Only upstream providers can stop floods larger than your own link."),
   "cdn_cache":("Serve from CDN cache","Web capacity x2.5",15,"Caching keeps the site usable for real users under load."),
   "report":("Report incident","Escalate to SecOps",10,"Escalation brings in the ISP, CDN and management early."),
   "drop_all":("Drop ALL inbound traffic","Emergency kill-switch (trap)",-20,"Dropping everything stops the attack but also takes your own service offline.")}),
 "brute": dict(name="Brute-force / password spraying on the login portal", desc="Password spraying on a login portal", start=5,
  nodes=[N("attacker","Attacker","attacker",-8,0,0,"Credential-guessing tool"), N("users","Real users","users",-6,-3,1,"Legitimate logins"),
         N("firewall","Firewall / WAF","firewall",-3,0,0), N("login","Login portal","server",1,0,0,"SSH / web login"),
         N("dir","Directory (accounts)","database",4.5,1.8,0), N("data","Customer data","database",4.5,-1.8,0,"Crown jewels")],
  edges=E(("attacker","firewall"),("users","firewall"),("firewall","login"),("login","dir"),("dir","data")),
  phases=[(0,"Quiet"),(5,"Low-and-slow probing"),(12,"Password spraying"),(28,"Distributed brute force")],
  actions={"block_ip":("Block attacker IP","Strong for ~12s, then the attacker rotates IPs",10,"IP blocks are easily evaded by rotating proxies."),
   "login_throttle":("Login throttling","Delay after each failure, ~2% collateral",25,"Throttling makes each guess slower, killing brute-force economics."),
   "lockout":("Account lockout policy","Lock after 5 fails, ~3% legit lockouts",20,"Lockouts stop guessing but can be abused to lock real users out."),
   "captcha":("CAPTCHA on login","Stops ~60% of bots",15,"CAPTCHA raises the cost of automation."),
   "mfa":("Enforce MFA","A cracked password alone no longer gives access",40,"MFA is the single best control: stolen or guessed passwords stop being enough."),
   "force_reset":("Force reset of weak passwords","Resets progress, passwords 4x harder",30,"Weak and default passwords are what brute force actually finds."),
   "revoke":("Revoke sessions / contain breach","Stops data exfiltration",20,"After a breach, killing sessions limits the damage."),
   "report":("Report incident","Escalate to SecOps",10,"Escalation brings in IR support early."),
   "disable_login":("Disable the login service","Emergency kill-switch (trap)",-20,"This stops the attack by taking your own login offline.")}),
 "sqli": dict(name="SQL injection on the customer portal", desc="UNION & blind SQL injection stealing customer data", start=6,
  nodes=[N("attacker","SQLi attacker","attacker",-8,0,0,"Automated injection tool"), N("users","Real users","users",-6,-3,1,"Legitimate customers"),
         N("waf","WAF","firewall",-3,0,0,"Payload inspection"), N("web","Customer portal","server",1,0.8,0,"Unparameterised query"),
         N("api","API tier","server",1,-1.8,-0.4,"Read-only endpoints"), N("db","Customer database","database",5.5,0,0,"PII + payment data"),
         N("siem","Query audit logs","monitor",1,3,-1,"SIEM / DB logging")],
  edges=E(("attacker","waf"),("users","waf"),("waf","web"),("waf","api"),("web","db"),("api","db"),("web","siem"),("api","siem")),
  phases=[(0,"Reconnaissance"),(6,"Error-based probing"),(14,"UNION-based extraction"),(30,"Blind extraction"),(48,"Destructive queries")],
  actions={"block_ip":("Block source IP","Rotating proxies bypass it quickly",10,"Injection tools rotate sources; an IP block only buys minutes."),
   "waf":("Enable WAF virtual patching","Blocks payload signatures, ramps ~6s, ~2% collateral",30,"A WAF stops known injection patterns at the edge, before they reach the application."),
   "param_queries":("Parameterised queries","Removes the vulnerability itself",40,"Prepared statements make user input data, never code: the whole injection class is gone."),
   "db_least_priv":("Least-privilege DB account","App can read but not drop or alter",25,"Even a successful injection cannot drop tables or read what the application never queries."),
   "error_sanitize":("Custom error pages","Blinds error-based extraction, ~10% slower",15,"Hiding SQL errors denies the attacker the feedback loop they read data through."),
   "input_validation":("Strict input validation","Allow-list types and lengths, ~2% collateral",20,"Validating input early removes the strings the attack depends on."),
   "rate_limit":("Rate-limit queries","Caps extraction speed, ~1% collateral",15,"Extraction is thousands of tiny queries; a rate limit caps how much can leave per minute."),
   "rotate_creds":("Rotate DB credentials + audit","Invalidate anything already stolen",20,"Rotating credentials after containment evicts anyone who already obtained them."),
   "report":("Report incident","Escalate to SecOps",10,"Escalation brings incident response, forensic logging and DBA support in early."),
   "offline":("Take the portal offline","Emergency kill-switch (trap)",-20,"Pulling the app stops the attack but also stops every customer from using the service.")}),
 "ransom": dict(name="Ransomware outbreak after a phishing click", desc="Encryption worm spreading from one workstation", start=4,
  nodes=[N("attacker","Phishing / C2 broker","attacker",-8,0,0,"Delivers the payload"), N("users","Staff (unaffected)","users",-6,-3,1,"Everyone else"),
         N("firewall","Email + internet edge","firewall",-4,0,0), N("ws1","WS-1 (infected)","workstation",-1.2,1.7,0,"Patient zero"),
         N("ws2","WS-2 (healthy)","workstation",-1.2,-1.7,0,"Lateral-movement target"),
         N("fs","File server FS-01","database",2.6,1.7,0,"Shared documents"), N("dc","Domain controller","server",2.6,-1.7,0,"Accounts"),
         N("backup","Backup / recovery","monitor",6,0,0,"Immutable offline copies")],
  edges=E(("attacker","firewall"),("users","firewall"),("firewall","ws1"),("firewall","ws2"),("ws1","fs"),("ws1","dc"),("ws2","fs"),("fs","dc"),("dc","backup")),
  phases=[(0,"Initial access"),(8,"Lateral movement"),(22,"Encryption begins"),(45,"Backup targeting")],
  actions={"block_ip":("Block C2 domain / IP","Stops fresh payloads, not the active infection",10,"Blocking the broker stops new downloads but the already-infected host keeps encrypting."),
   "edr_isolate":("EDR containment of WS-1","Cuts the infected host off, ramps ~4s",30,"Network isolation of the infected endpoint stops both encryption and spread at the source."),
   "segment":("Segment network / block east-west SMB","Stops spread between workstations and servers",25,"Segmentation denies the worm the lateral paths it needs to reach new machines."),
   "offline_backup":("Verify offline / immutable backups","Makes recovery certain if applied in time",30,"Offline immutable backups are the difference between an incident and a catastrophe."),
   "patch":("Patch the exploited vulnerability","Removes the escalation path",20,"Unpatched internal weaknesses are how a single click becomes domain-wide encryption."),
   "macro_filter":("Block macros / quarantine phishing","Stops the initial access vector",15,"Email filtering and macro policy stop the click that starts the whole chain."),
   "restore":("Restore from verified backup","Recovers encrypted data (needs intact backups)",25,"Restoring from immutable backups beats negotiating: recovery becomes a process, not a gamble."),
   "report":("Report incident","Escalate to SecOps / IR retainer",10,"Escalation brings forensics, negotiation support and recovery crews in early."),
   "pay_ransom":("Pay the ransom","Emergency gamble (trap)",-20,"Payment funds attackers, marks you as a target, and data is rarely returned intact.")}),
 "mitm": dict(name="Man-in-the-middle: ARP spoofing on the LAN", desc="ARP poisoning, SSL stripping and credential theft", start=4,
  nodes=[N("attacker","Rogue laptop","attacker",-8,0,0,"ARP spoofer on the LAN"), N("users","Clients (LAN)","users",-6,-3,1,"Employees' machines"),
         N("switch","Access switch","firewall",-3,0,0,"Port security / SPAN"), N("gateway","Gateway","router",0.5,0,0,"Default route"),
         N("server","Login service","server",4,1.6,0), N("pki","PKI / certificate monitor","monitor",4,-1.6,0,"Cert issuance + anomalies")],
  edges=E(("attacker","switch"),("users","switch"),("switch","gateway"),("gateway","server"),("server","pki")),
  phases=[(0,"Network recon"),(6,"ARP poisoning"),(18,"SSL stripping"),(34,"Credential capture"),(52,"Session hijack")],
  actions={"block_ip":("Block rogue host","Attacker re-joins from a new MAC/IP",10,"Port-blocking one MAC buys minutes: attackers simply re-ARP from new hardware or a spoofed address."),
   "arp_inspection":("Dynamic ARP inspection + static ARP","Stops the poisoning itself, ramps ~5s",35,"Dynamic ARP inspection validates ARP against DHCP bindings, so spoofed replies are dropped at the switch."),
   "enforce_tls":("Enforce TLS 1.2+ / HSTS / pinning","Intercepted traffic stays encrypted",30,"Even a fully redirected client sends only ciphertext: stripping attacks need the downgrade to work."),
   "nac_8021x":("802.1X network access control","Rogue devices cannot join at all",25,"802.1X authenticates the device before it gets a port, removing the rogue laptop from the LAN."),
   "reset_sessions":("Force password + session reset","Invalidates everything already captured",20,"Resetting credentials and sessions evicts an attacker who already recorded them."),
   "port_security":("Switch port security / DHCP snooping","Limits per-port MACs, ~1% collateral",15,"Limiting MACs per port and snooping DHCP replies starves classic LAN spoofing."),
   "ids":("Enable IDS on the SPAN port","Detects spoofing patterns, ~5s to alert",15,"An IDS watching the mirror port sees duplicate MACs and gateway ARP mismatches immediately."),
   "report":("Report incident","Escalate to SecOps",10,"Escalation brings network and SOC support to hunt the rogue device."),
   "ignore_cert":("Disable certificate warnings","Emergency 'convenience' (trap)",-20,"Clicking through certificate warnings hands the attacker exactly the interception you were preventing.")}),
}
GOOD_ISO = {"ddos": {"botnet", "dns"}, "brute": {"attacker"}, "sqli": {"attacker"},
            "ransom": {"attacker", "ws1"}, "mitm": {"attacker"}}

# --- plain-English layer: categories, one-liners, glossary, defensive chain ---
# category groups the scenario list in the sidebar (sectionalised by attack surface)
META = {
 "ddos":  ("Network",  "A mob of fake visitors blocks your door so real customers can't get in."),
 "mitm":  ("Network",  "An eavesdropper pretends to be your network and reads everything passing through."),
 "sqli":  ("Data",     "Sneaky code typed into a search box makes the database hand over customer data."),
 "brute": ("Identity", "Somebody tries thousands of passwords on the front door until one works."),
 "ransom":("Endpoint", "One clicked email locks every shared file and demands a payment."),
}

ACTION_PLAIN = {
 "ddos": {"block_ip": "Ban the caller-ID of one attacker - but the mob has millions of fake IDs, so it barely helps.",
  "syn_cookies": "Let the door note handshakes on paper instead of holding them open, so it can't be jammed.",
  "close_resolver": "Stop your open servers from shouting answers at strangers - attackers used them as megaphones.",
  "scrubbing": "Send attack traffic through a cleaning service upstream so only the dirt arrives at you.",
  "isp_filter": "Ask your internet provider to stop the flood before it ever reaches your line.",
  "cdn_cache": "Serve saved copies of your pages so your own servers do far less work.",
  "report": "Tell your security team and provider - an early call brings help before damage spreads.",
  "drop_all": "Panic button: slam every door shut. The attack stops - and so does your business."},
 "brute": {"block_ip": "Ban one address; the guesser just switches to another one.",
  "login_throttle": "Make the site pause after each wrong password, so guessing takes forever.",
  "lockout": "Lock an account after 5 wrong tries - but attackers can abuse it to lock out real staff.",
  "captcha": "Ask a quick 'are you human?' puzzle - robots fail it.",
  "mfa": "Require a second proof (a code on your phone), so a stolen password isn't enough.",
  "force_reset": "Make everyone change weak passwords now, wiping out the attacker's progress.",
  "revoke": "Kick out every signed-in session - like changing the locks after a break-in.",
  "report": "Call the security team; they can hunt for what the attacker already touched.",
  "disable_login": "Turn the login page off entirely - it stops the attack and your users too."},
 "sqli": {"block_ip": "Ban one source address; injection tools hop between many.",
  "waf": "A filter in front of the site that throws out requests which look like code tricks.",
  "param_queries": "Treat everything the user types as plain text, never as code - the trick stops working.",
  "db_least_priv": "Give the website a database login that can read but not delete or change tables.",
  "error_sanitize": "Show friendly error pages instead of database details the attacker reads like a map.",
  "input_validation": "Only accept input that matches the expected shape, length and characters.",
  "rate_limit": "Allow only so many requests per second, so data can't be siphoned quickly.",
  "rotate_creds": "Change the database password and audit who used it - kicks out anyone already inside.",
  "report": "Get the security team and DBA involved before more data leaves.",
  "offline": "Switch the site off completely - the attack stops, and so does all customer traffic."},
 "ransom": {"block_ip": "Block the attacker's address - too late, the infected PC is already encrypting.",
  "edr_isolate": "Use endpoint software to unplug the sick computer from the network, remotely.",
  "segment": "Put walls between desks and servers so the worm can't walk across.",
  "offline_backup": "Check you have copies of files the attacker can never touch or delete.",
  "patch": "Install the security update that would have blocked the attack path.",
  "macro_filter": "Quarantine suspicious email and block macros - stops the booby-trap being opened.",
  "restore": "Rebuild your files from the clean copies instead of paying anyone.",
  "report": "Bring in incident response: forensics, negotiation help and a recovery crew.",
  "pay_ransom": "Pay the criminals - no guarantee of your files, and you become a target again."},
 "mitm": {"block_ip": "Block the rogue device; it re-joins with a new disguise.",
  "arp_inspection": "Make the switch verify who really owns each address, so lies are dropped.",
  "enforce_tls": "Encrypt everything end-to-end - even if intercepted, the attacker sees gibberish.",
  "nac_8021x": "Only authenticated devices get a network port at all.",
  "reset_sessions": "Change passwords and log everyone out, invalidating anything already stolen.",
  "port_security": "Limit how many device addresses each port allows, which starves spoofing.",
  "ids": "Watch a mirror of the network for signs of spoofing and raise the alarm.",
  "report": "Get the SOC hunting for the rogue device on the premises.",
  "ignore_cert": "Tell users to click through security warnings - handing the eavesdropper what it needs."},
}

# The defensive chain, in the order a packet meets it (from the trainer's sketch)
CHAIN = [
 ("Router", "The network's post office: it decides which direction every packet travels."),
 ("Firewall", "The doorman with a list: only allowed conversations get through."),
 ("IDS / IPS", "The bodyguard: an IDS spots trouble and shouts; an IPS stops it at the door."),
 ("DMZ", "A waiting room for public servers (web, mail) so visitors never reach the private offices."),
 ("Internal switch / LAN", "The office corridors where staff machines and servers talk to each other."),
 ("SIEM", "The alarm panel: it collects logs from everything and cries foul on suspicious patterns."),
 ("Endpoint - EPP / EDR", "Antivirus on steroids: EPP stops malware getting in, EDR spots it running and can remotely contain the machine."),
]

GLOSSARY = [
 ("DDoS", "A mob of fake visitors blocking your door so real customers can't get in."),
 ("SYN flood", "Shouting 'hello' at the shop thousands of times and never waiting for a reply, so the door jams."),
 ("DNS amplification", "Whispering a tiny question to open servers that then shout a huge answer at your site."),
 ("Scrubbing CDN", "A junk-filtering bypass road that cleans attack traffic before it reaches you."),
 ("Brute force", "Trying every key on a giant keyring until one opens the lock."),
 ("Password spraying", "Trying the single most common password across many accounts so nobody gets locked out."),
 ("Credential harvest", "Stealing usernames and passwords, then logging in as if they were you."),
 ("MFA", "A second key - even if the password leaks, the attacker still can't get in."),
 ("SQL injection", "Pasting sneaky code into a form so the database obeys the attacker instead of the website."),
 ("WAF", "A bouncer for your website that throws out requests that look like tricks."),
 ("Ransomware", "A digital padlock on your files with a payment demand - and the key often doesn't work."),
 ("Spear phishing", "A bait email written specifically for one person, using details about them."),
 ("Attachment attack", "A file that looks like an invoice or parcel but runs code when opened."),
 ("ARP spoofing / MITM", "Claiming to be the router so your traffic passes through the attacker's hands."),
 ("TLS / HSTS", "The scrambled tunnel for your data; HSTS forces the tunnel to always be on."),
 ("IDS / IPS", "A bodyguard at the door: one watches and warns, the other watches and blocks."),
 ("DMZ", "A waiting room for public servers so strangers never wander into the private network."),
 ("SIEM", "Your security alarm panel - every log in one place, shouting when something looks wrong."),
 ("EPP / EDR", "Protection on each laptop/server: EPP prevents, EDR detects and can hit the brakes."),
 ("Immutable backup", "A save file the attacker can't edit or delete."),
 ("Rate limiting", "One customer at a time, so a crowd can't rush the counter."),
 ("CAPTCHA", "A quick 'prove you're human' puzzle that robots struggle with."),
]

# Email classification training (the TRAINING -> EMAIL box from the trainer's sketch:
# every mail is one of Genuine / Phishing / Spam). Answers are withheld until answered.
QUIZ = [
 dict(frm="news@github.com", subj="Your weekly repository digest",
  body="Hi Sam,\n\nHere's what happened in your repositories this week:\n - 3 pull requests merged\n - 1 new issue assigned to you\n\nView your notifications: https://github.com/notifications\n\nYou receive this because you subscribed to the digest.",
  a="genuine", clue="Real sender domain, no urgency, the link matches the sender, and you opted in - that's what genuine mail looks like."),
 dict(frm="priya@yourcompany.com", subj="Standup moved to 9:15",
  body="Morning team,\n\nThe daily standup is moving to 9:15 starting tomorrow. No links, just a heads-up - bring your updates.\n\n- Priya",
  a="genuine", clue="A normal internal note from a colleague: known address, no links, no threats, no request for passwords."),
 dict(frm="statements@yourbank.example", subj="Your monthly statement is ready",
  body="Your February statement is available in online banking.\n\nFor your safety, never share codes or passwords - we will never ask for them by email.\n\nLog in by typing our address into your browser.",
  a="genuine", clue="Matches your real bank domain, asks for nothing secret and tells you to type the address yourself. Even so: never click - type the address."),
 dict(frm="security@apple-id-verify.top", subj="Verify your Apple ID within 24 hours or be locked out",
  body="Dear Customer,\n\nUnusual activity was detected. Verify your account NOW or access will be permanently suspended.\n\nhttps://apple-id-verify.top/login?sid=8821\n\nFailure to act within 24 hours is permanent.",
  a="phishing", clue="Lookalike domain (not apple.com), a countdown threat, a generic greeting and a link that wants your password - four red flags in one mail."),
 dict(frm="ceo@company.co", subj="Quick favour - I'm in a meeting",
  body="Are you at your desk? I need 5 gift cards ($100 each) for a client meeting right now.\n\nBusy, so just reply with the codes - I'll expense it tomorrow. Keep this between us for now.",
  a="phishing", clue="CEO fraud (spear phishing): a boss's name, an urgent unusual payment, gift cards, and a request for secrecy. Real bosses ask in person."),
 dict(frm="delivery@dhl-parcel-info.com", subj="DHL: delivery failed - open attached waybill",
  body="Your parcel could not be delivered.\n\nPlease open the attached 'Waybill_PDF.js' to confirm your address and pay the re-delivery fee.\n\nAttachment: Waybill_PDF.js (48 KB)",
  a="phishing", clue="Unexpected courier notice, a spoofed company domain and an attachment that isn't really a PDF - opening it runs code."),
 dict(frm="winner@prize-notify.biz", subj="CONGRATULATIONS! You've won a FREE iPhone 15!",
  body="🎉 You are today's lucky winner! Click here to claim your FREE iPhone 15 within 12 hours:\n\nhttp://claim-now.biz/7fd2\n\nNO PURCHASE NECESSARY!",
  a="spam", clue="Unsolicited prize spam: shouting capitals, an emoji, a random short link and a fake deadline. You didn't enter any prize."),
 dict(frm="noreply@crypto-double.io", subj="Turn $250 into $5,000 - guaranteed 1,900% return",
  body="Our AI trading bot doubles your money every 48 hours. GUARANTEED returns, zero risk.\n\nDeposit now: https://crypto-double.io/invest\n\nSpots limited - 3 places left!",
  a="spam", clue="'Guaranteed' high returns and scarcity pressure are the oldest spam/scam scripts. Nothing is guaranteed - this is junk."),
 dict(frm="deals@super-promo-zone.com", subj="CHEAP MEDS + FREE GIFT CARD + 80% OFF click now!!!",
  body="VIAGRA 80% OFF !! BEST PRICES ONLINE !! FREE GIFT CARD WAITING CLICK NOW WIN iPAD!!!\n\nUnsubscribe*  (*never works)",
  a="spam", clue="Classic junk-mail shape: all caps, exclamation marks, unrelated offers and a broken unsubscribe link. Straight to the bin."),
]
EMAIL_SCENARIO = dict(id="email", name="Email training: Genuine / Phishing / Spam",
                      desc="Sort real mail from attacks and junk", cat="Email", quiz=True,
                      plain="A quick game: spot which emails are safe, which try to steal from you, and which are just junk.")
SCENARIOS = [EMAIL_SCENARIO] + [dict(id=k, name=v["name"], desc=v["desc"], cat=META[k][0],
                                     plain=META[k][1], quiz=False) for k, v in KINDS.items()]

def _quiz_pub(i):
    q = QUIZ[i]
    return dict(index=i, frm=q["frm"], subj=q["subj"], body=q["body"])

def _quiz_end(answers, score):
    total, pts = len(QUIZ), round(len(QUIZ) and score / len(QUIZ) * MAXS)
    frac = score / max(total, 1)
    o = "success" if frac >= .8 else "partial" if frac >= .5 else "failure"
    fb = [dict(k="tip", text="Rule of thumb: read the real sender address (not the display name), hover a link before clicking, and treat urgency as a red flag."),
          dict(k="tip", text="Phishing wants your password or your wallet; spam just wants attention. Either way: don't click - report it.")]
    fb += [dict(k="missed", text=f"'{q['subj']}' was {q['a'].upper()} - {q['clue']}")
           for i, q in enumerate(QUIZ) if answers[i] != q["a"]]
    return dict(type="end", outcome=o, score=pts, max=MAXS,
                msg=f"You classified {score} of {total} emails correctly.", feedback=fb)

class Sim:
    def __init__(s, kind):
        s.kind, s.K = kind, KINDS[kind]
        s.t = s.pts = s.pen = s.surge = s.n = s.asum = s.exfil = 0
        s.done, s.iso, s.mist, s.over, s.seen = {}, set(), [], {}, set()
        s.first, s.avail, s.breached = None, 1.0, False
        # scenario-specific state
        s.destroyed = False                       # sqli: destructive query succeeded
        s.spread = s.enc = 0.0                         # ransom
        s.backup_lost = False
        s.backup_ok = False
        s.poison = s.creds = s.hijack = 0.0       # mitm
        s.acc = [dict(n=n, d=d, p=0.0, c=False) for n, d in (("admin",300),("svc-backup",600),("jsmith",1500),("alice",1e12))]
    def age(s, a): return s.t - s.done[a] if a in s.done else -1
    def ramp(s, a, d): return min(1, s.age(a) / d) if a in s.done else 0
    def once(s, k, msg, ev):
        if k not in s.seen:
            s.seen.add(k)
            ev.append(msg)
            siem(s.kind, s.t, msg)
    def act(s, i):
        a = s.K["actions"].get(i)
        if not a or i in s.done: return dict(ok=False, msg="Already active." if a else "Unknown action.")
        s.done[i] = s.t
        if a[2] < 0:
            s.pen -= a[2]
            s.mist.append(f"{a[0]}: {a[3]}")
        else:
            s.pts += a[2]
            if s.first is None: s.first = max(0, s.t - s.K["start"])
        siem(s.kind, s.t, f"DEFENCE applied: {a[0]} ({'+' if a[2]>=0 else ''}{a[2]} pts)")
        if i == "force_reset":
            for c in s.acc:
                if c["d"] < 1e11:
                    c["p"], c["c"], c["d"] = 0.0, False, c["d"] * 4
        if i == "reset_sessions":
            s.creds *= .15
            s.hijack = 0.0
        if i == "offline_backup" and not s.backup_lost: s.backup_ok = True
        return dict(ok=True, msg=f"{a[0]}: {'-' if a[2]<0 else '+'}{abs(a[2])} pts. {a[3]}")
    def isolate(s, n):
        if n in s.iso:
            s.iso.discard(n)
            siem(s.kind, s.t, f"RECONNECTED '{n}'")
            return dict(ok=True, msg=f"{n} reconnected.")
        s.iso.add(n)
        if n in GOOD_ISO[s.kind]:
            s.pts += 10
            siem(s.kind, s.t, f"ISOLATED attack-related node '{n}' (+10 pts)")
            return dict(ok=True, msg=f"{n} isolated: attack reduced (+10 pts).")
        if n in ("users",):
            return dict(ok=True, msg="Users isolated.")
        s.pen += 15
        s.mist.append(f"Isolated healthy component '{n}': self-inflicted outage.")
        siem(s.kind, s.t, f"ISOLATED healthy node '{n}' - self-inflicted outage (-15 pts)")
        return dict(ok=True, msg=f"'{n}' isolated: this cuts YOUR service (-15 pts).")
    def stat(s, i, ld):
        s.over[i] = s.over.get(i, 0) + 1 if ld >= 1 else 0
        return "down" if s.over[i] >= 4 else "critical" if ld > .8 else "warning" if ld > .45 else "normal"
    def phase(s): return [p for p in s.K["phases"] if s.t >= p[0]][-1][1]
    def step(s): return {"ddos": s.ddos, "brute": s.brute, "sqli": s.sqli, "ransom": s.ransom, "mitm": s.mitm}[s.kind]()
    def finish_tick(s, loads, status, packets, meters, stats, chart, ev):
        if s.t >= s.K["start"]:
            s.n += 1
            s.asum += s.avail
        for i in s.iso: loads[i], status[i] = 0, "isolated"
        phase, score = s.phase(), max(0, s.pts - s.pen)
        arriving, passed = chart[1], chart[2]
        _line(BLOCK_LOG, _csv_row([_wall(), s.kind, f"{s.t:.1f}", phase, f"{chart[0]:.0f}",
                                   f"{arriving:.0f}", f"{passed:.0f}", f"{max(0, arriving-passed):.0f}",
                                   f"{(max(0, arriving-passed)/arriving*100):.1f}" if arriving > 0 else "0.0",
                                   score, len(s.iso)]))
        return dict(t=s.t, phase=phase, loads=loads, status=status, packets=packets, meters=meters, stats=stats,
                    chart=chart, events=ev, score=score)
    def ddos(s):
        t, d, ev = s.t, s.done, []
        raw = 0 if t < 6 else 3000 if t < 14 else 45000 if t < 30 else 130000
        raw *= (1.6 if t < s.surge else 1) * random.uniform(.93, 1.07)
        closed = "close_resolver" in d or "dns" in s.iso
        atk = raw * (.4 if t >= 30 and closed else 1)
        atk *= 1 - .85 * s.ramp("scrubbing", 6)
        atk *= 1 - .5 * s.ramp("isp_filter", 10)
        atk *= 1 - .35 * s.ramp("block_ip", 1)
        if "botnet" in s.iso: atk *= .2
        syn_share = 1 if 14 <= t < 30 else .4 if t >= 30 else .3
        if "syn_cookies" in d: atk *= 1 - .7 * syn_share
        loss = min(.5, .05 * ("syn_cookies" in d) + .02 * s.ramp("scrubbing", 6) + .03 * s.ramp("isp_filter", 10) + .03 * closed)
        legit = 4000 * random.uniform(.95, 1.05) * (1 - loss)
        edge_cap = 0 if ("drop_all" in d or {"firewall", "lb"} & s.iso) else 70000
        el = (legit + atk) / edge_cap if edge_cap else 5.0
        es = min(1, 1 / el)
        cap = sum(6000 for w in ("web1", "web2") if w not in s.iso) * (2.5 if "cdn_cache" in d else 1)
        wl = (legit + atk * .25) * es / cap if cap else 5.0
        s.avail = .6 * s.avail + .4 * (1 - loss) * es * min(1, 1 / wl)
        syn = min(1, atk * syn_share / 30000 + .05)
        if atk > 2500: s.once("a", "SIEM: abnormal inbound volume vs baseline (possible DDoS)", ev)
        if syn > .6: s.once("b", f"Firewall SYN backlog at {round(syn*100)}%: half-open connections piling up", ev)
        if t >= 30 and not closed: s.once("c", "DNS replies ~50x larger than queries: amplification in progress", ev)
        if s.avail < .7: s.once("d", f"SLA breach: only {round(s.avail*100)}% of real users served", ev)
        loads = dict(botnet=.2 if t >= 6 else .05, users=.2, dns=min(1, raw * .6 / 90000) if t >= 30 and not closed else .1, firewall=max(el, syn),
                     lb=el, web1=wl, web2=wl, db=wl * .5, scrub=s.ramp("scrubbing", 6) * .6)
        loads = {k: min(1, v) for k, v in loads.items()}
        status = {k: s.stat(k, v) for k, v in loads.items()}
        ratio = min(1, atk / max(raw, 1))
        pk = [dict(s="users", t="firewall", k="legit", b=False)]
        if raw: pk += [dict(s="botnet", t="firewall", k="syn" if t < 30 else "amp", b=random.random() > ratio) for _ in range(min(12, 1 + int(raw / 12000)))]
        meters = [dict(l="Real users served", v=s.avail, inv=1), dict(l="Edge link load", v=min(1, el)), dict(l="Web tier load", v=min(1, wl)), dict(l="SYN backlog", v=syn)]
        stats = [f"Attack arriving: {raw:,.0f} req/s", f"Attack getting through: {atk:,.0f} req/s", f"Real users: {legit:,.0f} req/s"]
        return s.finish_tick(loads, status, pk, meters, stats, [legit, raw, atk], ev)
    def brute(s):
        t, d, ev = s.t, s.done, []
        raw = 0 if t < 5 else 4 if t < 12 else 25 if t < 28 else 60
        raw *= 1.6 if t < s.surge else 1
        eff = raw
        if "block_ip" in d: eff *= .2 if s.age("block_ip") < 12 else .7
        for a, f in (("login_throttle", .15), ("lockout", .25), ("captcha", .4)):
            if a in d: eff *= f
        if "attacker" in s.iso: eff *= .25
        off = "disable_login" in d or "login" in s.iso
        if off: eff = 0
        for c in s.acc:
            if c["c"] or c["d"] > 1e11: continue
            c["p"] = min(1, c["p"] + eff / 4 * DT / c["d"])
            if c["p"] >= 1:
                c["c"] = True
                ev.append(f"SIEM: password for '{c['n']}' was guessed")
                siem(s.kind, s.t, ev[-1])
                if "mfa" not in d and not s.breached:
                    s.breached = True
                    ev.append(f"BREACH: successful login to '{c['n']}' from unusual location; attacker is inside")
                    siem(s.kind, s.t, ev[-1])
        if s.breached and "revoke" not in d: s.exfil = min(1, s.exfil + .04)
        loss = .02 * ("login_throttle" in d) + .03 * ("lockout" in d) + .02 * ("captcha" in d)
        s.avail = 0 if off else 1 - loss
        if raw > 10: s.once("a", "SIEM: failed-login spike across many accounts (password spraying)", ev)
        if raw > 40: s.once("b", "Distributed source IPs: attempts now come from many addresses", ev)
        loads = dict(attacker=.3 if raw else .05, users=.2, firewall=min(1, raw / 60), login=min(1, eff / 60 + .1), dir=.2 + .5 * s.breached, data=s.exfil)
        status = {k: s.stat(k, v) for k, v in loads.items()}
        if s.breached: status["login"] = status["dir"] = "compromised"
        if s.exfil > 0: status["data"] = "compromised"
        ratio = min(1, eff / max(raw, 1))
        pk = [dict(s="users", t="firewall", k="legit", b=False)]
        if raw: pk += [dict(s="attacker", t="firewall", k="brute", b=random.random() > ratio) for _ in range(min(10, 1 + int(raw / 8)))]
        if s.exfil > 0 and "revoke" not in d: pk += [dict(s="dir", t="data", k="exfil", b=False), dict(s="login", t="dir", k="exfil", b=False)]
        meters = [dict(l=f"{c['n']}: {'CRACKED' if c['c'] else 'strong password' if c['d']>1e11 else 'guess progress'}", v=c["p"]) for c in s.acc]
        meters += [dict(l="Data exfiltrated", v=s.exfil), dict(l="Real logins succeeding", v=s.avail, inv=1)]
        stats = [f"Guesses/s arriving: {raw:.0f}", f"Guesses/s reaching login: {eff:.0f}", f"Breached: {'YES' if s.breached else 'no'}"]
        return s.finish_tick(loads, status, pk, meters, stats, [4, raw, eff], ev)
    def sqli(s):
        t, d, ev = s.t, s.done, []
        raw = 0 if t < 6 else 6 if t < 14 else 18 if t < 30 else 40 if t < 48 else 70
        raw *= (1.6 if t < s.surge else 1) * random.uniform(.93, 1.07)
        eff = raw
        if "block_ip" in d: eff *= .25 if s.age("block_ip") < 12 else .7
        eff *= 1 - .9 * s.ramp("waf", 6)
        if "input_validation" in d: eff *= .5
        if "rate_limit" in d: eff *= .6
        if "param_queries" in d: eff *= .15
        if "attacker" in s.iso: eff *= .15
        if "web" in s.iso: eff = 0
        blind = .5 if "error_sanitize" in d else 1.0
        priv = .25 if "db_least_priv" in d else 1.0
        steal = eff * DT * .0002 * blind * priv * (.5 if "rotate_creds" in d else 1)
        s.exfil = min(1, s.exfil + steal)
        if t >= 48 and "db_least_priv" not in d and not s.destroyed:
            s.destroyed = True
            ev.append("CRITICAL: DROP TABLE executed on 'customers' - destructive SQL succeeded")
            siem(s.kind, s.t, ev[-1])
        loss = .02 * ("waf" in d) + .02 * ("input_validation" in d) + .01 * ("rate_limit" in d) + min(.3, eff / 200)
        offline = "offline" in d or "web" in s.iso
        s.avail = 0 if offline else .6 * s.avail + .4 * (1 - loss)
        if raw > 0: s.once("a", "SIEM: HTTP 500s on /search with SQL syntax anomalies (possible injection)", ev)
        if t >= 14 and eff > 2: s.once("b", "UNION SELECT probes succeeding: column count of 'customers' leaked", ev)
        if s.exfil > .3: s.once("c", "Database read volume far above baseline: bulk data extraction in progress", ev)
        if s.avail < .7: s.once("e", f"SLA breach: only {round(s.avail*100)}% of real users served", ev)
        if "waf" in d and s.ramp("waf", 6) >= 1: s.once("f", "WAF virtual patch active: injection signatures dropped at the edge", ev)
        if "param_queries" in d and s.age("param_queries") > 4: s.once("g", "Prepared statements deployed: payloads now treated as data, not code", ev)
        loads = dict(attacker=.25 if raw else .05, users=.2, waf=min(1, .1 + eff / 40),
                     web=min(1, .3 + eff / 60), api=min(1, .2 + eff / 80), db=min(1, .25 + s.exfil * .5 + eff / 120), siem=.2)
        loads = {k: min(1, v) for k, v in loads.items()}
        status = {k: s.stat(k, v) for k, v in loads.items()}
        if s.destroyed: status["db"] = "compromised"
        ratio = min(1, eff / max(raw, 1))
        pk = [dict(s="users", t="waf", k="legit", b=False)]
        if raw: pk += [dict(s="attacker", t="waf", k="inject", b=random.random() > ratio) for _ in range(min(10, 1 + int(raw / 8)))]
        if s.exfil > 0 and steal > 0: pk += [dict(s="web", t="db", k="steal", b=False)]
        meters = [dict(l="Data exfiltrated", v=s.exfil), dict(l="Real users served", v=s.avail, inv=1),
                  dict(l="Injection success rate", v=min(1, eff / max(raw, 1))), dict(l="Database load", v=loads["db"])]
        stats = [f"Payload probes arriving: {raw:.0f}/s", f"Reaching the application: {eff:.0f}/s",
                 f"Data exfiltrated: {s.exfil*100:.1f}%", f"Destructive query: {'YES' if s.destroyed else 'blocked/pending'}"]
        return s.finish_tick(loads, status, pk, meters, stats, [4000 * (1 - loss), raw, eff], ev)
    def ransom(s):
        t, d, ev = s.t, s.done, []
        raw = 0 if t < 4 else 8 if t < 8 else 22 if t < 22 else 45
        raw *= (1.6 if t < s.surge else 1) * random.uniform(.93, 1.07)
        eff = raw
        if "block_ip" in d: eff *= .3 if s.age("block_ip") < 12 else .75
        eff *= 1 - .95 * s.ramp("edr_isolate", 4)
        eff *= 1 - .6 * s.ramp("segment", 4)
        eff *= 1 - .8 * s.ramp("patch", 5)
        if "macro_filter" in d: eff *= .4
        if "attacker" in s.iso: eff *= .3
        if "ws1" in s.iso: eff *= .35
        if t >= 8: s.spread = min(1, s.spread + eff * DT * .004)
        if t >= 22: s.enc = min(1, s.enc + eff * DT * .0004 * (1 + .4 * s.spread))
        if t >= 45 and "offline_backup" not in d and not s.backup_lost:
            s.backup_lost = True
            ev.append("CRITICAL: backup agent stopped - recovery points are now under attacker control")
            siem(s.kind, s.t, ev[-1])
        if "restore" in d and s.backup_ok: s.enc = max(.03, s.enc - .07)
        loss = min(1, .55 * s.enc + .12 * s.spread)
        s.avail = .6 * s.avail + .4 * (1 - loss)
        if t >= 4 and raw > 0: s.once("a", "PHISHING: malicious attachment opened on WS-1; host beaconing to unknown C2", ev)
        if s.spread > .2: s.once("b", "Lateral movement: WS-1 opened SMB/RDP sessions to new hosts", ev)
        if s.enc > .02: s.once("c", "FILES: rapid renames to .locked on FS-01 - ransomware encryption started", ev)
        if s.enc > .3: s.once("e", f"SLA breach: {round(s.enc*100)}% of shared files unavailable", ev)
        if "edr_isolate" in d and s.age("edr_isolate") > 4: s.once("f", "EDR containment active: infected endpoint cut off from the network", ev)
        if "segment" in d and s.age("segment") > 4: s.once("g", "East-west filtering on: workstation-to-server traffic now restricted", ev)
        if "restore" in d and s.backup_ok and s.age("restore") > 3: s.once("h", "Restore job running from verified offline backups", ev)
        loads = dict(attacker=.3 if raw else .05, users=.15, firewall=min(1, .2 + eff / 60),
                     ws1=min(1, .3 + eff / 40 + s.enc), ws2=.1 + .5 * s.spread, fs=min(1, .2 + s.enc * .75),
                     dc=.2 + .3 * s.spread, backup=.95 if s.backup_lost else .2 + .4 * s.ramp("offline_backup", 3))
        loads = {k: min(1, v) for k, v in loads.items()}
        status = {k: s.stat(k, v) for k, v in loads.items()}
        if t >= 8: status["ws1"] = "compromised"
        if s.enc > .5: status["fs"] = "compromised"
        ratio = min(1, eff / max(raw, 1))
        pk = [dict(s="users", t="firewall", k="legit", b=False)]
        if raw: pk += [dict(s="attacker", t="firewall", k="spread" if t < 22 else "encrypt", b=random.random() > ratio) for _ in range(min(10, 1 + int(raw / 6)))]
        if t >= 22 and s.enc > 0: pk += [dict(s="ws1", t="fs", k="encrypt", b=False), dict(s="ws1", t="dc", k="encrypt", b=False)]
        meters = [dict(l="Files encrypted", v=s.enc), dict(l="Endpoints infected", v=s.spread),
                  dict(l="Backups intact", v=0 if s.backup_lost else 1, inv=1), dict(l="Users able to work", v=s.avail, inv=1)]
        stats = [f"C2 / lateral commands: {raw:.0f}/s", f"Executing: {eff:.0f}/s",
                 f"Files encrypted: {s.enc*100:.0f}%", f"Backups: {'LOST' if s.backup_lost else 'intact' if s.backup_ok else 'unverified'}"]
        return s.finish_tick(loads, status, pk, meters, stats, [4000 * (1 - loss), raw, eff], ev)
    def mitm(s):
        t, d, ev = s.t, s.done, []
        raw = 0 if t < 4 else 12 if t < 18 else 30 if t < 34 else 55
        raw *= (1.6 if t < s.surge else 1) * random.uniform(.93, 1.07)
        eff = raw
        if "block_ip" in d: eff *= .3 if s.age("block_ip") < 12 else .75
        eff *= 1 - .95 * s.ramp("arp_inspection", 5)
        eff *= 1 - .8 * s.ramp("nac_8021x", 6)
        eff *= 1 - .6 * s.ramp("port_security", 5)
        eff *= 1 - .4 * s.ramp("ids", 5)
        if "attacker" in s.iso: eff *= .25
        if t >= 6: s.poison = min(1, s.poison + eff * DT * .003)
        tlsf = s.ramp("enforce_tls", 3)
        steal = s.poison * (1 - .95 * tlsf)
        if "ignore_cert" in d: steal = max(steal, .6)
        s.creds = min(1, s.creds + steal * DT * .05)
        if t >= 34 and s.creds > .25: s.hijack = min(1, s.hijack + steal * DT * .03)
        loss = .25 * s.poison + .15 * s.hijack + (.05 if "ignore_cert" in d else 0)
        s.avail = .6 * s.avail + .4 * (1 - min(1, loss))
        if t >= 6 and raw > 0: s.once("a", "ARP: duplicate IP/MAC answers on the LAN - possible ARP spoofing", ev)
        if t >= 18 and tlsf < 1: s.once("b", "TLS downgrade observed: connections renegotiated to older ciphers (SSL stripping)", ev)
        if s.creds > .25: s.once("c", "SIEM: login credentials visible in cleartext on the SPAN port", ev)
        if s.hijack > 0: s.once("d", "CRITICAL: session cookie replayed from an unfamiliar ASN - hijack in progress", ev)
        if s.avail < .7: s.once("e", f"SLA breach: only {round(s.avail*100)}% of real sessions succeeding", ev)
        if "arp_inspection" in d and s.ramp("arp_inspection", 5) >= 1: s.once("f", "Dynamic ARP inspection active: gateway MAC bindings verified at the switch", ev)
        if "enforce_tls" in d and tlsf >= 1: s.once("g", "HSTS + TLS 1.2 enforced: intercepted traffic stays encrypted", ev)
        loads = dict(attacker=.3 if raw else .05, users=min(1, .2 + .5 * s.poison), switch=min(1, .2 + eff / 50),
                     gateway=min(1, .25 + .6 * s.poison), server=min(1, .3 + s.hijack * .5), pki=.2 + .3 * s.creds)
        loads = {k: min(1, v) for k, v in loads.items()}
        status = {k: s.stat(k, v) for k, v in loads.items()}
        if s.creds > .5: status["server"] = "compromised"
        ratio = min(1, eff / max(raw, 1))
        pk = [dict(s="users", t="switch", k="legit", b=False)]
        if raw: pk += [dict(s="attacker", t="switch", k="poison", b=random.random() > ratio) for _ in range(min(10, 1 + int(raw / 6)))]
        if s.poison > .3: pk += [dict(s="switch", t="gateway", k="poison", b=False)]
        meters = [dict(l="Clients poisoned", v=s.poison), dict(l="Credentials captured", v=s.creds),
                  dict(l="TLS enforced", v=tlsf), dict(l="Legit sessions succeeding", v=s.avail, inv=1)]
        stats = [f"ARP spoof packets: {raw:.0f}/s", f"Getting through: {eff:.0f}/s",
                 f"Clients redirected: {s.poison*100:.0f}%", f"Credentials captured: {s.creds*100:.0f}%"]
        return s.finish_tick(loads, status, pk, meters, stats, [4000 * (1 - loss), raw, eff], ev)
    def grade(s, avg):
        """Returns (outcome, bonus, message, extra_feedback_tips) for the end screen."""
        tips = []
        if s.kind == "ddos":
            o = "success" if avg >= .85 else "partial" if avg >= .6 else "failure"
            return o, round(avg * 80), f"{round(avg*100)}% of real users were served on average.", tips
        if s.kind == "brute":
            o = "success" if not s.breached else "partial" if s.exfil < 1 else "failure"
            bonus = {"success": 100, "partial": 30, "failure": 0}[o] + round(avg * 40)
            msg = {"success": "No account was taken over.", "partial": "Breach occurred but data loss was contained.", "failure": "Breach and full data exfiltration."}[o]
            tips.append(dict(k="tip", text=f"Accounts cracked: {sum(c['c'] for c in s.acc)}. Weak passwords fall first; MFA makes cracked passwords useless."))
            return o, bonus, msg, tips
        if s.kind == "sqli":
            o = "success" if s.exfil < .10 and not s.destroyed else "partial" if s.exfil < .60 else "failure"
            bonus = {"success": 100, "partial": 30, "failure": 0}[o] + round(avg * 40)
            msg = {"success": "No customer data was taken and the schema survived.",
                   "partial": f"{round(s.exfil*100)}% of customer data was read, but the breach was contained.",
                   "failure": "Customer data exfiltrated" + (" and tables dropped." if s.destroyed else ".")}[o]
            tips.append(dict(k="tip", text=f"Data exfiltrated: {s.exfil*100:.1f}%"
              + ("; destructive query succeeded - least privilege would have blocked it." if s.destroyed else ". Least-privilege DB accounts cap blast radius.")))
            return o, bonus, msg, tips
        if s.kind == "ransom":
            o = "success" if s.enc < .15 else "partial" if s.enc < .55 else "failure"
            bonus = {"success": 100, "partial": 30, "failure": 0}[o] + round(avg * 40)
            msg = {"success": "Outbreak contained: almost no data was encrypted.",
                   "partial": f"{round(s.enc*100)}% of files encrypted, but recovery is possible.",
                   "failure": f"{round(s.enc*100)}% of files encrypted" + (" and backups were destroyed." if s.backup_lost else ".")}[o]
            tips.append(dict(k="tip", text=f"Files encrypted: {round(s.enc*100)}%; backups "
              + ("LOST - verify offline/immutable copies BEFORE an incident." if s.backup_lost else "intact - restore beats negotiating.")))
            return o, bonus, msg, tips
        # mitm
        o = "success" if s.creds < .15 else "partial" if s.creds < .50 else "failure"
        bonus = {"success": 100, "partial": 30, "failure": 0}[o] + round(avg * 40)
        msg = {"success": "The interception was stopped before credentials leaked.",
               "partial": f"{round(s.creds*100)}% of credentials captured; reset them and close the vector.",
               "failure": "Credentials captured and sessions hijacked."}[o]
        tips.append(dict(k="tip", text=f"Credentials captured: {round(s.creds*100)}%. Encryption in depth (TLS/HSTS) survives even a full network MITM."))
        return o, bonus, msg, tips
    def end(s):
        avg, f = s.asum / max(s.n, 1), s.first
        speed = 0 if f is None else 40 if f < 5 else 25 if f < 12 else 10 if f < 25 else 0
        fb = [dict(k="tip", text=f"Real-user availability averaged {round(avg*100)}%."),
              dict(k="tip", text="First mitigation " + (f"{f:.1f}s after the attack began (+{speed} pts)." if f is not None else "never applied (+0 pts)."))]
        o, bonus, msg, extra = s.grade(avg)
        fb += extra
        fb += [dict(k="mistake", text=m) for m in s.mist]
        fb += [dict(k="missed", text=f"{a[0]}: {a[3]}") for i, a in s.K["actions"].items() if i not in s.done and a[2] > 0]
        score = min(MAXS, max(0, s.pts - s.pen + bonus + speed))
        siem(s.kind, s.t, f"RUN END outcome={o.upper()} score={score}/{MAXS} availability={avg*100:.0f}%")
        return dict(type="end", outcome=o, score=score, max=MAXS, msg=msg, feedback=fb)

app = FastAPI(title="CyberRange")

@app.websocket("/ws")
async def ws(w: WebSocket):
    await w.accept()
    task = None
    sim = None
    quiz = None
    ctl = dict(paused=False, extra=0, end=False)
    await w.send_json(dict(type="scenarios", items=SCENARIOS))
    await w.send_json(dict(type="glossary",
                           chain=[dict(term=a, defn=b) for a, b in CHAIN],
                           terms=[dict(term=a, defn=b) for a, b in GLOSSARY]))
    async def run(sm):
        K = sm.K
        ctl.update(paused=False, extra=0, end=False)
        await w.send_json(dict(type="init", kind=sm.kind, name=K["name"], nodes=K["nodes"], edges=K["edges"], duration=DUR,
                               actions=[dict(id=i, label=a[0], desc=a[1], pts=a[2],
                                             plain=ACTION_PLAIN.get(sm.kind, {}).get(i, ""))
                                        for i, a in K["actions"].items()]))
        siem(sm.kind, sm.t, f"RUN START '{K['name']}'")
        while sm.t < DUR + ctl["extra"] and not ctl["end"]:
            if ctl["paused"]:
                await asyncio.sleep(DT)
                continue
            sm.t += DT
            await w.send_json(dict(type="tick", dur=DUR + ctl["extra"], **sm.step()))
            await asyncio.sleep(DT)
        await w.send_json(sm.end())
    try:
        while True:
            m = await w.receive_json()
            ty = m.get("type")
            if ty == "start" and m.get("kind") in [s["id"] for s in SCENARIOS]:
                if task: task.cancel()
                if m["kind"] == "email":
                    sim = None
                    quiz = dict(idx=0, score=0, answers=[])
                    siem("email", 0, f"RUN START 'Email training: Genuine / Phishing / Spam' ({len(QUIZ)} emails)")
                    await w.send_json(dict(type="quiz_start", total=len(QUIZ), index=0, score=0, item=_quiz_pub(0)))
                else:
                    quiz = None
                    sim = Sim(m["kind"])
                    task = asyncio.create_task(run(sim))
            elif quiz is not None and ty == "quiz_answer":
                it = QUIZ[quiz["idx"]]
                ok = m.get("answer") == it["a"]
                quiz["answers"].append(m.get("answer"))
                quiz["score"] += 1 if ok else 0
                siem("email", quiz["idx"], f"QUIZ answer={m.get('answer')} correct={ok} subj={it['subj'][:50]!r}")
                await w.send_json(dict(type="quiz_check", correct=ok, answer=it["a"], clue=it["clue"],
                                       score=quiz["score"], total=len(QUIZ), index=quiz["idx"]))
            elif quiz is not None and ty == "quiz_next":
                quiz["idx"] += 1
                if quiz["idx"] < len(QUIZ):
                    await w.send_json(dict(type="quiz", total=len(QUIZ), index=quiz["idx"],
                                           score=quiz["score"], item=_quiz_pub(quiz["idx"])))
                else:
                    siem("email", len(QUIZ), f"RUN END score={quiz['score']}/{len(QUIZ)} classified")
                    await w.send_json(_quiz_end(quiz["answers"], quiz["score"]))
                    quiz = None
            elif quiz is not None and ty == "quiz_close":
                # The ✕ on the email-training popup: drop the quiz state so the
                # trainee can go back to the range and start something else.
                siem("email", quiz["idx"], f"RUN END closed early after {len(quiz['answers'])} of {len(QUIZ)} emails")
                quiz = None
            elif sim and ty in ("pause", "resume"):
                ctl["paused"] = paused = (ty == "pause")
                siem(sim.kind, sim.t, f"INSTRUCTOR: session {'paused' if paused else 'resumed'}")
                await w.send_json(dict(type="paused", paused=paused))
            elif sim and ty == "restart":
                kind = sim.kind
                if task: task.cancel()
                quiz = None
                sim = Sim(kind)
                task = asyncio.create_task(run(sim))
                siem(kind, 0, "INSTRUCTOR: session restarted from the top")
            elif sim and ty == "abort":
                kind = sim.kind
                if task: task.cancel()
                sim = None
                quiz = None
                siem(kind, 0, "INSTRUCTOR: session ended early by operator")
                await w.send_json(dict(type="aborted"))
            elif sim and ty == "action":
                await w.send_json(dict(type="result", **sim.act(m.get("id"))))
            elif sim and ty == "isolate":
                await w.send_json(dict(type="result", **sim.isolate(m.get("node"))))
            elif sim and ty == "trainer" and m.get("event") == "surge":
                sim.surge = sim.t + 8
                siem(sim.kind, sim.t, "TRAINER: injected attack surge (+60% for 8s)")
                await w.send_json(dict(type="result", ok=True, msg="Instructor injected a traffic surge."))
            elif sim and ty == "trainer":
                ev = m.get("event")
                msg = None
                if ev == "skip":
                    nxt = [p[0] for p in sim.K["phases"] if p[0] > sim.t + DT]
                    if nxt:
                        sim.t = max(sim.t, nxt[0] - DT)
                        msg = f"Instructor jumped time forward to the next phase (t={sim.t:.0f}s)."
                    else:
                        msg = "Already in the final phase - nothing to skip to."
                elif ev == "extra":
                    ctl["extra"] += 15
                    msg = f"Instructor added +15s bonus time (session now {DUR + ctl['extra']}s)."
                elif ev == "alert":
                    msg = "CRITICAL: instructor-injected alert - triage it like a real detection."
                elif ev == "grade":
                    ctl["end"] = True
                    msg = "Instructor ended the run early - grading what happened so far."
                if msg:
                    siem(sim.kind, sim.t, f"INSTRUCTOR: {msg}")
                    await w.send_json(dict(type="result", ok=True, msg=msg))
    except WebSocketDisconnect: pass
    finally:
        if task: task.cancel()

app.mount("/", StaticFiles(directory=str(Path(__file__).parent.parent / "frontend"), html=True), name="ui")
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
