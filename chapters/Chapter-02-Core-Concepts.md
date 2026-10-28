# SOAR Professional Track

## Chapter 2: SOAR Core Concepts

> In Chapter 1 you mapped what analysts do. Now we learn the vocabulary and building blocks SOAR platforms use to automate it. These terms appear in every job interview and every platform (Shuffle, Splunk SOAR, XSOAR — the names vary slightly, the concepts don't).

---

## 2.1 The Three Words in "SOAR" Mean Different Things

People say "SOAR" as one blob, but each letter-group is a distinct capability:

**Orchestration** = making different tools *talk to each other*. Your SIEM, VirusTotal, email gateway, firewall, and ticketing system don't naturally connect. Orchestration is the plumbing — one platform coordinating all of them. Think of a conductor: he doesn't play instruments, he makes them play together.

**Automation** = executing tasks *without a human*. Looking up a hash, extracting a URL, creating a ticket. Automation is each individual instrument playing by itself.

**Response** = the *actions that change something*: block the IP, quarantine the email, disable the account, isolate the host. This is where SOAR touches production systems — and where mistakes hurt, which is why response steps often need human approval.

> 💬 **Interview one-liner:** *"Orchestration connects the tools, automation removes the manual work, response takes the containment actions."*

---

## 2.2 The Building Blocks of Every SOAR Platform

### 1. Integrations (also called "apps" or "connectors")

Pre-built bridges between the SOAR platform and an external tool. A "VirusTotal app" knows how to call VirusTotal's API; a "Jira app" knows how to create tickets. When a company asks "does your SOAR integrate with X?", they're asking if this bridge exists — and if it doesn't, a SOAR engineer writes a custom one in Python (Chapter 7).

### 2. Triggers

What starts a playbook. Three main types:

- **Alert/webhook trigger** — SIEM sends an alert → playbook fires (most common)
- **Scheduled trigger** — run every hour (e.g., pull new threat intel)
- **Manual trigger** — analyst clicks "run" on a case

### 3. Playbooks (also called "workflows")

The heart of SOAR: a flowchart of automated steps. Made of:

- **Actions** — one task each ("get hash report", "send email")
- **Conditions/branches** — the IF/ELSE decision points
- **Variables** — data passed between steps (the URL extracted in step 2 is used by step 4)

### 4. Cases (also called "incidents" or "containers")

The record that ties everything together — the alert, enrichment results, playbook outputs, analyst notes, and final verdict. Case management is why SOAR replaces "50 browser tabs and a notepad."

### 5. Enrichment

Adding context to raw data. An alert says "IP 185.220.101.5 connected to server X." Enrichment asks: Is this IP on blocklists? What country? Is it a Tor exit node? Have we seen it before? Raw alert → enriched alert is the difference between "an IP did something" and "a known-malicious Tor node touched our payroll server."

---

## 2.3 Anatomy of a Playbook

Lab 1's phishing flow, redrawn the way a SOAR platform sees it:

```
TRIGGER: New phishing report received (webhook)
   │
   ├─► ACTION: Parse email (extract sender, URLs, attachments)
   │
   ├─► ACTION: Get URL reputation (VirusTotal)
   ├─► ACTION: Get file hash reputation (VirusTotal)     ← these can run in PARALLEL
   ├─► ACTION: Check sender domain age (WHOIS)
   │
   ├─► CONDITION: malicious_score >= threshold?
   │        │
   │   YES  │                          NO
   │        ▼                           ▼
   │   ACTION: Quarantine email    ACTION: Close case as
   │   ACTION: Block sender          false positive
   │   ACTION: Search other        ACTION: Notify reporter
   │           recipients            "email is safe"
   │   ACTION: Notify analyst
   │           (human approval
   │            for credential
   │            reset)
   │
   └─► ACTION: Update case with all results
```

Two new ideas hiding in that diagram:

- **Parallel execution:** the three enrichment lookups don't depend on each other, so they run simultaneously. Humans work serially; playbooks don't have to. This is a big part of the 60-min → 2-min speedup.
- **Thresholds:** "malicious_score >= threshold" — *you* decide that number. Too low → false positives get quarantined and users get angry. Too high → real phishing slips through. Tuning thresholds is ongoing SOAR engineering work, not a one-time setting.

---

## 2.4 The Golden Rule of SOAR Design

> ### ⭐ Automate the investigation, gate the destruction.

Read-only actions (lookups, searches, enrichment) are safe to fully automate — worst case, you wasted an API call. Write actions (blocking, deleting, disabling) can cause outages — imagine auto-blocking an IP that turns out to be your CEO's home network, or your own VPN. Professional playbooks fully automate everything up to the decision, then either act automatically only on very high confidence, or pause for one-click human approval. (Implemented for real in Chapter 8.)

---

# 🧪 Lab 2: Design a Malware-Alert Playbook

Same idea as Lab 1, but now you design in *playbook language* (triggers, actions, conditions, variables) instead of analyst steps.

### Scenario

Your EDR (endpoint detection tool) raises this alert:

> *"Suspicious executable `invoice_scan.exe` detected on host LAPTOP-0231, user: m.alfarsi, SHA256: ab3f…9c. Process attempted outbound connection to IP 91.242.217.85."*

### Your Task — write/draw a playbook containing:

1. **The trigger** (what kind, and what data arrives with it)
2. **At least 4 enrichment actions** — mark which can run in parallel
3. **At least 1 condition** with a concrete, numeric threshold you choose (e.g., "VT detections ≥ ?")
4. **Both branches** — the malicious path and the benign path
5. **At least one human-approval gate** on the malicious path — and a one-line justification of *why* you gated that specific action
6. **Variables** — list 4+ pieces of data extracted from the alert that later steps will use

**Bonus question:** one of the response actions you might consider is "isolate the host from the network." What's the argument for automating it fully, and what's the argument for gating it? (There's no single right answer — this exact debate happens in real SOC meetings.)

---

# ✅ Lab 2 Solution: "EDR_Suspicious_Executable_v1"

## 1. Trigger

**Type:** Webhook/alert trigger — EDR pushes the alert to SOAR the moment it fires (never scheduled polling for malware; every minute counts).

**Data arriving in the payload** → parsed into **variables**:

| Variable | Value from alert |
|---|---|
| `$hostname` | LAPTOP-0231 |
| `$username` | m.alfarsi |
| `$file_name` | invoice_scan.exe |
| `$file_hash` | ab3f…9c (SHA256) |
| `$dest_ip` | 91.242.217.85 |
| `$timestamp` | alert time |

That's 6 variables — every later step consumes these.

## 2. Enrichment Actions (all four run in PARALLEL — none depends on another)

```
├─► ACTION 1: VirusTotal — hash reputation ($file_hash)
│      → returns $vt_detections (e.g., 47/74 engines)
├─► ACTION 2: VirusTotal + AbuseIPDB — IP reputation ($dest_ip)
│      → returns $ip_abuse_score, country, is_tor
├─► ACTION 3: EDR query — process tree on $hostname
│      → what spawned invoice_scan.exe? (email? USB? browser download?)
└─► ACTION 4: SIEM query — search $file_hash and $dest_ip across ALL hosts
       → returns $other_infected_hosts (is this one laptop or an outbreak?)
```

⚠️ Action 4 is the one beginners forget — **scoping**. One infected laptop and ten infected laptops are different incidents with different responses.

## 3. Condition (the threshold)

```
CONDITION: $vt_detections >= 5  OR  $ip_abuse_score >= 80
```

- **Why 5, not 1?** Single-engine detections are often false positives (one paranoid vendor flagging a legit tool). Five independent engines agreeing is a strong signal.
- **Why OR, not AND?** Brand-new malware may have 0 VT detections (too new), but if it's calling a known-bad C2 server, that alone is damning. Requiring both would miss fresh threats.

## 4. Both Branches

### BENIGN path (condition = NO)

```
├─► ACTION: Tag case "likely false positive"
├─► ACTION: Add all enrichment results to case notes
├─► ACTION: Close case — but notify analyst channel with a one-line summary
└─► ACTION: Log the hash in an allowlist-review queue (if this file keeps
            triggering alerts, a human should tune the EDR rule — lesson 7
            of the alert lifecycle: feed lessons back)
```

> Benign ≠ silent. Auto-closed cases still get logged and sampled — that's how you catch a badly tuned threshold.

### MALICIOUS path (condition = YES)

```
├─► ACTION (auto): Isolate $hostname from network via EDR      ← see debate below
├─► ACTION (auto): Block $dest_ip at the firewall
├─► ACTION (auto): Add $file_hash to EDR blocklist org-wide
├─► ACTION (auto): Open high-severity case, assign to Tier 2
├─► ⏸ HUMAN APPROVAL GATE: Disable m.alfarsi's account + force credential reset
└─► ACTION (auto): Notify SOC channel + email IT manager with summary
```

## 5. The Human-Approval Gate — Justification

Gated: **account disable/credential reset**, not the technical containment.

> *Disabling a human's account stops their entire workday and may be unnecessary (the malware ran, but there's no evidence yet the user's credentials were stolen) — a Tier 2 analyst should confirm credential theft indicators first.*

Blocking an IP or a hash is reversible in seconds and affects no one if wrong; locking a person out mid-workday has real business cost.

## 6. Bonus Debate: Auto-Isolate the Host, or Gate It?

**Case for full automation:** malware spreads laterally in minutes. If this is ransomware, a 20-minute wait for human approval can be the difference between 1 encrypted laptop and 400. Isolation is also reversible — reconnecting a wrongly isolated host takes one click.

**Case for gating:** what if `$hostname` is a server, not a laptop? Auto-isolating a production database because of a false positive = self-inflicted outage. Also, isolation tips off a live attacker that they've been detected, which can trigger destructive "scorched earth" behavior.

**Real-world compromise:** auto-isolate *workstations*, gate isolation of anything in the *server* subnet. The playbook checks which category `$hostname` belongs to. This is called **asset-criticality-based response** — mentioning it in an interview signals you've thought past tutorials.

---

## ⭐ The Pattern to Memorize

Every professional playbook has the same skeleton:

```
Parse → Enrich (parallel) → Score → Branch → Contain (gated by risk) → Document → Feed back
```

Lab 1's phishing flow, this malware flow, and the brute-force flow in Chapter 6 are all the same skeleton with different organs.

---

## 📝 Active Recall Check

Answer from memory before moving to Chapter 3:

1. Why OR instead of AND in the condition?
2. Which action did we gate, and what's the one-line reason?
3. What does the SIEM scoping query (Action 4) tell us that the other three enrichments can't?
4. State the golden rule of SOAR design.
5. Name the three trigger types and when each is used.

---

*Next: **Chapter 3 — Building Your Lab**: install Docker, deploy Shuffle, connect free threat-intel APIs. Your designs become running software.*
