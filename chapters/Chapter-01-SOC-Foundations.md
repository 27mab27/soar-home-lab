# SOAR Professional Track

## Chapter 1: SOC & Incident Response Foundations

> Before you can automate security work, you need to understand the work being automated. That's this chapter.

---

## 1.1 What a SOC Actually Does

A **Security Operations Center (SOC)** is the team that watches an organization's systems 24/7 for signs of attack. Their raw material is **alerts** — notifications generated when something suspicious happens:

- A user logged in from two countries in one hour
- An endpoint ran a strange PowerShell command
- An email contained a known-bad link

### SOC Tiers

| Tier | Role | Description |
|------|------|-------------|
| **Tier 1** | Triage Analyst | First line. Looks at incoming alerts, decides "real threat or false alarm?", escalates real ones. Repetitive, high-volume work — **this is the tier SOAR automates most.** |
| **Tier 2** | Incident Responder | Investigates escalated incidents deeply, contains threats (isolate machine, reset passwords). |
| **Tier 3** | Threat Hunter / Engineer | Proactively hunts hidden threats, tunes detection rules, builds tooling. As a SOAR engineer, you'll live near this tier. |

---

## 1.2 The Tools: SIEM vs SOAR vs XDR

People confuse these constantly, so nail this now:

- **SIEM** (Security Information and Event Management — e.g., Splunk, Wazuh, Sentinel): collects logs from everywhere, applies detection rules, and **generates alerts**. It's the *eyes*.
- **SOAR** (e.g., Splunk SOAR, Cortex XSOAR, Shuffle): takes those alerts and **acts on them** — enriches them with threat intel, opens cases, blocks IPs, emails users. It's the *hands*.
- **XDR**: a vendor-integrated bundle that combines detection and some response across endpoints/email/cloud. Think of it as SIEM + SOAR-lite from one vendor.

### The Classic Flow

```
logs → SIEM detects → alert → SOAR playbook runs → enrichment → decision → response action
```

---

## 1.3 The Alert Lifecycle

Every alert goes through the same journey:

1. **Detection** — SIEM rule fires
2. **Triage** — is it real? What's the severity?
3. **Enrichment** — gather context: who is this user, is this IP known-malicious, what does VirusTotal say about this file hash?
4. **Investigation** — reconstruct what happened
5. **Containment** — stop the bleeding (isolate host, block IP, disable account)
6. **Eradication & recovery** — remove the threat, restore systems
7. **Lessons learned** — tune rules, update playbooks

**Key insight:** Steps 2–3 consume most of a Tier 1 analyst's day, and they're mechanical: look up an IP in a reputation database, check a hash, check the user's login history. A human takes 15–30 minutes per alert. A SOAR playbook does it in seconds. **That's the entire business case for SOAR.**

---

## 1.4 The Metrics That Justify SOAR

Two acronyms you must know for interviews:

- **MTTD** (Mean Time To Detect): average time from attack starting to the SOC noticing.
- **MTTR** (Mean Time To Respond): average time from detection to containment.

SOAR's value is measured in **MTTR reduction**. If manual phishing triage takes 45 minutes and your playbook does it in 90 seconds, you've cut MTTR by ~97% for that alert type.

### Alert Fatigue

A mid-size SOC gets thousands of alerts daily; most are false positives. Analysts burn out and start ignoring alerts — which is how real breaches slip through. SOAR fights this by auto-closing obvious false positives so humans only see what matters.

---

# 🧪 Lab 1: Map a Manual Phishing Workflow

This lab is on paper (or a text file) — no tools yet. It matters because **you cannot automate a process you haven't mapped**. This is literally the first step of every real SOAR project.

### Scenario

An employee, Sara, reports a suspicious email to the SOC. It claims to be from "Microsoft Support," contains a link, and has a PDF attachment.

### Your Task

Write out every single step a Tier 1 analyst would take manually, from receiving Sara's report to closing the ticket. For each step, note:

1. **The action** (e.g., "extract the URL from the email")
2. **The tool/source used** (e.g., "urlscan.io")
3. **Estimated time** (e.g., "3 min")
4. **Decision points** — where the path branches (e.g., "IF the URL is malicious → … ELSE → …")

Aim for 10–15 steps. Include at minimum:

- Header analysis (who really sent it?)
- URL reputation check
- Attachment hash check
- Checking whether other employees received the same email
- The two possible endings (confirmed phishing vs. false alarm) with what happens in each

At the end, total up the time. That number is what we'll destroy with automation in Chapter 5.

---

# ✅ Lab 1 Solution: Manual Phishing Triage Workflow

**Scenario:** Sara reports a suspicious "Microsoft Support" email with a link and PDF attachment.

| # | Action | Tool / Source | Time |
|---|--------|---------------|------|
| 1 | Acknowledge Sara's report, open a ticket | Ticketing system (Jira/ServiceNow) | 3 min |
| 2 | Retrieve the original email safely (as attachment, not by clicking) | Email gateway / user forwards as .eml | 3 min |
| 3 | Analyze email headers: check the real sender, SPF/DKIM/DMARC results, originating IP | Header analyzer (MXToolbox) | 5 min |
| 4 | **Decision:** Does the sender domain match Microsoft's real domains? → *No, it's "micros0ft-support.xyz" → continue* | Manual inspection | 1 min |
| 5 | Extract the URL from the email body (defang it: hxxps://) | Manual copy | 1 min |
| 6 | Check URL reputation | VirusTotal, urlscan.io | 4 min |
| 7 | Extract the PDF attachment and compute its hash (SHA256) — never open it | Sandbox / hashing tool | 3 min |
| 8 | Check the hash reputation | VirusTotal | 3 min |
| 9 | If verdicts are unclear, detonate attachment in a sandbox | Any.Run / Joe Sandbox | 10 min |
| 10 | **Decision point:** Is anything confirmed malicious? | Analyst judgment | 2 min |

### Path A — IF MALICIOUS

| # | Action | Tool / Source | Time |
|---|--------|---------------|------|
| 11a | Search the mail gateway — who else received this email? | Email security console | 5 min |
| 12a | Delete/quarantine the email from all affected mailboxes | Email gateway | 5 min |
| 13a | Block the sender domain and malicious URL at the gateway/proxy | Email gateway + web proxy | 4 min |
| 14a | Check whether any recipient clicked the link or opened the attachment | SIEM / EDR (proxy logs) | 8 min |
| 15a | If someone clicked: escalate to Tier 2, reset that user's credentials | IAM + escalation | 5 min |
| 16a | Notify affected users, thank Sara (positive reinforcement matters) | Email | 3 min |
| 17a | Document findings and IOCs (domain, URL, hash, IP), close ticket as **True Positive** | Ticketing system | 5 min |

### Path B — IF BENIGN

| # | Action | Tool / Source | Time |
|---|--------|---------------|------|
| 11b | Reply to Sara explaining it's safe | Email | 3 min |
| 12b | Document the check performed, close ticket as **False Positive** | Ticketing system | 3 min |

### Totals

- **Malicious path: ~60 minutes**
- **Benign path: ~35 minutes**

---

## Key Observations (The Actual Lesson)

**1. Steps 1–9 are pure mechanics.** Extracting URLs, hashing files, querying VirusTotal — no human judgment involved. A playbook does all of it in under 60 seconds. This becomes Chapter 5's automation target.

**2. The decision points (steps 4, 10) are where design happens.** In a playbook, these become IF/ELSE branches based on scores — e.g., "VirusTotal detections ≥ 5 → malicious path." Deciding those thresholds is the *engineering* part of SOAR engineering.

**3. Some steps stay human.** Step 15a (credential reset after a confirmed click) is the kind of action many companies want a human to approve — that's "human-in-the-loop," coming in Chapter 9.

**4. The math that sells SOAR:** ~60 min manual vs ~2 min automated. If the SOC gets 20 phishing reports a day, that's nearly 20 analyst-hours daily recovered. When a manager asks "why do we need SOAR?", this table *is* your answer.

---

## 📝 Active Recall Check

Answer from memory before moving to Chapter 2:

1. Which steps in the workflow become IF/ELSE branches in a playbook?
2. What's the difference between what SIEM does and what SOAR does in this scenario?
3. What do MTTD and MTTR stand for, and which one does SOAR mainly improve?
4. Which SOC tier does SOAR automate the most, and why?

---

*Next: **Chapter 2 — SOAR Core Concepts**, where we turn this table into a real playbook flowchart.*
