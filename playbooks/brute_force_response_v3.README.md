# brute_force_response_v3

Automated triage for SSH brute-force alerts: Wazuh detects the attack, this Shuffle
playbook validates and enriches the source IP, opens a TheHive alert for confirmed
attackers, and asks a human before blocking anything.

`brute_force_response_v3.json` is the Shuffle export with every credential and personal
email address redacted (see [Files](#files)).

## Trigger

- **Source:** Wazuh 4.14.8 manager, via a custom integration script (`custom-shuffle`)
  that POSTs to this playbook's Shuffle webhook.
- **Subscription:** `<group>authentication_failures</group>` AND `<level>10</level>` —
  correlated brute-force rules only, never single failed logins. In practice this is
  rule **5763** ("sshd: brute force trying to get access to the system"), which fires
  after repeated failures from the same source IP within 120 seconds.
- **Payload** (reshaped by the integration script so the playbook never parses raw Wazuh alerts):

  ```json
  {"src_ip": "185.220.101.5", "rule_id": "5763",
   "rule_desc": "sshd: brute force trying to get access to the system. Authentication failed.",
   "level": 10, "full_log": "<original log line>"}
  ```

## Integrations

| System | Node | Read / write | Call |
|---|---|---|---|
| VirusTotal v3 | `Virustotal_v3_1` | read | IP address report |
| AbuseIPDB v2 | `http_1` | read | `GET /api/v2/check?ipAddress=…&maxAgeInDays=90` |
| TheHive 5.4 | `Create_TheHive_Alert` | **write** | `POST /api/v1/alert`, authenticated as service account `shuffle-bot` |
| Shuffle User Input | `Approve_Block` | human decision | pauses the run until an analyst answers |

Every IP that passes the input gate and allowlist costs one VirusTotal and one AbuseIPDB
lookup. VirusTotal's free tier allows 4 per minute.

## Decision flow

```
Webhook ─► Input_Gateway ─┬─ src_ip not IPv4 (or missing) ─────────► Rejected_Input
                          ├─ src_ip on allowlist ──────────────────► Verdict_Allowlisted
                          └─ valid and not allowlisted ─┬─► VirusTotal ─┐
                                                        └─► AbuseIPDB ──┴─► Enrichment_Results
Enrichment_Results ─┬─ VT HTTP ≠ 200 ────────────────────────────────► Enrichment_Failed_VT
                    ├─ AbuseIPDB HTTP ≠ 200 ─────────────────────────► Enrichment_Failed_AbuseIPDB
                    ├─ both 200 AND VT malicious > 2 ─► Verdict_malicious ─► Create_TheHive_Alert
                    │                                       ─► Approve_Block ⏸ ─► Execute_Block
                    └─ both 200 AND VT malicious < 3 ─► Verdict_clean
```

- **Input gate:** `src_ip` must match a strict IPv4 regular expression. This is done in an
  edge condition rather than Python on purpose: the value is compared as data and is never
  spliced into code, so the gate cannot be injected by the input it validates.
- **Allowlist:** `8.8.8.8`, `1.1.1.1`, `10.99.0.1` (stand-in for the company VPN).
- **Verdicts require proof that both lookups succeeded.** Shuffle reports these nodes as
  `success: true` even when the API answered 401, 404 or 422, so the conditions test the
  HTTP `status` field, not `success`.

## Actions taken

What this playbook can change in the world:

1. **Creates a TheHive alert** — only on a MALICIOUS verdict. Type `brute-force`, source
   `wazuh-via-shuffle`, severity 3, tags `ssh / brute-force / automated`, and the attacker
   IP as an observable flagged as an IOC. `sourceRef` is built from rule ID and IP; TheHive
   refuses a second alert with the same reference. (Not exercised in this lab.)
2. **Blocks the attacker IP at the firewall — SIMULATED.** `Execute_Block` only prints the
   `iptables` command it would run. No system is changed. It runs only after human approval.

Nothing else is written anywhere. Enrichment is read-only.

## Human gates

| Gate | Guards | Who approves |
|---|---|---|
| `Approve_Block` | the firewall block | any analyst with access to the Shuffle approval form |

- The run pauses in `WAITING` after the TheHive alert is created. The analyst sees the IP,
  the Wazuh rule and level, and answers `true` (block) or `false` (abort).
- Shuffle records the approving user and their answer in the node's `click_info`, so the
  audit trail separates the two identities: `shuffle-bot` created the case, a named human
  authorised the block.
- No answer means no block. The run simply stays waiting.
- Lab quirk: the approval form link carries `backend_url=http://shuffle-backend:5001`, which
  a browser cannot resolve. Rewrite it to `backend_url=https://localhost:3443`.

## Failure modes

| Failure | Behaviour | Class |
|---|---|---|
| `src_ip` missing, empty, malformed or IPv6 | `Rejected_Input`; no API calls made | fail closed |
| VirusTotal non-200 (bad key 401, rate limit 429, outage 5xx) | `Enrichment_Failed_VT` → human review; no verdict | fail closed — 401 tested; 429 and 5xx follow from the same `status ≠ 200` rule but were not reproduced |
| AbuseIPDB non-200 | `Enrichment_Failed_AbuseIPDB` → human review; no verdict | fail closed |
| Both lookups fail | both failure nodes fire | fail closed |
| **TheHive down, or rejects the alert** (including 400 for a duplicate `sourceRef`) | **not checked** — the run continues to `Approve_Block`, so a block can be approved with no case on record | **fail open — known gap** |
| Approver never answers | run stays `WAITING`; block never executes | fail safe, but stalls silently |
| Shuffle unreachable from Wazuh | integration script errors, Wazuh logs it, no retry; the alert exists only in Wazuh | fail silent — outside this playbook |

There is no automatic retry. A 429 or 5xx goes straight to human review.

## Known limits

- **IPv4 only.** IPv6 attackers are rejected as invalid input rather than enriched.
- **The verdict uses VirusTotal's malicious count alone.** AbuseIPDB must answer successfully
  and its score is shown, but it does not influence the decision.
- **Thresholds have never been measured** against analyst case resolutions. `> 2` is an opinion.
- **No cache-before-query.** IPs already recorded as IOCs in TheHive are looked up again,
  spending quota.
- **Low-and-slow and distributed attacks are invisible.** Rule 5763 needs repeated failures
  from one IP inside 120 seconds — it actually fired on the 10th attempt in testing, despite
  `frequency="8"`. Slower attempts, or an attack spread across many IPs, never alert.
- **Repeat suppression.** Rule 5763 has `ignore="60"`; a second burst from the same IP within
  60 seconds is not re-alerted.
- **Rules that store the IP elsewhere** (for example Windows logon events) reach the playbook
  with `src_ip: "unknown"` and are rejected.
- **The allowlist lives in three edge conditions.** Changing it means editing all three
  identically.
- **Severity is hardcoded** to 3 rather than mapped from the enrichment scores.
- **Variable syntax is fragile.** Shuffle treats `-` and `.` directly after a variable as part
  of its name or path, so `$exec.src_ip.` or `$exec.rule_id-x` silently render wrong. Every
  message in this playbook ends variables with a space or a newline.

## Verification

Tests run against v3 on 2026-10-20:

| Test | Input | Result |
|---|---|---|
| Garbage input | `{"src_ip": "not-an-ip"}` | `Rejected_Input` only — zero API calls |
| Allowlist | `{"src_ip": "8.8.8.8"}` | `Verdict_Allowlisted` only — zero API calls |
| Dead VirusTotal key | `185.220.101.5`, key corrupted | VT HTTP 401 → `Enrichment_Failed_VT`; `Verdict_clean` skipped |
| End to end via Wazuh | 12 failed SSH logins from 8.8.8.8 replayed into the manager | rule 5763 → integration → v3 → `Verdict_Allowlisted`, zero API calls |

Re-run after the message fix, through the webhook as Wazuh calls it:

| Test | Input | Result |
|---|---|---|
| Allowlist | `8.8.8.8` | `Verdict_Allowlisted` only — zero API calls |
| Garbage input | `not-an-ip` | `Rejected_Input` only — zero API calls |
| Missing field | payload with no `src_ip` | `Rejected_Input` only — zero API calls |
| Rate-limit attempt | 6 alerts for `9.9.9.9` within ~20 s | all six VirusTotal calls returned 200 — the free tier did not throttle a burst of six, so the 429 path stayed untested |

The fixed `Enrichment_Failed_*` messages were not rendered in a live failure, because forcing
one requires breaking an API key. Every variable in them is now followed by a newline — the
same construct as `Enrichment_Results`, which rendered correctly in all six runs above.

The same dead-key and garbage tests against v1 and v2 both returned **CLEAN** — fail open.
That is the reason v3 exists.

## Files

| File | Contents |
|---|---|
| `brute_force_response_v3.json` | Shuffle workflow export, sanitized with `tools/scrub_workflow.py` |
| `README.md` | this document |

The export contains placeholders such as `<REDACTED:APIKEY>`,
`<REDACTED:ABUSEIPDB_API_KEY>` and `<REDACTED:THEHIVE_API_KEY>`, and the real webhook ID is
replaced by the dummy `00000000-0000-4000-8000-000000000001` (anyone holding a webhook URL can
trigger the playbook). To run it: import the JSON
into Shuffle, replace each placeholder with a real key, start the webhook, and point the
Wazuh integration's `<hook_url>` at the new webhook ID.

## Changelog

- **v1** (2026-10-13) — copy of `ip_enrichment_v1` fired by the Wazuh integration;
  VirusTotal and AbuseIPDB in parallel, MALICIOUS / CLEAN on the VirusTotal malicious count.
- **v2** (2026-10-17) — MALICIOUS creates a TheHive alert through a service account, with the
  IP as an observable; human approval gate before a simulated block; `sourceRef` dedup key
  fixed after Shuffle silently dropped a variable followed by a hyphen.
- **v3** (2026-10-20) — input gate, allowlist, and fail-closed enrichment checks on HTTP
  status, after chaos testing showed v1/v2 auto-closing a known attacker as CLEAN when an API
  key was wrong or the input was garbage. Nodes renamed by job. Failure messages fixed so
  no punctuation follows a variable (`$exec.src_ip.` had printed the whole payload).
