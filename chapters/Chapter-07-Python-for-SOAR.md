# Chapter 7: Python for SOAR

*(Taken before Chapter 6 by deliberate re-sequencing — your Lab 5c finding is the syllabus for this chapter.)*

Drag-and-drop nodes got you far: five chapters, three working playbooks. But you've now personally hit the wall — the URL sitting extracted-but-unused, the domain-age check that Lab 1's manual analyst had and your playbook lost, the typosquat that scored as clean as GitHub. All three fixes are a few lines of Python each.

---

## Verified on this lab before you start

Shuffle's Python sandbox runs inside the `shuffle-tools` app container. Confirmed working here:

| Check | Result |
|---|---|
| Python version | 3.10.18 |
| `requests` available | yes, 2.32.3 |
| Outbound internet | yes — `rdap.org` returns HTTP 200 |
| `execute_python` parameters | a single `code` field |

So the RDAP detector will work. That was not a given: many SOAR sandboxes block outbound network, and if yours had, Detector 2 would need rewriting as an HTTP node instead.

---

## 7.1 Where Python lives in a SOAR platform

Every serious SOAR platform has an "escape hatch" node: a box where you write code that runs inside the workflow, receiving upstream data and emitting a result downstream. In Splunk SOAR they're custom functions, in XSOAR automation scripts, in Shuffle it's **Shuffle Tools → Execute python**. Same concept everywhere, so this skill transfers 1:1 to enterprise platforms.

The contract is always: **read inputs → compute → output JSON**. SOAR Python is not leetcode; it's plumbing — dictionaries, string operations, HTTP calls, and honest error handling.

## 7.2 The four skills that cover 90% of SOAR Python

**1. Dictionaries all the way down.** Every API response you've seen is nested dicts:

```python
count = data["body"]["data"]["attributes"]["last_analysis_stats"]["malicious"]
# safer — returns a default instead of crashing if a key is missing:
count = data.get("body", {}).get("data", {}).get("attributes", {}) \
            .get("last_analysis_stats", {}).get("malicious", 0)
```

That `.get()` chain looks ugly and is everywhere in production playbooks. APIs omit fields constantly, and a playbook that crashes on a missing key is a playbook that silently stops defending you.

**2. HTTP with requests.**

```python
import requests
r = requests.get("https://rdap.org/domain/github.com", timeout=10)
if r.status_code == 200:
    data = r.json()
```

**3. JSON in and out.**

```python
import json
print(json.dumps({"verdict": "PHISHING", "risk_score": 85}))
# in Shuffle, what you print becomes the node's output
```

**4. Error handling as a first-class citizen.** In scripts, errors are annoying. In automation running unattended at 3am, unhandled errors are dangerous — a crashed enrichment step can make a malicious email look clean. The rule: **fail loud, default safe.** If a lookup fails, say so explicitly (`"age_days": null, "error": "rdap_lookup_failed"`) rather than pretending the answer was "fine".

## 7.3 The three detectors from your 5c finding

### Detector 1 — Lexical typosquat check (no API at all)

```python
def typosquat_check(domain):
    brands = ["microsoft", "google", "paypal", "apple", "amazon", "github", "netflix"]
    subs = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a"}
    normalized = domain.lower()
    for bad, good in subs.items():
        normalized = normalized.replace(bad, good)
    hits = [b for b in brands if b in normalized and b not in domain.lower()]
    return {"is_typosquat": len(hits) > 0, "impersonating": hits}
```

`micros0ft-support.xyz` → substitutions make it `microsoft-support.xyz` → "microsoft" is in the normalized string but **not** in the original → typosquat. `github.com` → "github" is in the original too, so no flag. That `b not in domain.lower()` clause is the clever bit: it exempts the real brand domains.

**Verified output on this lab:**

```
micros0ft-support.xyz  →  {'is_typosquat': True,  'impersonating': ['microsoft']}
github.com             →  {'is_typosquat': False, 'impersonating': []}
```

### Detector 2 — Domain age via RDAP (free, keyless)

RDAP is the modern WHOIS: structured JSON, no API key.

```python
import requests
from datetime import datetime, timezone

def domain_age_days(domain):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if r.status_code == 404:
            return {"age_days": None, "note": "domain_not_registered"}
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration":
                reg = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return {"age_days": (datetime.now(timezone.utc) - reg).days}
        return {"age_days": None, "note": "no_registration_event"}
    except Exception as e:
        return {"age_days": None, "error": str(e)}
```

Note the three distinct "I don't know" shapes — unregistered, missing field, network failure — each labelled differently.

**Verified output on this lab:**

```
micros0ft-support.xyz  →  {'age_days': None, 'note': 'domain_not_registered'}
github.com             →  {'age_days': 6907}
```

The phishing domain isn't registered at all, so RDAP 404s. **An email claiming to come from an unregistered domain is itself deeply suspicious** — the sender is forged. Even the error path carries signal. That's SOAR thinking.

### Detector 3 — Risk scoring: combining weak signals into a strong verdict

The lesson from your 5c: no single signal is reliable. Fresh domains beat reputation; typosquats have false positives; hash checks miss link-only phishing. The professional pattern is weighted scoring:

```python
def risk_score(hash_mal, domain_mal, typosquat, age_days):
    score, reasons = 0, []
    if hash_mal >= 3:
        score += 100; reasons.append(f"attachment flagged by {hash_mal} engines")
    if domain_mal >= 3:
        score += 60;  reasons.append(f"domain flagged by {domain_mal} engines")
    if typosquat["is_typosquat"]:
        score += 40;  reasons.append(f"typosquat of {typosquat['impersonating']}")
    if age_days is None:
        score += 30;  reasons.append("domain unregistered or age unknown")
    elif age_days < 30:
        score += 40;  reasons.append(f"domain only {age_days} days old")
    verdict = "PHISHING" if score >= 60 else ("SUSPICIOUS" if score >= 30 else "LIKELY_BENIGN")
    return {"risk_score": score, "verdict": verdict, "reasons": reasons}
```

Three design choices worth noticing. Signals are **weighted by reliability** — hash detection is near-certain, so 100; typosquat alone is 40, suggestive but not conviction. There's a **third verdict tier**, SUSPICIOUS, which routes to a human instead of forcing borderline cases into a binary. And `reasons` builds the evidence-carrying rule from Chapter 4 **into the data structure itself** — the verdict explains itself.

**Verified scoring on this lab:**

| Case | Score | Verdict |
|---|---|---|
| Link-only phishing (clean hash) | **70** | **PHISHING** |
| Phishing with EICAR attachment | 170 | PHISHING |
| GitHub newsletter | 0 | LIKELY_BENIGN |

Your 5c blind spot is closed: typosquat (40) + unregistered domain (30) = 70, which convicts on the link alone.

## 7.4 Putting Python inside Shuffle

1. Open `phishing_triage_v1` → **Save As** → `phishing_triage_v2`. Never edit a working playbook in place; version like software.
2. Drag a **Shuffle Tools** node between `Evidence Summary` and the verdicts. Rename it `Risk_Scoring`. Action: **Execute python**.
3. Paste one script containing all three functions **above** the glue below.

**Glue code — hardened version.** The original draft used `int("$var" or 0)`, which raises `ValueError` if the variable fails to resolve and leaves the literal `$vt_...` in the string. Since an enrichment crash must never look like a clean email, parse defensively:

```python
import json

def as_int(v, default=0):
    try:
        return int(str(v).strip())
    except Exception:
        return default

hash_mal      = as_int("""$vt_attachment_hash.body.data.attributes.last_analysis_stats.malicious""")
domain_mal    = as_int("""$vt_sender_domain.body.data.attributes.last_analysis_stats.malicious""")
sender_domain = """$exec.sender_domain""".strip()

ts  = typosquat_check(sender_domain)
age = domain_age_days(sender_domain)
result = risk_score(hash_mal, domain_mal, ts, age["age_days"])
result["typosquat"]  = ts
result["domain_age"] = age
print(json.dumps(result))
```

Shuffle substitutes the `$variables` into the code **as text** before running it, which is why they sit inside quotes. Triple quotes are safer than single: a substituted value containing a quote character would otherwise break the script.

> **Correction — found in Chapter 9.** Triple quotes are escaping, not validation, and they only
> raised the bar: a sender domain containing `"""` closes the string and crashes this script
> (`Syntax Error: unterminated triple-quoted string literal`). The real fix is upstream — an
> allowlist pattern on the input, checked in an edge condition so the value is compared as data
> and never spliced into code. `phishing_triage_v3` does this; see
> [`evidence/ch10-01-phishing-v3-injection-rejected.png`](../evidence/ch10-01-phishing-v3-injection-rejected.png).

4. Rewire the two verdict edges to come out of `Risk_Scoring` instead of `Evidence Summary`. Conditions now test `$risk_scoring.verdict`: **equals** `PHISHING` for the phishing branch, **does not equal** `PHISHING` for the other.

> **Correction — found while building, and again in Chapter 9.**
> 1. The path is `$risk_scoring.message.verdict`. Shuffle wraps whatever a Python node prints in
>    `{"success": ..., "message": {...}}`, so `$risk_scoring.verdict` resolves to nothing.
> 2. "Does not equal PHISHING" is a **fail-open** design. When the script crashes the verdict is
>    empty, empty doesn't equal PHISHING, and the email is closed as benign — exactly what the
>    Chapter 9 injection test produced. The benign edge must require a positive answer, **equals
>    `LIKELY_BENIGN`**, with SUSPICIOUS, empty and crashed results routed to a human.
>    `phishing_triage_v3` is built this way.
5. Add `$risk_scoring.risk_score` and `$risk_scoring.reasons` to both verdict texts.
6. If the node fails, click it and read the Python traceback — it names the exact line. Debugging tracebacks is part of this chapter's curriculum, not a detour.

---

## 🧪 Lab 7: `phishing_triage_v2`

1. **Screenshot:** v2 canvas with the `Risk_Scoring` node wired in.
2. **The kill shot:** fire the malicious payload but with the *clean* empty-file hash. v1 called this BENIGN; v2 must catch it. Screenshot the Risk Scoring output showing score, verdict and reasons.
3. **Regression test:** fire the GitHub payload — must still be LIKELY_BENIGN. A v2 that flags everything is worse than v1.
4. **Written:**
   - a) Exact score and reasons for the link-only run — which detector(s) caught what the hash missed?
   - b) Change one weight or threshold you disagree with, and defend it in 2–3 sentences. There is no correct answer; there is only reasoning.
   - c) `typosquat_check` has false-negative classes — name one realistic phishing domain it would miss, and why.

**Bonus:** wire in your unused urlscan.io key. POST the extracted URL to `https://urlscan.io/api/v1/scan/` (header `API-Key`, body `{"url": ..., "visibility": "public"}`), wait ~20s, GET the result, and fold its verdict into the scoring. That's Detector 4, and it completes the trilogy from 5c.

### The kill-shot payload

```bash
curl -k -X POST https://localhost:3443/api/v1/hooks/YOUR_WEBHOOK_ID \
  -H "Content-Type: application/json" \
  -d '{
    "from": "support@micros0ft-support.xyz",
    "sender_domain": "micros0ft-support.xyz",
    "subject": "Your account will be suspended",
    "body": "Dear user, verify immediately at hxxps://micros0ft-support[.]xyz/login or your account closes in 24h.",
    "attachment_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }'
```

Same phishing email, clean attachment hash. This is the exact case v1 waved through.
