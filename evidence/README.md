# Evidence

Screenshots from the lab, in the order the work happened. Each one shows a single result.
All image metadata has been stripped.

## Chapter 9 — chaos testing

The first four show the defects as found: each test turned a known attacker or a malicious
input into an auto-closed "clean" verdict.

| Screenshot | What it shows |
|---|---|
| [`ch09-01-dead-key-fails-open.png`](ch09-01-dead-key-fails-open.png) | VirusTotal key corrupted. VirusTotal answers `WrongCredentialsError`, yet the node reports `success: true`; the empty malicious count is read as 0 and the known Tor exit `185.220.101.5` — AbuseIPDB score 100 — is closed as **CLEAN**. |
| [`ch09-02-garbage-input-fails-open.png`](ch09-02-garbage-input-fails-open.png) | `src_ip` set to `not-an-ip`. AbuseIPDB answers HTTP 422, the node still reports success, and the verdict is **CLEAN**. |
| [`ch09-03-missing-field-fails-open.png`](ch09-03-missing-field-fails-open.png) | A payload with no `src_ip` at all. AbuseIPDB is called with an empty address (`ipAddress=&`) and the verdict is **CLEAN**. Found by accident. |
| [`ch09-04-injection-crash-benign.png`](ch09-04-injection-crash-benign.png) | `"""` in the phishing sender domain closes a string inside the Python scoring code: `Syntax Error: unterminated triple-quoted string literal`. The crash leaves the verdict empty and the email is closed as **benign**. |

The fixes, in `brute_force_response_v3`:

| Screenshot | What it shows |
|---|---|
| [`ch09-05-v3-canvas-during-build.png`](ch09-05-v3-canvas-during-build.png) | The v3 workflow while the input gate and allowlist were being added. Taken before the nodes were renamed, so the gate still appears as `Shuffle Tools 1`. |
| [`ch09-06-v3-garbage-rejected.png`](ch09-06-v3-garbage-rejected.png) | `not-an-ip` stopped at the input gate: `Rejected Input`, no API calls made. |
| [`ch09-07-v3-allowlisted.png`](ch09-07-v3-allowlisted.png) | `8.8.8.8` short-circuited by the allowlist: no enrichment, no action. |
| [`ch09-08-v3-dead-key-fails-closed.png`](ch09-08-v3-dead-key-fails-closed.png) | Same corrupted key as the first screenshot: VirusTotal's HTTP 401 now routes to `Enrichment Failed VT` — *"Do NOT treat as clean."* Taken before a formatting fix, so the message prints the whole payload where it should print only the IP. |

## Chapter 10 — closing the remaining holes

| Screenshot | What it shows |
|---|---|
| [`ch10-01-phishing-v3-injection-rejected.png`](ch10-01-phishing-v3-injection-rejected.png) | The same `"""` payload against `phishing_triage_v3`: stopped at `Rejected Domain` before any enrichment or scoring runs. |
| [`ch10-02-phishing-v3-link-only-70.png`](ch10-02-phishing-v3-link-only-70.png) | Regression: link-only phishing still scores 70 → PHISHING (typosquat of `microsoft`, sender domain not registered). |
| [`ch10-03-phishing-v3-github-benign.png`](ch10-03-phishing-v3-github-benign.png) | Regression: a GitHub newsletter scores 0 → LIKELY_BENIGN, so the stricter benign rule still lets legitimate mail through. |
| [`ch10-04-thehive-fixed-sourceref.png`](ch10-04-thehive-fixed-sourceref.png) | The TheHive alert created by `brute_force_response_v3`, created by the service account, with the corrected reference `wazuh rule 5763 from 185.220.101.5`. The *Detection: < 1 second* metric shown here is not end-to-end latency — see [architecture.md](../architecture.md#measured-latency). |

## Earlier chapters

Screenshots from Chapters 3–9 live next to their chapter files in [`../chapters/`](../chapters/),
named `labN-*.png` — including the first Wazuh-triggered run (Chapter 6), the approval gate and
case promotion (Chapter 8). Where one showed a personal email, webhook ID, approval token, or local
username and hostname, that area is blacked out. All image metadata has been stripped.
