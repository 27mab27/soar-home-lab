# Chapter 4: Your First Real Playbook

This is the chapter where you cross the line from "installed a tool" to "built automation." We're building `ip_enrichment_v1`: an alert containing an IP arrives, two threat-intel sources are queried in parallel, a condition decides, and a formatted verdict comes out. Small, but it's the real skeleton from Chapter 2 (Parse → Enrich → Score → Branch → Document), and every bigger playbook in this course grows from it.

---

## Before you start: is the lab up?

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E "frontend|backend|opensearch|orborus"
docker inspect shuffle-backend --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
```

The second command must list **both** `shuffle_shuffle` and `shuffle_swarm_executions`. If it doesn't, executions will hang on EXECUTING forever — see the troubleshooting section of Chapter 3, or just run:

```bash
docker network connect shuffle_swarm_executions shuffle-backend
```

---

## 4.0 Register AbuseIPDB (5 minutes)

1. Go to `abuseipdb.com` → Register (free, no credit card).
2. Verify your email.
3. Log in → click your username → **Account** → **API** tab → **Create Key**.
4. Copy the key into your local `api-keys.txt` (same rules as before: never in chat, never on GitHub, never in a screenshot).

**Why AbuseIPDB alongside VirusTotal?** VirusTotal tells you what security engines *think*. AbuseIPDB tells you what the internet *experienced* — its score (0–100) comes from real abuse reports: this IP brute-forced SSH, sent spam, scanned ports. Two independent signal types is the multi-signal design that saved you from blocking 8.8.8.8 in Chapter 3.

## 4.1 The design (30 seconds on paper first — always)

```
TRIGGER: Webhook receives {"src_ip": "..."}
   │
   ▼
START NODE: Receive_alert (Shuffle Tools, repeat back to me)
   │
   ├─► ACTION A: VirusTotal — get IP report        ┐ parallel
   ├─► ACTION B: AbuseIPDB — check IP              ┘
   │
   ├─► CONDITION: VT malicious >= 3  OR  AbuseIPDB score >= 75 ?
   │        YES ▼                        NO ▼
   │   Format MALICIOUS verdict     Format CLEAN verdict
```

## 4.2 Build it in Shuffle

### Step 1 — New workflow

Workflows → Create → name it `ip_enrichment_v1`. Good habit from day one: version numbers in names. Real SOCs iterate playbooks like software.

### Step 2 — The webhook trigger

1. From the **Triggers** section in the left panel, drag the **Webhook** trigger onto the canvas.
2. Click it. You'll see a Webhook URI like `https://localhost:3443/api/v1/hooks/webhook_abc123`. Copy it.
3. Click **Start** on the trigger so it's listening.

This URL is how any external system (in Chapter 6, your SIEM) will fire this playbook. Today you'll play the role of the SIEM using `curl`.

### Step 2b — The start node (do not skip this)

Shuffle executes downward from a single **start node**. A trigger does not fan out; it hands control to exactly one node. If you connect two actions directly to the webhook, Shuffle makes one the start node and **silently skips the other** with `"Skipped because it's not under the startnode"`.

Parallelism therefore comes from *one node branching to two*, never from two nodes sharing a trigger.

1. Drag a **Shuffle Tools** node onto the canvas. Action: **Repeat back to me**, message `$exec.src_ip`. Rename it `Receive_alert`.
2. Connect **Webhook → Receive_alert**.
3. Right click it and **Set as startnode** if it isn't already.

Every enrichment node then hangs off `Receive_alert`:

```
Webhook ──► Receive_alert ──┬──► Virustotal v3 1
                            └──► Http 1
```

This is also why Shuffle drops a `Change Me` node into every new workflow. It is the start node, and deleting it before you have a replacement leaves the workflow unsaveable, since a workflow needs at least one action.

### Step 3 — VirusTotal node

1. Drag your **Virustotal v3** app onto the canvas (activated in Chapter 3).
2. Connect **Receive_alert** to it by dragging from that node's edge to this one.
3. Action: **Get an ip address report**.
4. In the **ip** field, don't type an IP — we want the one from the webhook. Use the autocomplete in the field and select the execution argument, which inserts:

```
$exec.src_ip
```

`$exec` is Shuffle's variable for "whatever the trigger received." This is the **Parse** step: data flowing from trigger into action.

### Step 4 — AbuseIPDB node, via the HTTP app

Shuffle has an AbuseIPDB app, but build this one with the generic **Http** app instead. Prebuilt apps exist for maybe 2,500 tools. The other ten thousand tools you'll meet in your career are integrated exactly this way, with raw API calls. This is the skill.

1. Drag the **Http** app onto the canvas. Connect it from the **start node** (`Receive_alert`), not from the VirusTotal node. Both enrichment nodes hanging off the *same parent* is what makes them run in parallel.
2. Action: **GET**.
3. URL:

```
https://api.abuseipdb.com/api/v2/check?ipAddress=$exec.src_ip&maxAgeInDays=90
```

4. Headers, one per line. The header name is `Key` with a capital K, and AbuseIPDB rejects the request if you get that wrong:

```
Key: YOUR_ABUSEIPDB_KEY
Accept: application/json
```

### Step 5 — The condition and verdict nodes

1. Drag a **Shuffle Tools** app onto the canvas and connect it after the VirusTotal node. Action: **Repeat back to me**. It just formats text, which is perfect for verdicts.
2. In its message, build the verdict using results from both enrichment nodes:

```
===== IP ENRICHMENT VERDICT =====
IP: $exec.src_ip
VT malicious engines: $virustotal_v3_1.body.data.attributes.last_analysis_stats.malicious
AbuseIPDB score: $http_1.body.data.abuseConfidenceScore
Country: $virustotal_v3_1.body.data.attributes.country
Owner: $virustotal_v3_1.body.data.attributes.as_owner
Verdict: MALICIOUS - escalate to analyst
```

Node names like `$virustotal_v3_1` must match **your** node names. Click a node to see its exact name. Use the autocomplete popup to pick fields rather than typing paths blind — a silently empty variable is almost always a name mismatch.

3. Now the branching. Click the edge connecting VirusTotal → Shuffle Tools. Edges in Shuffle can carry conditions. Add:

```
$virustotal_v3_1.body.data.attributes.last_analysis_stats.malicious   larger than   2
```

4. Duplicate the Shuffle Tools node, set its message to the CLEAN version (`Verdict: CLEAN - auto-close`), and give its incoming edge the opposite condition (`less than 3`).

> **Correction — found in Chapter 9.** This edge fails open. If the lookup fails (a dead API key,
> a rate limit, an invalid input), the malicious count comes back empty, Shuffle compares it as
> 0, and `less than 3` passes — so the run auto-closes as clean. A clean verdict must also require
> proof the lookup worked (`$node.status` equals `200`), with failures routed to a human. See
> `brute_force_response_v3` and [`evidence/ch09-01-dead-key-fails-open.png`](../evidence/ch09-01-dead-key-fails-open.png).

You now have a real branch: same input, two possible paths.

> **Simplification note.** Shuffle's edge conditions make a clean OR across two different nodes' outputs awkward in a first playbook, so today's condition tests VirusTotal only, while the verdict text still displays both scores for the analyst. In Chapter 7, when we can write Python inside workflows, we'll implement the full `VT >= 3 OR Abuse >= 75` logic properly. Design ideal versus platform reality is itself a real SOAR lesson.

### Step 6 — Save. Always save.

Shuffle executes the saved workflow, not what's on screen.

## 4.3 Fire it like a SIEM would

From your Mac terminal. The `-k` flag is needed because of the self-signed certificate:

```bash
# Test 1: clean IP
curl -k -X POST https://localhost:3443/api/v1/hooks/YOUR_WEBHOOK_ID \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "8.8.8.8"}'

# Test 2: dirty IP (known Tor exit node)
curl -k -X POST https://localhost:3443/api/v1/hooks/YOUR_WEBHOOK_ID \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "185.220.101.5"}'
```

Then open the workflow's execution view and watch: the trigger fires, both enrichment nodes light up together, and only **one** verdict node executes per run.

---

## 🧪 Lab 4: Deliverables

1. **Screenshot:** the canvas showing your full workflow — trigger, two parallel enrichment nodes, two verdict nodes with conditioned edges.
2. **Screenshot or paste:** execution result for `8.8.8.8`. Must show the CLEAN verdict node ran.
3. **Screenshot or paste:** execution result for `185.220.101.5`. The MALICIOUS verdict should run. It's a well-known Tor exit node; if VirusTotal engines score it under 3, note the number you got — that itself is a threshold-tuning conversation.
4. **Written answers:**
   - a) In your two runs, what were the VirusTotal malicious counts and AbuseIPDB scores for each IP?
   - b) Why do both enrichment nodes hang off the same start node instead of being chained one after the other? What would `"Skipped because it's not under the startnode"` have told you?
   - c) A colleague says "set the threshold to `malicious >= 1` to be safe." Using what you learned from the 8.8.8.8 JSON in Chapter 3, argue against it in two sentences.

**Bonus (portfolio-grade):** add a third parallel enrichment node, an HTTP GET to `http://ip-api.com/json/$exec.src_ip` (free geolocation, no key needed), and include its country and ISP in your verdict text.

---

**Troubleshooting is part of the lab.** Webhook returns nothing → is the trigger Started? Node fails red → click it and read the error (auth, or a bad variable path?). Variable resolves to empty → node name mismatch, use autocomplete. Execution hangs on EXECUTING and never finishes → that's the backend overlay network problem from Chapter 3, not your playbook.
