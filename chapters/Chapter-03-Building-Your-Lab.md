# Chapter 3: Building Your Lab

This chapter has no theory to memorize; it's pure setup. By the end, you'll have a real SOAR platform running on your own machine. Instructions cover macOS, Windows, and Linux.

## 3.1 What we're installing and why

- **Docker** — a tool that runs applications in isolated "containers." Shuffle ships as containers, so this is the engine underneath. (Docker is also a core DevOps/security skill on its own — knowing it is CV material.)
- **Shuffle** — the open-source SOAR platform. Free, runs locally, used by real companies. Everything you design becomes drag-and-drop workflows here.
- **Free API keys** — VirusTotal, AbuseIPDB, urlscan.io. These are the threat-intel services your playbooks will query, and their free tiers are enough for our whole course.

**Minimum specs:** 8 GB RAM (16 GB comfortable), ~20 GB free disk, virtualization enabled in BIOS (usually already on).

## 3.2 Step 1 — Install Docker

**macOS:**
1. Download **Docker Desktop for Mac** from `docker.com`. Pick the build that matches your chip: **Apple Silicon** (M1/M2/M3/M4) or **Intel**. Not sure which you have? Apple menu → About This Mac → look at "Chip" or "Processor".
2. Open the `.dmg`, drag Docker into Applications, and launch it. Approve the one-time privileged-helper prompt.
3. Wait until the whale icon in the menu bar stops animating and says "Docker Desktop is running."
4. Docker Desktop for Mac bundles `docker compose`, so nothing else to install. `git` is included with Xcode Command Line Tools — if `git --version` prompts you to install them, accept.

> **Apple Silicon note:** Shuffle's images are built for `linux/amd64`. Docker Desktop runs them through emulation (Rosetta), which is fine for a lab but slower. If a container fails to start with an architecture error, add `platform: linux/amd64` under that service in `docker-compose.yml`.

**Windows:**
1. Download **Docker Desktop** from `docker.com` and run the installer.
2. When asked, keep **"Use WSL 2"** checked (WSL 2 = a lightweight Linux layer inside Windows; Docker needs it).
3. If the installer complains WSL is missing: open **PowerShell as Administrator** and run:
   ```powershell
   wsl --install
   ```
   Reboot, then re-run Docker Desktop.
4. Start Docker Desktop and wait until the whale icon in the taskbar stops animating.

**Linux (Ubuntu/Debian):**
```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo usermod -aG docker $USER   # run docker without sudo
# log out and back in for the group change to apply
```

**Verify (all systems)** — open a terminal:
```bash
docker --version
docker run hello-world
```
If `hello-world` prints a greeting, Docker works. If you get an error, paste it here and we'll fix it before continuing — do not skip past a broken Docker.

## 3.3 Step 2 — Deploy Shuffle

In your terminal (on Windows, use PowerShell or the WSL terminal; on Mac, use Terminal or iTerm):

```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
```

(No git? Windows: install from `git-scm.com`. Linux: `sudo apt install git`. Mac: `xcode-select --install`.)

**Linux only** — Shuffle's database container needs to own its data folder (not needed on Mac or Windows, where Docker Desktop handles permissions):
```bash
mkdir shuffle-database
sudo chown -R 1000:1000 shuffle-database
```

Then launch everything:

```bash
docker compose up -d
```

The first run downloads several images — this takes 5–15 minutes depending on your internet. `-d` means "run in background."

**Low-RAM machines (important on an 8 GB Mac)** — Shuffle's `docker-compose.yml` gives OpenSearch a 3 GB Java heap:

```yaml
- "OPENSEARCH_JAVA_OPTS=-Xms3072m -Xmx3072m"
```

Docker Desktop on an 8 GB Mac typically only offers ~3.8 GB to containers in total, so that single setting eats the whole budget and the stack thrashes or gets OOM-killed. Rather than editing Shuffle's tracked file, drop a `docker-compose.override.yml` next to it — Compose merges it automatically:

```yaml
services:
  opensearch:
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1024m -Xmx1024m"
      - bootstrap.memory_lock=false
```

Confirm it took effect before starting:
```bash
docker compose config | grep OPENSEARCH_JAVA_OPTS
```

A 1 GB heap is plenty for a lab. Delete the override if you later raise Docker Desktop's memory limit.

Also create the files directory the backend mounts, or Docker will invent it as a root-owned folder:
```bash
mkdir -p shuffle-files
```

Check that containers are alive:
```bash
docker ps
```
You should see several containers with `shuffle` in their names (frontend, backend, orborus, database), all with status `Up`.

## 3.4 Step 3 — First login

1. Open your browser → **https://localhost:3443** (or http://localhost:3001)
2. Your browser will warn about an untrusted certificate — that's expected for a local install; proceed anyway.
3. The **first account you register becomes the admin**. Use a proper password and save it — there's no "forgot password" email on a local install.
4. You'll land on the Shuffle dashboard: Workflows, Apps, and a getting-started screen.

Take a screenshot of this dashboard. Seriously — this is the "before" photo of your portfolio.

## 3.5 Step 4 — Get your free threat-intel API keys

Register on each of these (free tier, no credit card):

| Service | What it gives your playbooks | Free-tier limit (approx.) | Where the key lives |
|---|---|---|---|
| **VirusTotal** (virustotal.com) | File-hash, URL, IP, domain reputation from ~70 engines | 4 requests/min, 500/day | Profile → API Key |
| **AbuseIPDB** (abuseipdb.com) | IP abuse confidence score (0–100) | 1,000 checks/day | Account → API |
| **urlscan.io** | Scans a URL and returns screenshots + verdicts | reasonable free quota | Settings → API |

Save all three keys in a local text file called `api-keys.txt`. **Rule from day one, because in a job this is fireable:** API keys are credentials. Never paste them in chat, never commit them to GitHub, never screenshot them.

*Note: free-tier limits change over time — whatever the exact numbers are when you register, the workflow is the same.*

## 3.6 Step 5 — Connect VirusTotal to Shuffle (your first integration)

1. In Shuffle, go to **Apps** and search for **VirusTotal** → activate it.
2. Open **Workflows → New workflow**, name it `test_connection`.
3. Drag the **VirusTotal** app onto the canvas.
4. Click it → in the right panel choose action **Get an IP address report**, paste your API key when prompted to authenticate, and set the IP field to `8.8.8.8` (Google's DNS — a famously clean IP).
5. Hit the **▶ Execute** button.
6. Click the running node and inspect the result: you should see a JSON response full of data about 8.8.8.8.

If you see JSON — congratulations, your SOAR platform just made its first automated threat-intel query. That's orchestration (Shuffle ↔ VirusTotal), automation (no human clicked virustotal.com), and it took ~2 seconds.

## 3.7 Useful Docker commands for daily lab life

```bash
docker compose down        # stop Shuffle (from the Shuffle folder)
docker compose up -d       # start it again
docker ps                  # what's running?
docker compose logs backend --tail 50   # troubleshoot: read backend logs
```

Your workflows and account survive stop/start — data lives in the `shuffle-database` folder.

---

## 🧪 Lab 3: Prove your lab works

Deliverables — all four, no skipping:

1. **Screenshot 1:** output of `docker ps` showing Shuffle containers `Up`.
2. **Screenshot 2:** Shuffle dashboard, logged in.
3. **Screenshot 3:** your `test_connection` workflow showing a successful (green) VirusTotal execution for `8.8.8.8`.
4. **The reading exercise:** in the JSON result, find and write down: (a) the country VirusTotal associates with 8.8.8.8, (b) the number of engines flagging it as malicious (should be 0 or near it), and (c) who owns the IP (`as_owner` field). Reading JSON responses is a skill you'll use in every remaining chapter — Chapter 7 depends on it.

**Bonus:** run the same lookup on `185.220.101.5` (a known Tor exit node) and compare the two results. Notice which fields change — those differing fields are exactly what our playbook conditions will test in Chapter 4.

---

**Check disk space before you pull, not after.** This is the one that will actually bite you. The image pull needs several GB, and if the disk fills *during* the pull, Docker's content store takes write errors on half-written layers. The failure mode is nasty: the daemon starts returning `input/output error`, `docker system df` and `docker images` break, and you cannot even prune to recover, because pruning itself needs to write metadata. Docker ends up deadlocked — too full to fix itself.

Check first:
```bash
df -h /System/Volumes/Data      # macOS: the real data volume, NOT "df -h /"
docker system df                # what Docker is already holding
```

On macOS, `df -h /` reports the sealed read-only system volume and its numbers are misleading. Always look at `/System/Volumes/Data`.

Find Docker's biggest images before you decide what to drop:
```bash
docker images --format '{{.Size}}\t{{.Repository}}:{{.Tag}}' | sort -rh | head -20
```

If Docker is already deadlocked, the graceful cleanups will fail and the only reliable fix is to delete its virtual disk. Quit Docker Desktop completely first, then:
```bash
rm -f ~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw
```
Restart Docker Desktop and it recreates an empty disk. **This deletes every image and volume you have**, so know what you will need to re-download. Note that `Docker.raw` is a sparse file: `ls -lh` will claim it is the size of your whole disk, so measure it with `du -sh` instead.

**Expected on first boot:** the backend logs will spam `connection refused` and `Error in initial database connection. Retrying in 5 seconds` for the first minute or two. That is not a failure — OpenSearch takes a while to initialise its security layer, and the backend simply retries until it wins. You are done waiting when you see:

```
[DEBUG] Initialized Shuffle database connection. Setting up environment.
[DEBUG] No orgs. Setting NEW org "default"
```

Check the cluster directly if you want certainty (`"status":"green"` is what you want):
```bash
curl -sk -u "admin:<SHUFFLE_OPENSEARCH_PASSWORD from Shuffle/.env>" https://localhost:9200/_cluster/health
```

**Execution hangs forever on EXECUTING, with "Is Orborus running?"** Two separate causes, both hit on a small Mac.

*Cause 1: the worker cannot reach the backend.* Shuffle runs workers as Docker **Swarm** services on an overlay network (`shuffle_swarm_executions`), while the backend sits on a bridge network. The backend needs to be on both. Recreating the backend container (any `docker compose up -d backend`, e.g. after editing `.env`) silently drops the overlay attachment. The worker then runs your action but cannot post the result home:

```
Failed making stream results request: dial tcp: lookup shuffle-backend
on 127.0.0.11:53: no such host
```

The run sits at EXECUTING rather than failing, because the work succeeded and only the reply was lost. Fix:

```bash
docker network connect shuffle_swarm_executions shuffle-backend
```

Verify with `docker inspect shuffle-backend --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'` — you want **both** networks listed.

*Cause 2: app containers are being OOM-killed.* Shuffle defaults to `SHUFFLE_APP_REPLICAS=3`, so every app runs three copies. With six apps that is 18 containers plus core services, which will not fit in a 3.8 GB Docker budget. Containers die with **exit code 137** (SIGKILL, out of memory) mid-execution and the run returns no results. Count the casualties:

```bash
docker ps -a --filter "exited=137" --format '{{.Names}}' | wc -l
```

Set `SHUFFLE_APP_REPLICAS=1` in `.env`, and scale the already-running services down immediately:

```bash
for s in $(docker service ls --format '{{.Name}}' | grep -v shuffle-workers); do
  docker service scale $s=1 --detach
done
```

Replicas exist for parallel throughput in production. A single-user lab never needs them.

**Nodes are "SKIPPED because it's not under the startnode".** Dragging an app onto the canvas does **not** connect it to anything, and Shuffle only runs nodes reachable from the start node. Either delete the default `Change Me` node so yours becomes the start, or draw a connection into your node. Then **Save** — Shuffle executes the saved workflow, not what is on screen.

**Troubleshooting notes:** if anything fails — Docker won't start, containers restart-loop, localhost won't load, VirusTotal auth fails — paste the exact error and we'll debug it together. Getting a lab running *is* part of the skill; every SOAR engineer has fought Docker at 2am.

**Next:** Chapter 4 — Your First Real Playbook: the IP-enrichment workflow with actual verdict logic.
