#!/usr/bin/env python3
"""
scrub_workflow.py - remove credentials from a Shuffle workflow export
before it goes anywhere near git.

Usage:
    python3 tools/scrub_workflow.py <raw_export.json> <clean_output.json> [--keys api-keys.txt]
                                    [--keep-emails] [--keep-webhooks]

The raw export is only read, never modified. The script never talks to
Shuffle, so the live workflow cannot be changed by it.

Five passes:
  1. Every value listed in api-keys.txt is replaced wherever it appears,
     with a placeholder naming which key it was.
  2. Shuffle parameters named apikey/password/token/... are blanked.
  3. HTTP header lines such as "Key: ..." or "Authorization: Bearer ..."
     are blanked, even if the key is not in api-keys.txt.
  4. Email addresses are redacted (Shuffle stamps the editor's address into
     fields such as updated_by). Reserved placeholder addresses are kept.
     Pass --keep-emails to skip this pass.
  5. Webhook IDs are replaced. Anyone holding a webhook URL can trigger the
     playbook, so each real webhook ID becomes a fixed dummy UUID
     (00000000-0000-4000-8000-00000000000N) everywhere it appears - trigger
     id, hook URL, and the branch that leaves the trigger - so the exported
     graph stays wired and importable. Any other /api/v1/hooks/<...> path
     segment becomes <REDACTED:WEBHOOK>. Pass --keep-webhooks to skip.

Then it verifies the result. If any known secret, real webhook ID, or
non-placeholder email address survives anywhere in the output, it exits non-zero and writes
nothing. Secret values are never printed.

Limitation: pass 1 only knows the secrets in api-keys.txt. A credential that
is in neither that file nor a recognised header/parameter cannot be detected,
so read the warnings and skim the output before committing it.
"""
import argparse
import json
import re
import sys
from pathlib import Path

PLACEHOLDER = "<REDACTED:{}>"
SECRET_PARAM_NAMES = {"apikey", "api_key", "password", "secret", "token", "access_token"}
HEADER_RE = re.compile(
    r"(?im)^(\s*(?:Key|X-Api-?Key|Api-?Key|Authorization)\s*:\s*(?:Bearer\s+|Basic\s+)?)(\S+)"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
# Placeholders that are safe to publish: Shuffle's own User Input default,
# and the RFC 2606 reserved example domains.
SAFE_EMAILS = {"test@test.com"}
SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")


UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
WEBHOOK_ID_RE = re.compile(r"webhook_(" + UUID + r")")
HOOK_PATH_RE = re.compile(r"(/api/v1/hooks/)([A-Za-z0-9_-]+)")
DUMMY_UUID = "00000000-0000-4000-8000-{:012d}"


def collect_webhook_ids(data):
    """Real webhook IDs: WEBHOOK trigger ids plus any webhook_<uuid> string."""
    ids = set()
    for t in (data.get("triggers") or []) if isinstance(data, dict) else []:
        if isinstance(t, dict) and t.get("trigger_type") == "WEBHOOK" and t.get("id"):
            ids.add(str(t["id"]))
    for s in all_strings(data):
        ids.update(WEBHOOK_ID_RE.findall(s))
    return {wid: DUMMY_UUID.format(i) for i, wid in enumerate(sorted(ids), 1)}


def is_safe_email(addr):
    a = addr.lower()
    return a in SAFE_EMAILS or a.rsplit("@", 1)[-1] in SAFE_EMAIL_DOMAINS


def load_known_secrets(path):
    secrets = {}
    if not path.exists():
        return secrets
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_]+)\s*=\s*(\S+)\s*$", line)
        if m and m.group(2) != "PASTE_KEY_HERE" and len(m.group(2)) >= 8:
            secrets[m.group(1)] = m.group(2)
    return secrets


def scrub_string(s, known, counts, redact_emails, hooks):
    for name, val in known.items():
        if val in s:
            counts[name] = counts.get(name, 0) + s.count(val)
            s = s.replace(val, PLACEHOLDER.format(name))

    def blank_header(m):
        if m.group(2).startswith("<REDACTED"):
            return m.group(0)
        counts["header"] = counts.get("header", 0) + 1
        return m.group(1) + PLACEHOLDER.format("HEADER_SECRET")

    s = HEADER_RE.sub(blank_header, s)

    for real, dummy in (hooks or {}).items():
        if real in s:
            counts["webhook_id"] = counts.get("webhook_id", 0) + s.count(real)
            s = s.replace(real, dummy)
    if hooks is not None:
        def blank_hook(m):
            seg = m.group(2)
            if any(d in seg for d in hooks.values()) or seg.startswith("<REDACTED"):
                return m.group(0)
            counts["webhook_path"] = counts.get("webhook_path", 0) + 1
            return m.group(1) + PLACEHOLDER.format("WEBHOOK")
        s = HOOK_PATH_RE.sub(blank_hook, s)

    if redact_emails:
        def blank_email(m):
            if is_safe_email(m.group(0)):
                return m.group(0)
            counts["email"] = counts.get("email", 0) + 1
            return PLACEHOLDER.format("EMAIL")
        s = EMAIL_RE.sub(blank_email, s)
    return s


def walk(node, known, counts, redact_emails, hooks):
    if isinstance(node, dict):
        # Shuffle stores node fields as {"name": "apikey", "value": "..."}
        name = str(node.get("name", "")).lower()
        value = node.get("value")
        if name in SECRET_PARAM_NAMES and isinstance(value, str) and value and not value.startswith("<REDACTED"):
            counts["param:" + name] = counts.get("param:" + name, 0) + 1
            node["value"] = PLACEHOLDER.format(name.upper())
        for k, v in list(node.items()):
            node[k] = walk(v, known, counts, redact_emails, hooks)
        return node
    if isinstance(node, list):
        return [walk(x, known, counts, redact_emails, hooks) for x in node]
    if isinstance(node, str):
        return scrub_string(node, known, counts, redact_emails, hooks)
    return node


def all_strings(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            yield from all_strings(v)
    elif isinstance(node, list):
        for x in node:
            yield from all_strings(x)
    elif isinstance(node, str):
        yield node


def find_leaks(data, serialized, known, redact_emails, real_hook_ids):
    leaks = [f"known secret {name}" for name, val in known.items() if val in serialized]
    for s in all_strings(data):
        for m in HEADER_RE.finditer(s):
            if not m.group(2).startswith("<REDACTED"):
                leaks.append(f"unredacted header '{m.group(1).split(':')[0].strip()}'")
    if redact_emails and any(not is_safe_email(e) for e in EMAIL_RE.findall(serialized)):
        leaks.append("email address that is not a known placeholder")
    if any(wid in serialized for wid in real_hook_ids):
        leaks.append("real webhook ID")
    return leaks


def main():
    ap = argparse.ArgumentParser(description="Scrub credentials from a Shuffle workflow export.")
    ap.add_argument("raw", type=Path, help="raw export from Shuffle (contains secrets)")
    ap.add_argument("out", type=Path, help="where to write the scrubbed copy")
    ap.add_argument("--keys", type=Path, default=Path(__file__).resolve().parent.parent / "api-keys.txt",
                    help="file of NAME=VALUE secrets to hunt for (default: ../api-keys.txt)")
    ap.add_argument("--keep-emails", action="store_true",
                    help="do not redact email addresses")
    ap.add_argument("--keep-webhooks", action="store_true",
                    help="do not replace webhook IDs / hook URLs")
    args = ap.parse_args()

    if args.raw.resolve() == args.out.resolve():
        sys.exit("refusing: output must be a different file from the raw export")

    known = load_known_secrets(args.keys)
    if not known:
        print(f"WARNING: no secrets loaded from {args.keys}; only header/parameter patterns will be scrubbed")

    data = json.loads(args.raw.read_text(encoding="utf-8"))
    counts = {}
    redact_emails = not args.keep_emails
    hooks = None if args.keep_webhooks else collect_webhook_ids(data)
    data = walk(data, known, counts, redact_emails, hooks)
    serialized = json.dumps(data, indent=2, ensure_ascii=False)

    leaks = find_leaks(data, serialized, known, redact_emails, list(hooks or {}))
    if leaks:
        print("REFUSING TO WRITE - secrets survived scrubbing:")
        for leak in sorted(set(leaks)):
            print("   ", leak)
        sys.exit(1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(serialized + "\n", encoding="utf-8")

    print(f"wrote {args.out}")
    print("redactions:", ", ".join(f"{k} x{v}" for k, v in sorted(counts.items())) or "none")
    emails = sorted(set(EMAIL_RE.findall(serialized)))
    hexes = HEX64_RE.findall(serialized)
    if emails and not redact_emails:
        print(f"note: {len(emails)} email address(es) remain - check none are personal before publishing")
    elif emails:
        print(f"note: only placeholder email(s) remain: {', '.join(emails)}")
    if hexes:
        print(f"note: {len(hexes)} 64-hex string(s) remain - usually SHA256 test hashes, but confirm none is a key")
    print("verified: no known secret appears in the output")


if __name__ == "__main__":
    main()
