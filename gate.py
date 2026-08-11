"""Verificate Gate — GitHub Action entrypoint.

Runs the Verificate merge gate on the changed code files of a pull request, posts an inline
summary comment, and exits non-zero if the gate VETOES (so it can be a required status check
that blocks merge). Design principle: fail CLOSED only on a real veto; fail OPEN on any
infrastructure error (MCP unreachable, timeouts) so gate outages never block your merges.

Env: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH, optional VERIFICATE_MCP_URL,
VERIFICATE_API_KEY, FAIL_ON (reject|off), MAX_FILES.
"""
from __future__ import annotations
import base64, json, os, ssl, sys, urllib.request, urllib.error

REPO = os.environ.get("GITHUB_REPOSITORY", "")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
# GitHub Actions OIDC: present only if the caller's workflow grants `permissions: id-token: write`.
OIDC_REQ_URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
OIDC_REQ_TOKEN = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
MCP_URL = os.environ.get("VERIFICATE_MCP_URL", "https://mcp.verificate.ai/mcp")
VKEY = os.environ.get("VERIFICATE_API_KEY", "").strip()
FAIL_ON = os.environ.get("FAIL_ON", "reject").strip().lower()
MAX_FILES = int(os.environ.get("MAX_FILES", "25"))
MARK = "<!-- verificate-gate -->"
CODE_EXT = {".py",".js",".ts",".tsx",".jsx",".go",".java",".rb",".rs",".c",".cc",".cpp",
            ".cs",".php",".sql",".sh",".kt",".swift",".scala"}
LANG = {".py":"python",".js":"javascript",".ts":"typescript",".tsx":"typescript",".jsx":"javascript",
        ".go":"go",".java":"java",".rb":"ruby",".rs":"rust",".cpp":"cpp",".cs":"csharp",".php":"php",".sql":"sql"}
_ctx = ssl.create_default_context()

def github_oidc_token():
    """Fetch a GitHub Actions OIDC JWT (audience=verificate-gate) so the gate's free tier
    can meter per-repository instead of per shared-runner IP. Returns '' if the workflow
    didn't grant `permissions: id-token: write` — the gate then falls back to the IP tier."""
    if not OIDC_REQ_URL or not OIDC_REQ_TOKEN:
        return ""
    try:
        req = urllib.request.Request(OIDC_REQ_URL + "&audience=verificate-gate",
            headers={"Authorization": f"Bearer {OIDC_REQ_TOKEN}", "User-Agent": "verificate-gate"})
        with urllib.request.urlopen(req, context=_ctx, timeout=15) as r:
            return (json.loads(r.read() or b"{}").get("value") or "").strip()
    except Exception as e:
        print(f"::warning::could not obtain OIDC token ({type(e).__name__}); using IP free tier.")
        return ""

_OIDC = github_oidc_token()

def gh(path, method="GET", data=None):
    req = urllib.request.Request("https://api.github.com" + path, method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
                 "User-Agent": "verificate-gate"})
    if data is not None:
        req.data = json.dumps(data).encode()
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")

def mcp_validate(code, lang):
    def rpc(method, params, rid):
        body = json.dumps({"jsonrpc":"2.0","id":rid,"method":method,"params":params}).encode()
        h = {"Content-Type":"application/json","Accept":"application/json, text/event-stream",
             "User-Agent":"verificate-gate/1.0 (+https://verificate.ai)"}
        # Signed OIDC token → the portal meters the free tier per-repository (not per
        # shared runner IP) with the repo identity proven, not merely claimed.
        if _OIDC: h["X-Verificate-OIDC"] = _OIDC
        if VKEY: h["Authorization"] = f"Bearer {VKEY}"
        req = urllib.request.Request(MCP_URL, data=body, method="POST", headers=h)
        raw = urllib.request.urlopen(req, context=_ctx, timeout=120).read().decode()
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"): line = line[5:].strip()
            if line.startswith("{"):
                try: return json.loads(line)
                except json.JSONDecodeError: continue
        return {}
    rpc("initialize", {"protocolVersion":"2024-11-05","capabilities":{},
                       "clientInfo":{"name":"verificate-gate-action","version":"1"}}, 0)
    resp = rpc("tools/call", {"name":"validate_ai_output",
               "arguments":{"ai_output":code,"validation_type":"code_generation","context":{"language":lang}}}, 2)
    parts = resp.get("result", {}).get("content", [])
    text = "\n".join(p.get("text","") for p in parts if p.get("type")=="text").strip()
    if text.startswith("{"):
        try:
            obj, _ = json.JSONDecoder().raw_decode(text)  # first JSON object; ignore trailing trial note
            return obj
        except json.JSONDecodeError:
            pass
    # Not a verdict (e.g. free-tier upsell / trial note) — the gate could not score this.
    return {"_unavailable": True, "text": text[:200]}

def upsert_comment(pr, body):
    try:
        comments = gh(f"/repos/{REPO}/issues/{pr}/comments?per_page=100")
        existing = next((c for c in comments if MARK in (c.get("body") or "")), None)
        if existing:
            gh(f"/repos/{REPO}/issues/comments/{existing['id']}", "PATCH", {"body": body})
        else:
            gh(f"/repos/{REPO}/issues/{pr}/comments", "POST", {"body": body})
    except Exception as e:
        print(f"::warning::could not post comment: {e}")

def main():
    ev = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    pr = (ev.get("pull_request") or {}).get("number") or ev.get("number")
    head = (ev.get("pull_request") or {}).get("head", {}).get("sha")
    if not pr:
        print("Not a pull_request event; nothing to gate."); return 0
    try:
        files = gh(f"/repos/{REPO}/pulls/{pr}/files?per_page=100")
    except Exception as e:
        print(f"::warning::could not list files ({e}); failing open."); return 0
    targets = [f for f in files if f.get("status") in ("added","modified")
               and any(f["filename"].endswith(e) for e in CODE_EXT)][:MAX_FILES]
    if not targets:
        upsert_comment(pr, f"{MARK}\n### ✅ Verificate Gate — no code changes to review.")
        print("No code files changed."); return 0

    rows, vetoed_any, errors, capped = [], False, 0, False
    for f in targets:
        ext = "." + f["filename"].rsplit(".",1)[-1]
        try:
            meta = gh(f"/repos/{REPO}/contents/{f['filename']}?ref={head}")
            code = base64.b64decode(meta["content"]).decode("utf-8","replace")
            res = mcp_validate(code, LANG.get(ext, "text"))
        except Exception as e:
            errors += 1
            print(f"::warning::Verificate gate error on {f['filename']}: {type(e).__name__}: {str(e)[:160]}")
            rows.append((f["filename"], "⚠️ gate error (skipped)", "")); continue
        if res.get("_unavailable"):
            errors += 1; capped = True
            print(f"::warning::Verificate gate unavailable for {f['filename']} — shared free-tier limit reached on this runner. "
                  f"Add a VERIFICATE_API_KEY secret (free, no card: https://verificate.ai/auth/signup) to get your own quota.")
            rows.append((f["filename"], "⚠️ skipped — free limit reached", "")); continue
        prot = res.get("protection", {})
        vetoed = bool(prot.get("vetoed"))
        rejected = vetoed or res.get("valid") is False or str(res.get("assessment",{}).get("verdict","")).lower() in ("reject","rejected")
        score = res.get("score")
        issues = res.get("issues") or []
        if vetoed: vetoed_any = True
        status = "❌ REJECTED" if rejected else "✅ approved"
        detail = ("vetoed by " + ", ".join(prot.get("vetoed_by") or [])) if vetoed else (f"score {score}" if score is not None else "")
        rows.append((f["filename"], status, detail))
        for iss in issues[:4]:
            rows.append(("　↳", str(iss)[:140], ""))

    lines = [MARK, "### 🛡️ Verificate Gate",
             f"Reviewed **{len(targets)}** changed code file(s)"
             + (f" · {errors} skipped (gate error)" if errors else "") + ".", "",
             "| File | Verdict | Detail |", "|---|---|---|"]
    for name, status, detail in rows:
        lines.append(f"| `{name}` | {status} | {detail} |")
    if vetoed_any:
        lines += ["", "**A deterministic reality gate vetoed a change — fix the findings above and push again.** "
                  "A veto is authoritative and cannot be overridden."]
    else:
        lines += ["", "No veto. " + ("Warnings noted above." if errors else "Changes cleared the gate.")]
    if capped:
        lines += ["", "> ⚠️ **Some files were skipped — the shared free trial on this runner is used up, so the gate couldn't score them.** "
                  "The gate failed **open**, so this did **not** block your merge. "
                  "To get your own quota (free, no card, 30 days), sign up at "
                  "[verificate.ai/auth/signup](https://verificate.ai/auth/signup) and add the key as a repo secret named "
                  "**`VERIFICATE_API_KEY`** — validations resume on the next push."]
    lines += ["", "_Verificate — the merge gate for AI-written code. [Why](https://github.com/Verificate-Dev/verificate-mcp-quickstart/blob/master/COMPARISON.md)_"]
    upsert_comment(pr, "\n".join(lines))

    if vetoed_any and FAIL_ON == "reject":
        print("::error::Verificate Gate: a change was VETOED — blocking merge until fixed.")
        return 1
    print("Verificate Gate: passed (no veto).")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Global fail-open: never block a merge on an unexpected gate error.
        print(f"::warning::Verificate Gate errored, failing open: {e}")
        sys.exit(0)
