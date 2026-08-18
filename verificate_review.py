#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificate-review — Verificate Gate CI entrypoint with cross-file context (VCG).
Builds the Verificate Context Graph over the repo, then reviews target files (changed-in-PR by default)
through the gate WITH each file's security_graph, so the gate suppresses guarded false-positives and
raises cross-file taint. Emits SARIF (GitHub code-scanning) + a PR-markdown summary, and exits non-zero
on a sustained critical so it FAILS the CI build.

Usage:
  verificate_review.py --repo . --changed --base origin/main --sarif verificate.sarif
  verificate_review.py --repo . --files path/a.ts path/b.py
"""
import argparse, json, os, re, ssl, subprocess, sys, urllib.request
from pathlib import Path
from vcg import VCG, MemStore

GATE_URL = os.environ.get("VERIFICATE_MCP_URL", "https://mcp.verificate.ai/mcp")
GATE_KEY = os.environ.get("VERIFICATE_API_KEY", "")
_ctx = ssl.create_default_context()
CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".rb", ".php"}

# ---------------- hardened cross-file taint (aliasing + sanitizer-on-path) ----------------
SOURCE_RX = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(req\.(?:query|body|params|headers|cookies)|request\.(?:args|form|json|values)|process\.env|os\.environ|event\.(?:body|queryStringParameters))")
ASSIGN_RX = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(.+?);")
GUARD_CALL_RX = re.compile(r"\b(sanitize|saniti[sz]e|validate|escape|isSafe|resolve|normalize|basename|safeJoin|assertInside|checkPath|encodeURI|parseInt|Number)\s*\(", re.I)
SINK_ARG_RX = {  # sink -> regex capturing the dangerous arg identifier
    "writeFileSync": r"writeFileSync\s*\(\s*([A-Za-z_]\w*)",
    "readFileSync":  r"readFileSync\s*\(\s*([A-Za-z_]\w*)",
    "appendFileSync":r"appendFileSync\s*\(\s*([A-Za-z_]\w*)",
    "exec":          r"\bexec\s*\(\s*([A-Za-z_]\w*)",
    "execSync":      r"\bexecSync\s*\(\s*([A-Za-z_]\w*)",
    "eval":          r"\beval\s*\(\s*([A-Za-z_]\w*)",
    "spawn":         r"\bspawn\s*\(\s*([A-Za-z_]\w*)",
    "sendFile":      r"sendFile\s*\(\s*([A-Za-z_]\w*)",
}
IMPORT_RX = re.compile(r"import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+['\"]([^'\"]+)['\"]")
FUNC_PARAMS_RX = re.compile(r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>")

def _tainted_vars(txt):
    """Fixpoint taint propagation with aliasing + sanitizer clearing."""
    tainted = {m.group(1) for m in SOURCE_RX.finditer(txt)}
    for _ in range(6):
        changed = False
        for m in ASSIGN_RX.finditer(txt):
            var, expr = m.group(1), m.group(2)
            if GUARD_CALL_RX.search(expr):          # sanitized => CLEAN (clears taint even if it aliases a source)
                if var in tainted: tainted.discard(var); changed = True
                continue
            refs = set(re.findall(r"[A-Za-z_]\w*", expr))
            if (refs & tainted) and var not in tainted:  # alias/propagate untrusted value
                tainted.add(var); changed = True
        if not changed: break
    return tainted

def _sink_functions(txt, rel):
    """Functions whose PARAM reaches a sink unguarded -> a 'sink function' importable by other files."""
    out = {}
    tv = _tainted_vars(txt)
    for m in FUNC_PARAMS_RX.finditer(txt):
        fname = m.group(1) or m.group(3)
        params = [x.strip().split(":")[0].strip() for x in (m.group(2) or m.group(4) or "").split(",") if x.strip()]
        body_tainted = set(params) | tv
        # propagate within the function body approximately via the same fixpoint on the whole file
        for sink, rx in SINK_ARG_RX.items():
            for sm in re.finditer(rx, txt):
                if sm.group(1) in body_tainted and sm.group(1) in params:
                    out[fname] = (sm.group(1), sink)
    return out

def taint_scan(files, repo):
    facts, sinkfns = {}, {}
    for p in files:
        rel = p.relative_to(repo).as_posix()
        txt = p.read_text(encoding="utf-8", errors="replace")
        imports = {}
        for m in IMPORT_RX.finditer(txt):
            tgt = (Path(rel).parent / m.group(2)).as_posix() if m.group(2).startswith(".") else m.group(2)
            for s in [x.strip() for x in m.group(1).split(",") if x.strip()]:
                imports[s] = tgt
        facts[rel] = dict(txt=txt, tainted=_tainted_vars(txt), imports=imports)
        for fn, sig in _sink_functions(txt, rel).items():
            sinkfns[(rel.rsplit(".", 1)[0], fn)] = sig
    # per-file taint findings (cross-file: untrusted source -> imported sink-function; and intra-file sink)
    taint_by_file = {}
    for rel, f in facts.items():
        found = []
        # intra-file: SINK(taintedvar)
        for sink, rx in SINK_ARG_RX.items():
            for m in re.finditer(rx, f["txt"]):
                if m.group(1) in f["tainted"]:
                    found.append({"flow": f"{rel}: untrusted `{m.group(1)}` -> {sink}({m.group(1)})",
                                  "cwe": "CWE-22/CWE-78 (path/command injection)"})
        # cross-file: callee(taintedvar) where callee is an imported sink-function
        for callee, argvar in re.findall(r"\b([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)", f["txt"]):
            if argvar in f["tainted"] and callee in f["imports"]:
                key = (f["imports"][callee], callee)
                if key in sinkfns:
                    pn, sink = sinkfns[key]
                    found.append({"flow": f"{rel}: untrusted `{argvar}` -> {callee}() -> {key[0]}.*: {sink}({pn})",
                                  "cwe": "CWE-22/CWE-73 (cross-file path traversal / file write)"})
        if found: taint_by_file[rel] = found
    return taint_by_file

# ---------------- gate ----------------
def gate(code, lang, security_graph):
    ctx = {"language": lang, "security_graph": security_graph,
           "intent": "CI security+quality review with Verificate Context Graph cross-file context."}
    body = {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_ai_output",
        "arguments":{"ai_output":code[:120000],"validation_type":"code_generation","context":ctx}}}
    h = {"Content-Type":"application/json","Accept":"application/json, text/event-stream","User-Agent":"verificate-ci/1.0"}
    if GATE_KEY: h["Authorization"] = f"Bearer {GATE_KEY}"
    req = urllib.request.Request(GATE_URL, data=json.dumps(body).encode(), headers=h)
    raw = urllib.request.urlopen(req, timeout=200, context=_ctx).read().decode()
    if "data:" in raw and '"result"' not in raw.split("\n",1)[0]:
        for ln in raw.splitlines():
            if ln.startswith("data:"): raw = ln[5:].strip(); break
    return json.loads(json.loads(raw)["result"]["content"][0]["text"])

def lang_of(path):
    return {"ts":"typescript","tsx":"typescript","js":"javascript","jsx":"javascript","py":"python",
            "go":"go","java":"java","rb":"ruby","php":"php"}.get(path.rsplit(".",1)[-1], "text")

# ---------------- target selection ----------------
def changed_files(repo, base):
    try:
        out = subprocess.check_output(["git","-C",str(repo),"diff","--name-only",f"{base}...HEAD"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        out = subprocess.check_output(["git","-C",str(repo),"diff","--name-only","HEAD~1"], text=True, stderr=subprocess.DEVNULL)
    return [repo/f.strip() for f in out.splitlines() if f.strip() and Path(f.strip()).suffix in CODE_EXT and (repo/f.strip()).exists()]

def all_source(repo):
    files = []
    for p in repo.rglob("*"):
        if p.suffix in CODE_EXT and p.is_file() and not any(x in p.as_posix() for x in ("/node_modules/","/.git/","/dist/","/build/","/vendor/",".spec.",".test.","__tests__")):
            files.append(p)
    return files

# ---------------- SARIF ----------------
def to_sarif(results):
    rules, out = {}, []
    for r in results:
        for iss in r["issues"]:
            sev = iss.split("|",1)[0].replace("[llm]","").replace("[vcg]","").strip().lower()
            rid = "verificate/" + (sev or "quality")
            rules.setdefault(rid, {"id":rid,"shortDescription":{"text":f"Verificate {sev}"}})
            level = {"critical":"error","high":"error","medium":"warning","low":"note"}.get(sev,"warning")
            out.append({"ruleId":rid,"level":level,"message":{"text":iss},
                        "locations":[{"physicalLocation":{"artifactLocation":{"uri":r["file"]},"region":{"startLine":1}}}]})
    return {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{
        "tool":{"driver":{"name":"Verificate Gate","informationUri":"https://verificate.ai/gate","rules":list(rules.values())}},
        "results":out}]}

def post_pr_comment(md):
    """Best-effort: post the summary as a PR comment (parity with the old gate.py behaviour)."""
    tok, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    ev = os.environ.get("GITHUB_EVENT_PATH"); pr = None
    if ev and os.path.exists(ev):
        try: pr = json.load(open(ev)).get("pull_request", {}).get("number")
        except Exception: pass
    if not (tok and repo and pr): return
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{repo}/issues/{pr}/comments",
            data=json.dumps({"body": md}).encode(),
            headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json", "User-Agent": "verificate-ci"})
        urllib.request.urlopen(req, timeout=20)
    except Exception as e:
        print("pr comment skipped:", str(e)[:80])

def main():
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # CI is utf-8; never let a print mask the verdict
    except Exception: pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="."); ap.add_argument("--base", default=os.environ.get("VERIFICATE_BASE","origin/main"))
    g = ap.add_mutually_exclusive_group(); g.add_argument("--changed", action="store_true"); g.add_argument("--all", action="store_true")
    ap.add_argument("--files", nargs="*"); ap.add_argument("--sarif", default="verificate.sarif")
    ap.add_argument("--max-files", type=int, default=int(os.environ.get("MAX_FILES", "25")))
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY","")); ap.add_argument("--fail-on", default="critical")
    a = ap.parse_args()
    repo = Path(a.repo).resolve()
    ctx_files = all_source(repo)                     # VCG context = whole repo
    targets = [repo/f for f in a.files] if a.files else (all_source(repo) if a.all else changed_files(repo, a.base))
    targets = [p for p in targets if p.exists()]
    if a.max_files and len(targets) > a.max_files:
        print(f"note: {len(targets)} changed files exceeds --max-files {a.max_files}; reviewing the first {a.max_files}")
        targets = targets[:a.max_files]
    print(f"VCG context files: {len(ctx_files)} | reviewing: {len(targets)} target(s)")
    if not targets:
        print("no code targets changed — gate PASS"); Path(a.sarif).write_text(json.dumps(to_sarif([]))); return 0
    # A CI run is stateless: build the VCG fresh, in-process (a hosted service would use per-tenant Redis).
    vcg = VCG(repo, MemStore()); vcg.build(ctx_files)
    taint = taint_scan(ctx_files, repo)
    results, fail = [], False
    for p in targets:
        rel = p.relative_to(repo).as_posix()
        sg = vcg.retrieve_subgraph(rel)
        sg["taint"] = taint.get(rel, [])
        v = gate(p.read_text(encoding="utf-8", errors="replace"), lang_of(rel), sg)
        issues = v.get("issues", []); vcg_meta = v.get("vcg") or {}
        crit = [i for i in issues if "critical|" in i.lower()]
        results.append({"file": rel, "valid": v.get("valid"), "score": v.get("score"), "issues": issues,
                        "vcg": vcg_meta, "crit": len(crit)})
        if not v.get("valid") and (a.fail_on == "critical" and crit or a.fail_on == "any"): fail = True
        print(f"  {rel}: valid={v.get('valid')} score={v.get('score')} crit={len(crit)} vcg={vcg_meta}")
    Path(a.sarif).write_text(json.dumps(to_sarif(results), indent=1))
    md = ["## 🛡️ Verificate Gate — CI review (with cross-file context)", "",
          f"Reviewed **{len(targets)}** changed file(s). Context graph over **{len(ctx_files)}** files.", ""]
    for r in results:
        icon = "❌" if not r["valid"] else "✅"
        md.append(f"- {icon} `{r['file']}` — score {r['score']}, {r['crit']} critical"
                  + (f" · VCG suppressed {r['vcg'].get('suppressed',0)} guarded FP, raised {r['vcg'].get('raised',0)} cross-file taint" if r['vcg'] else ""))
    md_text = "\n".join(md)
    if a.summary:
        try: Path(a.summary).write_text(md_text, encoding="utf-8")
        except Exception: pass
    post_pr_comment(md_text)
    print("\n" + md_text)
    print(f"\nSARIF -> {a.sarif} | CI verdict: {'FAIL' if fail else 'PASS'}")
    return 1 if fail else 0

if __name__ == "__main__":
    sys.exit(main())
