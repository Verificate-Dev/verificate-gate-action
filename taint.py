#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deepened taint analysis for the VCG. Two outputs per file:
  - flows: untrusted-source -> dangerous-sink paths (to RAISE real vulns)
  - injection_reachable: bool — does an UNTRUSTED (network/external) source actually reach a dangerous
    sink? If FALSE, an "injection/RCE/command-injection" finding is a FALSE POSITIVE (the sink is fed only
    by operator-controlled input: CLI args, env, build constants, local config) and should be SUPPRESSED.

"Untrusted" is NETWORK/EXTERNAL input only — NOT CLI args (argparse/click/sys.argv) or env vars, which the
operator controls (they can already run any command). This distinction is what kills the dev-CLI FP class."""
import re

# UNTRUSTED = remote/attacker-controllable. Deliberately excludes argparse/click/sys.argv/os.environ.
UNTRUSTED_SRC = re.compile(
    r"(req\.(?:body|query|params|headers|cookies|files|url|originalUrl|hostname)"
    r"|request\.(?:args|form|json|values|files|data|GET|POST|body|headers|get_json)"
    r"|event\.(?:body|queryStringParameters|headers|pathParameters)"
    r"|flask\.request|self\.request|ctx\.request|@app\.(?:route|post|get)"
    r"|websocket\.recv|\.readAsText|FormData|multipart|payload\[|message\.body)")
# Sources that are OPERATOR-controlled (trusted) — a value from here reaching a sink is NOT a vuln.
OPERATOR_SRC = re.compile(r"(argparse|add_argument|click\.option|click\.argument|sys\.argv|os\.environ|process\.env|getenv|typer\.)")
SINK_FULL = {"os.system", "subprocess.run", "subprocess.call", "subprocess.popen", "subprocess.check_output",
             "subprocess.check_call", "importlib.import_module", "pickle.load", "pickle.loads", "yaml.load",
             "marshal.load", "cursor.execute", "child_process.exec", "child_process.execsync"}
SINK_LAST = {"writefilesync", "readfilesync", "appendfilesync", "createwritestream", "sendfile", "exec",
             "execsync", "eval", "spawn", "popen", "render_template_string", "__import__", "execfile", "system"}
def _is_sink(callee):
    cl = callee.lower()
    return cl in SINK_FULL or cl.split(".")[-1] in SINK_LAST
GUARD = re.compile(r"\b(sanitiz|validate|escape|isSafe|resolve|normalize|basename|safe_join|safeJoin"
                   r"|assertInside|shlex\.quote|quote|parametriz|bindparam|allowlist|whitelist)\b", re.I)
ASSIGN = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(.+?);|^\s*(\w+)\s*=\s*(.+)$", re.M)

# Blank the CONTENTS of string/template/docstring literals (keep newlines) before analysis, so an untrusted->
# sink "flow" that only exists inside a TEST FIXTURE, DOCSTRING, or the analyzer's own pattern DEFINITIONS is
# NOT counted as a real reachable flow. Without this, a static-analyzer/detector file reports itself reachable.
_LITERAL_RX = re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`')
def _strip_literals(text):
    return _LITERAL_RX.sub(lambda m: "".join(c if c == "\n" else " " for c in m.group(0)), text)

def _tainted_vars(text):
    """Fixpoint: vars carrying an UNTRUSTED value, with aliasing; a guard call clears taint."""
    tainted = set()
    for m in re.finditer(r"(?:const|let|var)?\s*(\w+)\s*=\s*([^\n;]+)", text):
        var, expr = m.group(1), m.group(2)
        if UNTRUSTED_SRC.search(expr) and not GUARD.search(expr):
            tainted.add(var)
    for _ in range(6):
        changed = False
        for m in re.finditer(r"(?:const|let|var)?\s*(\w+)\s*=\s*([^\n;]+)", text):
            var, expr = m.group(1), m.group(2)
            if GUARD.search(expr):
                if var in tainted: tainted.discard(var); changed = True
                continue
            if UNTRUSTED_SRC.search(expr) and var not in tainted:
                tainted.add(var); changed = True; continue
            refs = set(re.findall(r"[A-Za-z_]\w*", expr))
            if (refs & tainted) and var not in tainted:
                tainted.add(var); changed = True
        if not changed: break
    return tainted

def analyze(text):
    """Return {injection_reachable, flows, has_sink, has_untrusted}."""
    text = _strip_literals(text)  # ignore flows that only exist inside string/fixture/docstring literals
    tainted = _tainted_vars(text)
    has_untrusted = bool(UNTRUSTED_SRC.search(text))
    sinks = []
    for m in re.finditer(r"([A-Za-z_][\w.]*)\s*\(\s*([A-Za-z_]\w*)", text):
        callee, arg = m.group(1), m.group(2)
        if _is_sink(callee):
            sinks.append((callee, arg))
    has_sink = bool(sinks)
    flows = []
    for callee, arg in sinks:
        if arg in tainted:
            flows.append({"flow": f"untrusted `{arg}` -> {callee}(...)", "cwe": "CWE-78/CWE-22 (injection)"})
    injection_reachable = bool(flows)
    return {"injection_reachable": injection_reachable, "flows": flows,
            "has_sink": has_sink, "has_untrusted": has_untrusted}

if __name__ == "__main__":
    cases = {
        "dev-CLI (argparse->subprocess) — should be UNreachable (suppress)":
            "import argparse, subprocess\np=argparse.ArgumentParser()\np.add_argument('--npm-install')\na=p.parse_args()\nsubprocess.run(a.npm_install, shell=True)\n",
        "real (req.query->exec) — should be REACHABLE (raise)":
            "app.post('/run', (req,res)=>{\n  const cmd = req.query.cmd;\n  exec(cmd);\n});\n",
        "sanitized (req->shlex.quote->exec) — should be UNreachable":
            "const raw = req.query.cmd;\nconst safe = shlex.quote(raw);\nexec(safe);\n",
    }
    for name, code in cases.items():
        r = analyze(code)
        print(f"  {name}\n     injection_reachable={r['injection_reachable']} flows={len(r['flows'])} (sink={r['has_sink']} untrusted={r['has_untrusted']})")
