#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificate Context Graph (VCG) — P1 prototype.
Build an EAV+edges security graph of a repo into a Redis temporary memory (falls back to an
in-process store with identical hash/set semantics if no Redis server), retrieve a file's
SECURITY SUBGRAPH (the guard code that wraps its sinks, via IMPORTS/SANITIZES/ENFORCES edges),
and run a deterministic guarded-path verifier over the gate's findings.

Entities  E:<id>            hash: type, path, name, role, value
Edges     EDGE:<rel>:<src>  set of dst   (rel in IMPORTS, DEFINES, SANITIZES, ENFORCES, FLOWS_TO)
"""
import os, re, json, sys
from pathlib import Path

# ---------- store: Redis if a server is reachable, else an in-memory twin ----------
class MemStore:
    def __init__(s): s.h = {}; s.sets = {}
    def hset(s, k, m): s.h.setdefault(k, {}).update(m)
    def hgetall(s, k): return s.h.get(k, {})
    def sadd(s, k, *v): s.sets.setdefault(k, set()).update(v)
    def smembers(s, k): return s.sets.get(k, set())
    def keys(s, pat):
        rx = re.compile("^" + re.escape(pat).replace("\\*", ".*") + "$")
        return [k for k in list(s.h) + list(s.sets) if rx.match(k)]
    def flushdb(s): s.h.clear(); s.sets.clear()

def get_store():
    try:
        import redis
        r = redis.Redis(host=os.environ.get("REDIS_HOST", "localhost"), port=6379, decode_responses=True, socket_connect_timeout=1)
        r.ping(); print("[store] using Redis"); return r
    except Exception:
        print("[store] no Redis server — using in-process twin (same semantics; prod points REDIS_HOST at a real Redis)")
        return MemStore()

# ---------- role tagging (security semantics) ----------
SINK_RX   = re.compile(r"\b(fs\.(write|append|createWriteStream|unlink|rename)|child_process|execSync|\bexec\(|\beval\(|spawn|new Function|vm\.|yaml\.load\(|pickle\.load|subprocess|os\.system|writeFileSync)\b")
SOURCE_RX = re.compile(r"\b(req\.(body|query|params|headers|cookies)|request\.(args|form|json|values)|process\.env|os\.environ|req\.get\()\b")
GUARD_NAME_RX = re.compile(r"saniti[sz]|Sanitizer|validat|Validator|escape|isSafe|blocklist|denylist", re.I)
BLOCK_RX  = re.compile(r"(?:const|let|var)\s+(\w*(?:unsafe|blocked|forbidden|denied|reserved|blocklist|denylist)\w*)\s*=\s*new Set\(\[(.*?)\]\)", re.I | re.S)
IMPORT_TS = re.compile(r"import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+['\"]([^'\"]+)['\"]")
IMPORT_PY = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+(.+)$", re.M)
DEF_TS    = re.compile(r"export\s+(?:const|function|class|type|interface|abstract class)\s+(\w+)")
DEF_PY    = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+(\w+)", re.M)

def module_key(path, imp):
    """Resolve a relative TS import (./expression-sandboxing) to a repo-relative file id."""
    if imp.startswith("."):
        base = (Path(path).parent / imp).as_posix()
        return base  # sans extension; matched loosely later
    return imp

class VCG:
    def __init__(s, repo, store): s.repo = Path(repo); s.store = store
    def build(s, files):
        s.store.flushdb() if hasattr(s.store, "flushdb") else None
        defines = {}  # symbol -> file id (for resolving imports to definitions)
        for p in files:
            rel = p.relative_to(s.repo).as_posix()
            txt = p.read_text(encoding="utf-8", errors="replace")
            fid = rel.rsplit(".", 1)[0]  # id without extension
            role = "file"
            # blocklists (with VALUES)
            for m in BLOCK_RX.finditer(txt):
                name, body = m.group(1), m.group(2)
                vals = [v.strip().strip("'\"") for v in body.split(",") if v.strip()]
                s.store.hset(f"E:{fid}#{name}", {"type": "const", "path": rel, "name": name,
                                                 "role": "blocklist", "value": json.dumps(vals)})
                s.store.sadd(f"EDGE:DEFINES:{fid}", f"{fid}#{name}")
                defines[name] = fid
            # exported/def symbols + role
            for m in list(DEF_TS.finditer(txt)) + list(DEF_PY.finditer(txt)):
                name = m.group(1)
                srole = "guard" if GUARD_NAME_RX.search(name) else "symbol"
                s.store.hset(f"E:{fid}#{name}", {"type": "symbol", "path": rel, "name": name, "role": srole})
                s.store.sadd(f"EDGE:DEFINES:{fid}", f"{fid}#{name}")
                defines[name] = fid
            # sinks / sources at file level
            if SINK_RX.search(txt):   role = "sink"
            if SOURCE_RX.search(txt): role = "source" if role == "file" else "source+sink"
            s.store.hset(f"E:{fid}", {"type": "file", "path": rel, "name": rel, "role": role})
            # imports -> edges
            for m in IMPORT_TS.finditer(txt):
                syms = [x.strip().split(" as ")[0].strip() for x in m.group(1).split(",") if x.strip()]
                tgt = module_key(rel, m.group(2))
                for sym in syms:
                    s.store.sadd(f"EDGE:IMPORTS:{fid}", f"{sym}@{tgt}")
        # resolve ENFORCES (a guard file that references a blocklist symbol enforces it) + SANITIZES
        s.defines = defines
        for p in files:
            rel = p.relative_to(s.repo).as_posix(); fid = rel.rsplit(".", 1)[0]
            txt = p.read_text(encoding="utf-8", errors="replace")
            for name, dfile in defines.items():
                meta = s.store.hgetall(f"E:{dfile}#{name}")
                if meta.get("role") == "blocklist" and re.search(rf"\b{name}\b", txt):
                    # this file uses the blocklist -> its guard symbols ENFORCE it (same-file is the common case)
                    for g in s.store.smembers(f"EDGE:DEFINES:{fid}"):
                        if s.store.hgetall(f"E:{g}").get("role") == "guard":
                            s.store.sadd(f"EDGE:ENFORCES:{g}", f"{dfile}#{name}")
        return defines

    def resolve(s, sym, tgt):
        """Find the entity id for an imported symbol (sym@tgt), tolerant of extension/path form."""
        cand = f"{tgt}#{sym}"
        if s.store.hgetall(f"E:{cand}"): return cand
        # fall back: any DEFINES of sym whose file matches the tgt tail
        for fid, dfile in [(k, v) for k, v in getattr(s, "defines", {}).items()]:
            pass
        did = s.defines.get(sym)
        return f"{did}#{sym}" if did else None

    def retrieve_subgraph(s, rel, max_depth=3):
        """Assemble file rel's SECURITY SUBGRAPH by walking the guard chain transitively across files:
        expression.ts -> PrototypeSanitizer(sandboxing) -> isSafeObjectProperty(utils) -> unsafeObjectProperties."""
        fid = rel.rsplit(".", 1)[0]
        guards, blocklists, seen = set(), {}, set()
        frontier, depth = [fid], 0
        while frontier and depth < max_depth:
            nxt = []
            for cur in frontier:
                if cur in seen: continue
                seen.add(cur)
                for edge in s.store.smembers(f"EDGE:IMPORTS:{cur}"):
                    sym, tgt = edge.split("@", 1)
                    eid = s.resolve(sym, tgt)
                    if not eid: continue
                    if s.store.hgetall(f"E:{eid}").get("role") == "guard":
                        guards.add(eid)
                        for b in s.store.smembers(f"EDGE:ENFORCES:{eid}"):
                            bm = s.store.hgetall(f"E:{b}")
                            if bm.get("value"): blocklists[bm["name"]] = json.loads(bm["value"])
                        nxt.append(eid.split("#")[0])  # follow the guard's file for deeper guards
            frontier, depth = nxt, depth + 1
        return {"file": rel, "guards": sorted(guards), "blocklists": blocklists}

# ---------- deterministic guarded-path verifier ----------
VECTOR_TOKENS = {"__proto__", "prototype", "constructor", "getprototypeof", "setprototypeof", "proto"}
def guarded(finding_text, blocklists):
    """A prototype-pollution / property-access finding is GUARDED if every dangerous property it names
    is in a blocklist the file's guards enforce."""
    low = finding_text.lower()
    named = {t for t in VECTOR_TOKENS if t in low}
    if not named: return False
    allblocked = {b.lower() for vals in blocklists.values() for b in vals}
    # normalise __proto__ token
    allblocked |= {"proto"} if "__proto__" in allblocked else set()
    return bool(named) and named.issubset(allblocked | {"proto"} if "__proto__" in "".join(allblocked) else allblocked)

if __name__ == "__main__":
    REPO = Path(r"C:\Users\craig\AppData\Local\Temp\claude\E--001-Projects-Verificate-v1\c36bfdca-6739-4918-83ba-c4788a3b1b24\scratchpad\n8n_repo")
    src = REPO / "packages/workflow/src"
    files = [p for p in src.rglob("*.ts") if p.is_file() and ".spec." not in p.name and ".test." not in p.name]
    vcg = VCG(REPO, get_store())
    vcg.build(files)
    sg = vcg.retrieve_subgraph("packages/workflow/src/expression.ts")
    print("\n=== retrieved security subgraph for expression.ts ===")
    print("guards:", sg["guards"])
    print("blocklists enforced:", sg["blocklists"])
