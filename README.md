# 🛡️ Verificate Gate

**Block a pull request when your AI writes a fake API, a mock passed off as done, or a test that games itself.** A GitHub Action that runs every changed code file through the Verificate merge gate — 17 deterministic reality gates (hallucinated-API detection, mock/placeholder veto, reward-gaming & bypass detection) + a frontier-model review — and **fails the check on a veto, so the merge is blocked** until it's fixed.

[![Verificate Gate](https://img.shields.io/badge/gated%20by-Verificate-2ea44f?logo=shield)](https://github.com/Verificate-Dev/verificate-gate-action)
[![Benchmark](https://img.shields.io/badge/vs%20LLM%20self--review-0%2F6%20%E2%86%92%206%2F6-2ea44f)](https://github.com/Verificate-Dev/verificate-mcp-quickstart/blob/master/COMPARISON.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)

## What it looks like on a PR

When a change tries to ship broken AI code, the gate comments and blocks the merge:

> ### 🛡️ Verificate Gate
> | File | Verdict | Detail |
> |---|---|---|
> | `payment.py` | ❌ **REJECTED** | vetoed by `code_reality_gate` |
> | ↳ | Placeholder detected: **FIXME** comment indicating broken code |
> | ↳ | `stripe.Refund.create_partial` **does not exist** in the Stripe SDK — AttributeError |
> | ↳ | Missing idempotency key in financial transaction |
>
> **A deterministic reality gate vetoed a change — fix the findings and push again.**

The `verificate-gate` check goes **red** and the PR shows **Merging is blocked** until it's fixed. (Real output — this is the action gating its own repo.)

## Why not just ask the model to review its own code?

Because in a natural workflow (*"is this OK to merge?"*) it doesn't look for these failure modes — and **agents reward-hack and hallucinate APIs far more than humans**. Measured, reproducibly:

| Adversarial case | LLM self-review | **Verificate Gate** |
|---|---|---|
| Reward-gaming (`assert True` test) | caught **0 / 6** | **6 / 6** |
| Hallucinated API (nonexistent SDK call) | caught **0 / 6** | **6 / 6** |

[Full benchmark + reproducible scripts →](https://github.com/Verificate-Dev/verificate-mcp-quickstart/blob/master/COMPARISON.md)

## Add it in 5 lines

```yaml
# .github/workflows/verificate-gate.yml
name: Verificate Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions: { contents: read, pull-requests: write }
jobs:
  verificate-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: Verificate-Dev/verificate-gate-action@v1
        with:
          verificate-api-key: ${{ secrets.VERIFICATE_API_KEY }}   # optional; free tier works without
          fail-on: reject
```

Then make it required: **Settings → Branches → Require status checks → `verificate-gate`.** Now nothing merges while the gate vetoes an AI-written change.

> **First run on CI?** The no-key free tier is shared per runner IP, so on busy shared runners it can already be used up. Grab your **own** free key (no card, 30 days — [verificate.ai/auth/signup](https://verificate.ai/auth/signup)) and add it as a repo secret named `VERIFICATE_API_KEY`. That gives you a private quota that isn't affected by other repos on the same runner. The gate always fails **open**, so a used-up trial never blocks your merge — it just skips and tells you how to get a key.

## Inputs
| Input | Default | Description |
|---|---|---|
| `verificate-api-key` | — | Optional token (lifts the free-tier per-runner cap; the free tier of 25/runner works without one). |
| `fail-on` | `reject` | `reject` blocks the merge on a veto; `off` = comment only. |
| `max-files` | `25` | Max changed code files reviewed per PR. |

## How it behaves (safe by design)
- **Fails closed only on a real veto** (blocks merge). **Fails *open* on any infra error** (gate unreachable, timeout) — a gate outage never blocks your team's merges.
- Reviews only **changed** code files. No code is executed — read-only.
- No signup required to try. Works with public or private repos.

---
*Verificate — the merge gate for AI-written code. [verificate.ai](https://verificate.ai)*
