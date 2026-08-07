# Verificate Gate — GitHub Action

Make the **Verificate merge gate** a required status check on your pull requests. Every changed code
file is run through 17 deterministic reality gates (hallucinated-API detection, mock/placeholder
veto, reward-gaming & bypass detection) plus a frontier-model review. A **veto blocks the merge**;
findings are posted as an inline PR comment.

> **Benchmark:** a frontier model reviewing code in a natural workflow missed reward-gaming and a
> hallucinated API in **0 of 6 runs each**; the gate catches both **6/6** — deterministically.
> [Full comparison](https://github.com/Verificate-Dev/verificate-mcp-quickstart/blob/master/COMPARISON.md)

## Use it

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
          verificate-api-key: ${{ secrets.VERIFICATE_API_KEY }}   # optional (free tier works without)
          fail-on: reject
```

Then make it required: **Settings → Branches → branch protection → Require status checks →
`verificate-gate`.** Now no PR merges while the gate vetoes an AI-written change.

## Behaviour
- **Fails closed only on a real veto** (blocks merge). **Fails open on any infra error** (MCP
  unreachable, timeout) so gate outages never block your merges.
- No signup required (25 free validations/runner); pass a token to lift the cap on busy repos.
- Reviews up to `max-files` changed code files per PR.
