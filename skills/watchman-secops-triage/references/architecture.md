# Where this triage sits in the Watchman agent loop

Watchman is a stdlib-only, single-file Python SecOps agent that runs in-cluster
(`agent-system` namespace, 6-node K3s). This skill packages its investigation contract.

```
Alertmanager webhook (POST /alert)
        │
        ▼
  parse alert  ──►  agent loop (max 6 steps)
        │                 │
        │        LLM picks a read-only tool:
        │          - es_search  (Elasticsearch logs)
        │          - kube_read  (Kubernetes GET/LIST)
        │                 │
        │        each observation wrapped in <data>…</data>
        │        injection patterns scanned at code level (⚠)
        │                 ▼
        │            finish → classification + confidence + evidence + proposals
        ▼                 │
  append-only audit log ◄─┘   (every step reconstructible)
        │
        ▼
  Telegram proposal card  (+ best-effort email)  — a PROPOSAL, never an executed action
  GET /state  — read-only monitoring snapshot (run states, usage, model IDs)
```

Key properties:

- **LLM backend:** NVIDIA NIM `nvidia/nemotron-3-super-120b-a12b` via
  `integrate.api.nvidia.com/v1` (OpenAI-compatible), with 503 retry.
- **No mutation:** the registered tool set is read-only; the only output is a proposal.
- **Auditability:** `alert_in` / `llm_out` / `tool` / `skill_call` / `finish` records.
- **Optional Build Skill adapter:** off by default; when enabled it adds one external
  query tool whose calls are recorded as `skill_call` audit entries — it does not touch
  cluster resources.
