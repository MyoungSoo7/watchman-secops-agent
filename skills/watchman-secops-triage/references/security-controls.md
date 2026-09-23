# Security controls enforced by this skill (6 axes)

Summary of the live-measured control matrix (full evidence: `eval/CONTROL-MATRIX.md`
in the watchman-agent repo). Each axis maps to an agent-native risk class
(prompt injection, excessive agency, tool misuse, data exfiltration, output
handling).

| # | Control | What it stops | Evidence (live) |
|---|---|---|---|
| ① | Prompt-injection detection (⚠) | Hidden instructions in alert/log data | Real payload injected → `injection_suspects=2`, agent did not obey |
| ② | Public-host write guard | Writes via the public endpoint | `POST /alert` on public host → HTTP 403 read-only |
| ③ | Egress allowlist (port+CIDR) | Reaching unapproved ports/destinations | `:80`/`:8080` blocked; `:443` allowed for NIM/SMTP only |
| ④ | No automatic execution | Excessive agency / tool misuse | Only `es_search`/`kube_read` (read) registered; output is a proposal card |
| ⑤ | Red-team detection harness | Regression in injection defense | 12/12 detected, 0 false positives, CI exit 0 |
| ⑥ | Non-root + read-only rootfs | Container escape / persistence | `uid=65534`, root FS read-only, `drop:[ALL]` |

## Honesty notes

- Axis ③ is a port+CIDR **allowlist**, not a full external block — external 443/587 is
  intentionally open for NIM inference and SMTP.
- Axis ④ has no approval/execution gate implemented because there is **no execution path
  at all** — the agent cannot mutate the cluster, so nothing needs gating yet.
