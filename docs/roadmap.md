# Vex — Roadmap

**v1 (current)** — stdio transport, deterministic keyword/structural detection on tool descriptions, drift detection, default-deny policy, hash-chained audit log, rate limiting. Covers Claude Code, Claude Desktop, and any agent that spawns MCP servers as child processes.

Everything below is judged against the v1 commitments: a single auditable binary, **deterministic** detection (no model calls in the core), **dependency-light**, **local-first / single-user**, and "secure the protocol boundary, not the model." Items that pull against those are kept but flagged — see [Deliberately deferred](#deliberately-deferred-against-the-current-grain).

Direction, in one line: **deepen detection, lower adoption friction, then extend reach.** Detection depth and onboarding come before HTTP and stateful analysis, because they compound the value of what already ships.

---

## Status legend

- **Next** — high leverage, low risk, aligned with the grain. The near-term queue.
- **Planned** — clearly in scope, larger or dependent on a "Next" item landing first.
- **Later** — real, but a bigger lift or a new surface; needs its own design pass.
- **Deferred** — against the current grain or speculative; recorded so we don't relitigate it casually.

---

## 1. Detection depth (deterministic)

No model calls, still sub-millisecond, still a single binary. This is the primary direction.

| Item | Status | Notes |
|---|---|---|
| **Parameter-schema scanning** | Next | Extend description scanning from the top-level `description` into parameter descriptions and `inputSchema` field text — the model reads all of it. Recursively traverse and scan every string value. Detectors are already pure functions over text; this is a new *call site*, not a new engine. |
| **Encoding & obfuscation tells** | Next | base64- and hex-shaped blobs in a description that has no reason to carry them; high-entropy strings with no semantic justification. v1 already handles zero-width and homoglyph smuggling; this is the same evasion class, extended. |
| **Tool-name shadowing** | Planned | Flag a server advertising a tool named to impersonate a trusted one (a second server exposing `filesystem.read`, `github.create_pr`). Needs a small curated list of well-known names + a cross-server collision check. Block on collision unless explicitly allowlisted. |
| **Cross-tool orchestration language** | Planned | Descriptions that reference *other tools by name* ("after calling X, always call Y first") — the setup move for confused-deputy chains. Flag for review; this is a signal, not a verdict. |
| **Instruction-to-data ratio** | Later | A description should *describe*; one that is mostly directives at the model is suspicious by shape regardless of keywords. Catches paraphrased injections that dodge exact patterns. Needs tuning against the benign corpus to avoid false positives on legitimately instructive descriptions. |
| **Tool-output scanning** | Later | A second inspection surface. v1 inspects the catalog; tool *results* also flow into the model and can carry injection. Larger because it changes which message classes get the full detector pass, with its own fail-open/closed call decided explicitly per message class. |

---

## 2. Argument / value-level enforcement (new surface)

v1's policy matches on tool **names**. The natural next enforcement surface is the **argument values** of an otherwise-allowed call: `filesystem.read_file` is allowed, but the path is `/etc/shadow`; a fetch tool is allowed, but the URL is `169.254.169.254`.

| Item | Status | Notes |
|---|---|---|
| **Cloud-metadata / SSRF guard** | Planned | Block calls whose arguments target cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, link-local ranges). Concrete, high-value, fully deterministic — a clean first use case for value-level rules and a sharp standalone win. |
| **Argument value rules ("light WAF")** | Later | Generalize the above: declarative rules over argument values (`tool = "filesystem.read_file"`, `path contains "shadow"`). This is a genuine expansion of scope — it crosses from name-level to value-level policy — so it gets its own design pass: rule grammar, where it sits relative to the allowlist, and how findings are audited without logging the raw values (audit redaction still binds — log shape/hashes, not values). |

> **Why this belongs here and SIEM/roles don't:** value-level deny rules are still *local, deterministic, single-user* policy — same shape as the existing engine, one layer deeper. They don't pull Vex toward multi-tenancy or external services.

---

## 3. Adoption & onboarding tooling

The highest-leverage, lowest-risk work for a tool now distributed on npm / PyPI / crates.io. Friction at first-run is what loses users.

| Item | Status | Notes |
|---|---|---|
| **`vex-mcp init`** | Next | Generate a starter `vex.toml` with sensible defaults (`default_action = "deny"`, an example allowlist, audit path). Removes "write TOML from memory" as the first experience. |
| **`vex-mcp doctor`** | Next | Diagnostic: is `VEX_CONFIG` set and pointing at a real file? Is the TOML valid? Does the wrapped server command actually launch? Report version/OS. Users *will* misconfigure the path or the server command — give them a way to see why. |
| **Example policies** | Next | A `policies/` directory of starting points: `filesystem.toml`, `github.toml`, `postgres.toml`, a strict `production.toml`. Users don't know a server's tool surface up front; ship known-good baselines. |
| **`vex-mcp discover` / `protect`** | Planned | Scan standard client config locations (Claude Desktop, Cursor, VS Code, Claude Code `.mcp.json`) and list discovered MCP servers; `protect` rewrites them to spawn through Vex. High convenience; must be conservative about touching user config (dry-run first, back up before writing). |

---

## 4. Observe-before-enforce

| Item | Status | Notes |
|---|---|---|
| **Warn-only mode** | Next | A mode where Vex inspects, audits, and logs verdicts but forwards everything (`mode = "warn_only"` vs the default `"block"`). Lets a team adopt Vex as a monitor first and turn on enforcement once they trust the policy. Cheap, since the verdict is already computed; this only changes the ACT step for non-`Allow` verdicts. The fail-closed defaults remain the *default*; this is an explicit opt-out, not a new default. |

---

## 5. Credibility / benchmarks

| Item | Status | Notes |
|---|---|---|
| **Published latency benchmarks** | Next | We repeatedly claim "sub-millisecond." Prove it: benchmark Vex against a raw MCP server, publish p50/p95/p99. Security tools have a reputation for adding latency; a number kills the objection. Also functions as a regression guard on the hot path. |

---

## 6. CI / shift-left (offline scanning)

These exploit a property we already have: **detectors are pure functions with no I/O.** They can run outside the proxy, over a static catalog, with no server spawned.

| Item | Status | Notes |
|---|---|---|
| **`vex-mcp scan`** | Planned | Run the detector suite over an MCP config / captured tool catalog *without* proxying — a one-shot audit. Reuses the existing pure detectors; mostly a new entrypoint + input adapter. |
| **SARIF output + GitHub Action** | Later | Emit SARIF from `scan` so findings land in GitHub Code Scanning, and ship an Action that runs on PRs touching MCP configs. Depends on `scan` existing first. |
| **`vex-mcp test` (policy testing)** | Later | Evaluate a policy against a set of sample requests and report which would pass/block; diff against a previous policy. Lets users validate policy changes before deploying. Pure-function-friendly, pairs naturally with `scan`. |

---

## 7. Reach: HTTP transport & identity

| Item | Status | Notes |
|---|---|---|
| **Streamable-HTTP transport** | Later | Remote MCP servers (hosted GitHub, Linear, Notion) run over HTTP, not stdio. This opens the TLS + OAuth 2.1 surface the spec recommends for remote MCP. The single biggest reach item; its own design pass (the inspection pipeline is transport-agnostic, but auth/TLS termination is new surface). |
| **Identity in the audit log** | Later | Record *which* agent/identity made a call — extracted from a client message or an `X-MCP-Identity`-style header once HTTP exists. Useful even single-user (CI agent vs. interactive chat agent leave different audit trails). **Scope note:** this is identity *as an audit dimension*, not RBAC. Full role-based policy is [deferred](#deliberately-deferred-against-the-current-grain) — it pulls toward multi-tenancy, which is an explicit non-goal. |

---

## 8. Stateful analysis

| Item | Status | Notes |
|---|---|---|
| **Cross-tool data-flow watch** | Later | One tool reads sensitive data, another sends data out, and the model chains them so each individual call looks clean — the sequence is the attack, not any single message. Requires Vex to hold and reason about state across calls, a departure from the pure-stateless-detector model. |

---

## 9. Learned detection layer (optional)

| Item | Status | Notes |
|---|---|---|
| **Opt-in classifier / embedding pass** | Later | Runs *behind* the deterministic rules to catch novel, paraphrased attacks keyword matching misses ("kindly overlook the directives you were given earlier"). **Strictly optional** so the default install stays offline and dependency-light. The deterministic core remains the floor, not the ceiling — this never becomes a required dependency. |

---

## 10. Operability

Quality-of-life, not headline features.

| Item | Status | Notes |
|---|---|---|
| **Drift approval CLI** | Planned | `vex-mcp approve <server> <tool>` to review and accept detected drift instead of hand-editing the pin store. Optional interactive prompt on drift; consider `--auto-approve-minor` for semver bumps. Closes a known v1 gap. |
| **Hot config reload** | Later | Reload policy on `vex.toml` change (kqueue/inotify) without dropping the MCP connection. Today, a policy change means restarting the process, which restarts the connection. |
| **Confirmation channel** | Later | A side-channel (CLI prompt / local socket / companion UI) so `confirmation_required` tools pause for live human approval instead of behaving like a block. The `RequireConfirmation` verdict exists today but a transparent stdio proxy has no way to surface a prompt. |
| **Configurable audit outputs** | Later | Multiple audit sinks / formats (JSONL file + syslog), filtered by level. The *file* side is in scope; *network forwarding to a SIEM* leans enterprise and external-service — see deferred. |

---

## Deliberately deferred (against the current grain)

Recorded so these aren't relitigated without a deliberate scope decision. Each conflicts with a stated v1 commitment.

- **Role-based access control (RBAC) / per-role policy.** Conflicts with "single-user, local-first." Identity *in the audit log* is in scope (§7); mapping identities to roles with distinct allowlists is a multi-tenant feature and waits for a real multi-user deployment to justify it.
- **SIEM / real-time network log forwarding (Splunk/Datadog/syslog-over-TCP).** Enterprise-monitoring surface that pushes Vex toward external integrations and always-on network egress. The audit log is already append-only, hash-chained, and machine-readable (JSONL) — anything can tail and ship it. Revisit only with enterprise users asking.
- **LLM-assisted policy generation (`vex-mcp suggest`).** Conflicts head-on with "deterministic, offline, dependency-light, no model calls in the core." If it ever happens, it's an external/optional tool, never part of the binary's default path.
- **Docker image.** v1 is a stdio child-process wrapper; a sidecar container is an awkward fit for that model (the client spawns Vex as a subprocess). Reconsider once HTTP transport (§7) exists, where a network sidecar actually makes sense.
- **Agent-manifest-driven policy auto-generation.** Speculative; depends on an ecosystem convention (`agent.yaml`-style manifests) that isn't settled. Revisit if such manifests become common.
