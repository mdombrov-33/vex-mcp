# CLAUDE.md — Vex

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

## Project: Vex (`vex-mcp`)

A transparent MCP security proxy, written in Rust, that sits between an MCP client and the servers it talks to — inspecting tool descriptions for injection, pinning tool definitions to detect rug-pulls, enforcing a default-deny capability policy, and writing a tamper-evident audit log. **Full rationale, threat model, and worked code live in `DESIGN.md`. This file is the every-session rules; `DESIGN.md` is the reference you read on demand.**

**This is a learning project first.** The point is learning Rust properly — ownership, async, lifetimes, the type system — by building one real tool, not by going fast. When in doubt between "the idiomatic Rust way" and "the quick way," prefer idiomatic, and explain the difference if it's non-obvious. Favor std/`tokio` over pulling in a new crate unless the crate is the point of the lesson.

**Build order matters.** Work milestone by milestone: (M0) transparent byte-forwarding proxy spawning the real MCP server as a child process → (M1) parse/classify the JSON-RPC stream → (M2) tool-description injection scanner, the first real detector → (M3) hash-based pinning + drift detection → (M4) policy engine (default-deny allowlist, verdict types) → (M5) tamper-evident hash-chained audit log. Each milestone is scoped to teach a specific slice of Rust in isolation. Don't jump ahead because a later feature seems easy. If a task seems to require a later milestone's concepts early, **say so** rather than quietly doing it. (Full milestone detail: `DESIGN.md` §5.)

---

### Non-negotiables (these are correctness, not style)

- **stdio is sacred.** stdout is the JSON-RPC protocol channel. All logs/diagnostics go to stderr via `tracing`, never `println!`. A stray `println!` is a protocol-breaking bug, not a style nit — treat it as a correctness issue. (`DESIGN.md` §2.1, §10.9.)
    
- **Fail-open vs fail-closed is a per-message-class decision, encoded as a type — not a default.** Tool-call requests and un-inspectable tool catalogs fail **closed**; passive-response inspection errors fail **open**. It lives in `failure_mode_for(MessageClass)`, not in comments. Adding a new detector or path and the failure mode isn't obvious? Ask which it should be — don't default to either. (`DESIGN.md` §2.2, §10.6.)
    
- **Detectors are pure functions.** Modules under `detect/` take a parsed message and return findings (or a verdict) — no I/O, no logging, no shared mutable state. If a detector needs state (drift needs the pin store), pass it in as an explicit parameter; never reach for global/shared state to avoid a signature change. (`DESIGN.md` §10.4.)
    
- **Audit redaction is non-negotiable.** Never log raw parameter values that could contain secrets/PII — log shape/hashes, not values. This applies to operational (`tracing`) logs too, not just the audit log. Audit logs record _what happened_, not the secrets that passed through. (`DESIGN.md` §3.4, §10.10.)
    

---

### Rust conventions for this repo

Apply these by default; the worked code for each is in `DESIGN.md` §10, and §12 is the one-screen index.

- **Raw JSON only at the boundary.** Permissive serde structs live in `protocol/`; convert inward to validated domain types via `TryFrom`. Nothing downstream of the parse boundary handles raw `String`/`Value` for a security-relevant concept. (§10.2)
- **Newtypes for security-relevant concepts** — `ServerId`, `ToolName`, `ToolDescription`, `ToolDefinitionHash`, etc. If it matters to policy, detection, audit, or identity, it gets a type. Not ceremony — it makes confused states unrepresentable. (§10.1)
- **Enums, not boolean soup**, for `Verdict`, `GatewayAction`, `MessageClass`, `FailureMode`. Lean on exhaustive `match` to force completeness. (§10.3)
- **Policy is a pure decision function**, separate from detection: detectors produce findings, policy turns `(message/findings, policy)` into a `Verdict`. (§10.5)
- **Config deserializes in `config/`, then converts into typed `Policy`.** Raw TOML doesn't leak past the boundary. (§10.7)
- **`main.rs` stays small:** load config → init telemetry → assemble `Application` → run. Dependencies assembled at the edge and injected. (§10.8)
- **Errors:** small explicit errors in domain code; `anyhow` with `.context(...)` at the application edge. (§10.15)
- **Tests:** unit tests next to the domain type (`#[cfg(test)]`); **corpus tests** (malicious + deliberate near-miss benign) for every detector — a description legitimately containing "ignore" must not trip; **black-box tests** drive the whole proxy and assert side effects (forwarded / blocked / refusal synthesized / audit record written / pin updated / drift detected), not just return values; detectors **never panic** on attacker input. (§10.11–§10.14)
- **CI** runs `cargo fmt -- --check`, `cargo clippy -- -D warnings`, `cargo test` on every change. Red `main` = broken security boundary. (§10.16)
- **Avoid `unsafe`. Avoid reflexive `clone()` to silence the borrow checker** — use ownership intentionally. When ownership gets hard, that's the lesson; sit in it.

> The throughline: **use the type system and tests as part of the design, not as cleanup afterward.** If a change makes an invalid state representable, that's a design smell — reach for a type before reaching for a runtime check.

---

## Agent skills

### Issue tracker

Issues live in GitHub Issues (uses the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default label vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — one `CONTEXT.md` + `docs/adr/` at the repo root (not yet created; `DESIGN.md` currently fills this role). See `docs/agents/domain.md`.