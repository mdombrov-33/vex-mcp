# Vex

Vex is a transparent MCP security gateway, written in Rust, that sits on the wire between an MCP client and the MCP server(s) it talks to — inspecting, deciding on, and recording every message that crosses the boundary.

## Language

**Vex**:
The system as a whole: the security gateway. Owns both pipes (client-facing and server-facing), runs the inspection pipeline, and makes the forward/block/flag decision. "Gateway" is folded into this definition rather than being a separate term — Vex *is* the gateway.
_Avoid_: Proxy (undersells the decision-making — a proxy that only forwards bytes isn't what Vex is), the gateway (use "Vex" instead, even though the concept is the same).

**Server identity**:
The identity of an MCP server, for pinning/policy/audit purposes, is the user-assigned name from Vex's own config (the key under which the user told Vex to spawn it) — not the binary path/args, and never anything the server itself reports at runtime (that's attacker-controlled). Repointing the same config name at a different binary is a form of drift Vex should eventually be able to catch, not something the identity model should hide.
_Avoid_: Deriving identity from the spawn command or from server-reported fields.

**Tool description**:
The natural-language text a server advertises for a tool — what the poisoning scanner (§3.1) inspects. Just the text, nothing else.
_Avoid_: Using "description" loosely to mean the whole tool definition.

**Tool definition**:
Everything about a tool that can change without changing its identity: its description plus its parameter schema. Deliberately excludes the tool name and server identity — those two together are the pin *key*; the definition is what's compared *under* that key. This is what gets hashed into a `ToolDefinitionHash` for pinning.

**Pin**:
A stored fingerprint (hash of the tool definition) recorded the first time Vex sees a given `(server identity, tool name)` pair.

**Audit log**:
The append-only, tamper-evident record of every message Vex has ever decided on. Hash-chained **across Vex's entire lifetime, not per run** — on startup, Vex continues the chain from the last record already on disk rather than starting fresh. This is what makes "tamper-evident" actually mean something: editing or deleting an old record from a past run breaks verification today, not just within the run that wrote it. A missing/corrupt log file on disk is a real failure Vex must surface loudly, not paper over by quietly starting a new chain — see ADR-0004.

**Drift**:
What's detected when a pinned tool's current definition no longer matches its stored pin: any byte-level difference at all, with no judgment about whether the change is benign. v0 does no semantic diffing — a typo fix and a malicious instruction injected into the same description both count as drift identically. Distinguishing "benign" from "dangerous" drift is explicitly not v0's job. Checked on **every** `tools/list` response Vex sees, not once per process lifetime — there's no separate notion of "session" in the design; a long-lived Vex process re-checks every time the server re-advertises its tools.
_Avoid_: Treating drift as inherently malicious — it's a signal that something changed, to be handed to policy, not a verdict itself. Avoid "session" as a term distinct from "`tools/list` response."

**Message class**:
Which bucket an inbound/outbound message falls into, which in turn decides its failure mode (§Fail-open / fail-closed):

- `tools/call` request — a privileged action. Fails closed.
- `tools/list` response — the tool catalog; controls what future actions look legitimate. Fails closed.
- **Known-safe request** — a request method Vex explicitly recognizes as non-privileged (`initialize`, `ping`, `resources/*`, `prompts/*`, …). Fails open.
- **Passive response** — any other recognized response shape. Fails open.
- **Unknown** — a request method Vex's parser has never been told about: not `tools/call`, not on the known-safe list. Fails **closed** — see ADR-0002.

The line that matters: an unrecognized *response* shape is data the model reads (fail open is acceptable); an unrecognized *request* method is an action being asked of the server, and Vex doesn't yet know whether it's privileged — so it defaults to blocking it, the same default-deny instinct as the M4 policy engine, just applied one layer earlier.

**Finding**:
A single rule-level observation a detector produces about a message (which rule fired, how severe). Findings are inputs to policy, never decisions themselves.

**Verdict**:
The single decision policy reaches for a message — `Allow` / `Flag` / `Block` / `RequireConfirmation`. A `Verdict` is the union of two independent sources: detector findings (did this message's content look malicious) and static policy rules unrelated to content (is this tool even on the allowlist). A perfectly clean-looking tool call can still be `Block`ed for being off-allowlist, with zero findings behind it — `Verdict` is not strictly downstream of `Finding`.

**RequireConfirmation**:
A `Verdict` variant expressing "a human should approve this before it proceeds" — distinct from `Block`. No confirmation channel exists yet (Vex has no UI of its own; see ADR-0003), so until one is built, Vex's actual behavior for this verdict is identical to `Block`: fail closed with a reason that says confirmation is required but not yet wired up.
