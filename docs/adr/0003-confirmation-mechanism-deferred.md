# The confirmation mechanism is out of scope for v0/v1; `RequireConfirmation` behaves like `Block` until it exists

`RequireConfirmation` is a distinct `Verdict` so policy can express "a human should approve this," separately from an outright `Block`. But Vex is a transparent stdio proxy with no UI of its own — neither the client nor the server is supposed to know it's there (§2.2). There's no obvious, non-fragile channel for Vex to actually interrupt and ask a human something: it can't safely repurpose the model's own tool-call channel to relay a question (the model would have to faithfully forward it, and the human's answer would have to come back through a channel MCP wasn't designed for), and it has no side-channel UI of its own in v0.

**Decision:** the type exists now so the policy engine and M4 don't need a breaking change later, but the *mechanism* for actually asking a human (a CLI prompt, a local socket, a companion UI — whatever it ends up being) is explicitly deferred past v1. Until it's built, Vex's behavior for `RequireConfirmation` is identical to `Block`: fail closed, with a reason explaining that confirmation is required but not yet wired up. A human unblocks it today by editing the policy file, not by answering a live prompt.

## Considered Options

- **No live confirmation in v0/v1; behaves like `Block` until a mechanism exists** (chosen) — keeps the type honest about intent without inventing something fragile.
- **Relay the question through the model's own tool-call channel** — rejected: depends on the model faithfully forwarding an out-of-band question and the human's reply finding its way back through a channel not designed for it.
- **Build a real side-channel (CLI prompt / local socket) now** — rejected for v0: real scope, and not on the M0–M5 critical path (§5).

## Consequences

Anyone implementing M4 should not be surprised that `RequireConfirmation` and `Block` produce the same `GatewayAction` today — that's deliberate, not a missing `match` arm. Building a real confirmation channel later is additive: only `GatewayAction::PauseForConfirmation`'s actual implementation changes, not the `Verdict` type.
