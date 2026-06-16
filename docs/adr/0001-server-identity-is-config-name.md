# Server identity is the user-assigned config name, not the binary path

Vex pins tool definitions per `(server, tool name)` and needs a stable notion of "which server is this" to make that pinning meaningful. The obvious-looking choice is to identify a server by the command/binary Vex spawns for it — that's the thing actually running. We rejected that: the spawn command is a property of the *config file*, and a security-relevant identity should track what the *human approved*, not an implementation detail that can change (a relocated binary, a wrapper script) without the human's intent changing. We also rejected anything the server reports about itself at runtime (e.g. an `initialize` field), since that's attacker-controlled and unusable as a security boundary.

**Decision:** `ServerId` is the user-assigned name from Vex's own config — the key under which the user told Vex to spawn that server. Not the binary path/args, never server-reported data.

## Considered Options

- **Binary path/args** — stable and concrete, but conflates "did the config change" with "did the tool's behavior change," and a relocated binary would falsely look like a new server.
- **User-assigned config name** (chosen) — matches what the human actually approved; repointing the same name at a different binary is itself a future drift signal, not something the identity model should hide.
- **Server-reported identity** — rejected outright; the server is exactly the thing we don't trust.

## Consequences

If the config name for a server ever needs to change, that's a deliberate identity change — existing pins under the old name won't carry over automatically. This is acceptable for v0 (re-approving pins under a renamed server is a small, visible cost) but worth knowing if a "rename without re-pinning" feature is ever requested.
