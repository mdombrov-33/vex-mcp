# Unrecognized request methods fail closed; unrecognized response shapes still fail open

The original design lumped every message Vex doesn't have a typed parser for — malformed JSON-RPC, a future-spec field, *and* any request method other than `tools/call` — into a single `Unknown` bucket that failed open, to avoid breaking the proxy every time the protocol gained a field. That conflated two very different risks: an unrecognized *response* is just data flowing to the model (safe to forward if we can't inspect it), but an unrecognized *request* is an action being asked of the server — exactly the shape of thing Vex exists to gate. Defaulting that open meant a brand-new privileged request type (anything that isn't spelled `tools/call`) would sail through unexamined until someone updated Vex to recognize it, which is the opposite of the default-deny posture the M4 policy engine is supposed to establish.

**Decision:** split the request side of `Unknown` out. Vex now explicitly enumerates the **known-safe** non-privileged request methods (`initialize`, `ping`, `resources/*`, `prompts/*`, and friends) and fails open only for those plus passive responses. `Unknown` narrows to mean "a request method nobody told Vex about" and fails **closed** — blocked by default until Vex is taught about it. Unrecognized response *shapes* are unaffected and still fail open.

## Considered Options

- **Keep `Unknown` failing open for everything** (original design) — simplest, but leaves a real gap: a novel privileged request type would be invisible to policy entirely.
- **Fail closed for everything unrecognized, requests and responses alike** — rejected: would also block unrecognized response shapes, which is unnecessary collateral damage (responses are data, not actions) and a bigger source of breakage as the spec evolves.
- **Split by request vs. response, with an explicit known-safe allowlist for benign requests** (chosen) — requires maintaining a small list of "boring" request methods, but keeps the security-relevant gap closed without breaking basic protocol functions like the handshake.

## Consequences

Every new non-`tools/call` request method MCP introduces needs an explicit decision: is it known-safe (add it to the allowlist) or does it stay `Unknown` (and get blocked) until reviewed? This is a maintenance cost, but it's the same cost the project already accepts for the M4 capability allowlist — reviewing new capability before trusting it, rather than trusting by default.
