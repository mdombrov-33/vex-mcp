# The audit hash-chain spans Vex's entire lifetime, not one run per chain

The audit log's whole purpose (§3.4) is forward integrity: a later compromise shouldn't be able to silently rewrite history. Two designs were available — restart the hash chain fresh every time Vex starts (simpler, and arguably "good enough" since each run's records are still internally tamper-evident), or treat the chain as one continuous structure across every run Vex has ever made, picking up from the last record on disk at startup.

**Decision:** one continuous chain for the audit log's entire lifetime. On startup, Vex reads the last record already on disk and continues the chain from its hash, rather than starting a new chain. A missing or corrupted log file is a hard failure Vex must surface, not something it silently works around by starting fresh.

**Why:** a per-run chain only proves a single run wasn't tampered with internally — it says nothing about whether *yesterday's* run was edited after Vex exited. Since nothing else in the design re-verifies old runs against each other, a per-run chain would let someone delete or rewrite an entire past run's records and have today's chain start clean with no trace, which defeats the stated goal (T8 repudiation / forward integrity) entirely.

## Considered Options

- **Per-run chain, fresh genesis each start** — simpler, but the integrity guarantee doesn't actually span what "audit log" implies; rejected.
- **One continuous chain across all runs** (chosen) — matches what "tamper-evident audit log" is supposed to mean, at the cost of needing real handling for "log file missing/corrupted" instead of treating that as a fresh start.

## Consequences

Vex needs an explicit, loud failure path for "the audit log file is missing or its tail doesn't parse as a valid chain link" at startup — this can't be silently treated as "first run." That's an M5 implementation detail, but the decision here is what makes it a *requirement* rather than a nice-to-have.
