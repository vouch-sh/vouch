# Development Discipline

Hard-won rules from the #626 key-rotation session (2026-07-06, PR #633).
Read by the team lead, `rust-architect`, `rust-developer`, `rust-code-reviewer`,
and `/rust-agents:solve-issue` before design, implementation, or review work.

## Design decisions

1. **Operator-facing workflow models are user decisions.** When a design chooses
   between automated and operator-driven behavior (rotation schedules, cleanup,
   approvals), present every viable model to the user — including the "boring"
   fully-manual one — before implementation starts. An architect or critic may
   recommend and rank; they may not silently eliminate a model the user would
   recognize from other products.
2. **Lead with prior art.** Before proposing a novel operational design, survey
   how established systems solve it (AWS KMS, Auth0, Keycloak, Vault, DNSSEC
   rollover, ACME) and name the model being followed. A design anchored as
   "this is Auth0's rotate/revoke model" settles in one round; an unanchored
   one churns for hours.
3. **Explain with artifacts, not abstractions.** Proposals for UI or
   operational behavior must show the concrete experience: button labels, the
   exact warning text, timelines with real hours. If the user asks "what do
   you mean by X" twice, stop describing and draw the screen.
4. **State the cost before building.** Before implementation starts, give the
   expected size (files, rough line count) and the slimmest viable
   alternative. A one-question scope checkpoint is cheaper than a rework.

## Implementation

5. **The design's type plan is part of the contract.** If the approved design
   names shared types or helpers (one enum, one ID function), the
   implementation ships them. Three functions differing only in a constant, or
   two enums encoding the same fact, is a rewrite — not a review nit.
6. **Fix the class, not the instance.** When a bug reveals an invariant
   ("every key mutation must invalidate the cache"), enumerate every code path
   that touches the invariant and fix them all in one pass before closing.
   Piecemeal fixes invite N more review rounds finding the same bug's
   siblings: the cache-invalidation invariant alone cost four bugbot rounds.
7. **Scripted bulk edits must prove they landed.** Text replacement that
   no-ops on a missed anchor (python `str.replace`, `sed`) silently drops
   changes — this shipped a transaction guard that existed only in a doc
   comment. After any scripted edit, grep for the new text AND the absence of
   the old; an edit that changed nothing is a failure, not a success. Prefer
   edit tools that error on a missed match.
8. **Completion reports need evidence.** "Done, all tests pass" is accepted
   only with the commands run and their actual counts. The recipient greps the
   diff for the claimed artifacts (new tests, new functions) before advancing
   the pipeline — twice in one session "complete" arrived with zero tests
   written.

## Diagnostics and retries

9. **Diagnostics are read-only.** Never inspect config with positional
   arguments — `git config <key> <value>` is the WRITE syntax and one such
   "read" broke commit signing for the whole repo. Use `git config --get` /
   `--list --show-origin`. The same caution applies to any tool where read and
   write share a verb.
10. **Three strikes, then re-diagnose.** If the same command fails three
    times, stop retrying and re-verify the diagnosis from scratch (traces,
    logs, changed state). The failure cause can change *while retrying*:
    twenty signing retries blamed a locked 1Password vault long after the real
    blocker had become a corrupted config entry.

## Agent teams

11. **Judge liveness by evidence, not silence.** Before declaring a teammate
    stuck, check the filesystem: source mtimes, `target/` fingerprints, new
    handoff files. One "stuck" agent was mid-compaction and delivered the
    entire test suite; one "running" agent had produced nothing for an hour.
12. **Stand down before reassigning.** Never let two writers share a working
    tree: send an explicit stand-down, snapshot the diff to a patch file, and
    only then hand the work to a replacement.
