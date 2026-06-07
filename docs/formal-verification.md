# Formal Verification Strategy (Kani-first)

> **Status:** Strategy / design document. **No verification harnesses are
> implemented yet.** This file is intentionally a standalone developer reference
> and is *not* part of the mdBook site (`docs/src/`); it will not appear in the
> published docs TOC.

This document lays out how Vouch can use **formal verification** to define
machine-checkable specifications for the RFCs it implements, and recommends a
phased, low-friction path to get there. It catalogs concrete target functions and
the invariants worth proving, and is honest about what these tools *cannot* do.

---

## 1. Why formal verification here

Vouch is a high-assurance authentication system: it issues short-lived credentials
only after hardware-backed human-presence proof, and it implements a large surface
of security-critical specifications — OAuth 2.0, OIDC, FIDO2/WebAuthn, DPoP, PKCE,
token exchange, HTTP message signatures, and CMS/BER parsing.

Correctness today is guarded by several complementary layers:

- **Unit tests** throughout each crate.
- **Property-based tests** with `proptest` (`crates/vouch-tests/tests/proptest.rs`).
- **Fuzz targets** with libFuzzer (`fuzz/fuzz_targets/`:
  `fuzz_ber_parse`, `fuzz_httpsig`, `fuzz_cose_key`, `fuzz_attestation_object`).
- **Mutation testing** with `cargo-mutants`.

These are excellent at *finding* bugs but each samples the input space: proptest
and fuzzing explore many inputs, not *all* inputs. **Formal verification closes
that gap for the cases where it matters most** — total functions that must behave
correctly over an adversarial, attacker-chosen input space.

Formal verification is **defense-in-depth**, not a replacement. It complements the
existing layers; it does not remove the need for any of them.

The functions where proofs add the most value share a profile:

- Pure or near-pure logic with a clear mathematical specification (set algebra,
  encoding round-trips, window/claim validation, parser bounds).
- A hard safety or security property: *no panic*, *no integer overflow*,
  *no privilege escalation*, *deterministic output*.
- Adversarial inputs where "we tested a lot of cases" is weaker than "we proved it
  for all bounded cases".

---

## 2. Tooling choice: Kani-first, Verus-later

Two mature Rust verification tools are relevant. We recommend **Kani first** and
treat **Verus as a deferred, optional track**.

### 2.1 Kani (recommended starting point)

[Kani](https://model-checking.github.io/kani/) is a **bounded model checker** for
Rust built on the CBMC backend. You write proof harnesses that look like tests,
gated behind `#[cfg(kani)]` and annotated `#[kani::proof]`, using `kani::any()` to
produce symbolic ("nondeterministic") inputs and `kani::assume()` to constrain
them. Kani then exhaustively explores all execution paths within the configured
bounds and reports any input that violates an assertion — or proves none exists.

Why it fits Vouch:

- **Bundled toolchain, additive to our build.** `cargo kani` ships and manages its
  own toolchain. It runs as a *separate* invocation alongside our pinned stable
  toolchain (`rust-toolchain.toml` → `rustc 1.96.0`) without changing how the
  normal build, `clippy`, or tests work. A Kani CI job is purely additive.
- **Harnesses live next to the code**, `#[cfg(kani)]`-gated — the same locality the
  codebase already uses for `#[cfg(any(test, feature = "test-utils"))]` helpers.
  No separate fork of the function under test.
- **Verifies the real function**, compiled from the actual source, not a hand-written
  re-implementation.

Strengths and limits to keep in mind:

- **Bounded inputs.** Proofs hold up to the bounds you assume (e.g. slice length
  ≤ N). Choosing meaningful bounds is part of the spec. Kani can still prove
  *panic-freedom* and *overflow-freedom* for all inputs within those bounds, which
  is exactly what we want for parsers and encoders.
- **Loop unwinding bounds.** Unbounded loops need an `#[kani::unwind(n)]` bound;
  recursion (e.g. the BER parser) needs bounding too. This is a feature for us —
  it forces explicit reasoning about depth limits like `MAX_BER_DEPTH`.
- **Opaque cryptography.** Kani cannot reason "through" SHA-256 or signature
  verification (see §2.3). We verify the *logic around* crypto and model hashes
  abstractly where needed.

### 2.2 Verus (deferred, optional)

[Verus](https://github.com/verus-lang/verus) is a **deductive verifier**: it proves
functions correct against pre/post-conditions using an SMT solver, with no input
bounds (it reasons about *all* inputs symbolically). It is more powerful than
bounded model checking in principle.

The cost is significant for a codebase like ours:

- **Custom `rustc` fork.** Verus does not run on stock stable Rust; it requires its
  own compiler toolchain, a heavier parallel-toolchain maintenance burden than
  Kani's bundled `cargo kani`.
- **Restricted subset.** Every verified function must be written inside Verus's
  `verus!{}` macro using its restricted language subset. You cannot verify code
  that pulls in `tokio`, `aws-lc-rs`, `axum`, etc. In practice this means
  *rewriting* the logic as a pure reference module rather than verifying our
  existing functions in place.

Because of this, **Verus is recommended only for *new*, pure reference modules**
(e.g. a verified `ScopeSet`-intersection oracle in a dedicated `vouch-spec` crate),
not for the near-term verification of existing handlers. It is documented here as a
future track, explicitly deferred.

### 2.3 What neither tool does

- **No timing / constant-time guarantees.** Vouch uses `subtle`'s constant-time
  `ct_eq` for secret comparisons (PKCE challenge, DPoP nonce/`ath`). Kani and Verus
  can prove these comparisons return the *correct boolean result*, but they say
  **nothing about the comparison's *timing***. Constant-time / side-channel
  properties are out of scope for functional verifiers and need dedicated tooling
  such as `dudect` or `ctgrind`/`ct-verif`.
- **No replacement for fuzzing/proptest/mutants.** These tools find different
  classes of issues (unbounded inputs, runtime behavior, test-suite quality).
  Formal verification is additive.
- **Crypto is opaque.** Hashing and signature verification are treated as
  uninterpreted functions. Where a proof depends on a hash, we model it abstractly
  (e.g. an injective function: `h(a) == h(b) ⟺ a == b` within the modeled domain)
  and bound input sizes, rather than asking the solver to reason about SHA-256
  internals.

---

## 3. RFC → invariant catalog

This is the core of the strategy: concrete targets and the machine-checkable
property for each. Line numbers are accurate as of this writing; treat them as
pointers, not contracts.

### 3.1 Encoding round-trips

| RFC / area | Target (`file:line`) | Invariant |
|---|---|---|
| Base64url encoding | `Encoded<T,E>` — `crates/vouch-common/src/encoding.rs:75`; `from_base64url` `:158` | `from_base64url(to_string(x)) == x` for bounded byte lengths; `from_base64url` on **arbitrary** input never panics (returns `Err` instead). |
| Agent wire protocol | `crates/vouch-agent/src/wire.rs` (length-prefixed JSON frames) | encode→decode round-trip identity; decoding truncated/oversized frames is panic-free. Already proptested — a prime candidate to *promote* to a bounded proof. |

### 3.2 OAuth/OIDC token logic

| RFC | Target (`file:line`) | Invariant |
|---|---|---|
| **PKCE — RFC 7636 / RFC 9700 §2.1.1** | `AuthorizationCode::validate_pkce` — `crates/vouch-server/src/services/oidc/token.rs:664` | Accepts **iff** `base64url(SHA256(verifier)) == stored_challenge` (SHA-256 modeled as an abstract injective function); rejects when a challenge is present but the verifier is missing; accepts when no challenge is stored. *Timing of the `ct_eq` at the comparison is out of scope (§2.3).* |
| **DPoP — RFC 9449** | `validate_dpop_claims` — `crates/vouch-server/src/services/oidc/dpop.rs:358`; window math uses `saturating_sub` at `:383` | No arithmetic panic for **all** `i64` values of `iat` (guaranteed by `saturating_sub`); a proof is accepted (timestamp-wise) **iff** `age ∈ [-60, max_age_seconds]` (60s skew allowed into the future). |
| **DPoP determinism — RFC 9449** | `compute_access_token_hash` `:261`; `thumbprint` `:112` | Output is deterministic and independent of map/field iteration order — canonical JWK member ordering yields a stable thumbprint; equal inputs yield equal `ath`. |
| **Token exchange — RFC 8693** | `calculate_granted_scope` — `crates/vouch-server/src/services/oidc/exchange.rs:549` (uses `ScopeSet` — `crates/vouch-server/src/services/oidc/scope.rs:68`, `all()` `:87`, `intersection()` `:105`, `is_empty()` `:99`) | **No privilege escalation:** `granted ⊆ requested ∩ available`. For the FIDO2 path (`available = None`), the result never exceeds `ScopeSet::all()`. Empty intersection ⇒ `None` (never an empty grant masquerading as success). This is **pure set algebra — the single strongest Kani fit in the codebase.** |
| **JWT `typ` — RFC 9068 / RFC 8725** | `JwtType` enum `crates/vouch-server/src/crypto/jwt.rs:29`; `as_header_str` `:49`; `from_header_str` `:64` | Round-trip identity over **all** variants: `from_header_str(as_header_str(t)) == Some(t)`; `from_header_str` is **total** — never panics on any arbitrary `&str`, returns `None` for unknown values. |

### 3.3 Parser robustness

| RFC / area | Target (`file:line`) | Invariant |
|---|---|---|
| **BER/DER (CMS)** | `crates/vouch-server/src/crypto/ber.rs`: `read_tlv` `:53`, `read_tlv_ber` `:91`, `MAX_BER_DEPTH = 32` `:36`, depth guard `:165` | Panic-freedom on **arbitrary bounded** byte slices; recursion depth never exceeds `MAX_BER_DEPTH`; long-form length decoding never integer-overflows. Already libFuzzed (`fuzz_ber_parse`) + proptested — the **prime candidate to upgrade a fuzz harness into a bounded Kani proof**. |

### 3.4 HTTP message signatures

| RFC | Target (`file:line`) | Invariant |
|---|---|---|
| **RFC 9421 §2.5** | `build_request_base` `crates/vouch-httpsig/src/signature_base.rs:17`; `build_request_base_with_params_str` `:29` | The signature base is **deterministic**; the `@signature-params` line is always **last** and carries **no trailing newline**; the number of component lines in the base equals the covered-component count. |
| **RFC 9530** | `crates/vouch-httpsig/src/digest.rs`: `content_digest` `:44`, `verify_content_digest` `:77` | `Content-Digest` encode→parse round-trip; parsing arbitrary header values is panic-free; `verify_content_digest` accepts **iff** the digest matches the body. |

---

## 4. How a Kani harness looks (illustrative — not committed)

The intended pattern, so the team can act on this later. This code is illustrative
and is **not** added in this task.

```rust
// In e.g. crates/vouch-server/src/services/oidc/exchange.rs, gated out of the
// normal build. Kani harnesses need the same lint exceptions vouch-tests uses.
#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod kani_proofs {
    use super::*;

    /// RFC 8693: token-exchange must never escalate scope.
    /// Proves `granted ⊆ requested ∩ available` for bounded scope sets.
    #[kani::proof]
    fn granted_scope_never_escalates() {
        // Symbolic, bounded inputs.
        let requested: ScopeSet = kani::any();      // (with a bounded Arbitrary impl)
        let available: ScopeSet = kani::any();

        if let Some(granted) = calculate_granted_scope(
            Some(&requested.to_space_delimited()),
            Some(&available),
        ) {
            // Core security property: no scope appears that wasn't both
            // requested AND available.
            for scope in granted.iter() {
                assert!(requested.contains(scope));
                assert!(available.contains(scope));
            }
            // And a non-None result is never empty.
            assert!(!granted.is_empty());
        }
    }
}
```

**Abstract-hash modeling for PKCE/DPoP.** Because Kani cannot reason through
SHA-256, a PKCE proof substitutes an abstract injective hash for the real digest in
the harness (behind `#[cfg(kani)]`), so the property under proof becomes the
*logic* — "accept iff `hash(verifier) == challenge`, reject on missing verifier" —
rather than the cryptographic strength of SHA-256 (which is assumed, not proven):

```rust
#[cfg(kani)]
fn model_hash(input: &[u8]) -> Hash {
    // Uninterpreted but injective within the bounded modeled domain:
    // model_hash(a) == model_hash(b)  <=>  a == b
    kani::any_where(|h: &Hash| /* injectivity constraint */ true)
}
```

---

## 5. Proposed integration (described, not implemented)

When the team decides to act, the lowest-friction integration is:

- **Harness location.** `#[cfg(kani)]`-gated modules **beside the code** under
  proof, mirroring the existing `#[cfg(any(test, feature = "test-utils"))]`
  pattern. No new crate is required for the Kani track.
- **Lint exceptions.** Kani harness modules carry
  `#![allow(clippy::unwrap_used, clippy::indexing_slicing, …)]`, the same exception
  model the `vouch-tests` crate already uses (the workspace's strict no-panic
  lints are inappropriate inside proof scaffolding).
- **CI.** A **new, additive** GitHub Actions job running `cargo kani` with a pinned
  Kani version, parallel to the existing `fmt` / `clippy` / `test` / `build` jobs
  in `.github/workflows/ci.yml`. Start it **non-blocking** (report-only) so it
  never gates merges until the proofs and runtimes are stable.
- **Makefile.** A `make verify` target alongside the existing `make test-fuzz`, so
  proofs are runnable locally with one command.
- **Verus future track (deferred).** A separate `vouch-spec` crate of *pure,
  verified reference algorithms* (e.g. a verified `ScopeSet` intersection) usable as
  an oracle that the production code is differentially tested against. This requires
  the Verus toolchain and is explicitly out of scope for the near term.

---

## 6. Phased rollout recommendation

| Phase | Scope | Rationale |
|---|---|---|
| **0** | *This document.* | Agree the strategy, catalog, and tool choice. |
| **1 — pilot** | Scope set algebra (`calculate_granted_scope`) + JWT `typ` round-trip + BER `MAX_BER_DEPTH` panic/overflow-freedom. | Highest value, lowest friction: pure logic, no crypto modeling, immediate security payoff (no escalation, no parser panic). |
| **2** | PKCE + DPoP window (with abstract-hash modeling), encoding round-trips, HTTP-signature base. | Builds on Phase 1; introduces the abstract-hash technique and bounded round-trip proofs. |
| **3** | Make the `cargo kani` CI job **blocking** once proofs and runtimes are stable. | Turns the additive, report-only job into an enforced gate. |
| **4 — optional** | Verus `vouch-spec` reference-oracle crate. | Deferred; only if the deductive-proof payoff justifies the parallel-toolchain cost. |

---

## 7. Summary

- **Use Kani first.** Bundled toolchain, additive CI, harnesses next to the code,
  proves panic-/overflow-freedom and functional invariants over bounded adversarial
  inputs.
- **Defer Verus** to a future, optional pure-reference-module track because of its
  custom-`rustc` fork and restricted-subset rewrite cost.
- **Be honest about limits:** these tools prove *functional* correctness, not
  *constant-time* behavior, and they treat crypto as opaque — so we verify the logic
  around crypto and model hashes abstractly.
- **Start where it pays off most:** scope set algebra, JWT `typ`, and BER depth
  bounds — pure logic with concrete security and robustness guarantees.
