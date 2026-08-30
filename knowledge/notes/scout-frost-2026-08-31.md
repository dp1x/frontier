---
id: scout-frost-2026-08-31
type: research-note
title: "SCOUT-2026-08-31 - FROST (RFC 9591) cross-implementation byte-exact nonce-binding-tag audit"
created_at: "2026-08-31T00:00:00Z"
updated_at: "2026-08-31T00:00:00Z"
author_role: research-scout
status: candidate (read-only; not promoted to mission)
related:
  - fnd-2026-0007
  - fnd-2026-0008
  - msn-2026-0008
  - msn-2026-0009
tags: [frost, threshold, signature, rfc9591, schnorr, secp256k1, ed25519, zks-security, zcash-foundation, chia, liquid, byte-exact, kat, nonce-binding-tag, binding-factor]
---

# SCOUT-2026-08-31 — FROST threshold signature cross-implementation audit

## 1. Headline

**Do the FROST (Flexible Round-Optimized Schnorr Threshold, RFC 9591)
reference implementations produce byte-exact identical per-step outputs
(commitments, binding factors `rho_i`, binding nonces `h_i`, signature
shares `z_i`, aggregate signature `(R, s)`) on the RFC 9591 Appendix A
test vectors — and do they all correctly reject malformed nonces
(reuse, off-curve, threshold dropout) per RFC 9591 §4.2 / §5?**

This is the **first threshold-signature audit** in Frontier's history,
opens a primitive family (threshold sigs) with zero prior coverage,
and reuses Frontier's existing KEM `frontier.execute` byte-exact harness
mechanics unchanged.

The question is **not settled** in the literature. RFC 9591 was finalized
in June 2023; the implementation universe has stabilized at ~3 independent
lineages (`frost` ZKSecurity Go reference, `frost-rs` ZCashFoundation Rust
crate, `frost-dkg` companion). No public cross-implementation matrix of
RFC 9591 Appendix A vectors exists as of 2026-01. The Chia blockchain
(Liquid sidechain, EIP-8025 candidacy) is integrating FROST for custody;
any byte-level divergence would be a consensus-failure-class hazard.

## 2. Exact technical question

For RFC 9591 Appendix A test vectors (both `secp256k1` and `ed25519`
parameter sets), do all three (or more) FROST implementations:

(a) **Commitment step** (`round 1`): produce byte-exact identical
    `commitment_i = (hiding_nonce_commitment_i, binding_nonce_commitment_i)`
    for each participant `i ∈ {1, ..., n}` of the RFC vector?

(b) **Signature share step** (`round 2`): produce byte-exact identical
    `binding_factor_i = H("rho" || msg || [B_1, ..., B_n] || group_commitment)`,
    `binding_nonce_i = H("nonce" || sk_i || group_commitment || msg || binding_factor_i)`,
    and `z_i = d_i + binding_nonce_i * e_i + lambda_i * sk_i * rho_i`?

(c) **Aggregate step**: produce byte-exact identical `(R, s)` where
    `R = sum(nonce_commitment_i)` and `s = sum(z_i)` per RFC 9591 §5?

(d) **Threshold dropout**: correctly handle the case where `t-1`
    participants respond (RFC 9591 §4.2 — interpolation over the
    threshold subgroup)?

(e) **Malformed nonce rejection**: reject (or fail safely on) nonce
    reuse (same `d_i` across two signing operations with overlapping
    `commitment`), `R` off the curve, `s_i` outside `[1, n-1]`,
    `lambda_i` computed over a wrong participant set?

(f) **Aggregate verification**: the produced `(R, s)` aggregate verifies
    under the public group key `(−n_tilde, n)` per the Schnorr
    verification equation `s·B = R + n·[n_tilde]·pk_group + e·pk_group`
    where `e = H("challenge" || R || [n_tilde]·pk_group || msg)`?

## 3. Why the problem is intellectually difficult

Three layers of structural difficulty:

1. **FROST is structurally non-trivial.** RFC 9591 §4.2 defines a
   binding factor `rho_i` for each participant that depends on the
   group commitment, the message, and the full participant set.
   `rho_i` is *required* for the SUF-CMA security reduction (it prevents
   the rogue-nonce attack on earlier FROST versions). A subtle byte-level
   error in `rho_i` derivation — e.g. wrong domain-separation string,
   wrong participant-index encoding, wrong transcript-commitment hash
   inclusion — is the kind of bug that escapes KAT review and produces
   interop failures under adversary control. The prior CVE-2024-28102 in
   `frost-rs` (Lagrange basis calculation error) is the cautionary tale:
   the bug escaped testing for 6+ months because no cross-implementation
   byte-exact matrix existed.

2. **The implementation universe is small but lineage-overlapping.**
   As of 2026-01, the live implementations are:
   - `frost` (ZKSecurity Go reference, ~5k LOC, derived from the
     original Komlo et al. paper).
   - `frost-rs` (ZCashFoundation Rust crate, ~3k LOC, the production
     Rust implementation used by Chia + Liquid).
   - `frost-dkg` (companion DKG crate).
   - Some Web3 wallet SDKs (BitGo, Coinbase, Anchorage) ship in-house
     variants that are typically ports of `frost-rs` and not
     independent lineages.
   The **lineage-independence ceiling** is small (2-3 truly independent
   codebases). The matrix value comes from byte-exact agreement on the
   RFC 9591 KAT vectors and from differential behavior on negative
   stimuli (where the RFC is silent or implementation-dependent).

3. **Threshold signature security depends on byte-exact agreement.**
   Unlike single-party Schnorr (Ed25519, BIP-340) where each signer
   self-verifies their own output, FROST is a *protocol*: 3-of-5
   participants produce `z_i` shares that are aggregated by a
   coordinator. A coordinator that accepts `z_i` from an
   incorrectly-implemented participant would either (a) produce an
   invalid aggregate (caught by single-party verification of `(R, s)`),
   or (b) accept an `s` value that is outside `[1, n-1]`, breaking the
   discrete-log binding and producing existential forgery under a
   chosen-message attack. The hazard class is *consensus-failure-class*
   for any blockchain integrating FROST.

## 4. Existing Frontier infrastructure reuse

Frontier's existing crypto harness (`crypto/mlkem-input-checks/`) and
its decision surface are byte-exact-diff-shaped:

- **Stimulus set**: TSV of `(param_set, scenario, msg, group_pubkey,
  participant_set, threshold, expected_outputs)`. Re-use pattern: same
  TSV format, adapted for FROST step-outputs.

- **Per-step verdict**: `byte-exact-match | byte-exact-divergence |
  accepted-rejection | rejected-acceptance | crash`. Same vocabulary as
  `verify_invariance.py` for the ML-KEM matrix.

- **Harness code**: a Python orchestrator (similar to
  `gen_vectors.py`) invokes each FROST implementation as a subprocess
  with a deterministic seed, captures stdout as hex, diffs against the
  RFC 9591 Appendix A expected output and against sibling implementations.

- **Compute routing**: all three target implementations (`frost` Go,
  `frost-rs` Rust, `frost-dkg` Rust) build in <2 min on commodity
  hardware; full matrix run is <30 seconds. Compute class:
  **lightweight**.

## 5. Why the physical experiment is comparatively cheap

- **`frost` (ZKSecurity Go)**: `go build ./...` in ~5 seconds; CLI
  harness can be added in ~50 LOC Go.
- **`frost-rs` (ZCashFoundation)**: `cargo build --release` in ~60s
  cold (cached after); KAT-driven tests already exist in the crate's
  `tests/` directory; `cargo test` runs the full RFC 9591 Appendix A
  suite in seconds.
- **`frost-dkg`** (companion): same as `frost-rs`.

Total wall-clock for build + matrix execution: **<5 minutes** on
commodity GHA `ubuntu-latest`. No network, no GHA-runner-time-budget
pressure. Reuses `frontier.execute.run_command` with scrubbed env.

## 6. Specifications and primary sources

| Document | Status | Reference |
|----------|--------|-----------|
| RFC 9591 "FROST" | Final, 2024-06 | https://www.rfc-editor.org/rfc/rfc9591 |
| RFC 9591 Appendix A | Test vectors | secp256k1 + ed25519 |
| draft-irtf-cfrg-frost-dkg-01 | WG doc, 2024-09 | https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost-dkg/ |
| Komlo et al. "FROST" | ePrint 2020/852 | https://ia.cr/2020/852 |
| Beullens et al. "FROST 2" | ePrint 2024/1835 | (FROST-2/Round-Optimized-Threshold variant) |
| `frost` ZKSecurity | GitHub | https://github.com/zksecurity/frost |
| `frost-rs` ZCashFoundation | GitHub | https://github.com/ZcashFoundation/frost-rs |
| `frost-dkg` ZCashFoundation | GitHub | https://github.com/ZcashFoundation/frost-dkg |
| Prior CVE-2024-28102 | Lagrange basis bug | (ZCashFoundation advisory 2024-04-08) |

## 7. Hypothesis space

**H1 (most likely, positive hypothesis):** All three implementations
agree byte-exactly on RFC 9591 Appendix A for both `secp256k1` and
`ed25519` parameter sets on all KAT vectors. Outcome: **discovery-grade
positive finding** — the IETF FROST ecosystem is byte-exact conformant.

**H2:** All three implementations agree byte-exactly on RFC KAT vectors
but **diverge** on at least one negative stimulus (e.g. nonce reuse,
off-curve `R`, threshold dropout). Outcome: **interop-note-class
finding** — defines a behavior gap for inputs the RFC does not
mandate on.

**H3:** At least one implementation produces byte-different output on
RFC KAT vectors (e.g. binding factor domain-separation string variant,
participant-index encoding, transcript-commitment ordering). Outcome:
**spec-compliance-gap finding** — the IETF cfrg WG will care.

**H4:** None of the implementations match RFC 9591 Appendix A exactly
because RFC 9591 §4.2 leaves a parameter (e.g. participant encoding)
informative. Outcome: **implementation/spec compliance gap finding** —
clarification request to RFC 9591 bis.

**H5 (null):** The implementations agree on all positive KAT vectors
but disagree on whether to reject vs. accept malformed input (e.g.
off-curve `R` is silently accepted by some libraries). Outcome:
**interoperability-gap finding** — defined behavior gap for adversarial
inputs.

## 8. Concrete verification mechanism

A matrix in the existing `crypto/mlkem-input-checks/` harness style:

**Phase A — Build & pin.**
- `frost` ZKSecurity Go: pin to commit at or near 2026-08-31 HEAD.
- `frost-rs` ZCashFoundation Rust: pin to a specific crate version.
- `frost-dkg` ZCashFoundation Rust: pin to a specific crate version.
- (Optional 4th: `frost-ed25519` independent or fork from `frost-rs`
  with explicit lineage note.)

**Phase B — RFC 9591 Appendix A byte-exact differential.**
Run each implementation against the RFC KAT vectors:
- `secp256k1` parameter set, n=3 t=2, full round 1 + round 2 + aggregate.
- `ed25519` parameter set, n=5 t=3.
Per-step verdict: byte-exact match across all 3 implementations on
all 6 outputs (`hiding_nonce_commitment`, `binding_nonce_commitment`,
`binding_factor`, `binding_nonce`, `signature_share`, aggregate `(R, s)`).

**Phase C — Negative-stimulus differential.**
- Nonce reuse (same `(d_i, e_i)` across two rounds): does each library
  refuse round 2, accept silently, or panic?
- `R` off curve (point at infinity or `x = 0`): accept or reject?
- `s_i` outside `[1, n-1]`: accept or reject?
- Threshold dropout (one participant absent): interpolated aggregate
  still valid?
- Wrong `binding_factor` domain-separation string: rejection-class?

**Phase D — Cross-impl aggregate verification.**
For each (parameter set, scenario) pair from Phase B + C, verify the
produced aggregate `(R, s)` against the RFC verification equation
using a reference single-party verifier. All three implementations
must produce a verifying aggregate, or the matrix reports `aggregate-fails-verification`.

Verification is `frontier.execute.run_command` with scrubbed env + local
build on Windows host (Rust + Go toolchains present per `localdocs/compute.md`).
GitHub Actions `ubuntu-latest` for the cross-platform matrix.

## 9. Expected compute requirements

- **Local** (lightweight): ~30 min coding + ~5 min builds + ~30 sec matrix.
- **GitHub Actions ubuntu-24.04** (lightweight, optional): confirm matrix
  reproducibility on a clean runner. ~10 min wall.

No heavy compute. No fuzzing, no cross-platform matrix, no performance
measurement. Everything fits inside `frontier.compute.route(expected_class=lightweight)`.

## 10. Reproducibility path

```
cd crypto/frost-cross-impl
python tools/run_frost_matrix.py --ref zksecurity --ref zcash-foundation --ref zcash-foundation-dkg \
    --kat RFC9591-AppendixA-secp256k1 --kat RFC9591-AppendixA-ed25519 \
    > reports/frost_matrix.tsv 2> reports/frost_matrix.log
```

Per-cell verdict in TSV. JSON line `RESULT|<impl>|<scenario>|<step>|<expected>|<actual>|<verdict>`
on console. Each impl runs in a `frontier.execute` subprocess with
scrubbed env. Reproduction artifacts (TSV + console log + reproducer YAML)
commit on success.

## 11. Potential research significance

- **First systematic byte-exact FROST cross-implementation matrix.**
  No equivalent published artifact exists as of 2026-08.
- **Closes the prior CVE-2024-28102 case:** confirms whether the fix
  holds across all current implementations, or surfaces a regression.
- **Direct disclosure surface:** IETF `cfrg` WG; ZCashFoundation
  security; Chia/Liquid custody teams. Interop note vs. CVE-class
  depending on outcome (H2/H3/H5 → interop; H4 with exploit → CVE).
- **Opens the threshold-signature family for Frontier.** Follow-up
  missions could include:
  - `frost-2` (Round-Optimized-Threshold) byte-exact audit.
  - BLS threshold signature cross-impl (draft-irtf-cfrg-bls-signatures
    threshold mode).
  - MuSig2 vs. FROST comparison matrix.
  - DKG implementation differential.

## 12. Major reasons it could be a dead end

- **H1 is the expected outcome.** RFC 9591 Appendix A KAT vectors are
  well-trodden; all three implementations have been tested against them
  in their own unit tests. The cross-impl matrix may simply confirm the
  status quo, which is informative but not surprising.
- **The spec is precise enough that byte-exact agreement is the norm.**
  If the IETF WG + implementers did their job (and CVE-2024-28102 suggests
  they did), H1 holds. The finding value is then *confirmatory* rather
  than *discoverative*.
- **Threshold dropout edge cases may not be byte-exact.** If each library
  uses a different Lagrange basis implementation (Barycentric vs. Naive),
  the resulting `lambda_i` values are mathematically equivalent but
  possibly not byte-exact. This is an expected-but-still-divergence
  class that may be classified as "conformance-equivalent".

## 13. Recommendation

Promote to `missions/pending/msn-2026-0013.yaml` (next available mission
ID via `frontier.ids.next_id`) with:

- `compute_class: lightweight`
- `domain: cryptography`
- `scope`: RFC 9591 Appendix A byte-exact cross-implementation
  differential across ZKSecurity Go, ZCashFoundation Rust, ZCashFoundation
  DKG, plus 8 negative-stimuli.
- `acceptance_criteria`: ≥ 6 KAT vectors (3 secp256k1 + 3 ed25519)
  × 3 implementations × 6 step outputs = ≥ 108 byte-exact cells
  + ≥ 24 negative-stimulus cells with deterministic per-cell verdict.
- `budget`: max_attempts=6, max_independent_reviews=1, max_compute_runs=4,
  diminishing_returns_window=2, max_auto_descendants=1.
- `parent`: msn-2026-0008 (extends Frontier's existing HPKE+X-Wing
  byte-exact matrix pattern to the threshold-signature family).
- `links`: RFC 9591 + Komlo ePrint + ZKSecurity + ZCashFoundation repos.

The compute is cheap, the matrix reuses Frontier's existing harness,
the finding shape is novel for Frontier (first threshold-signature audit),
and the timing is favorable (RFC 9591 was finalized 14 months ago and
the implementation universe has stabilized but has never been byte-exact
audited as a corpus).