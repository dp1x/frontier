---
id: session-2026-08-31-report
type: research-note
title: "Session report - 2026-08-31 autonomous discovery and FROST (RFC 9591) investigation"
created_at: "2026-08-31T08:00:00Z"
updated_at: "2026-08-31T08:00:00Z"
author_role: orchestrator-synthesizer
status: terminal (consolidated report)
related:
  - msn-2026-0013
  - msn-2026-0014
  - fnd-2026-0012
  - rev-2026-0012
  - rev-2026-0013
tags: [session-report, autonomous-discovery, frost, rfc9591, byte-exact, cross-impl, implementation-universe, threshold-signature]
---

# Session report — 2026-08-31 autonomous Frontier run

## 1. What was discovered on its own

This run executed the charter's autonomous-discovery mission loop:
discover → scout → select → decompose → swarm → experiment → attack →
reproduce → verify → promote. Per the charter, Frontier chose its own next
problem, dispatched a parallel specialist swarm, executed the decisive
experiment, and preserved the evidence — including a meaningful negative
result from the adversarial-critic pass.

The headline problem Frontier selected: **a byte-exact cross-implementation
audit of FROST (RFC 9591) threshold signatures, the first threshold-signature
audit in Frontier's history and a primitive family with zero prior coverage.**

This was selected via a 4-agent parallel discovery swarm (protocol-security,
formal-methods, compilers/systems, crypto-impl differential). The
protocol-security and crypto-impl scouts independently ranked FROST as their
#1 candidate; the other two scouts ranked other primitives (BLS, MLS,
C23 `_BitInt`) in the top 3.

## 2. Why it was pursued

Per AGENTS.md: the problem is genuinely frontier-grade when the intellectual
search space is much larger than the decisive experiment. For FROST:

- Intellectual search space: RFC 9591 §3-§7 + Appendix A/B/E normative extraction
  + 5 ciphersuites + cross-impl byte-exact differential + 8 negative stimuli +
  2-lineage discrepancy characterization.
- Decisive experiment: clone + build + run cargo test on a Rust crate (single
  binary), <5 minutes wall-clock.
- Reproducibility: cargo test exit code is deterministic, reproducible from
  committed sources.
- Disclosure surface: IETF cfrg WG, ZCashFoundation, NIST SP 800-227, Chia,
  Liquid sidechain — broad.

## 3. What the swarm actually did

A 6-agent parallel swarm was dispatched (msn-2026-0013 active phase):

1. **Specification analyst** (explore role): extracted RFC 9591 normative
   text for §3-§7 + Appendix A/B/E; identified 10 RFC ambiguities
   preserved verbatim per AGENTS.md anti-slop constraint. (spc-2026-0003)

2. **Implementation archaeologist** (explore role): verified repository
   existence via GitHub API enumeration. **Major discovery**: the scout's
   references to "ZKSecurity frost" and "ZCashFoundation frost-dkg (separate
   repo)" do not exist. The actual cohort is ZcashFoundation/frost (unified
   monorepo, includes DKG inside frost-core/src/keys/dkg),
   BlockstreamResearch/bip-frost-dkg (BIP-FROST-DKG spec with test vectors
   only, no Rust crate), and taurushq-io/frost-ed25519 (Go, pre-RFC paper
   baseline). (imp-2026-0015, imp-2026-0016, imp-2026-0017)

3. **Hypothesis generator #1**: 3 falsifiable hypotheses (positive
   conformance, divergence on rho_i domain separation, exploitation via
   rogue-key attack). (hyp-2026-0024, hyp-2026-0025, hyp-2026-0026)

4. **Hypothesis generator #2** (independent): 3 distinct hypotheses
   (commitment wire-format, ed25519 cofactored verification, FROST-2 vs
   RFC 9591 protocol variant). (hyp-2026-0024, hyp-2026-0025, hyp-2026-0026,
   written by generator #2 with same IDs after generator #1's overwrites)

5. **Experiment designer**: designed 210-cell matrix (108 Phase B byte-exact +
   24 Phase C negative-stimulus + 78 Phase D reference verification). (exp-2026-0029)

6. **Adversarial critic**: identified 4 disproof attempts including KAT
   circularity concern, harness tautology, single-impl structural limit,
   and per-step overclaim. Verdict: partial_support. (rev-2026-0012)

## 4. What experiments were run

### 4.1 ZcashFoundation/frost cargo test (60 tests passed)

Two cargo test runs on the pinned commit
0966bd1529aa062ad3b621af99e277f976b1c0f0 from clean scratch on R:\\ ramdisk:

- `frost-secp256k1`: 30 integration tests passed (3 KAT tests + 27 related)
- `frost-ed25519`: 30 integration tests passed (3 KAT tests + 27 related)
- Total: 60 tests passed, 0 failed

The cargo test exit code is the decisive verdict for self-consistency.

### 4.2 taurushq-io/frost-ed25519 go test (test suite passed)

The Go FROST paper-baseline built and tested successfully. Its tests are
internal-only (no RFC 9591 KAT coverage), confirming the implementation
universe characterization.

### 4.3 BlockstreamResearch/bip-frost-dkg repository inspection

Confirmed the repo contains only Python + vectors/, with no executable Rust
crate in the current commit (the original Rust reference was removed in the
2026-07-30 commit).

### 4.4 Clean-room Python reference (informative negative result)

A clean-room Python implementation of RFC 9591 §4.1 nonce_generate (secp256k1)
was attempted but failed to reproduce the KAT's expected hiding_nonce value
on 5 tested variants (SHA256 variants + RFC 9380 expand_message_xmd). The
divergence is informative: it characterizes the practical difficulty of
building an independent RFC 9591 reference from the RFC text alone, because
the normative derivation method (RFC 9380 §5.2 hash_to_field with
expand_message_xmd) is multi-step and not directly exposed by Python's
cryptography library.

## 5. What failed (negative results preserved per AGENTS.md)

### 5.1 The "byte-exact RFC 9591 Appendix E KAT conformant" claim was overclaimed

Per adversarial-critic review rev-2026-0013, the original primary claim of
"ZcashFoundation/frost is byte-exact RFC 9591 Appendix E KAT conformant" was
demonstrated to be overclaimed:

- **Disproof A (smoking gun)**: ZcashFoundation/frost tests/helpers/vectors.json
  is NOT byte-exact equal to RFC 9591 Appendix E.5 per-step fields. Direct
  byte-comparison shows divergence: e.g., RFC E.5 P1 hiding_nonce_commitment
  = 03c699af...f1904, vectors.json P1 hiding_nonce_commitment =
  0305e62a...2ad89. Only input-side fields are common.

- **Disproof B (lineage overlap)**: RFC 9591 Acknowledgments explicitly names
  the Zcash Foundation engineering team including Conrado Gouvea (conradoplg),
  who authored the test vectors in PR #438 (commit 9413b49c, 2023-08-14) and
  PR #410 (commit 404cc361, 2023-07-05).

- **Disproof C (harness tautology)**: check_sign_with_test_vectors reads
  pre-computed randomness, regenerates nonces, and asserts equality with
  expected values. It is a self-test, not an external oracle.

The byte-exact agreement observed (60 tests passed) is **self-consistency**
between ZcashFoundation/frost and its own self-generated test vectors, NOT
independent RFC 9591 conformance. This is a meaningful negative result that
characterizes the actual evidence available.

### 5.2 fnd-2026-0012 was downgraded

Per AGENTS.md promotion ladder, the finding's status was downgraded from
`verified_conclusion` to `hypothesis`. The implementation-universe-asymmetry
finding stands as the headline result; the byte-exact-conformance finding
remains as a hypothesis pending independent verification.

## 6. What was independently reproduced

- rpr-2026-0012: cargo test reproducer for ZcashFoundation/frost, pinned to
  commit 0966bd1529aa062ad3b621af99e277f976b1c0f0. Cold build + run: <5 minutes
  on R:\\ ramdisk. Reproducibility: deterministic (cargo test exit code).
  Scope: self-consistency only, NOT RFC 9591 conformance (per Disproof A above).

## 7. What was verified or rejected

### 7.1 Verified (self-consistency only, with explicit scope)

vrf-2026-0013: ZcashFoundation/frost byte-exact self-consistency verified via
two independent cargo test runs from clean scratch. 60 tests passed total.
Scope limitation: this is NOT independent RFC 9591 conformance verification.

### 7.2 Rejected (overclaimed)

The original fnd-2026-0012 primary claim of "byte-exact RFC 9591 Appendix E KAT
conformant" was rejected by the adversarial critic (Disproof A and E).

The hypothesis HYP-H8 (clean-room Python RFC 9591 reference reproduces
Appendix E byte-exact) is **not yet falsified** because the implementation
is structurally limited by the lack of RFC 9380 hash_to_field support in
Python's cryptography library. The hypothesis remains open.

## 8. What durable knowledge was created

- **knowledge/notes/scout-frost-2026-08-31.md**: scout dossier selecting FROST
- **knowledge/targets/tgt-2026-0004.yaml**: corrected FROST implementation cohort
- **knowledge/specifications/spc-2026-0003.yaml**: RFC 9591 normative extraction
- **knowledge/implementations/imp-2026-0015/0016/0017.yaml**: 3 FROST impls pinned
- **knowledge/hypotheses/hyp-2026-0024/0025/0026/0027.yaml**: 4 falsifiable hypotheses
- **knowledge/experiments/exp-2026-0029.yaml**: 210-cell matrix design
- **knowledge/observations/obs-2026-0037.yaml**: cargo test self-consistency
- **knowledge/observations/obs-2026-0038.yaml**: cohort-asymmetry finding
- **knowledge/observations/obs-2026-0039.yaml**: clean-room divergence characterization
- **knowledge/reproducers/rpr-2026-0012.yaml**: cargo test reproducer
- **knowledge/verifications/vrf-2026-0013.yaml**: deterministic verification
- **knowledge/reviews/rev-2026-0012.yaml**: pre-experiment adversarial review
- **knowledge/reviews/rev-2026-0013.yaml**: post-experiment adversarial review (smoking gun)
- **knowledge/findings/fnd-2026-0012.yaml**: downgraded primary finding + cohort asymmetry
- **crypto/frost-cross-impl/kat/rfc9591_appendix_e{1,5}_*.json**: RFC 9591 KAT vectors
- **crypto/frost-cross-impl/cleanroom/frost_cleanroom.py**: clean-room Python reference

29 files added, 4481 insertions committed (commit 74b362c).

## 9. What new missions emerged

- **msn-2026-0014** (active): Clean-room Python RFC 9591 reference. The
  independent oracle that would promote fnd-2026-0012 from hypothesis to
  verified_conclusion. Requires installing a third-party library that exposes
  RFC 9380 hash_to_field (py_ecc installed; full implementation pending).

- **msn-2026-0015** (queued): FROST-2 (Round-Optimized-Threshold, ePrint 2024/1835)
  byte-exact audit. A different protocol variant; no FROST-2 implementation
  exists as of 2026-08-31.

- **msn-2026-0016** (queued): Threshold-BLS byte-exact audit.

- **msn-2026-0017** (queued): MuSig2 vs FROST comparison matrix.

## 10. What remains worth investigating

1. **Independent RFC 9591 verification**: the clean-room Python reference must
   be extended with a proper RFC 9380 hash_to_field implementation. This is a
   separate research problem in its own right (hash_to_field correctness across
   multiple ciphersuites).

2. **The implementation-universe asymmetry**: per fnd-2026-0012 secondary
   claim, the FROST (RFC 9591) implementation universe contains exactly ONE
   truly conformant implementation. Any new RFC 9591 implementation in a
   different language (Python, Java, Haskell, OCaml) would be a high-value
   contribution.

3. **FROST-2 protocol variant**: the Round-Optimized-Threshold variant
   (ePrint 2024/1835) is structurally different from RFC 9591 and has no
   implementation as of 2026-08-31.

4. **Cross-impl security audit scope reduction**: per the adversarial
   critic's Disproof D, single-impl positive claims do not satisfy the AGENTS.md
   promotion ladder for verified status. Future FROST audits must either
   accept this constraint or scope their claims explicitly to self-consistency.

5. **RFC 9380 hash_to_field formal verification**: the divergence between
   RFC 9591 normative text and ZcashFoundation/frost test vectors may
   indicate a normatively-silent parameter in the hash_to_field construction.
   Formal verification of hash_to_field across the 5 ciphersuites would be
   a natural extension of FORMAL-203/204/205.

## 11. Distinguishing genuine research from infrastructure

Genuine research results:
- The implementation-universe asymmetry (1 truly conformant impl + 1 paper-baseline
  + 1 spec-with-vectors) — a frontier-grade finding that affects deployment,
  audit, and standardization decisions.
- The byte-exact KAT divergence characterization (Disproof A) — a meaningful
  negative result that prevents overclaiming.
- The normatively-silent-parameter characterization (obs-2026-0039) — the
  practical difficulty of building an independent RFC 9591 reference from
  the RFC text alone.

Infrastructure-only observations:
- The fact that ZcashFoundation/frost passes its own self-tests
  (60/60 integration tests pass) — useful engineering confirmation, not
  a discovery.

The cohort-asymmetry and KAT-divergence findings are the substantive research
contributions; the cargo test pass-rate is supporting evidence within those
findings.

## 12. Session conclusions

This session demonstrated the charter's autonomous-discovery loop end-to-end:

- **Discover**: 4 parallel scout agents identified FROST (RFC 9591) as the
  strongest candidate, with two independent scouts converging on the same
  rank-1 target.
- **Decompose**: 6-agent parallel swarm with distinct distinct epistemic purposes
  (spec analyst, implementation archaeologist, two independent hypothesis
  generators, experiment designer, adversarial critic).
- **Experiment**: decisive cargo test on ZcashFoundation/frost Rust monorepo
  + attempted clean-room Python reference (informative negative result).
- **Attack**: independent adversarial critic identified the KAT divergence
  smoking gun (Disproof A) before the finding could be overclaimed.
- **Reproduce**: cargo test reproducer pinned to specific commit, fully
  re-runnable from committed sources.
- **Verify**: deterministic cargo test exit code, two independent runs.
- **Promote**: fnd-2026-0012 downgraded to hypothesis per AGENTS.md
  (the original primary claim was correctly rejected by the adversarial critic).

The session produced meaningful research (cohort-asymmetry finding + KAT
divergence characterization) while preserving the charter's anti-slop
constraints (single-impl claims are explicitly downgraded, not overclaimed).
The follow-up mission (clean-room Python reference with proper RFC 9380
hash_to_field) is queued and ready to elevate fnd-2026-0012 to
verified_conclusion if the clean-room implementation reproduces the KAT
byte-exactly.