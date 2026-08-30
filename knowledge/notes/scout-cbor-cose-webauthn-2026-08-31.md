---
id: scout-cbor-cose-webauthn-2026-08-31
type: scout-note
created_at: "2026-08-31T10:00:00Z"
updated_at: "2026-08-31T10:00:00Z"
provenance:
  created_by:
    kind: model-agent
    role: orchestrator-synthesizer
    model: minimax-m3
    tool: "synthesizing 6 parallel scout reports"
related_artifacts:
  - tgt-2026-0005
  - spc-2026-0004
---

# Scout synthesis 2026-08-31 - Selection of CBOR/COSE canonical-encoding audit

## Background

Six parallel scout agents were commissioned at the start of the
2026-08-31 autonomous research shift, each scouting one candidate
research territory outside Frontier's prior PQC/KEM coverage:

1. **CBOR/COSE/WebAuthn canonical-encoding conformance** across
   independent libraries (Rust ciborium, Go fxamacker, Python cbor2,
   Java jackson, Java upokecenter, JS cbor-x, C tinycbor, Haskell
   cborg, OCaml ocaml-cbor, Erlang cbor-erlang).
2. **QUIC v2 / RFC 9000 §8 Retry token replay/validation** across
   picoquic, msquic, ngtcp2, Chromium QUICHE, Cloudflare quiche-Rust,
   OpenSSL QUIC.
3. **X.509 / RFC 5280 path validation edge cases** across Go
   crypto/x509, OpenSSL, BoringSSL, RustCrypto webpki, Mozilla NSS.
4. **C23 `_BitInt(N)` cross-vendor conformance** across GCC, Clang,
   MSVC.
5. **DNS resolver behavior on malformed DNSSEC records** across
   Unbound, BIND9, Knot Resolver, systemd-resolved, PowerDNS
   Recursor, dnsmasq.
6. **WebAuthn / FIDO2 attestation statement verification** across
   go-webauthn, webauthn-rs, py_webauthn, SimpleWebAuthn,
   webauthn-server-core.

## Frontier economic test criteria applied

Per the charter: prefer problems where the dominant bottleneck is
reasoning, search, specification interpretation, implementation
archaeology, hypothesis generation, mathematical exploration, proof
strategy, adversarial analysis, or test design, while the actual
physical or formal experiment is small enough to run on ordinary
CPUs, a small number of cloud runners, a deterministic formal
kernel, or a modest controlled environment.

Applied rubric (1-5 scale per criterion, higher = better fit):

| Criterion                              | CBOR/COSE | QUIC Retry | X.509 Path Val | C23 _BitInt | DNS/DNSSEC | WebAuthn Attest |
|----------------------------------------|-----------|------------|----------------|-------------|------------|------------------|
| Intellectual difficulty               | 5         | 4          | 5              | 4           | 4          | 5                |
| Reasoning/search burden                | 5         | 4          | 5              | 5           | 4          | 5                |
| Independence of evidence available     | 5         | 5          | 5              | 5           | 5          | 5                |
| Verification strength                  | 5         | 4          | 5              | 5           | 4          | 4                |
| Physical compute requirement           | 5         | 3          | 5              | 4           | 5          | 5                |
| Reproducibility                        | 5         | 4          | 5              | 5           | 4          | 4                |
| Technical significance                | 4         | 4          | 5              | 3           | 4          | 4                |
| Novelty potential                      | 5         | 5          | 5              | 4           | 5          | 5                |
| Public artifact quality                | 5         | 4          | 5              | 4           | 4          | 4                |
| Prior art coverage                     | 4         | 3          | 3              | 3           | 3          | 3                |
| Durability of product                  | 5         | 4          | 5              | 4           | 4          | 4                |
| **Total (out of 55)**                  | **53**    | **46**     | **53**         | **46**      | **46**     | **48**           |

## Selection rationale

**Selected: CBOR/COSE canonical-encoding conformance audit** (tgt-2026-0005).

**Rejected alternatives and why:**

- **X.509 path validation** (also scored 53): equal score, but
  the search space is much larger (~80 hours of analyst time per
  scout estimate), and the disclosure surface is more complex
  (security-advisory class). It is a worthy follow-up mission but
  requires its own dedicated budget cycle. CBOR is the *smaller*,
  *more contained* deliverable that can complete in one mission.
- **WebAuthn attestation** (scored 48): good target but overlaps
  with CBOR/COSE (the underlying encoding layer). If the CBOR/COSE
  audit surfaces a finding in the CBOR-of-attestation-object
  surface, that finding naturally feeds a follow-up WebAuthn
  attestation mission. CBOR is the *root cause* layer; WebAuthn
  is the *application layer*. Per the "root cause first" principle,
  CBOR is the right primary target.
- **QUIC Retry token** (scored 46): strong target, but requires
  ~5 mission-weeks per scout estimate and significant build
  infrastructure for 6 implementations. Defer to follow-up.
- **C23 _BitInt** (scored 46): strong target, but env capability
  gap (fnd-2026-0011) is a real blocker. Defer.
- **DNS/DNSSEC** (scored 46): strong target, but scope is broader
  than appears (algorithm13/14/15/16 rollout + draft ML-DSA-44/65
  is its own research problem). Defer.

## Mission plan

The selected target decomposes into one primary mission + (up to 4)
follow-up missions:

**Primary: msn-2026-0015 - CBOR §4.2 deterministic-encoding
cross-implementation conformance matrix.**

Sub-components (all executable within one mission budget):
1. Normative cleanroom Python oracle implementing RFC 8949 §4.2
   (deterministic mode + canonical mode separately).
2. Adversarial vector generator (CDDL-synthesized inputs targeting
   each audit axis in spc-2026-0004).
3. Per-implementation adapter layer: 10 libraries.
4. Matrix runner: produce TSV of (library × vector × expected ×
   actual × verdict).
5. cbor.me reference diagnostic integration for any diverging
   cell.
6. Adversarial critic review of every positive finding.

**Follow-ups (queued, not auto-activated):**
- msn-2026-0016 (pending): COSE RFC 8152/9052 message-encoding
  conformance (Sign1, Mac0, Encrypt0, etc.) using the same matrix
  machinery.
- msn-2026-0017 (pending): WebAuthn authenticator-data byte-level
  conformance using the same matrix machinery.
- msn-2026-0018 (pending): X.509 path validation edge-case audit
  (deferred from this session due to scope).
- msn-2026-0019 (pending): QUIC Retry token validation (deferred
  from this session due to scope).

## Anti-slop considerations

- CBOR/COSE was selected NOT because it is novel-sounding but
  because it has a concrete, reproducible experiment design and
  multiple distinct lineages with high independence.
- The intellectual:physical compute ratio (~95:5) is the actual
  selection criterion; novelty was secondary.
- Mission budget: max_attempts=4, max_compute_runs=4,
  max_independent_reviews=2, diminishing_returns_window=2,
  max_auto_descendants=1. Strict, not loose.

## Expected terminal outcomes

Three plausible terminal states (per AGENTS.md state machine):

1. **Verified finding** (`fnd-2026-XXXX` promoted to
   `verified_conclusion`): one or more reproducible cross-impl
   divergences in deterministic encoding with full evidence chain.
2. **Inconclusive-after-budget**: all implementations agree on all
   cells (acceptable negative result; documents that RFC 8949 §4.2
   conformance is uniform across the audited cohort).
3. **Superseded**: a finding emerges that is more naturally classified
   as COSE/WebAuthn-layer (handled by follow-up mission).

Any of these is a durable outcome. None requires over-claiming.

## Note on this scout

This scout note is preserved as `knowledge/notes/scout-cbor-cose-webauthn-2026-08-31.md`
and cross-referenced by `tgt-2026-0005.yaml` and `spc-2026-0004.yaml`.
The six underlying scout reports are not committed in their full
form (they are LLM outputs and would clutter the durable
repository); their conclusions are absorbed into this synthesis.