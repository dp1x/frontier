<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: deepresearch_mlkem_pre_disclosure.md -->

# Deep-research request: pre-disclosure verification for cross-implementation ML-KEM input-validation claims

**This prompt is self-contained and contains no local file paths, IDs, or repository
references. It does not assume access to any prior conversation, codebase, or dataset.**

---

## Why you are being asked

A family of security findings in a standards-conformance audit has reached a
"verified, ready to disclose" state without ever re-checking its own citations
against primary sources. Two of those findings turned out to be materially wrong
in ways that survived every internal review gate:

- One quoted, as a normative sentence, a requirement **that does not appear in
  the specification it attributed it to**. The quoted sentence existed in a
  *different* specification and had been spliced into the attribution. It
  survived two rounds of internal correction and a formal promotion.
- One asserted that a widely deployed implementation "does not perform a required
  input check", citing a source location that was **one layer of abstraction too
  high**. The check it claimed was absent existed, in a vendored dependency one
  call-frame below the cited function. The finding had been marked
  "publicly disclosable" for roughly a month.

A third finding's supporting **empirical** evidence (a log excerpt asserting
that execution reached a certain point) **contradicted its own source-code
reading**, and nobody noticed.

The common failure is not bad reasoning. It is that **nobody re-fetched the
cited sources before declaring the claim verified.** Your task is to establish,
for the claims below, what is actually true — and to be as useful by
refuting them as by confirming them.

---

## Background you need (stated as fact, to be verified by you)

- **FIPS 203** (NIST, final 2024-08-13) §7.2 specifies an *encapsulation key
  check* to be performed before `ML-KEM.Encaps` runs on an externally supplied
  key. It has two halves:
  1. **Type/length check**: the key must be exactly `384k + 32` bytes.
  2. **Modulus check**: `ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k]`,
     which fails exactly when some decoded coefficient is `>= q`, with `q = 3329`
     (12-bit lanes can hold values up to 4095, so 3329..4095 are non-canonical).

  FIPS 203 §7.2 allows the check to be performed somewhere other than the
  encapsulating party, citing NIST SP 800-227 §3.2 (final 2025-09-18).

- Real implementations are believed to place this check at **three structurally
  different points**: nowhere at all; inside the encapsulation routine; or at
  key-import time. The claims below assert specific placements for specific
  libraries.

---

## Questions

Answer each with **primary sources only** (official repositories at pinned
commits/tags, official specifications, official issue trackers). Model memory is
not a source. If you cannot reach a source, say `COULD NOT FETCH` and move on —
a gap is a useful result, a fabrication is not.

### 1. Ground truth on the specification text

Quote **verbatim**, with exact section numbers and URLs:

- FIPS 203 §7.2, both the length half and the modulus half.
- Any normative text stating *where* the check must occur, and whether deferral
  is permitted.

Then answer precisely: **is the check mandatory, deferrable to the caller, or
both?** Quote the sentence that decides it.

### 2. Per-implementation verification

For **each** library below, determine where the §7.2 check actually occurs, by
reading source at a **pinned version or commit** — not documentation summaries,
not blog posts, not the project's own claims about itself.

For each, report:
- the pinned version/commit you read, and the URL;
- whether the length half, the modulus half, both, or neither is enforced;
- the **exact file and line** where enforcement (or its absence) occurs;
- what happens on a **non-canonical key that is otherwise well-formed**: does the
  API return an error, silently reduce/canonicalize, or proceed? This
  distinction matters enormously and is frequently reported wrongly.
- whether the public API makes bypass **structurally possible** (e.g. a
  fixed-size array parameter with no length argument).

Libraries to check:

| Library | Language | Claimed placement to verify |
|---|---|---|
| PQClean (ML-KEM) | C | **no check anywhere** |
| mlkem-native (PQ Code Package) | C | **inside Encaps** |
| liboqs | C | **inside Encaps** (inherits from mlkem-native?) |
| OpenSSL 3.5.x | C | **at key import** |
| Go standard library `crypto/mlkem` | Go | **at key parse/import** |
| RustCrypto `ml-kem` | Rust | **at key import** |
| .NET (`System.Security.Cryptography`, ML-KEM) | C# | **at import, CNG backing** |
| libcrux (CrySPEN) | Rust/C | **a separate `validate_public_key` call exists** |

### 3. The abstraction-layer trap

For at least three libraries, deliberately trace the call path **from the
high-level API down to the leaf primitive** (e.g. from a TLS or KEX handshake
entry point, through the wrapper, into the KEM).

Report for each: **at which layer does validation actually happen?**

This question exists because a prior audit concluded "no check is performed"
after reading a *key-exchange wrapper* whose KEM callee did in fact validate.
Explicitly flag any implementation where a *wrapper* performs no check but a
*callee* does — that pattern is the single most common source of a false
"missing check" claim in this area.

### 4. Cross-API variance within a single library

For OpenSSL 3.5.x specifically: compare the paths by which an ML-KEM public key
can enter the library — DER/`SPKI` (`d2i_PUBKEY`) versus raw octets
(`EVP_PKEY_new_raw_public_key_ex`) — and versus .NET's entry points.

- Do they differ in strictness? If so, exactly how, with source citations?
- If a malformed key is accepted on one path, **trace forward**: does
  encapsulation subsequently succeed, and is the resulting shared secret
  identical to what a canonical key would produce?
- This matters because "accepted" and "exploitable" are different claims, and
  conflating them is a common overstatement.

### 5. Novelty — mandatory before any report

For each finding you confirm as a genuine deviation:

- Search the upstream project's issues, pull requests, release notes, and commit
  history for an **existing** report or fix.
- Report exact issue/PR numbers, URLs, state (open/closed/merged), and dates.
- **If there are no hits, say "searched and absent" and list the exact queries
  and sources you searched.** A confirmed absence is a valuable result; do not
  soften it into "I could not find" — be precise about which.
- If an issue exists, this is **not novel** and must be labelled as such.

### 6. Downstream protocols that mandate the check

Determine which IETF Internet-Drafts **normatively require** the check at a
protocol layer, and quote the exact sentences:

- TLS hybrid post-quantum key exchange (e.g. `draft-ietf-tls-ecdhe-mlkem`, and
  its successors; also X-Wing-based KEMs).
- SSH hybrid post-quantum key exchange (`draft-ietf-sshm-mlkem-hybrid-kex`, and
  the NTRU Prime variant `draft-ietf-sshm-ntruprime-ssh`).
- HPKE with post-quantum KEMs.
- IKEv2 multiple-key-exchange extensions.

Note carefully: for **NTRU Prime**, determine whether an equivalent
"modulus/coefficient range check" mandate **exists at all**, or whether that
standard simply has no analogue of FIPS 203 §7.2. If no analogue exists, say so
plainly — it would mean any "missing check" claim for that KEM is unfounded.

### 7. Structured NTRU Prime specifics

For `sntrup761` as used in SSH:
- Identify the reference implementation OpenSSH derives it from.
- Determine whether its public-key decode routine **silently reduces
  out-of-range coefficients** rather than rejecting.
- If it does, is that considered conformant, or a deviation? Cite whatever
  normative text governs the KEM's own input handling.

---

## Output requirements

- Every claim carries a **primary-source URL** you actually fetched, plus the
  pinned version/commit or section number.
- Label each item: `normative text` / `implementation source` / `maintainer
  statement` / `third-party analysis` / `inference` / `COULD NOT DETERMINE`.
  Inferences must be explicitly marked and must not be presented as fact.
- Include **raw code snippets with file paths and line numbers** for any claim
  about implementation internals.
- Produce **three explicit buckets**: *confirmed found* / *searched and absent*
  / *could not determine*.
- **List your negative results explicitly** — what you looked for and did not
  find is as valuable as what you found, and it is what prevents a false
  novelty claim.
- Where two sources disagree, say so and present both. Do not silently pick one.

## Explicit non-goals

- Do **not** assess exploitability, assign severity, or claim a vulnerability
  exists. Input-validation placement is a conformance question; whether it is
  *security-relevant* is a separate analysis that needs a threat model.
- Do **not** contact maintainers, open issues, or file anything. This is a
  report-only task; a human decides what is sent and to whom.
- Do **not** assert novelty without the searches in Question 5 actually run.
- Do **not** fabricate URLs, issue numbers, line numbers, dates, or version
  strings. An honest `COULD NOT FETCH` is worth more than a confident guess.
- If a claim turns out to be **already fixed upstream**, report that — a
  withdrawn finding is a valuable output, not a failed one.

## The single most important instruction

If your investigation concludes that something widely reported as a defect is
**not** a defect, say so directly and show the source that proves it. A refutation
with citations is a complete success for this task. Do not confirm a claim
merely because it is plausible, widely repeated, or consistent with the framing
of this request — this request deliberately presents claims in order to test
them, not to ratify them.
