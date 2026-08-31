---
id: scout-formal-proof-assistants-2026-08-31
type: scout-note
title: "SCOUT-2026-08-31 - Formal proof assistants (Lean 4, Rocq, F*, Agda, Idris 2, Isabelle) as a Frontier research direction"
created_at: "2026-08-31T22:00:00Z"
updated_at: "2026-08-31T22:00:00Z"
author_role: research-scout
status: candidate (read-only; not promoted to mission)
related:
  - msn-2026-0003 (FORMAL-203)
  - msn-2026-0006 (FORMAL-204)
  - msn-2026-0007 (FORMAL-205)
  - prf-2026-0001
  - prf-2026-0002
  - prf-2026-0003
  - tgt-2026-0001
  - spc-2026-0001
  - vrf-2026-0007
tags: [formal-verification, lean4, coq, rocq, fstar, agda, idris2, isabelle, hacl-star, everest, fiat-crypto, mitls, ml-kem, blake3, ed25519, hkdf, merkle, cbor, frontier-economic-test]
---

# SCOUT-2026-08-31 — Formal proof assistants as a Frontier research direction

## 1. Headline

Frontier already has a small, working Lean 4 formal track (`formal/`
directory, three completed missions FORMAL-203 / 204 / 205, kernel-checked
on `leanprover/lean4:v4.22.0` with 0 sorries and a stable axiom inventory
limited to `{propext, Classical.choice, Quot.sound}` — see
`knowledge/verifications/vrf-2026-0007.yaml`). The question this scout
investigates is: **what is the next well-scoped problem for that track, and
should Frontier broaden the track to other proof assistants (Rocq, F*,
Agda, Idris 2, Isabelle)?**

The motivating observation is that the FIPS 203 §7.2 mission series was
small enough that an experienced agent could complete each kernel-checked
artifact in a few hours, and the Frontier economic test (dominant
reasoning / search burden, tiny physical compute, deterministic
verifier, automatic reproducibility) is *unusually* well-satisfied by
formalization: the trusted kernel is the single source of truth and the
proof is byte-for-byte re-verifiable.

This scout maps the landscape, surveys prior art, and proposes a small
menu of candidate problems with explicit compute estimates and risk
profiles. It is **read-only**: no mission is commissioned, no artifact
is created beyond this note.

## 2. Landscape

### 2.1 Lean 4 + mathlib4

- **Status**: Open source (Apache 2.0), developed primarily by
  Microsoft Research and the Lean community. Lean 4 is self-hosted
  (the Lean 4 compiler is written in Lean 4).
- **Toolchain**: `leanprover/lean4` versions. Frontier pins
  `leanprover/lean4:v4.22.0` (commit `ba2cbbf09d4978f416e0ebd1fceeebc2c4138c05`).
  Elan is the version manager.
- **mathlib4**: continuous development on `master`, tagged against Lean
  4 releases. Size is roughly **>1.5–2 million lines of Lean source**
  (growing), thousands of `.lean` files, **~10⁵+ declarations**, with
  the `.lake` cache measured in hundreds of MB–GB. mathlib4 is the
  largest open formalization of mathematics and is the successor to
  the Lean 3 mathlib.
- **Build mechanics**: `lake new` + `lake build`. A small standalone
  proof (no mathlib) builds in seconds. A mathlib-dependent proof has
  a one-time clone-and-cache cost; subsequent `lake build` of a small
  file is seconds-to-tens-of-seconds when the cache is warm.
- **Crypto state**: Lean 4 is the newest of the three major
  proof-assistants used for verified crypto. mathlib4 has elliptic-curve
  (Weierstrass) theory and finite fields. There is **no publicly
  shipped full Ed25519 / SHA-2 / SHA-3 / ChaCha20 / BLAKE3 verified
  implementation in Lean 4** comparable to HACL* or Fiat-Crypto; the
  Lean 4 ecosystem is well-suited for spec-level work and
  proofs-of-correctness, but extraction to production-grade constant-
  time C is less mature than F* or Fiat-Crypto.
- **Frontier-specific note**: Frontier's existing `formal/` directory
  already runs Lean 4 + mathlib4 natively on **Windows** via
  `lake build` (see `formal/build_output.log`,
  `formal/build_output_r2.log`, `formal/build_output_r3.log`). This
  removes the WSL detour that is otherwise commonly recommended on
  Windows for Lean 4.

### 2.2 Coq → Rocq

- **Status**: Mature, INRIA-led, open source (LGPL 2.1). The project
  was renamed from **Coq to Rocq** in 2024 (pronounced /ʁɔk/, "rock")
  to address pronunciation/SEO problems with the original name; the
  rebrand references the original Rocquencourt Inria site. Existing
  Coq developments, papers, and tools remain valid; the core system
  and ecosystem continue under the new name. URLs are in transition
  toward `roc-prover.org`.
- **Ecosystem**: ssreflect, MathComp (Mathematical Components),
  CompCert (verified C compiler), VST (Verified Software Toolchain,
  used with Fiat-Crypto), Fiat-Crypto itself, CoqEAL, GeoCoq.
- **Crypto state**: Fiat-Crypto is the headline crypto artifact:
  Coq-based *synthesis* of high-performance, constant-time elliptic-
  curve arithmetic (Curve25519, P-256, etc.), with proofs that the
  generated C matches a high-level group/field spec. Generated code
  is in production use (e.g., BoringSSL). Bedrock / Bedrock2 is the
  surrounding Coq framework for low-level systems code.
- **Windows reality**: Rocq install on Windows is non-trivial. Coq's
  typical install path is Linux/macOS first; Windows requires either
  WSL, Cygwin, or a hand-rolled OPAM setup. This makes Rocq a
  **second-class citizen on the Frontier host** unless the team
  accepts WSL.

### 2.3 F* (F-star)

- **Status**: Microsoft Research / Inria, open source (Apache 2.0).
  Dependent types + refinement types + SMT (Z3). Designed for verified
  *programming* with extraction to efficient C/WASM/assembly.
- **Ecosystem**: Low\* (C-like imperative subset), Karamel (formerly
  Kremlin, the C/WASM/assembly extractor), Vale (for verified
  assembly), EverCrypt (verified crypto provider aggregator).
- **Crypto state — the canonical success story**: **Project Everest**
  (Microsoft Research + Inria + collaborators). Everest has produced:
  - **HACL\***: a verified modern cryptographic library in F\* covering
    ChaCha20, Poly1305, AES-GCM, SHA-2 family, HMAC, HKDF,
    Curve25519, Ed25519, with proofs of functional correctness,
    memory safety, and secret-independence (constant-time). Extracted
    to C; in production use (Mozilla NSS/Firefox, Linux kernel
    components, Tezos, WireGuard, Windows components). Foundational
    paper: *HACL\*: A Verified Modern Cryptographic Library* (CCS 2017).
  - **miTLS**: a formally verified TLS 1.2/1.3 reference implementation
    in F\*. Papers include the IEEE S&P 2017 *Implementing and Proving
    the TLS 1.3 Record Layer*. Used as a high-assurance reference and
    for interop testing of other stacks.
  - **EverCrypt**: a verified crypto provider that aggregates F\*
    verified code and (where needed) Vale-verified assembly.
  - **Vale**: verified assembly with constant-time and side-channel
    guarantees for performance-critical inner loops (AES-NI, SHA-NI,
    carry-less multiplication for Poly1305/GCM).
- **Windows reality**: F\* builds on Windows but is significantly more
  painful than on Linux; the typical Frontier-compatible path is WSL.
  Toolchain size is moderate (an F\* + Karamel + Z3 stack).

### 2.4 Agda

- **Status**: Chalmers / University of Gothenburg, open source
  (BSD-like). Pure dependently typed functional language with strong
  interactive proving; extracts to Haskell.
- **Ecosystem**: Standard library, cubical extensions, the
  *Programming Language Foundations in Agda* / *Verified Functional
  Programming in Agda* libraries.
- **Crypto state**: Less of a dedicated crypto library ecosystem than
  F*/Coq. Strong for **algebraic / number-theoretic foundations**
  that crypto relies on (groups, rings, fields, lattices, category-
  theoretic structure). Computational / game-based security proofs are
  rarer in Agda than in EasyCrypt, CryptoVerif, or F\*; Agda shines
  on "this code does exactly what the spec says."

### 2.5 Idris 2

- **Status**: Open source. Successor to Idris 1, redesigned with a
  more principled totality and erasure story, compilation to C, JS,
  and other backends. Edwin Brady's *Type-Driven Development with
  Idris* remains the standard text.
- **Crypto state**: Less dedicated crypto infrastructure than F*/Coq,
  but the C backend and totality story make Idris 2 attractive for
  "write a verified implementation, extract to C, ship it." Suitable
  for small, self-contained primitives where extraction quality and
  constant-time properties can be argued at the type level.

### 2.6 Isabelle / Isabelle-HOL

- **Status**: Cambridge (Larry Paulson et al.) / TU Munich, open
  source. Higher-order logic (not dependently typed) with powerful
  structured proof language (Isar), `sledgehammer`, and the
  Archive of Formal Proofs (AFP).
- **Install**: **There is no official Debian/Ubuntu package** for
  Isabelle; the recommended path on Linux is the official tarball
  from `https://isabelle.in.tum.de/`. On Arch, the AUR package
  `isabelle` is the community-supported path. Windows install is
  not officially supported and typically goes through WSL.
- **Crypto state**: Some security work in AFP, but Isabelle is
  markedly less used for crypto verification than F\* / Coq /
  Lean 4. Its strength is higher-order logic mathematics (including
  big proofs in analysis, set theory, formalized mathematics).

### 2.7 Specialised tools worth mentioning

- **EasyCrypt** (IMDEA): interactive proof assistant with a
  probabilistic relational Hoare logic (pRHL), SMT-backed. Designed
  specifically for game-based computational security proofs. Used
  for primitives and for hybrids with Jasmin, Vale, etc.
- **CryptoVerif** (Bruno Blanchet, Inria): *automatic* (or
  semi-automatic) computational-security prover for protocols,
  search-based game hopping. Complementary to ProVerif (symbolic).
- **Jasmin** (Inria / ENS): verified assembly with EasyCrypt or Coq
  proofs; used for high-assurance, high-perf primitives (Ed25519,
  X25519, Kyber-style PQ).
- **Dafny** (Microsoft Research): auto-active verifier, used in
  Ironclad / IronFleet for distributed systems; less common for crypto
  but some primitives exist.

## 3. Tractable scope for a Frontier mission

The economic test Frontier applies is: dominant burden is reasoning /
search / specification / proof strategy, while the *physical or formal
experiment* runs on commodity compute with a deterministic verifier
and automatic reproducibility.

Formalization is the cleanest possible fit for this test. The trusted
kernel is the single source of truth; the proof is byte-for-byte
re-verifiable from the source; no test-orchestration matrix is needed
because the kernel itself is the oracle.

### 3.1 Candidate problem menu (small, 1-4 h proof budget)

For each, the budget assumes an experienced agent, an existing
mathlib4 / library footprint, and no fresh math.

#### 3.1.1 Merkle inclusion path: completeness and soundness

- **What**: Inductive `mtree` (data) and `htree` (hash), an abstract
  `combine : Hash -> Hash -> Hash`, a `mcompute` fold over a list of
  `(sibling_hash, direction)` steps, `mverify d p root` defined as
  `mcompute (hash_leaf d) p = root`, and the two structural lemmas
  **completeness** (every genuine leaf has a verifying path) and
  **soundness** (a verifying path yields a hash-tree whose root
  matches and that contains the leaf hash).
- **Why tractable**: pure structural induction on lists and trees; no
  field arithmetic, no bit-bashing, no probabilistic arguments. The
  proof is roughly the example shown in §5 below; it ports almost
  verbatim to Lean 4 with `inductive`, `def`, `theorem ... by
  induction ...`.
- **Compute**: small standalone Lean 4 project, no mathlib required.
  `lake build` seconds.
- **Novelty vs. prior art**: Coq versions of this exist in teaching
  materials (and are well-known). A clean Lean 4 / mathlib4
  presentation would be a small reusable artifact. **Not high
  novelty, but clean.**
- **Frontier value**: *the proof strategy + spec-vs-impl gap analysis
  for a Merkle inclusion path is a real intellectual deliverable*
  (e.g., RFC 9162 Certificate Transparency / RFC 6962 OCSP / Bitcoin
  SPV all use this exact pattern; the same completeness/soundness
  argument is the formal backbone of a verifiable log).

#### 3.1.2 CBOR §4.2.3 length-first sort: correctness

- **What**: RFC 8949 §4.2.1 specifies that in canonical CBOR, map
  keys are sorted by length-then-bytes. §4.2.3 elaborates the
  "length-first" total order: shorter key bytes sort before longer,
  ties broken by lexicographic byte order. The formal claim is that
  this is a strict total order on a key set, and that the sort
  produces a stable permutation with no byte-level ties lost.
- **Why tractable**: well-defined total order over `ByteArray`;
  straightforward induction on lists.
- **Frontier value**: ties directly into the existing CBOR/COSE
  target (`tgt-2026-0005`, msn-2026-0015) — a formal statement of
  what the existing differential audit *expects* would be a strong
  complementary artifact. **High synergy, medium novelty** (some
  academic formalizations exist, but the Lean 4 + RFC 8949 pairing
  is unusual).
- **Compute**: small standalone Lean 4; no mathlib; seconds.

#### 3.1.3 HKDF-Expand correctness (RFC 5869)

- **What**: `HKDF-Expand(PRK, info, L) = T(1) || T(2) || ... || T(N)`
  where `T(i) = HMAC(PRK, T(i-1) || info || [i])`. Formal claim:
  the function is well-defined, total, has the byte-length property
  `|OKM| = L`, and the iteration terminates with the correct
  truncation.
- **Why tractable**: HMAC + SHA-256/-384/-512 are themselves the
  larger formalization hurdle. For a *spec-level* proof (no
  production extraction), the iteration property is a short
  induction on `Nat`.
- **Prior art**: HACL*'s HKDF implementation is verified in F\*. The
  Lean 4 version would not aim to compete on extraction quality;
  the intellectual deliverable is the spec-vs-impl gap and the
  HKDF §2.3 information-theoretic argument that the output is a
  PRF under PRK-distribution assumptions.
- **Frontier value**: medium. **Not first-mover territory**; clean
  educational / reusable artifact.

#### 3.1.4 SHA-256 / SHA-512 compression function in Lean

- **What**: The compression function `Compress(H, M) -> H'` per
  FIPS 180-4 §6.2.2 / §6.4.2. Formal claim: `compress` is a
  pure function of the 8-word working state and 16-word message
  block, with the exact 64-round / 80-round step definition.
- **Why tractable**: the function is *large* (bit-bashing,
  `Sigma_0`, `Sigma_1`, `Ch`, `Maj`, `ROTR` over 32- or 64-bit
  words) but not deep. Proof effort: a few hundred lines of
  Lean to express the spec correctly and prove it type-checks.
  A *reference oracle* against RFC test vectors would require
  extracting and running, which is out of scope for a Lean-only
  mission.
- **Frontier value**: a Lean 4 spec-only SHA-256 compression is
  **a clean reusable artifact**, but it does not replace a
  production implementation. Worth doing as a stepping stone to
  HKDF, HMAC, Ed25519.
- **Compute**: small mathlib-dependent Lean 4 build; tens of
  seconds.

#### 3.1.5 Ed25519 signature *verification* in Lean / F*

- **What**: Per RFC 8032 §5.1.7 step 1-6, the verifier checks:
  reject if `S` out of range, decode `A` and `R` as curve points,
  reject if invalid or small-order, compute
  `h = SHA-512(R || A || M) mod L`, accept iff `[S]B = R + [h]A`.
- **Why tractable at the spec level**: it's a short spec once the
  curve, group law, and SHA-512 are available. mathlib4 has
  Weierstrass curve theory; some Edwards curve material exists;
  field arithmetic for `p = 2^255 - 19` is available. **A
  spec-level `ed25519Verify` that calls mathlib4 abstractions
  and proves the RFC 8032 acceptance condition is achievable
  in a few hours of agent work.**
- **Why it would NOT be tractable at the implementation level**:
  verified constant-time scalar multiplication over `GF(2^255-19)`
  with full extraction is **thousands of lines and multi-person-
  year**; HACL*, Jasmin, and Fiat-Crypto already do it. Frontier
  cannot beat that in scope.
- **Frontier value**: medium. The gap analysis is interesting
  (which Ed25519 variants? per-implementation quirks around the
  cofactor check? "strict" vs "non-strict" decode?). But the
  "spec-level" result has been formalized before.

#### 3.1.6 BLAKE3 compression function

- **What**: BLAKE3 = BLAKE2s-derived compression (7 rounds,
  32-bit words, 16-word state), then a binary tree of parent
  compressions. A spec-only Lean 4 formalization of the
  compression function + a paper-vs-ref test-vector check is
  achievable.
- **Status**: there is **no widely-used complete Lean 4 / Coq
  formalization of BLAKE3** as of 2024-2025; HACL*/EverCrypt has
  BLAKE2 verified in F\*.
- **Frontier value**: **higher novelty than the Ed25519 case**
  precisely because the verified-artifact inventory for BLAKE3 is
  thinner. The intellectual work is the round-constant /
  permutation / flag encoding.

### 3.2 Problem categories that are *not* tractable in 1-4 h

- **Full HACL*-style constant-time C extraction** in F*: months,
  not hours. Out of scope for a single Frontier mission.
- **Fiat-Crypto-style synthesis** of field arithmetic: months to
  years. Out of scope.
- **FIPS 203 NTT, sampling, K-PKE.Encrypt/Decrypt functional
  correctness**: this is a follow-up to the existing
  FORMAL-203/204/205 track and is *non-trivial* — it's the
  natural next frontier mission for the Lean track, but not a
  single 1-4 h budget.
- **miTLS-style full TLS 1.3 handshake functional correctness**:
  multi-person-year. Out of scope.

## 4. Frontier value proposition for formalization

Restated from the request, with explicit evaluation against the
charter:

- **The trusted checker is the single source of truth.** This is
  *the* Frontier advantage: no human reviewer can be argued into
  accepting a proof the kernel rejects. Promotion to `verified`
  has a clear deterministic path (`frontier.validate` +
  `frontier.promotion` + adversarial review per AGENTS.md).
- **Reproducibility is automatic**: `lake build` (or `coqc`, or
  `fstar`, or `idris2 --check`) is the entire reproducibility
  story. No CI matrix, no environment replication.
- **Compute cost is small**: a Lean 4 / Coq / F\* / Idris 2
  verification of a small proof runs in seconds on the Frontier
  Windows host. Heavy proofs (large mathlib consumers) take
  longer but are still commodity compute. Per `localdocs/
compute.md`, this is the **lightweight** class — local, env-scrubbed
  scratch.
- **Intellectual work is exactly the Frontier sweet spot**: spec
  selection (which spec? which RFC section?), proof strategy
  (induction? reflection? tactic choice?), gap analysis (what
  does this *not* prove that the user thinks it proves?).
- **Honest negative results are first-class**: a failed proof
  attempt is preserved with status `rejected` / `disproved` /
  `inconclusive` per AGENTS.md, with the failed attempt as
  durable evidence. The Lean 4 mission series on FIPS 203 has
  already produced one or two such preserved intermediate states
  in the build logs.

### 4.1 Independence of evidence is structural

A formal proof does not depend on the implementing agent's
confidence, on inter-tool agreement, or on reviewer opinion. The
kernel either accepts the proof or it doesn't. This is the
strongest possible form of independence for a verification artifact.

### 4.2 Frontier's existing Lean 4 track is the natural base

- Frontier has `formal/` checked in.
- Lean 4 toolchain pin: `leanprover/lean4:v4.22.0`.
- mathlib4 dependency is already pulled via `lake-manifest.json`.
- Lake build logs (`formal/build_output*.log`) show reproducible
  successful builds on the Windows host.
- Three completed missions (FORMAL-203 / 204 / 205) and their
  verification records (`vrf-2026-0007.yaml` etc.) provide the
  exact pattern for a new formal mission.
- The `formalization-agent` role in `roles/README.md` is already
  named.

## 5. Existing relevant work (with URLs)

The scout lists prior art; nothing here is re-implemented or
duplicated by the proposed mission.

- **Project Everest**: <https://project-everest.github.io/>
- **HACL\***: <https://github.com/hacl-star/hacl-star>
  - *HACL\*: A Verified Modern Cryptographic Library*, Bhargavan
    et al., CCS 2017.
- **miTLS (TLS 1.2/1.3 in F\*)**:
  <https://github.com/project-everest/mitls-fstar>
  - *Implementing and Proving the TLS 1.3 Record Layer*,
    Bhargavan et al., IEEE S&P 2017.
- **EverCrypt** (verified crypto provider): in the Everest
  monorepo.
- **Vale** (verified assembly): in the Everest monorepo.
- **Fiat-Crypto**: <https://github.com/mit-plv/fiat-crypto>
- **Bedrock / Bedrock2**: <https://github.com/mit-plv/bedrock2>
- **Coq / Rocq** core: <https://rocq-prover.org/> (in transition
  from coq.inria.fr)
- **Lean 4**: <https://lean-lang.org/lean4/doc/setup.html>
- **mathlib4**: <https://github.com/leanprover-community/mathlib4>
- **F\***: <https://fstar-lang.org/>
- **Agda**: <https://wiki.portal.chalmers.se/agda/>
- **Idris 2**: <https://www.idris-lang.org/>
- **Isabelle**: <https://isabelle.in.tum.de/>
- **EasyCrypt**: <https://github.com/EasyCrypt/easycrypt>
- **CryptoVerif**: <https://github.com/INRIA/spasa/tree/master/
cryptoverif> (and Bruno Blanchet's Inria page)
- **Jasmin**: <https://github.com/jasmin-prover/jasmin>

## 6. Compute considerations

### 6.1 Lean 4 on Windows (Frontier host)

Already in production. `formal/lakefile.lean` declares the mathlib4
dependency at `v4.22.0`. `formal/lean-toolchain` pins the toolchain.
Build logs demonstrate reproducible success on the Frontier host.
**No new infrastructure required.**

For new agents not on Frontier's existing host, the typical Windows
install path is WSL2 + Elan + VS Code Remote-WSL. Native Windows
Elan exists but is rougher for mathlib cache.

### 6.2 Coq / Rocq on Windows

Not natively supported. Realistic paths:
- WSL2 with Rocq via OPAM (the upstream-supported path).
- Cygwin (community, slow-moving).

**Frontier would need to add WSL as an execution environment** if
it commits to Rocq. This is a non-trivial expansion of the
`localdocs/security.md` sandbox story; not recommended unless a
mission specifically requires Rocq.

### 6.3 F* on Windows

Native Windows build exists but is significantly more complex than
Lean 4 on Windows. Typical Frontier-compatible path is WSL2.
**WSL sandbox expansion would be required.**

### 6.4 Agda / Idris 2 on Windows

Both have native Windows installs; WSL is the smoother path for
large libraries. Agda's Haskell backend is the relevant one.
Idris 2 has a C backend.

### 6.5 Isabelle on Windows

No native support; WSL is the only realistic path on Frontier.

### 6.6 CI integration

- Lean 4: trivially integrates into GitHub Actions via
  `leanprover/lean4@v4.22.0` action or via `lake build`. The
  Frontier `formal/` directory is already laid out for this.
- Coq / F* / Isabelle: similarly trivial via apt + opam / fstar
  / Isabelle tarball installs in the workflow. But Windows runners
  would be the bottleneck; GitHub-hosted Linux runners are the
  default.

### 6.7 Verification time

For a small standalone proof (< 200 lines, no mathlib), `lake
build` is **seconds**. For mathlib-dependent proofs, the first
build is dominated by mathlib cache fetch (~hundreds of MB to a
few GB, then minutes-to-tens-of-minutes of warm cache). After
warm-up, per-edit rebuild is sub-second to a few seconds for
small files.

For F* proofs of similar size, `fstar.exe` invocation is similar
(seconds to tens of seconds per file). The Everest monorepo
demonstrates scale-up.

## 7. Risk assessment

| Risk dimension | Lean 4 (existing) | New Lean 4 mission | Rocq | F* | Agda / Idris 2 | Isabelle |
|---|---|---|---|---|---|---|
| Probability of completing a small proof in 1-4 h | High (proven track record) | **High** | Medium (Windows friction) | Medium (Windows + SMT friction) | Medium | Medium-High (not enough frontier) |
| Novelty vs. prior art | n/a | Low (Merkle / CBOR §4.2.3) to Medium (BLAKE3 spec) | Low (Fiat-Crypto dominates) | Low (Everest dominates) | Medium | Low (AFP already large) |
| Compute cost vs. research value | n/a | **Excellent** (lean, deterministic) | Good | Good (better extraction) | Good | Fair |
| "Easy" formalization with a real result? | n/a | **Yes — Merkle path completeness/soundness in Lean 4** is the cleanest choice; CBOR §4.2.3 length-first-sort is the second-cleanest and has highest synergy with the existing CBOR target. | Less compelling (Fiat-Crypto covers the obvious ground) | Less compelling (Everest covers the obvious ground) | Less compelling without an Idris 2 ecosystem anchor | Less compelling without an AFP anchor |

### 7.1 "Easy" formalizations that would be a real result

The single cleanest target is:

1. **Merkle inclusion path: completeness and soundness in Lean 4**
   (a small standalone Lean 4 proof, no mathlib, no Windows
   friction, the proof fits in < 200 lines, and the deliverable
   is a reusable component for any Frontier audit of a verifiable
   log, RFC 9162 CT, RFC 6962 OCSP, or Bitcoin SPV claim).

The second cleanest:

2. **CBOR §4.2.3 length-first sort correctness in Lean 4**,
   directly supporting `tgt-2026-0005`. This is "spec-of-the-spec
   the audit expects" — high synergy with active Frontier work,
   small standalone proof.

The third candidate is **BLAKE3 compression function in Lean 4**,
which is a *larger* deliverable (a few hundred lines) and where
the verified-artifact inventory is genuinely thinner. The novelty
case is real here.

### 7.2 What is **not** a good use of Frontier's formal track

- Re-implementing HACL\* / Fiat-Crypto scope. Out of scale.
- "Spec only" Ed25519 verification in Lean 4 unless tied to a
  specific implementation gap.
- Anything requiring WSL infrastructure that the team has not
  already budgeted.

## 8. Recommendations

The Frontier economic test passes cleanly for:

- **R1**: a small Lean 4 formalization of **Merkle inclusion path
  completeness and soundness** (best novelty-per-LOC among the
  smallest options; the cleanest "easy formalization with a real
  result").
- **R2**: a small Lean 4 formalization of **CBOR §4.2.3 length-
  first sort correctness**, complementary to msn-2026-0015
  (highest synergy with active work).
- **R3**: a Lean 4 spec of **BLAKE3 compression** as a stepping
  stone toward a future HKDF / HMAC / Ed25519 audit
  (highest novelty-per-LOC if the team accepts ~300 LOC of
  bit-bashing).

None of these should be commissioned in this scout note. The
decision of which (if any) to promote to a target and mission is
left to the orchestrator with a real budget proposal and an
adversarial reviewer attached.

**Frontier should NOT broaden its formal track to Rocq / F* /
Agda / Idris 2 / Isabelle** unless a specific mission requires
one of their unique capabilities (extraction quality for F*,
existing Coq developments for Rocq, etc.). The Windows / WSL
friction for these tools is real and the existing Lean 4 track
covers the dominant verification scenarios cheaply.

## 9. Honest disclosures / unknowns

- **Rocq ecosystem state**: I have not independently verified the
  current state of the `rocq-prover.org` migration or the exact
  Rocq release that ships the rename as the default package name.
  The Web search summary reports the 2024 rename but does not
  give a specific release number.
- **mathlib4 LOC count**: the cited ">1.5–2 million lines" figure
  is the community-reported range; exact numbers fluctuate as the
  library grows. This is not a Frontier-relevant precision
  question.
- **BLAKE3 in Lean 4**: I have not found a public Lean 4
  BLAKE3 formalization to cite. The BLAKE3 spec.md is
  authoritative and translatable; whether anyone has already done
  so is not verified by this scout.
- **Project Everest's current state in 2026-01+**: the cited CCS
  2017 paper and the GitHub repos are the durable artifacts; live
  state of HACL\* / EverCrypt / miTLS in 2026 is not independently
  re-verified here.
- **Windows install ergonomics for F\* / Rocq / Isabelle**: the
  Web sources describe the typical WSL path. Whether Frontier's
  specific Windows host can support these without further
  sandbox work has not been tested by this scout.
- **No Frontier knowledge has been fabricated or assumed**;
  citations are to publicly known projects. No standards numbers,
  CVE ids, or result statuses have been invented.

## 10. Anti-slop notes

- This scout does **not** commission a mission. It is a read-only
  research note.
- It does **not** recommend expanding agent count, token count,
  or commit count. The recommended missions (if any) are small.
- It does **not** over-claim novelty. The Merkle inclusion path
  proof is well-known in Coq pedagogy; the value is the Lean 4
  presentation and Frontier reuse, not "we invented it."
- The negative results (Rocq / F\* / Agda / Idris 2 / Isabelle
  are *not* recommended as new Frontier tracks) are stated
  directly, not buried.
- The "honest disclosures" section is real: the scout is honest
  about what was not verified.

---

# Appendix: Sketch of the Merkle inclusion path Lean 4 / Coq proof

For the reader's benefit and as the natural starting point of any
follow-up mission, the structural argument is:

```coq
(* Abstract hash and combination. *)
Parameter Hash : Type.
Parameter hash_leaf : nat -> Hash.
Parameter combine : Hash -> Hash -> Hash.

(* Data-carrying tree. *)
Inductive mtree : Type :=
| mleaf : nat -> mtree
| mnode : mtree -> mtree -> mtree.

Fixpoint mroot (t : mtree) : Hash :=
  match t with
  | mleaf d => hash_leaf d
  | mnode l r => combine (mroot l) (mroot r)
  end.

Inductive direction := L | R.
Definition mpath := list (Hash * direction).

Fixpoint mcompute (h : Hash) (p : mpath) : Hash :=
  match p with
  | [] => h
  | (sib, L) :: p' => mcompute (combine sib h) p'
  | (sib, R) :: p' => mcompute (combine h sib) p'
  end.

Definition mverify (d : nat) (p : mpath) (rt : Hash) : Prop :=
  mcompute (hash_leaf d) p = rt.

(* mcompute_app, completeness (every leaf has a path), and soundness
   (a verifying path reconstructs a hash-tree containing the leaf)
   are straightforward inductions over mtree / mpath; the definitions
   port verbatim to Lean 4 with `inductive`, `def`, `theorem ... by
   induction`. *)
```

The complete proof (with the two main lemmas) is roughly 80-120
lines of Coq / Lean. This is the right size for a Frontier Lean 4
mission: small enough for a single agent, large enough to be a real
deliverable, and reusable across any audit that involves a
verifiable log.

End of scout note.