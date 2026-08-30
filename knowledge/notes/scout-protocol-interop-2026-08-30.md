---
id: scout-protocol-interop-2026-08-30
type: research-note
title: "SCOUT-3 dossier - SSH hybrid KEM (ML-KEM + X25519) FIPS 203 s7.2 protocol-layer enforcement"
created_at: 2026-08-30T00:00:00Z
author_role: research-scout
scope: protocol-interoperability / standards-conformance
status: candidate (read-only; not promoted to mission)
related:
  - msn-2026-0005
  - msn-2026-0006
  - fnd-2026-0001
  - fnd-2026-0005
  - msn-2026-0008
  - msn-2026-0009
  - fnd-2026-0008
tags: [ssh, ml-kem, x25519, hybrid-kex, fips-203, section-7.2, kex, openssh, protocol-placement, interop]
---

# SCOUT-3 — Next protocol-interop research opportunity

## 1. Headline

**Does a deployed SSH server performing `mlkem768x25519-sha256` key exchange enforce FIPS 203 §7.2 encapsulation-key modulus check at the protocol boundary (as `draft-ietf-sshm-mlkem-hybrid-kex-10 §2.1` mandates) — and if not, what is the wire-level consequence?**

This is the natural, deliberately-bounded follow-up to msn-2026-0005 (TLS 1.3 X25519MLKEM768) and is the only remaining protocol-layer cohort msn-2026-0005 explicitly carved out as out-of-scope (`terminal_reason` of msn-2026-0005 lists "HPKE X-Wing, SSH hybrid KEX, OpenSSL+oqs-provider, OpenSSH"). It preserves the established matrix shape (loopback interop with deterministic tampered `pk` stimuli, alert / disconnect mapping) while opening a structurally different wire protocol with its own audit regime.

The question is **not settled** in the literature. The SSH draft -10 (2026-02-26) is in IESG review and ships the same s7.2 mandate the TLS draft has shipped since -05. There is no Frontier-equivalent, no public interop matrix, and no public report of server-cohort enforcement that I can find.

## 2. Exact technical question

Does `sshd`'s `mlkem768x25519-sha256` implementation perform the FIPS 203 §7.2 encapsulation-key check (len 384k+32 AND every 12-bit coefficient in [0, q−1]) on the client's `C_PK2` portion of `SSH_MSGKEX_HYBRID_INIT` before calling `Encaps`, with a `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (reason code 3) disconnect on failure, **per `draft-ietf-sshm-mlkem-hybrid-kex-10 §2.1`**?

Sub-questions:

- (a) **Length half**: does the SSH server reject `SSH_MSGKEX_HYBRID_INIT` whose `C_INIT` length is not `MLKEM768_PUBLICKEYBYTES (1184) + CURVE25519_SIZE (32) = 1216`?
- (b) **Modulus half**: does the SSH server reject `C_PK2` whose byte layout contains any 12-bit coefficient ≥ 3329 (i.e. 3330..4095)?
- (c) **Cross-cohort asymmetry**: does OpenSSH portable `sntrup761x25519-sha512` (draft-ietf-sshm-ntruprime-ssh-06, deployed since OpenSSH 9.5, **already in production on this Windows host's `ssh.exe 9.5.6.1`**) behave the same way for the analogous Streamlined NTRU Prime 761 encapsulation-key check? It cannot use FIPS 203 s7.2 verbatim, but the same hazard class — accepting a non-canonical wire-supplied KEM pk — applies under the same spec-mandated "encapsulation key checks" language (`draft-ietf-sshm-ntruprime-ssh` §2.1 cites the analogous `crypto_kem_sntrup761_enc` constraint).
- (d) **What message**: on rejection, what exactly does the peer see — `SSH_MSG_DISCONNECT` with reason `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` (3), a TCP reset, or (the dangerous case) nothing observable because the server silently encapsulated against an invalid `pk`?

## 3. Why the problem is intellectually difficult

Three layers of structural difficulty:

1. **The "check placement" hazard class is now identified but not closed.** FND-2026-0001 proved (in msn-2026-0001) that library-level ML-KEM implementations diverge structurally on §7.2 placement (nowhere / Encaps-time / import-time) and that PQClean-style "no-check anywhere" code paths silently accept any length-valid pk. msn-2026-0005 (FND-2026-0005) closed the gap at the TLS 1.3 X25519MLKEM768 protocol boundary for two stacks (Go, rustls+aws-lc-rs). The SSH protocol layer has not been audited. The hazard is the same, but the spec language, the message grammar, the rejection channel (TCP `SSH_MSG_DISCONNECT` instead of a TLS `AlertDescription`), and the deployed code base are all different. Closing the same hazard on a different wire protocol is a small decisive experiment that extends — does not duplicate — the prior matrix.

2. **The SSH draft's enforcement language is unusual and easy to read past.** §2.1 of draft-ietf-sshm-mlkem-hybrid-kex-10 reads:
   > "Before producing S_CT2, to prevent length extension attack attempts, the server MUST check that the length of the C_INIT is the sum of the expected length of each public key in the negotiated method, C_PK1 and C_PK2. **It also MUST perform the encapsulation key checks defined in Section 7.2 of [FIPS203].** If any of these checks fail, **the client MUST abort** using a disconnect message (SSH_DISCONNECT_KEY_EXCHANGE_FAILED)..."
   
   Note the asymmetry: the server is mandated to perform the check, but the *abort* is phrased as the client's responsibility on receipt of `S_REPLY`. This is genuine spec text, not a typo — it reflects how SSH's client-driven keying works (the server encapsulates; the client decapsulates and would be the one observing a malformed `S_REPLY`). It means a strict reading of the draft *allows* the server to silently encapsulate against a non-canonical `C_PK2`, with the client expected to catch the length violation on `S_REPLY`. This is precisely the structural class of "one-sided key-establishment failure" FND-2026-0001 characterized at the library level — but now visible at the protocol layer of a *deployed* wire protocol.

3. **The deployed code base matches the most-lenient reading.** Reading the current OpenSSH portable `kexmlkem768x25519.c` (master, v1.3, 2026-06-14) and its sibling `kexsntrup761x25519.c` (v1.3, 2024-09-15): in the server `enc()` path, the **only** check on `client_blob` (the concatenation `C_PK2 || C_PK1`) is `if (sshbuf_len(client_blob) != need)` returning `SSH_ERR_SIGNATURE_INVALID`. No coefficient range check. Direct call to `crypto_kem_mlkem768_enc(ct, shared_secret, client_pub)` (resp. `crypto_kem_sntrup761_enc`). That is, OpenSSH portable — the canonical reference implementation for SSH PQ hybrid KEX, with Damien Miller and Markus Friedl as authors of record — implements the most-permissive reading of the draft. If Frontier can empirically reproduce this observation end-to-end on a live sshd, this is a *positive* result for the spec but a *negative* result for the protocol-layer enforcement property, and it is the kind of finding that has clear disclosure surface (interoperability note, not a CVE — there is no attacker without active MITM, and the client is expected to abort per the same draft).

## 5. Why the physical experiment is comparatively cheap

The harness is a small fork of msn-2026-0005's `interop/protocol-placement/rustls_loopback/`:

- **OpenSSH portable** (`kexmlkem768x25519.c`, `kexsntrup761x25519.c`) is plain portable C; it builds on this Windows host with the same `cmake` + `cc` invocation used for the existing rustls+aws-lc-rs build in `interop/protocol-placement/rustls_loopback/rustls_server/`. No new build-system surface.
- **MITM stimulus harness** is the same `net.Pipe` + Go MITM pattern already in `rustls_loopback/main.go`. SSH's binary packet framing is simpler than TLS 1.3: the SSH `SSH_MSGKEX_HYBRID_INIT` message is `byte SSH_MSGKEX_HYBRID_INIT (30) || string C_INIT` (draft §2.1). The MITM mutator only needs to (i) parse `C_INIT` into `C_PK2 || C_PK1`, (ii) overwrite one coefficient in `C_PK2` (already 12-bit-encoded, same byte layout as `msn-2026-0005`'s `wire_coeff0_eq_q` family), (iii) adjust `packet_length` and `padding_length` (SSH binary packet protocol uses `uint32 packet_length || byte padding_length || payload || random padding || mac`, RFC 4253 §6). The same Go harness re-uses 6 length fields repaired in one pass, identical to msn-2026-0005.
- **Stimulus reuse**: the canonical `coeff0=q / coeff0=4095 / coeff255=4095 / truncate-by-1` family from `msn-2026-0005` and the `stimuli.tsv` reuses the exact byte positions used for TLS 1.3 X25519MLKEM768's 1216-byte hybrid share, because in SSH the layout is the *same concatenation order* (`KEM-pk || X25519-pk`, draft §2.1 explicitly: "C_INIT = C_PK2 || C_PK1").
- **Decision surface** is binary: server completes handshake → success; server sends `SSH_MSG_DISCONNECT` with reason code 3 → strict-enforcing; server hangs / TCP reset / silent-encap → lenient. Either verdict is informative.
- **Client-side second check**: a Go `golang.org/x/crypto/ssh` MITM client that completes a *full* hybrid handshake with `C_PK2` set to the tampered variant and then attempts decapsulation would record whether the *client side* rejects. (This parallels FND-2026-0005's two-cohort verdict.)
- **Compute class**: lightweight. One sshd binary build (~3 minutes cold, cached after), one loopback handshakes matrix (~seconds per variant × ≤10 variants × 2 KEMs = under 5 minutes).

The expensive cost is **not** compute — it is careful stimulus construction. The 12-bit coefficient byte layout of ML-KEM-768's `t-hat` portion is non-trivial (3 coefficients packed per pair of bytes, low-first), but the prior msn-2026-0005 harness already implements `coeffQ / coeffQMax / polyLo / tailHi` and reuses the same formulas. The replicate-by-position map is documented in `go_loopback/main.go:115-130` and `rustls_loopback/main.go:67-76`.

## 6. Specifications and primary sources

| Document | Status | URL |
|----------|--------|-----|
| FIPS 203 §7.2 | Final, 2024-08-13 | `https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf` (`localdocs/refs/fips203.pdf`) |
| `draft-ietf-sshm-mlkem-hybrid-kex-10` | IESG review queue (RFC Ed Ack), 2026-02-26 | `https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/` |
| `draft-ietf-sshm-ntruprime-ssh-06` | WG document, 2025-09-30 (the already-deployed sibling) | `https://datatracker.ietf.org/doc/draft-ietf-sshm-ntruprime-ssh/` |
| RFC 4253 §6 (binary packet framing) | RFC | `https://www.rfc-editor.org/rfc/rfc4253` |
| RFC 4253 §7 (KEX), RFC 5656 (ECDH), RFC 8731 (X25519) | RFC | `https://www.rfc-editor.org/info/rfc4253`, `/rfc5656`, `/rfc8731` |
| RFC 9794 (Terminology for PQ/T Hybrid Schemes) | RFC 2025-06 | `https://www.rfc-editor.org/rfc/rfc9794` |
| OpenSSH portable `kexmlkem768x25519.c` (master v1.3, 2026-06-14) | Implementation | `https://github.com/openssh/openssh-portable/blob/master/kexmlkem768x25519.c` |
| OpenSSH portable `kexsntrup761x25519.c` (master v1.3, 2024-09-15) | Implementation | `https://github.com/openssh/openssh-portable/blob/master/kexsntrup761x25519.c` |
| OpenSSH portable `kex.c` (master, dispatch path) | Implementation | `https://github.com/openssh/openssh-portable/blob/master/kex.c` |
| NIST SP 800-227 (KEM recommendations) | Sept 2025 | `https://doi.org/10.6028/NIST.SP.800-227` |
| Existing FND-2026-0001 (placement taxonomy) | Verified in repo | `knowledge/findings/fnd-2026-0001.yaml` |
| Existing FND-2026-0005 (rustls s7.2 enforcement) | Verified in repo | `knowledge/findings/fnd-2026-0005.yaml` |
| Existing msn-2026-0005 loopback harness | Verified in repo | `interop/protocol-placement/rustls_loopback/` |

## 7. Available implementations / formal systems

Two `sshd` binaries can be exercised:

- **OpenSSH portable** (master HEAD = 2026-06-14 v1.3): `mlkem768x25519-sha256` is gated by `USE_MLKEM768X25519` autoconf macro; OpenBSD native sshd enables it by default in OpenBSD 7.6+. portable is configurable; the experimental build used in Debian/Ubuntu 25+ ships it enabled.
- **OpenSSH portable** (already-built ntruprime path): `sntrup761x25519-sha512` is unconditionally built in OpenSSH ≥ 9.5 and is the *currently-shipped* default PQ KEX on Windows OpenSSH 9.5.6.1 (`where ssh.exe` on this host).
- **Erlang/OTP `ssh`**: pure Erlang implementation, supports `sntrup761x25519-sha512` since OTP 27. Useful as an *independent* cohort that does not share OpenBSD's `kex.c` dispatch code path. Avoids correlated-consensus risk.
- **Dropbear SSH**: lightweight C, supports `sntrup761x25519-sha512` since 2024.013. Useful as a third cohort; less mature on ML-KEM-X25519.
- **libssh / AsyncSSH / paramiko**: do not currently ship hybrid PQ KEX; out of scope.
- **Go `golang.org/x/crypto/ssh`**: client-side support for `sntrup761x25519-sha512` since Go 1.24; ML-KEM-X25519 client support was added in Go 1.25. Sufficient for the *client side* of the loopback matrix; we do not need a Go-native sshd.

A formal / machine-checked verification track is **not** the right shape for this question (it is purely a deployed-wire protocol behavior question, not a property-of-an-algorithm question). The closest formal analog — verifying "if a `C_INIT` is well-formed per draft §2.1 length rule then `Encaps` receives a `pk` whose `Encaps_internal_input_check` returns accept" — is straightforward and not novel after FORMAL-203/204 closed FIPS 203 §7.2's halves. Skipping formal track keeps scope tight.

## 8. Prior art (cited against existing protocol-placement work)

- `fnd-2026-0001.yaml` — established the **library-level** placement taxonomy for ML-KEM s7.2; proved the silent-divergence channel (PQClean accepts any length-valid pk). This dossier's SSH audit is the *protocol-layer extension* of the same finding shape.
- `fnd-2026-0005.yaml` (`msn-2026-0005`) — closed the protocol-layer s7.2 enforcement question for **TLS 1.3 X25519MLKEM768** across two server cohorts (Go stdlib + rustls+aws-lc-rs). **Explicitly carved out SSH hybrid KEX** as out-of-scope:
  > "Open remaining protocol-layer cohorts: HPKE X-Wing, SSH hybrid KEX, OpenSSL+oqs-provider, OpenSSH" (follow_up #1)
  > "Out-of-scope: HPKE X-Wing, SSH hybrid KEX, OpenSSL+oqs-provider, OpenSSH." (terminal_reason)
- `msn-2026-0008` / `msn-2026-0009` — closed the X-Wing + HPKE track at the *primitive-and-combiner* level (CIRCL byte-exact, no protocol-layer involvement). Not a protocol-layer audit; out of scope here.
- `interop/protocol-placement/{go_loopback,rustls_loopback}/` — the harness and reporting format (TSV + console log, `RESULT|...` JSON line, MITM-on-net.Pipe pattern, per-handshake verdict). This dossier's SSH matrix re-uses that format unchanged, so the resulting evidence artifacts (TSV + console log + YAML evidence graph objects) read as a third row in the same matrix.
- `crypto/mlkem-input-checks/stimuli/stimuli.tsv` — the byte-position stimulus table (canonical pk controls + 9 tampered pk variants) reuses 4 of these unchanged for the SSH variant. The remaining 5 (cross-param-set body, rho-tail mutation, congruent-plant) are out-of-scope for a server-cohort protocol-layer audit (they exercise library parse, not protocol framing).

## 9. Plausible hypotheses (3-5)

- **H1 (most likely):** OpenSSH portable `mlkem768x25519-sha256` server enforces only the *length* half of §7.2 on `C_INIT` (matching `kexmlkem768x25519.c`'s `sshbuf_len(client_blob) != need` check) and silently encapsulates against non-canonical coefficients. Wire verdict: server completes the handshake and produces `S_REPLY`. The client (Go `x/crypto/ssh` or upstream OpenSSH portable client) is expected to catch the `S_REPLY` length-mismatch on its own — but if our MITM keeps `S_REPLY` length well-formed, the client accepts and derives `K_PQ` from a decapsulation against a non-canonical `pk`. Outcome: success-or-disconnect depends only on length enforcement.
- **H2:** The OpenSSH portable `mlkem768x25519-sha256` *client* decapsulation path rejects non-canonical `pk` because the underlying `crypto_kem_mlkem768_dec` is the OpenBSD-native ML-KEM (which embeds s7.2 by FIPS 203 conformance); however this rejection is *triggered only on decapsulation*, not on `Encaps`. Combined with H1, this means the danger is on the server path, not the client path.
- **H3:** The `sntrup761x25519-sha512` (ntruprime) cohort in OpenSSH portable behaves identically to ML-KEM-X25519 in H1 (only length check, no polynomial-coefficient check). This is consistent with `kexsntrup761x25519.c`'s structure. If true, it is a **larger** finding because sntrup761 is already in production deployments worldwide (default PQ KEX in OpenSSH 9.5+) — a deployed hazard class is more interesting than an experimental one.
- **H4:** Erlang/OTP `ssh` (independent cohort, different codebase lineage) implements a stricter reading and rejects non-canonical `C_PK2` at the protocol layer with `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`. If true, this is a positive interop note: there is a reference for strict-mode implementations. If false, the lenient reading is correlated across implementations.
- **H5 (null hypothesis):** The SSH draft -10's "It also MUST perform the encapsulation key checks" language is unenforceable in practice because the wire-format concatenation order (`C_PK2 || C_PK1`) means the server's structural framing cannot distinguish the KEM-pk boundaries without additional bookkeeping that no implementation has shipped. This would explain why OpenSSH's `enc()` path is the way it is. Worth stating explicitly: under this null hypothesis the draft's mandate is structurally ambiguous and the lenient reading is the only implementation-feasible reading.

## 10. Concrete verification mechanism

A 4-stage matrix in the existing harness style:

**Stage A — Length-only (per draft §2.1 first MUST).** Stimuli:
- `control`: canonical `C_INIT = pk2(1184 B) || pk1(32 B)` = 1216 B.
- `truncate_last_byte`: 1215 B; all six length fields (packet_length, padding_length, string-length-of-C_INIT, string-length-of-C_PK2, MPINT X25519 length, the implicit "before-string" 4-byte field) repaired.
- `append_extra_byte`: 1217 B.

Verdict rule: server sends `SSH_MSG_DISCONNECT` reason 3 → strict; server completes handshake → lenient.

**Stage B — Modulus (per draft §2.1 second MUST).** Reuses four stimuli from msn-2026-0005:
- `wire_coeff0_eq_q` (first 12-bit coefficient = 3329)
- `wire_coeff0_eq_4095` (first = 4095)
- `wire_coeff255_eq_4095` (last 12-bit coefficient = 4095)
- `wire_cross_param_set` (insert 1088-B ML-KEM-512 ek body followed by an additional 32 B to reach 1216, cf. msn-2026-0001's congruent-plant family)

Verdict rule: same as Stage A, plus capture full `S_REPLY` ciphertext for the lenient case (decapsulate against canonical `pk` to confirm we get a valid `K_PQ` *server-side*, demonstrating the one-sided key-establishment failure mode concretely).

**Stage C — Client-side decapsulation parity.** Use `golang.org/x/crypto/ssh` (Go 1.26.4, supports `sntrup761x25519-sha512` natively; ML-KEM-X25519 client support is in Go 1.25+) as the *client* of the loopback. Run the same Stage B stimuli through the client to see whether the client catches any of them on `S_REPLY`. Record verdict separately: this is the FND-2026-0001 hazard class made directly visible at a wire protocol.

**Stage D — Cross-impl cohort (optional, gated by Stage A/B results).** Add Erlang/OTP `ssh` (Docker-isolated) and Dropbear sshd if Stage A shows the OpenSSH portable answer is "length-only" (H1). Skipped if Stage A shows strict enforcement — orthogonal cohort is then low marginal value.

Verification is `frontier.execute` with scrubbed env + GitHub Actions ubuntu-24.04 (where OpenSSH portable builds are well-trodden) for the OpenSSH cohort; Erlang cohort requires a Docker step but Frontier already has docker access via `frontier.execute`. Output is TSV + console log in `interop/protocol-placement/ssh_loopback/reports/`, promoted to `obs-2026-XXXX` once the matrix is complete.

## 11. Expected compute requirements

- **Local** (lightweight): writing the Go MITM mutator and SSH packet-length arithmetic. ~2-4 hours of careful coding. Trivially runnable on this Windows host against the Windows OpenSSH 9.5.6.1 client only (for the sntrup761x25519 case); ML-KEM-X25519 client requires OpenSSH portable built with `USE_MLKEM768X25519`.
- **GitHub Actions ubuntu-24.04** (medium): build OpenSSH portable master with `USE_MLKEM768X25519=1`, run loopback matrix. ~5 min cold build (faster with cargo cache re-use); ~30 sec per variant × 8 variants × 2 KEMs ≈ 5 min handshake matrix. Total CI budget: under 10 minutes per run. Two runs (Stage A+B and Stage C) = 20 minutes.
- **No heavy compute.** No fuzzing, no cross-platform matrix, no performance measurement. Everything fits inside `frontier.compute.route(expected_class=medium)`.

## 12. Reproducibility path

```
cd interop/protocol-placement/ssh_loopback
go run . reports/ssh_loopback_report.tsv reports/ssh_loopback_console.log \
    $OPENSSH_PORTABLE_SSHD_BIN

# Or via GHA: gh workflow run ssh-loopback.yml
# Expected exit 0, TSV rows for each (cohort, variant) pair with verdict.
```

The MITM mutator is `go_loopback/main.go`'s `mitm` pattern re-targeted to SSH's `SSH_MSGKEX_HYBRID_INIT (30)` payload grammar. SSH binary packet framing RFC 4253 §6 is straightforward (`uint32 packet_length || byte padding_length || payload || random padding || mac`). The Go harness does not need to validate host keys; use `-o StrictHostKeyChecking=no` equivalent and a self-signed key in the sshd config. All code runs in `frontier.execute` with scrubbed env. Reproduction artifacts (TSV + console log + reproducer YAML) commit on success.

## 13. Potential research significance

- **Closes an explicitly-out-of-scope gap** that msn-2026-0005 named in `terminal_reason` and `follow_up`. This is the highest-grade follow-up: directly enumerated, structurally adjacent, and verifiable with the same matrix shape.
- **Extends FND-2026-0001's "silently encapsulate against non-canonical pk" hazard from library-parse layer to protocol layer of a *different wire protocol*.** Same shape, new wire. If positive (lenient), produces an interop note for OpenSSH portable + draft-ietf-sshm-mlkem-hybrid-kex-10 spec ambiguity (analogous to FND-2026-0005's positive finding for rustls+aws-lc-rs but with the polarity inverted). If negative (strict), produces a positively-conforming-implementation interop note.
- **Makes the ntruprime cohort visible.** OpenSSH 9.5 with `sntrup761x25519-sha512` is *deployed in production today* on a non-trivial fraction of internet-facing SSH servers (the default PQ KEX since 2023). A confirmed wire-level s7.2-equivalent gap here is materially more security-relevant than the experimental ML-KEM cohort, even though the algorithm is NTRU Prime rather than ML-KEM.
- **Direct disclosure surface**: IETF `sshm` WG mailing list; OpenSSH portability mailing list; potential interoperability note (not CVE-class — no active attacker without MITM). Front-runner disclosure path: send the matrix to the WG before publishing, so the spec ambiguity can be addressed in draft -11 (the draft is currently in RFC Ed queue, so timing is favorable).

## 14. Major reasons it could be a dead end

- **H1 is the expected answer.** If OpenSSH portable is just length-checked (H1), then the matrix will produce a single verdict across both ML-KEM and sntrup761 cohorts (lenient on coefficient overflow). This is *informative* but not surprising; the prior-art taxonomy in FND-2026-0001 already implies this. The matrix still has disclosure value (interop note; spec clarification request), but it is not a discovery-grade finding.
- **Spec ambiguity collapse.** If the working group or spec editors clarify between -10 and an RFC that the "MUST" in §2.1 is to be read as "MUST only on length" (because the structural framing cannot distinguish boundary positions), then the audit is closed without a finding. This is a possible outcome if the matrix is run after a draft advancement.
- **Wire-format refactor.** OpenSSH master as of 2026-06-14 *added back* `mlkem768x25519-sha256` support (commit `81ca145` 2026-06-14) after removing it in 2024-09-05 (commit `62fb2b5`). The implementation may move in the next few months. If the experiment runs after a refactor that adds the modulus check, H1 flips to its negation and the finding is "fully conforming, no anomaly" — informative but not a discovery.
- **Independent-cohort ceiling.** Erlang/OTP and Dropbear both ship sntrup761x25519 but not ML-KEM-X25519 (Dropbear pending). The ML-KEM cross-cohort is constrained to OpenBSD/OpenSSH portable on OpenBSD and the upstream portable on Linux. Without a third ML-KEM-X25519 implementation, H4 cannot be evaluated, which means the "lenient-is-correlated" claim cannot be made strongly. This bounds the matrix but does not eliminate its value.
- **The matrix says what msn-2026-0005 already implies.** A Frontier reviewer may legitimately ask: "If we already know OpenSSH's KEM primitive layer likely doesn't check (FND-2026-0001), why audit the protocol layer?" Answer: because the *spec-mandated placement* (draft §2.1) places the check at the protocol layer precisely to defend against library-parse lenient implementations, and a deployed sshd may *still* enforce it at the protocol layer even if its library does not. The audit is non-redundant. But a strict-budget review could still deprioritize it as a confirmation rather than a discovery.

## 15. Recommendation

Promote to `missions/pending/msn-2026-0010.yaml` (or the next available mission ID via `frontier.ids.next_id`) with:

- `compute_class: medium`
- `domain: interop`
- `scope`: SSH hybrid KEX protocol-layer s7.2 enforcement (ML-KEM-X25519 + ntruprime-X25519 cohorts)
- `acceptance_criteria`: ≥ 6 stimuli (Stage A: 3, Stage B: 4) × ≥ 1 server cohort, with per-handshake verdicts, alert/disconnect mapping, and S_REPLY capture; cross-impl cohort (Erlang/OTP) optional, gated.
- `budget`: max_attempts=8, max_compute_runs=12 (two GHA runs + a Windows local run), max_independent_reviews=1.
- `objective` paraphrases the §2 question.
- `parent`: msn-2026-0005 (closes the gap that mission explicitly carved out).
- `links`: spec draft + RFC 4253 §6/§7 + FND-2026-0001 + FND-2026-0005.

The compute is medium-cheap, the matrix shape reuses an existing harness verbatim, the finding shape is novel (different protocol layer than msn-2026-0005, deployed production code path), and the timing is favorable (SSH draft -10 is in RFC Ed queue; disclosure window is open). It is the strongest next step in the protocol-interop domain given the current Frontier state.