<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_sntrup761_spec.md -->

# Specification audit: does `sntrup761x25519-sha512` mandate server-side coefficient validation?

Role: specification-analyst (read-only). Audit date: 2026-10-03.
Question: does the governing Internet-Draft mandate an explicit coefficient/input
validation check at the SSH protocol layer, or does it defer to the KEM implementation?

**Bottom line: NO.** The draft affirmatively states that no further validation is
required, and the KEM specification it defers to defines decoding as a *total* function
that reduces out-of-range input. Details, quotes and residual uncertainty below.

---

## 0. Version and status facts (checked, not assumed)

| Fact | Value | Source |
|---|---|---|
| Document audited | `draft-ietf-sshm-ntruprime-ssh-06` | https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ntruprime-ssh-06 |
| Date published | 30 September 2025 | datatracker header |
| Intended status | **Informational** | datatracker header |
| Expires | 3 April 2026 | datatracker header |
| Newer revision? | **Yes — it has been published as an RFC.** | https://datatracker.ietf.org/doc/draft-ietf-sshm-ntruprime-ssh/ |
| Current document | **RFC 9941**, M. Friedl, J. Mojzis, S. Josefsson, April 2026 | https://datatracker.ietf.org/doc/draft-ietf-sshm-ntruprime-ssh/ |
| RFC category | Informational | RFC 9941 |
| Datatracker history record | "Received changes through RFC Editor sync (changed state to RFC…changed IESG state to RFC Published)", 2026-04-10 | https://datatracker.ietf.org/doc/draft-ietf-sshm-ntruprime-ssh/history/ |
| Errata on RFC 9941 | **None** ("No matching errata found.") | https://errata.rfc-editor.org/search/?rfc_number=9941&status=verified_reported |

Revision chain (from datatracker history): `draft-josefsson-ntruprime-ssh-00`
(2023-05-09) … `-01`, `-02`, `-03` → `draft-ietf-sshm-ntruprime-ssh-00` (2024-11-07),
`-01`, `-02`, `-03`, `-04`, `-05`, `-06` (2025-09-30) → **RFC 9941** (2026-04-10).
`-06` is the final draft revision. The operative paragraph is **substantively identical**
in draft-06 §3 and RFC 9941 §3; the only differences are RFC Editor normalisations
(`section 11.1` → `Section 11.1 ("Disconnection Message")`, `1158 byte` → `1158-byte`,
`re-uses` → `reuses`, comma→semicolon before "see", Oxford comma in the reference list).

### Correction to the question's framing

The question asks for "§2.1". **This draft has no §2.1.** Its structure is:

```
1.  Introduction
2.  Requirements Language
3.  Key Exchange Method: sntrup761x25519-sha512
4.  Security Considerations        (draft-06: 5.)
5.  IANA Considerations
6.  References
    6.1 Normative / 6.2 Informative (draft-06: 7.1 / 7.2)
Appendix A. Test vectors
```

The ML-KEM draft has a §2.1 because it defines a generic abstraction in §2; the NTRU Prime
draft has no such abstraction — it specifies one concrete method directly in §3. So the
sections are **not** structurally comparable, which matters for the contrast in question 3.
I have audited the whole document; the validation question is settled entirely by §3 plus
the normative reference `[NTRUPrimePQCS]`.

---

## 1. Verbatim quotes — the ntruprime draft

Source: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ntruprime-ssh-06
(§3, "Key Exchange Method: sntrup761x25519-sha512"). HTML and plain-text renderings
(`https://www.ietf.org/archive/id/draft-ietf-sshm-ntruprime-ssh-06.txt`) agree.

These are the **only** sentences in the entire document bearing on input validation
(there are no other occurrences of "validat*", "coefficient", "canonical", or "reject"
anywhere in the body):

> The SSH_MSG_KEX_ECDH_INIT's value Q_C that holds the client's ephemeral public key MUST
> be constructed by concatenating the 1158 byte public key output from the key generator
> of sntrup761 with the 32 byte K_A = X25519(a, 9) as described in [NTRUPrimePQCS] and
> [RFC8731].  The Q_C value is thus 1190 bytes.

> The SSH_MSG_KEX_ECDH_REPLY's value Q_S that holds the server's ephemeral public key MUST
> be constructed by concatenating the 1039 byte ciphertext output from the key encapsulation
> mechanism of sntrup761 with the 32 byte K_B = X25519(b, 9) as described in
> [NTRUPrimePQCS] and [RFC8731].  The Q_S value is thus 1071 bytes.

> **Clients and servers MUST abort if the length of the received public keys Q_C or Q_S are
> not the expected lengths.  An abort for these purposes is defined as a disconnect
> (SSH_MSG_DISCONNECT) of the session and SHOULD use the SSH_DISCONNECT_KEY_EXCHANGE_FAILED
> reason for the message, see section 11.1 (Disconnection Message) of [RFC4253].  No further
> validation is required beyond what is described in [RFC7748], [RFC8731] and
> [NTRUPrimePQCS].**

That final sentence is the whole of it. Note carefully what it does:

- It imposes exactly **one** `MUST`: the **length** check.
- The abort mechanism is `MUST abort` + `SHOULD` disconnect reason.
- It then says in plain words that **no further validation is required**, and closes the
  question by reference to three documents.

### The Requirements Language clause (§2)

> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
> NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
> interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear
> in all capitals, as shown here.

This matters — see the ambiguity flagged in §4 below.

### Normative reference

> **[NTRUPrimePQCS]**  Bernstein, D.J., Brumley, B. B., Chen,, M., Chuengsatiansup, C.,
> Lange, T., Marotzke, A., Peng, B., Tuveri, N., Vredendaal, C. V., and B. Yang, "NTRU
> Prime: round 3", WWW https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf, DOI
> 10.5281/zenodo.13983972, October 2020, <https://doi.org/10.5281/zenodo.13983972>.

Listed under §7.1 **Normative References** in draft-06 (draft-06 §7.1; RFC 9941 §6.1).
So the whole NTRU Prime round-3 document is incorporated normatively.

---

## 2. Verbatim quotes — the NTRU Prime specification (`[NTRUPrimePQCS]`)

Source PDF: https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf
(Bernstein et al., "NTRU Prime: round 3", 7 October 2020, DOI 10.5281/zenodo.13983972;
linked from https://ntruprime.cr.yp.to/nist.html as the primary submission document.)
Quotes below are verbatim from the PDF (page numbers in parentheses). Note the extraction
renders `∈`, `←`, `′` and `≤` imperfectly; I have normalised only those glyphs.

### 2a. The decoder is specified to be total — this is the decisive passage (§3.1, p. 17)

> General-purpose encoding of sequences of integers. We define deterministic algorithms
> Encode and Decode with the following properties. Let M = (m0, . . . , mn−1 ) and
> R = (r0, . . . , rn−1 ) be sequences of integers. Assume that 0 ≤ ri < mi < 214 for
> each i. Then S = Encode(R, M ) is a sequence of bytes, and Decode(Encode(R, M ), M ) = R.
> The length of S depends only on M , not on R. **If S′ is any sequence of bytes of this
> length, then Decode(S′, M ) is a sequence of n integers, although not necessarily in the
> same range as R.**

This is the specification explicitly contemplating and *permitting* an arbitrary input byte
string that decodes to integers outside the intended range. It says what the decoder does
on such input (produce integers) and does not say the input is invalid.

### 2b. The parameter space defines decoding as a total map, with no validity predicate (§2.3.5, pp. 10–11)

> Streamlined NTRU Prime has the Streamlined NTRU Prime Core parameters, plus the following
> parameters:
>
> - sets SessionKeys, Confirm, PublicKeys, SecretKeys, Inputs, Ciphertexts of strings, each
>   set being the set of all strings of a specified length;
> - deterministic encoding algorithms PublicKeys → PublicKeys, SecretKeys → SecretKeys,
>   Inputs → Inputs, and Ciphertexts → Ciphertexts;
> - **deterministic decoding algorithms PublicKeys → PublicKeys, SecretKeys → SecretKeys,
>   Inputs → Inputs, and Ciphertexts → Ciphertexts that always invert encoding;**

`PublicKeys` here is "the set of all strings of a specified length" (1158 bytes for
sntrup761). The decoding algorithm is a **total function from that whole set**, required
only to invert encoding on valid encodings. There is no companion "validation" or "check"
algorithm in the parameter list.

### 2c. `Encap` — the server-side algorithm — has no rejection branch (§2.3.7, p. 11)

> The following randomized algorithm Encap, given an element of PublicKeys, outputs an
> element of Ciphertexts0 × SessionKeys, where Ciphertexts0 = Ciphertexts × Confirm:
>
> - **Input K ∈ PublicKeys. Decode K, obtaining K ∈ PublicKeys.**
> - Generate a uniform random r ∈ Inputs. Encode r as a string r ∈ Inputs.
> - Compute c = Encrypt(r, K ) ∈ Ciphertexts. Encode c as a string c ∈ Ciphertexts.
> - Compute C = (c, HashConfirm(r, K )) ∈ Ciphertexts × Confirm.
> - Output (C, HashSession(1, r, C)).

Five steps, no conditional, no error case. The input to `Encap` is a 1158-byte string; the
first step decodes it and proceeds. The algorithm as specified **cannot** fail on a
non-canonical public key — there is no specified behaviour for such a key beyond decoding.

### 2d. `Decap` likewise (§2.3.8, pp. 11–12)

> The following deterministic algorithm Decap, given an element of Ciphertexts0 × SecretKeys0 ,
> outputs an element of SessionKeys:
>
> - Input C = (c, γ) ∈ Ciphertexts × Confirm and (k, K, ρ) ∈ SecretKeys × PublicKeys × Inputs.
> - Decode c, obtaining c ∈ Ciphertexts.
> - Decode k, obtaining k ∈ SecretKeys.
> - Compute r0 = Decrypt(c, k) ∈ Inputs.
> - Compute r′0 , c′0 , C′ as in Encap.
> - If C′ = C then output HashSession(1, r, C). Otherwise output HashSession(0, ρ, C).
>   (The choice between these two outputs is secret information.)

The only conditional in the whole KEM is the **implicit-rejection** choice on the
*ciphertext*. That is the mechanism the spec uses for invalid *ciphertexts*. It is silent on
invalid *public keys* — consistent with §2a/§2b, since decoding a pk is defined to always
succeed.

### 2e. Public-key encoding (§3.1, p. 20)

> Encoding of public keys. The encoding of public keys is the encoding of field elements.

and (same section):

> Encoding of field elements. View each element of R/q as a polynomial r0 + r1 x +
> · · · + rp−1 xp−1 with each ri ∈ {−(q − 1)/2, . . . , −1, 0, 1, . . . , (q − 1)/2}. Add
> (q − 1)/2 to each coefficient to obtain a sequence of p elements of {0, 1, . . . , q − 1}.
> Apply Encode with M = (q, . . . , q) to obtain a string.

### 2f. Out-of-range pk bytes are representable — sntrup761 parameters (§3.5, p. 22)

> Streamlined NTRU Prime with p = 761, q = 4591, and w = 286.

**q = 4591 < 65536**, so the encoding packs two coefficients per byte and coefficients are
13 bits wide. Byte values that decode to a coefficient ≥ 4591 are therefore fully
representable on the wire, and — per §2a — the decoder maps them into range rather than
rejecting. This is a factual observation about the parameter set, not a claim about impact.

### 2g. The spec uses no BCP-14 keywords at all

Searched the full extracted text: there is **no** BCP 14 / RFC 2119 / RFC 8174 statement,
and **no** occurrence of `MUST` or `SHALL` in capitals as a normative keyword. Eighteen
lowercase occurrences of "must" exist in prose (e.g. §2.3.4, p. 9: "Implementors must be
careful to avoid leaking secret information through side channels, and in particular must
avoid implementing the weight test here as a branch."). Its normative force rests on its
status as the cited submission document and on the algorithm listings being introduced as
definitions ("The following randomized algorithm Encap…"), not on keyworded requirements.

---

## 3. Contrast: the ML-KEM draft

Source: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-mlkem-hybrid-kex-10
(Kampanakis, Stebila, Hansen; PQ SSH WG; February 2026, published 26 February 2026;
Informational; expires 30 August 2026).

§2.1, verbatim (your prior verification is confirmed — the quote in the task brief matches
the current text exactly):

> Before producing S_CT2, to prevent length extension attack attempts, the server MUST check
> that the length of the C_INIT is the sum of the expected length of each public key in the
> negotiated method, C_PK1 and C_PK2. **It also MUST perform the encapsulation key checks
> defined in Section 7.2 of [FIPS203].** If any of these checks fail, the client MUST abort
> using a disconnect message (SSH_MSG_DISCONNECT) with a SSH_DISCONNECT_KEY_EXCHANGE_FAILED
> as the reason.

Two further contrasts from the same section, also verbatim:

> For all method names, both the client and server MUST process the ECDH and X25519 public
> keys (C_PK1, S_PK1) as described in Section 4 of [RFC5656] and Section 3 of [RFC8731]
> respectively, **including validity and length checks** and SSH disconnect messages if the
> checks fail.

> The client MUST abort using a disconnect message (SSH_MSG_DISCONNECT) with a
> SSH_DISCONNECT_KEY_EXCHANGE_FAILED as the reason if the check fails or decapsulation fails
> for any other reason.

Also note this document *deliberately aligned itself with* the NTRU Prime draft (the one
under audit), which it cites as an informative reference:

> This specification's PQ/T Hybrid key exchange message abstraction, key derivation, and
> input to the SSH hash calculation, H, align with the ones defined in
> [I-D.ietf-sshm-ntruprime-ssh] which uses a different quantum-resistant KEM.

Despite that alignment, this draft kept the §7.2 `MUST` and the ntruprime draft has no
equivalent. That asymmetry is the finding.

### FIPS 203 §7.2 (the imported requirement)

Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
(NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", 13 August 2024;
landing page https://csrc.nist.gov/pubs/fips/203/final). Verbatim, p. 36:

> **7.2  ML-KEM Encapsulation**
>
> The encapsulation algorithm ML-KEM.Encaps of ML-KEM (Algorithm 20) accepts an
> encapsulation key as input, generates randomness internally, and outputs a ciphertext and
> a shared key. This algorithm requires input checking, as specified below.
>
> **Encapsulation key check.** To check a candidate encapsulation key ek, perform the
> following:
>
> 1. (Type check) If ek is not an array of bytes of length 384k + 32 for the value k
>    specified by the relevant parameter set, then input checking failed.
> 2. (Modulus check) Perform the computation
>
>        test ← ByteEncode12 (ByteDecode12 (ek[0 ∶ 384k]))                            (7.1)
>
>    (see Section 4.2.1). If test ≠ ek[0 ∶ 384k], then input checking failed. **This check
>    ensures that the integers encoded in the public key are in the valid range [0, q − 1].**
>
> If both checks pass, then ML-KEM.Encaps can be run with input ek′ := ek. It is important
> to note that this checking process does not guarantee that ek′ is a properly produced
> output of ML-KEM.KeyGen.
>
> **ML-KEM.Encaps shall not be run with an encapsulation key that has not been checked as
> above.** However, checking of the encapsulation key need not be performed by the
> encapsulating party, nor with every execution of ML-KEM.Encaps. Instead, assurance that
> these checks have been performed can be acquired through other means (see SP 800-227 [1]).

And at §3.3, "Requirements for ML-KEM Implementations" (p. 16):

> **Input checking.** The algorithms ML-KEM.Encaps and ML-KEM.Decaps require input checking.
> **Implementers shall ensure that ML-KEM.Encaps and ML-KEM.Decaps are only executed on
> inputs that have been checked, as described in Section 7.**

(Also relevant, §7.1 key pair check, p. 35, step 2: "(Encapsulation key check) Check ek as
specified in Section 7.2.")

---

## 4. Answers

### Q1. Does the draft REQUIRE explicit server-side coefficient validation?

# NO.

Reasoning from the quoted text only, with no inference:

1. **The affirmative requirement list contains exactly one check: length.** "Clients and
   servers MUST abort if the length of the received public keys Q_C or Q_S are not the
   expected lengths." No coefficient, canonicality, or pk-validity `MUST` exists anywhere in
   the document.
2. **The document affirmatively forecloses the inference.** "No further validation is
   required beyond what is described in [RFC7748], [RFC8731] and [NTRUPrimePQCS]." This is
   not silence; it is an explicit statement that additional validation is not required.
3. **The deferral target does not supply a check either.** The three named documents were
   read: RFC 7748 and RFC 8731 govern X25519 (whose checks are the length check the draft
   already cites, plus the shared-secret-zero condition they define), and `[NTRUPrimePQCS]`
   defines `Decode` as a total function that explicitly accepts arbitrary byte strings of
   the right length and produces integers "not necessarily in the same range as R"
   (§2a), specifies `Encap` with no rejection branch (§2c), and lists no validation
   algorithm among the KEM parameters (§2b).

So the answer is **not** "the draft mandates a check at the SSH layer" and **not** "the
draft is silent and therefore a check may be added at will." It is: the draft both declines
to mandate one and states none is required, and the reference it defers to declines to
define one.

**One ambiguity, flagged rather than resolved** (this is the only thing standing between
"NO" and a hair-splitting "AMBIGUOUS", and I think "NO" is right, but the ambiguity is real
and should be recorded):

> The sentence that appears to discharge the validation requirement — "No further validation
> is required beyond…" — uses **lowercase** "required". §2 of the same document states that
> BCP-14 keywords apply "when, and only when, they appear **in all capitals**". Read
> strictly, the phrase "No further validation is required" is therefore *not* itself a
> keyworded normative statement; it is ordinary English asserting the absence of a
> requirement.

Two consequences, and I decline to pick between them by inference:

- **Reading A (my assessment, but stated as an assessment):** the sentence is plain
  language stating the absence of a requirement, and an absence-of-requirement statement
  does not need to be keyworded in order to be true and effective. Result: NO.
- **Reading B:** because the sentence is non-keyworded, the document's *only* keyworded
  requirement is the length `MUST`, and the reference to `[NTRUPrimePQCS]` is the sole
  normative extension of the requirement set. On that reading the outcome is the same —
  `[NTRUPrimePQCS]` contains no validation requirement either — so **NO** is reached twice
  over.

Note also that Reading B does *not* license adding a check that neither document requires;
these documents constrain, they do not forbid. Nothing in the quoted text prohibits an
implementation from performing a stricter canonicality check. That is a statement about the
permissive scope of the specs, not a normative mandate.

### Q2. Is a SUPERCOP reference implementation that silently reduces inputs CONFORMANT with the draft as written?

**Yes — on the quoted text, and reasoning from those texts only.** Specifically:

- The one `MUST` the draft imposes (length of Q_C / Q_S) is a length check. A reducing
  decoder performs no length check of its own and does not interfere with the length check
  the wrapper performs.
- The draft's statement is "No further validation is required beyond what is described in
  [RFC7748], [RFC8731] and [NTRUPrimePQCS]" — and *no further validation* is performed.
- `[NTRUPrimePQCS]` describes precisely this behaviour and describes nothing else: `Decode`
  on "any sequence of bytes of this length" yields integers "not necessarily in the same
  range as R"; `Encap` decodes and proceeds with no failure branch; the parameter space
  specifies decoding as a total function on the full fixed-length string set.
- For sntrup761, q = 4591, so non-canonical encodings are representable on the wire and the
  specified decode is total over them.

So the behaviour is not merely permitted — it is **the specified behaviour** of the
referenced algorithm. An implementation that reduces rather than rejects is doing what
`[NTRUPrimePQCS]` says `Encap` does.

**Two limits on that statement, which I want on the record rather than buried:**

1. **Conformance is not a security judgement.** Nothing above says the reduction is safe,
   nor that it is not. It says only that the documents do not require a check and describe
   this behaviour. Whether silent reduction creates a reachable security consequence is a
   *separate* question that these quotes do not address and that I have not evaluated here.
   Per the repo's promotion ladder, an implementation discrepancy is not automatically a
   specification violation — and equally, absence of a violation is not a defence.
2. **The status of the finding.** "Conformant with the documents as written" is my reading
   of two documents' text. It is not a determination by the IESG, by an I-D reviewer, or by
   anyone with standing to make one. It should carry `epistemic_status` reflecting that it
   is a textual analysis, not a verified conclusion.

### Q3. Is the ML-KEM situation different in KIND, and how precisely?

**Yes — different in kind, not degree.** The precise difference:

The cross-reference *mechanism* is identical in both drafts. Each protocol-layer draft
points at its KEM specification for the KEM-side input handling. What differs is what sits
at the far end of that pointer.

- **ML-KEM case — the far end supplies a check, and it is independently mandatory.**
  FIPS 203 defines a named "Encapsulation key check" with two concrete steps (§7.2), states
  its purpose ("ensures that the integers encoded in the public key are in the valid
  range [0, q − 1]"), and imposes the requirement with **`shall`**: "ML-KEM.Encaps shall not
  be run with an encapsulation key that has not been checked as above", reinforced at §3.3
  ("Implementers shall ensure that ML-KEM.Encaps and ML-KEM.Decaps are only executed on
  inputs that have been checked"). FIPS 203 is a normative standard in its own right,
  independent of SSH. The SSH draft then makes it its own obligation with "It also MUST
  perform the encapsulation key checks defined in Section 7.2 of [FIPS203]." Two normative
  instruments, one mandatory regardless of the other.

- **NTRU Prime case — the far end supplies no check, and imposes no obligation.**
  `[NTRUPrimePQCS]` is a NIST submission document, not a standard; it contains no BCP-14
  keyworded requirement, no input-checking algorithm, no validity predicate on a public
  key, and a decode function specified as total (§2a, §2b) with `Encap` correspondingly
  branch-free (§2c). The SSH draft's only affirmative statement about validation beyond
  length is the plain-language "No further validation is required…". One instrument, and it
  declines.

So the difference is in kind along this axis: **whether the KEM specification the SSH draft
incorporates normatively itself mandates a public-key check with `shall`-level force.**
For ML-KEM it does; for sntrup761 no equivalent exists to mandate. The SSH-layer obligation
in the ML-KEM draft is an inheritance of an external requirement, not a free-standing
choice; there is nothing in the NTRU Prime chain for a protocol layer to inherit.

Two secondary observations on the contrast, marked as observations rather than conclusions:

- The ML-KEM draft says it *aligns with* the ntruprime draft's "message abstraction, key
  derivation, and input to the SSH hash calculation" — and it conspicuously does not claim
  to align its **validation** requirements. Whether that was a deliberate decision or an
  oversight is **not** something I verified; see §5.
- RFC 9941 is a **published RFC**, Informational. So the citation that now governs
  `sntrup761x25519-sha512` is RFC 9941, and draft-06 is superseded. Any artifact that cites
  draft-06 should be updated.

---

## 5. What remains UNCERTAIN / NOT VERIFIED

Explicitly marked. None of these is resolved above; each is a real gap.

1. **The WG mailing-list discussion could not be searched.** `https://mailarchive.ietf.org/`
   returned a Cloudflare interstitial ("Just a moment...") on every attempt — I tried the
   search endpoint twice with different queries and got no content. **I therefore have NOT
   verified whether the sshm WG discussed public-key validation, canonicality, or the
   absence of a §7.2-equivalent check** — in the WG list, in consensus calls, or anywhere
   outside the IESG evaluation record. This is the single largest gap in this audit and it
   bears directly on Q3's secondary observations. `web_search` was also unavailable (the
   CLI returned HTTP 426, "Your Grok CLI version (1.0.5) is outdated"). **If this question
   matters for a finding, the WG archive must be searched with a working client.**

2. **I read only the IESG ballot record, not the WG record.**
   https://datatracker.ietf.org/doc/draft-ietf-sshm-ntruprime-ssh/ballot/ — the comments
   I retrieved concern the reference's URL/DOI, "variant instance" wording, SHOULD/MAY and
   IANA "OK to implement", the Informational-vs-Standards-Track question, and nit-level
   editorial matters. **No reviewer raised input validation, coefficient validity, or
   non-canonical public keys in that record.** Absence of a comment in the IESG ballot is
   not evidence that no WG discussion occurred.

3. **OpenSSH's `sntrup761.c` behaviour was NOT independently verified.** The claim that
   `kex_kem_sntrup761x25519_enc` performs only a length check, and that SUPERCOP's
   `Rq_decode` silently reduces out-of-range coefficients rather than rejecting, was taken
   as **given background** in the task brief. I did not read the OpenSSH portable source at
   commit `0ef0f5a8`, did not confirm which SUPERCOP revision the code derives from, and did
   not confirm the absence of any validation elsewhere in the call path (e.g. in the KEX
   wrapper or in the surrounding `kex` code). **The conformance conclusion in Q2 is
   conditional on that background being accurate.** An adversary of that premise should
   check it before the finding advances.

4. **My search of the NTRU Prime PDF was text-based, over `pdftotext -layout` output.**
   Figure/table content that is purely graphical would not be covered, and glyph fidelity
   was imperfect (I normalised `∈`, `←`, `′`, `≤`, superscript exponents). I read the
   decisive passages directly in the extracted text and they are internally consistent, but
   a re-check against the rendered PDF is cheap and would remove this residual doubt. The
   keyword search (§2g) covered the full extracted text and found no BCP-14 statement.

5. **Other NTRU Prime documents were not checked.** Only the round-3 submission was
   examined, because that is what RFC 9941 cites normatively. I did not check the round-1
   (`ntruprime-20171130.pdf`) or round-2 (`ntruprime-20190330.pdf`) documents, the
   `mods2.pdf` change summary, the accompanying `Supporting_Documentation`, or the
   NTRU Prime "Security" / "Software" / "Warnings" web pages. If a validation obligation
   exists anywhere in the NTRU Prime corpus, it could only affect this audit by being
   incorporated — and only `[NTRUPrimePQCS]` is — but I did not confirm that.

6. **No security assessment was performed and none should be inferred.** I did not evaluate
   whether silent reduction of non-canonical sntrup761 public keys is exploitable, whether
   it affects IND-CCA2, whether `HashConfirm`'s binding to K changes the picture (note the
   spec does say "Decapsulation verifies that the ciphertext is the correct ciphertext for
   this input, preventing per-input ciphertext malleability" — §2d context — which is about
   ciphertexts, not public keys), or whether TinySSH behaves differently from OpenSSH.
   **Q2 answers a conformance question, not a security question.**

7. **The lowercase-"required" ambiguity in Q1 is a judgement call.** I assess the answer as
   NO, and I give the alternative reading and why it lands in the same place — but a
   language-lawyer reading that treats the sentence as fully non-normative, and then asks
   whether any other document supplies an obligation, is a defensible path to a different
   emphasis. I did not resolve it by fiat; both readings are on the record.

8. **Not checked:** whether any IANA SSH registry entry, NIST SP 800-227, or other
   standards document imposes an independent pk-validation duty on KEMs used in SSH.
   SP 800-227 is cited by both FIPS 203 and the ML-KEM draft; I did not read it.
