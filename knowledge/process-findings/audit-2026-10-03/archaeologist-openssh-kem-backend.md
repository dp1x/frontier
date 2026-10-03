<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: archaeologist_openssh_backend.md -->

# Implementation-Archaeology Report: OpenSSH portable `crypto_kem_*_enc` and the FIPS 203 §7.2 check

Role: `implementation-archaeologist` (read-only over target code; no repo edits, no commits).
Date of investigation: 2026-10-02.
Primary target commit: `0ef0f5a839831c213f24e3f2ae434765c607fb50` (the commit cited by
`knowledge/findings/fnd-2026-0009.yaml`).
Comparison point: `openssh-portable` `master` @ `87f0cd1892e501f835dd210abea5461807c8deba`.

## 0. Bottom line

**Yes — for ML-KEM-768, OpenSSH *does* perform an FIPS 203 §7.2 encapsulation-key check. It is not
in the SSH KEX layer; it is one layer down, inside `crypto_kem_mlkem768_enc`.**

- The check is at **`libcrux-mlkem-mldsa.c:90`** (commit `0ef0f5a8`):

  ```c
  if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&pk_internal))
          return -1;
  ```

- That function is libcrux's FIPS 203 §7.2 modulus check. The vendored C says so verbatim at
  **`libcrux_internal.h:26220-26226`**: *"Validate an ML-KEM public key. **This implements the
  Modulus check in 7.2 2.** Note that the size check in 7.2 1 is covered by the `PUBLIC_KEY_SIZE`
  in the `public_key` type."*
- The comparison itself is at **`libcrux_internal.h:26246`**: deserialize-to-reduced, re-serialize,
  `memcmp`-equivalent the full 1184 bytes.

**For NTRU Prime 761 the picture is the opposite: there is no check anywhere.** No equivalent of
the §7.2 style modulus check exists in `sntrup761.c`; `crypto_kem_sntrup761_enc` is a verbatim
SUPERCOP `crypto_kem/sntrup761/compact/kem.c` encapsulation.

**Consequence for `fnd-2026-0009`: the finding's ML-KEM half is MISATTRIBUTED and its central
claim is FALSE.** The empirical evidence it cites (sshd reached signature verification instead of
rejecting C_INIT) cannot be explained by the source, because the source rejects a non-canonical
`ek` with `SSH_ERR_INTERNAL_ERROR` before any ciphertext or signature is produced. That
discrepancy is itself a finding that needs explaining.

---

## 1. Provenance and integrity of what I read

Every local copy was verified by recomputing the git blob SHA-1 and comparing against the tree
listing returned by the GitHub trees API for commit `0ef0f5a8`:

| File | git blob SHA-1 | Pinned tree SHA | Match |
|---|---|---|---|
| `libcrux-mlkem-mldsa.c` | `1ce21b9c7a8d6c0f501f89a91988eb2a1ec786b9` | `1ce21b9c7a8d6c0f501f89a91988eb2a1ec786b9` | **MATCH** |
| `defines.h` | `634db453e5797481b2314130644be8f1b4b61021` | `634db453e5797481b2314130644be8f1b4b61021` | **MATCH** |
| `configure.ac` | `aba0291b6ba1cfc33fccccadba24c9031889ac8d` | `aba0291b6ba1cfc33fccccadba24c9031889ac8d` | **MATCH** |
| `sntrup761.c` | `a731e560f6f8ba426c13104b1f7daf6580001d34` | (not in truncated API view) | n/a — SHA-1 recomputed |
| `crypto_api.h` | `f8441ed6f5eb96de953eb6ef2ed5a88fd8905de2` | `f8441ed6f5eb96de953eb6ef2ed5a88fd8905de2` | **MATCH** |
| `kexmlkem768x25519.c` | `e2c2c0a86e4352acc97d33bdb9a27755d1e370f2` | `e2c2c0a86e4352acc97d33bdb9a27755d1e370f2` | **MATCH** |

Note: the recursive trees API response was truncated by the fetch tool at ~63 KB of 219 KB. I
parsed the saved JSON locally to recover the full 911-entry listing; that recovered the entries
quoted here. I did not need to guess any file name.

**All KEM-relevant files are byte-identical between `0ef0f5a8` and current master** (verified by
comparing blob SHAs):

```
SAME  libcrux-mlkem-mldsa.c      SAME  sntrup761.c
SAME  defines.h                 SAME  kexmlkem768x25519.c
SAME  kexsntrup761x25519.c      SAME  mlkem_mldsa.sh
SAME  sntrup761.sh              SAME  libcrux_internal.h
SAME  kexmlkem768ecdh.c         SAME  regress/unittests/crypto/test_mlkem.c
DIFF  crypto_api.h              DIFF  configure.ac
```

The two diffs are unrelated to KEM validation:
- `crypto_api.h` v1.12→v1.13: only Ed25519 API renames (`crypto_sign_ed25519` →
  `crypto_sign_ed25519_detached`, `..._open` → `..._verify_detached`, `..._keypair_from_seed` →
  `..._seed_keypair`). No KEM change.
- `configure.ac`: one extra `-Wno-error` CFLAG probe, removal of a NetBSD `BROKEN_READ_COMPARISON`
  define, and two added `AC_CHECK_FUNCS` entries. No KEM change.

**Therefore every KEM conclusion below holds for master HEAD `87f0cd18` as well as for `0ef0f5a8`.**

---

## 2. Which upstream project was the code assembled from?

VERIFIED, and it is **not** mlkem-native, not liboqs, not PQClean. The answer is **(d) something
else: CrySPEN `libcrux`**, plus SUPERCOP for sntrup761.

### 2.1 ML-KEM / ML-DSA: CrySPEN `libcrux`

`mlkem_mldsa.sh` (pinned + master, identical) is the provenance record. Its header:

```sh
#!/bin/sh
#       $OpenBSD: mlkem_mldsa.sh,v 1.1 2026/06/14 03:59:34 djm Exp $
#       Placed in the Public Domain.
#

WANT_LIBCRUX_REVISION="origin/jonas/combined-extraction-mldsa"

BASE="libcrux/combined_extraction/generated"
FILES="
	$BASE/eurydice_glue.h
	$BASE/combined_core.h
	...
	$BASE/libcrux_mlkem768_portable.h
"
```

It clones `https://github.com/cryspen/libcrux`, hard-resets to
`WANT_LIBCRUX_REVISION`, concatenates the generated headers, strips `#include`s, converts Rust
constructors to C compound literals, and emits `libcrux_internal.h` with this banner:

```
/* Extracted from libcrux revision $LIBCRUX_REVISION */
```

**COULD-NOT-DETERMINE (exact pin):** `WANT_LIBCRUX_REVISION` is a *branch name*
(`origin/jonas/combined-extraction-mldsa`), not a commit hash, and `LIBCRUX_REVISION` is computed at
generation time and never committed. So the exact libcrux commit OpenSSH vendored is **not
recorded anywhere in the repository**. This is a real supply-chain reproducibility gap worth
recording separately (it is a `dependency-analyst` observation, not mine to resolve).

Evidence that the code is Eurydice/C-callgrind extracted Rust, not hand-written C: the function
bodies retain Rust doc-comments and monomorphization names, e.g. `libcrux_internal.h:26228`:

```
A monomorphic instance of libcrux_ml_kem::ind_cca.validate_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
```

The glue file that OpenSSH actually calls — `libcrux-mlkem-mldsa.c` — is OpenSSH's own, by Damien
Miller (`$OpenBSD: libcrux-mlkem-mldsa.c,v 1.1 2026/06/14 03:59:34 djm Exp $`), ISC-licensed.

### 2.2 sntrup761: SUPERCOP 20240808

`sntrup761.c:1-8`:

```c
/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */
```

`sntrup761.sh:8-14` names the exact upstream files:

```sh
AUTHOR="supercop-20240808/crypto_kem/sntrup761/ref/implementors"
FILES=" supercop-20240808/cryptoint/crypto_int16.h
	supercop-20240808/cryptoint/crypto_int32.h
	supercop-20240808/cryptoint/crypto_int64.h
	supercop-20240808/crypto_sort/int32/portable4/sort.c
	supercop-20240808/crypto_sort/uint32/useint32/sort.c
	supercop-20240808/crypto_kem/sntrup761/compact/kem.c
"
```

So: **`crypto_kem/sntrup761/compact/kem.c` from SUPERCOP-20240808**, with OpenSSH-local `sed`
rewrites (notably replacing `crypto_kem_` → `crypto_kem_sntrup761_`, and swapping the reference
`Short_random`/`Small_random` for `randombytes()`-backed versions, `sntrup761.sh:90-110`).

---

## 3. ML-KEM-768: the full call chain, and where the check is

### 3.1 The SSH KEX layer (the layer `fnd-2026-0009` audited) — length check only

`kexmlkem768x25519.c`, `kex_kem_mlkem768x25519_enc()`. VERIFIED. The finding's quote of lines
117-119 is **accurate**:

```c
	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	if (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);
```

then, later in the same function:

```c
	/* generate and encrypt KEM key with client key */
	if (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
```

So the KEX layer itself is length-only. **The finding is right about this layer and wrong to stop
here.** The layer above the primitive is not where a FIPS 203 §7.2 check belongs; §7.2 is a
property of the encapsulation-key input, so the natural (and here actual) place to enforce it is
the encapsulation function that consumes `ek`.

### 3.2 The crypto_api wrapper — `crypto_kem_mlkem768_enc`

`libcrux-mlkem-mldsa.c:65-100`, VERIFIED, quoted in full:

```c
int
crypto_kem_mlkem768_enc(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    const uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES])
{
	uint8_t rnd[crypto_kem_mlkem768_ENCSEEDBYTES];
	int r;

	arc4random_buf(rnd, sizeof(rnd));
	r = crypto_kem_mlkem768_enc_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, sizeof(rnd));
	return r;
}

int
crypto_kem_mlkem768_enc_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    const uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    const uint8_t seed[crypto_kem_mlkem768_ENCSEEDBYTES])
{
	libcrux_mlkem768_enc_result enc;
	libcrux_mlkem768_pk pk_internal;
	libcrux_mlkem768_enc_rnd rnd;

	memcpy(pk_internal.data, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&pk_internal))
		return -1;
	memcpy(rnd.data, seed, sizeof(rnd.data));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_internal, rnd);
	memcpy(ct, enc.fst.data, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	memcpy(shared_secret, enc.snd.data, crypto_kem_mlkem768_BYTES);

	explicit_bzero(&enc, sizeof(enc));
	explicit_bzero(&rnd, sizeof(rnd));
	return 0;
}
```

**This is the answer to "does `crypto_kem_mlkem768_enc` perform an FIPS 203 §7.2 check?" — YES, at
`libcrux-mlkem-mldsa.c:90`.** It is unconditional, and it happens *before* `encapsulate` is called.

An important nuance the task brief anticipated: **libcrux's `encapsulate` does NOT self-validate.**
I read `libcrux_internal.h:25368-25411` (`libcrux_ml_kem_ind_cca_encapsulate_99`) and it goes
straight from entropy pre-processing to hashing `ek` and calling `ind_cpa_encrypt` — there is no
validation call anywhere in that function or in its callees. So the check is **not** inside
`encapsulate` (ruling out hypothesis (a) as literally stated, and (b) as well); it is a deliberate
guard written by OpenSSH in its own glue file, calling libcrux's public
`validate_public_key` entry point. That is a *stronger* provenance signal than hypothesis (a):
OpenSSH's author knew about the check and wired it in.

### 3.3 The check itself — libcrux's FIPS 203 §7.2 modulus check

`libcrux_internal.h:26220-26275`, VERIFIED. Comment and body:

```c
/**
 Validate an ML-KEM public key.

 This implements the Modulus check in 7.2 2.
 Note that the size check in 7.2 1 is covered by the `PUBLIC_KEY_SIZE` in the
 `public_key` type.
*/
/**
A monomorphic instance of libcrux_ml_kem::ind_cca.validate_public_key
...
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
static KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_public_key_b6(const Eurydice_arr_5f *public_key)
{
  Eurydice_arr_bb0
  deserialized_pk =
    libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_68(Eurydice_array_to_subslice_to_shared_210(public_key,
        libcrux_ml_kem_constants_ranked_bytes_per_ring_element((size_t)3U)));
  Eurydice_arr_5f
  public_key_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_key_b6(&deserialized_pk,
      Eurydice_array_to_subslice_from_shared_5f2(public_key,
        libcrux_ml_kem_constants_ranked_bytes_per_ring_element((size_t)3U)));
  return Eurydice_array_eq((size_t)1184U, public_key, &public_key_serialized, uint8_t);
}
```

and the public entry point, `libcrux_internal.h:26266-26275`:

```c
/**
 Validate a public key.

 Returns `true` if valid, and `false` otherwise.
*/
static inline bool
libcrux_ml_kem_mlkem768_portable_validate_public_key(const Eurydice_arr_5f *public_key)
{
  return libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_key_3b(public_key);
}
```

This is the canonical FIPS 203 §7.2 (2) construction: decode each ring element with the
*reduce*-then-re-encode path, re-serialize, and compare all 1184 bytes against the input. Any
coefficient `>= q = 3329` round-trips to a different byte string and the comparison fails. (Note
the constant `1184U` is `crypto_kem_mlkem768_PUBLICKEYBYTES`, matching `crypto_api.h:83`.)

Supporting decode path, `libcrux_internal.h:26202-26218`
(`..._deserialize_ring_elements_reduced_out_68`) and `:23655-23681`
(`..._deserialize_ring_elements_reduced_68`), which slices each
`LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT`-byte chunk and calls
`libcrux_ml_kem_serialize_deserialize_to_reduced_ring_element_ea`.

I checked for the specific patterns the brief asked about and they are **absent** by design —
libcrux does not implement the check as a `>= 3329` comparison or a `ct_memcmp`; it uses
decode/re-encode/compare. Its `Fq`/reduction is internal to the deserializer. So a grep for `3329`
or `kPrime` would have found nothing, and a grep-for-a-missing-check would have been misleading.

### 3.4 What happens on a REJECTED key

VERIFIED, by following the return value up the stack:

1. `libcrux_ml_kem_mlkem768_portable_validate_public_key` returns `false`.
2. `libcrux-mlkem-mldsa.c:90-91` → `return -1` **before** `encapsulate`, before any `arc4random`
   consumption, before any ciphertext bytes exist.
3. `crypto_kem_mlkem768_enc` returns `-1`.
4. `kexmlkem768x25519.c` → `r = SSH_ERR_INTERNAL_ERROR; goto out;`
5. sshd disconnects the connection.

**It is a hard rejection with an error code, not a silent reduce/accept.** No degenerate shared
secret is ever computed from a non-canonical `ek`. That is the correct and safe behaviour.

### 3.5 Decapsulation side

`crypto_kem_mlkem768_dec` (`libcrux-mlkem-mldsa.c:102-117`) performs **no** validation — it does not
need to, per FIPS 203: decapsulation takes the *secret* key, and the ciphertext `c` is
implicit-rejection-tolerant by design. Not a gap.

### 3.6 Test coverage

`regress/unittests/crypto/test_mlkem.c` (`$OpenBSD: test_mlkem.c,v 1.2 2026/06/16`) is **KAT-only**:
it runs 5 known-answer vectors through keygen/encaps/decaps and compares hashes. It does **not**
test the rejection path. So the `validate_public_key` guard is **untested in-tree**. The extraction
smoke test in `mlkem_mldsa.sh` does exercise it, but only on a *positive* case:

```c
	keypair = libcrux_ml_kem_mlkem768_portable_generate_key_pair(kp_seed);
	if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&keypair.pk))
		errx(1, "valid smoke failed");
```

i.e. it asserts a good key validates, and never asserts a bad key is rejected. OBSERVATION: a
negative unit test here would be cheap and would pin the security-relevant behaviour that
`fnd-2026-0009` got wrong.

---

## 4. NTRU Prime 761: no check anywhere

### 4.1 `crypto_kem_sntrup761_enc` — VERIFIED, full body

`sntrup761.c:2119-2127`:

```c
int crypto_kem_sntrup761_enc(unsigned char *c, unsigned char *k, const unsigned char *pk) {
  Inputs r;
  unsigned char r_enc[Small_bytes], cache[Hash_bytes];
  Hash_prefix(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  return 0;
}
```

`Hide` is `sntrup761.c:2113-2117`:

```c
static void Hide(unsigned char *c, unsigned char *r_enc, const Inputs r, const unsigned char *pk, const unsigned char *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_bytes, r_enc, cache);
}
```

`ZEncrypt` is `sntrup761.c:2071-2076`:

```c
static void ZEncrypt(unsigned char *C, const Inputs r, const unsigned char *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}
```

**There is no validation of `pk` on any path.** No range check, no re-encode/compare, no error
return. `crypto_kem_sntrup761_enc` returns `int` but **always returns `0`** — the return type
exists only for API symmetry with the `crypto_kem_*` namespace. It cannot signal rejection because
it never detects one.

### 4.2 What happens to an out-of-range coefficient instead — silent reduction

VERIFIED. `Rq_decode` (`sntrup761.c:2038-2044`) is the decode step:

```c
static void Rq_decode(Fq *r, const unsigned char *s) {
  uint16_t R[p], M[p];
  int i;
  for (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  for (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}
```

`Decode(R, s, M, p)` with `M[i] = q` is the generic NTRU Prime decoder that produces values in
`[0, q)` by construction (that is precisely how SUPERCOP's `compact` variant canonically decodes a
`pk`, whose coefficients are already required to be in `[0,q)` by the encoding `Rq_encode`,
`sntrup761.c:2030-2035`). Feeding it a non-canonical byte string yields *some* element of
`F_q^2` — it cannot error — and the ciphertext is computed against the implicitly reduced `h`.

**So the NTRU Prime half of `fnd-2026-0009` is behaviourally right but causally wrong**: the
cohort is indeed lenient, but not because OpenSSH "omitted" a check at the SSH layer. It is lenient
because the SUPERCOP reference KEM has no such check to omit, and `Rq_decode` silently reduces
instead of rejecting. There is no upstream oracle being ignored here.

**COULD-NOT-DETERMINE:** whether `draft-ietf-sshm-ntruprime-ssh-06` §2.1 actually mandates such a
check for NTRU Prime (the analogous requirement is a draft-text question, not a code question, and
I did not fetch the draft). The finding asserts it does. I am reporting only what the code does,
which is unambiguous: no check, silent reduction, always returns 0.

### 4.3 Coherence note

`fnd-2026-0009` claims OpenSSH "implements only the first half" of the §2.1 pair
(length check + encapsulation-key check) for **both** cohorts. The truth is asymmetric:

| Cohort | KEX layer | KEM primitive | Net behaviour |
|---|---|---|---|
| `mlkem768x25519-sha256` | length only | **§7.2 modulus check** (`libcrux-mlkem-mldsa.c:90`) | **STRICT** |
| `sntrup761x25519-sha512` | length only | none (SUPERCOP `compact/kem.c`) | **LENIENT** |

The finding treats these as one homogeneous defect. They are not.

---

## 5. How the KEM gets into the build: `configure.ac` question answered

**There is no `USE_MLKEM768X25519` configure option.** VERIFIED, and this contradicts the task
brief's premise (which asked how `USE_MLKEM768X25519=1` "pulls in the KEM").

I searched the complete `configure.ac` (164,403 bytes, 5941 lines, git blob SHA verified against
the tree listing; string counts `USE_MLKEM768X25519` = 0, `USE_SNTRUP761X25519` = 0, `USE_MLDSA` = 0,
`AC_DEFUN` = 0). The only `mlkem` hit in the whole file is unrelated:

`configure.ac:3355-3358`:
```m4
	case "$openssl_impl" in
	aws-lc|boringssl)
		# Brainpool does not work with AWC-LS or BoringSSL.
		unsupported_algorithms="$unsupported_algorithms mlkem768brainpoolp256r1-sha256"
```

The KEM is **compiled in unconditionally**, gated only on compiler-feature probes in `defines.h`.
`defines.h:993-1002`:

```c
/*
 * sntrup761 uses variable length arrays and c99-style declarations after code,
 * so only enable if the compiler supports them.
 */
#if defined(VARIABLE_LENGTH_ARRAYS) && defined(VARIABLE_DECLARATION_AFTER_CODE)
# define USE_SNTRUP761X25519	1
/* The ML-KEM768 and ML-DSA implementations also uses C89 features */
# define USE_MLKEM768X25519	1
# define USE_MLDSA		1
#endif
```

The backend is **vendored C source, in-tree**, not an external library and not an OpenSSL
provider. `Makefile.in:105,109`:

```make
	libcrux-mlkem-mldsa.o ssh-mldsa-eddsa.o \
	...
	kexsntrup761x25519.o kexmlkem768x25519.o sntrup761.o kexgen.o \
```

So `USE_MLKEM768X25519=1` on the configure command line, as used in `fnd-2026-0009`'s reproducer
and in the cited GHA run, is a **no-op**. It does not enable the KEM; the KEM is always on (given a
conforming C compiler). This matters for the finding's `scope` and `reproducer` fields, which
describe a *non-default opt-in build*; in fact on any standard Linux/Ubuntu build with a C99+
compiler these hybrid KEX methods are **always compiled in**. The scope statement is wrong in a way
that overstates how special the tested build was.

---

## 6. Epistemic ledger

VERIFIED (read directly, hashes pinned and checked):
- `crypto_kem_mlkem768_enc` → `..._enc_seeded` → `validate_public_key` at
  `libcrux-mlkem-mldsa.c:90`. **A FIPS 203 §7.2 check is performed, unconditionally, before
  encapsulation.**
- The check is the decode/re-encode/compare construction at `libcrux_internal.h:26234-26247`, with
  libcrux's own comment naming §7.2 2 at `:26223`.
- Rejection is hard: `-1` → `SSH_ERR_INTERNAL_ERROR` → disconnect. No ciphertext, no signature.
- libcrux's `encapsulate` (`libcrux_internal.h:25368-25411`) does **not** self-validate. The guard
  is OpenSSH-authored glue, not a libcrux side effect.
- `crypto_kem_sntrup761_enc` (`sntrup761.c:2119-2127`) performs **no** validation and always returns
  0; `Rq_decode` (`sntrup761.c:2038-2044`) silently reduces out-of-range input.
- Upstream origins: CrySPEN `libcrux` (via `mlkem_mldsa.sh`), SUPERCOP-20240808
  `crypto_kem/sntrup761/compact/kem.c` (via `sntrup761.sh`).
- `USE_MLKEM768X25519` is set unconditionally in `defines.h:1000`, gated on VLA + C99
  declarations-after-code. No configure option exists. Backend is vendored in-tree C.
- All KEM-relevant files are byte-identical between `0ef0f5a8` and master `87f0cd18`; the only two
  differing files changed for unrelated reasons (Ed25519 renames; generic configure probes).

INFERRED (well-supported, not directly executed):
- That a non-canonical ML-KEM `ek` reaching a correctly-built `0ef0f5a8` sshd produces
  `SSH_ERR_INTERNAL_ERROR` and a disconnect *before* the KEM shared secret exists. This follows
  necessarily from the three code facts above plus the call graph in `kexmlkem768x25519.c`; I did
  not build sshd and execute it.
- That the NTRU Prime "small-coefficient range check" the finding describes does not exist in this
  backend because the SUPERCOP `compact` variant never had one to omit.

COULD-NOT-DETERMINE:
- **The exact libcrux commit vendored into `libcrux_internal.h`.** `mlkem_mldsa.sh` pins a branch
  name, and the resolved SHA is printed to stderr at generation time but never committed. Not
  recoverable from the repository.
- **Whether `draft-ietf-sshm-ntruprime-ssh-06` §2.1 in fact mandates an encapsulation-key check.**
  Draft text was not fetched; this is a specification-analyst question.
- **Why the GHA run `33288641132` in `fnd-2026-0009` showed the server reaching signature
  verification.** The source says it cannot. Candidate explanations I cannot separate from here
  without the harness: the tampered byte did not actually produce a non-canonical `ek` (e.g. the
  mutation hit the `rho`/hash suffix bytes, or the 12-bit coefficient was set to a value that
  still round-trips); the built sshd was not from this commit; or `client_blob` layout differed
  from the assumption. This is now the most important open question in the finding and should block
  any further promotion of it.

---

## 7. What this means for `fnd-2026-0009`

I am not the role that demotes findings (`synthesizers assemble; adversarial-critic writes
reviews`; promotion rules live in `Agents.md`). Recording what I believe the evidence shows, for
whoever owns that decision:

1. **The ML-KEM half of the statement is false as written.** "The server does NOT perform the
   12-bit coefficient range check" is contradicted by `libcrux-mlkem-mldsa.c:90`. The finding
   audited `kexmlkem768x25519.c` and stopped one layer above the check. The verdict "LENIENT" for
   `mlkem768x25519-sha256` should be **STRICT**.
2. **The NTRU Prime half is directionally right but misattributed**, and its proposed remedy
   ("add the coefficient check to `kex_kem_sntrup761x25519_enc`") would be a patch to the wrong
   layer, in a file that is OpenBSD-imported and shared with OpenSSH proper.
3. **The `scope` field is wrong**: `USE_MLKEM768X25519=1` is a no-op; the tested cohort is not an
   opt-in build.
4. **The cited empirical evidence contradicts the source** and must be re-run and explained before
   the finding keeps any `verified_conclusion` status.
5. The one genuinely durable, correctly-scoped observation in the finding is the NTRU Prime
   leniency (§4), and that deserves its own, separate finding scoped to SUPERCOP
   `sntrup761/compact/kem.c`.

## 8. Files cited (absolute paths)

Local read-only copies made for this investigation (scratch, disposable, not repo artifacts):

- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\libcrux-mlkem-mldsa.c`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\libcrux_internal.h`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\sntrup761.c`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\sntrup761.sh`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\mlkem_mldsa.sh`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\crypto_api.h`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\defines.h`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\configure.ac`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\0ef0f5a8\Makefile.in`
- `C:\Users\Dhane\frontier\.scratch\openssh_src\master\…` (same set, for comparison)

Upstream, read at commit `0ef0f5a839831c213f24e3f2ae434765c607fb50` unless noted:

- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/libcrux-mlkem-mldsa.c#L90`
- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/libcrux_internal.h#L26220-L26275`
- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/kexmlkem768x25519.c#L117-L119`
- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/sntrup761.c#L2119-L2127`
- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/defines.h#L993-L1002`
- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/sntrup761.sh#L8-L14`
- `https://github.com/openssh/openssh-portable/blob/0ef0f5a839831c213f24e3f2ae434765c607fb50/mlkem_mldsa.sh`
- master: `https://github.com/openssh/openssh-portable/tree/87f0cd1892e501f835dd210abea5461807c8deba`

Repo artifacts read (unmodified):

- `C:\Users\Dhane\frontier\knowledge\findings\fnd-2026-0009.yaml`
- `C:\Users\Dhane\frontier\roles\README.md`

No repository file was created, edited, or committed. This report is the only file written.
