# Reference library

Primary-source documents kept in-repo so missions never depend on live network
access to cite the normative text. NIST FIPS publications are freely available;
committing them here is for reproducibility of citations.

| File | What it is | Why Frontier keeps it |
|------|------------|----------------------|
| `fips203.pdf` | NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (final, 2024-08-13). Source: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf> | Normative source for the bootstrap mission `msn-2026-0001` (ML-KEM encapsulation-key checking). |

Rules:

- Citations must reference section/algorithm/page inside the committed PDF, not
  a blog summary.
- When a standard updates, add the new revision as a new file; never overwrite
  the old one — superseded specs remain part of the evidence graph history.
- Related documents to acquire later: SP 800-227 (KEM recommendations),
  FIPS 204/205, official ACVP test-vector sets for ML-KEM.

## Key facts already extracted from fips203.pdf (verified 2026-08-23)

These are recorded so agents do not re-download or mis-cite. Page numbers refer
to the printed page markers in the committed PDF.

- **Encapsulation-key check (§7.2, pp. 35–36):** two steps.
  1. Type check: `len(ek) == 384k + 32`.
  2. Modulus check (Eq. 7.1): compute
     `test ← ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))` and require
     `test == ek[0:384k]`. This "ensures that the integers encoded in the
     public key are in the valid range [0, q−1]".
- **Check placement (§7.2, p. 36):** "ML-KEM.Encaps shall not be run with an
  encapsulation key that has not been checked as above. However, checking of
  the encapsulation key need not be performed by the encapsulating party, nor
  with every execution of ML-KEM.Encaps." Assurance may come from other means
  (SP 800-227).
- **Decapsulation checks (§7.3, pp. 36–37):** ciphertext type check
  (`32(du·k + dv)` bytes), dk type check (`768k + 96` bytes), hash check
  `H(dk[384k:768k+32]) == dk[768k+32:768k+64]`. Ciphertext checking shall be
  performed with **every** execution of Decaps.
- **Key-pair check (p. 35):** seed consistency, ek check, dk check,
  pair-wise consistency (encaps then decaps, reject unless K == K′).
- **ByteEncode/ByteDecode (Algorithms 5–6, §4.2.1):** d=12 decode reduces mod
  q = 3329 after interpreting 12-bit little-endian segments; values in
  [3329, 4095] can appear only for arrays not produced by ByteEncode₁₂ — the
  reason the §7.2 round-trip check works.
- **Sizes (Table 3, p. 39):** ek/dk/ct/ss = 800/1632/768/32 (512),
  1184/2400/1088/32 (768), 1568/3168/1568/32 (1024).
- **Parameter recommendation (p. 40):** NIST recommends ML-KEM-768 default.
- A planning note dated 2025-11-17 on the CSRC page flags errata ("potential
  updates") via a spreadsheet under Documentation on the FIPS 203 CSRC page —
  consult before claiming spec-level conclusions.
