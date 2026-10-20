# X.509 self-issued pathLenConstraint experiment (preserved evidence)

## Expected classifications (RFC 5280)

- T1 `R -> C(pathLenConstraint=0) -> EE`: ACCEPT.
- T2 `R -> C(pathLenConstraint=0) -> I_C -> EE`: REJECT at C.
- T3 `R -> C(pathLenConstraint=0) -> S(self-issued, no pathLenConstraint) -> EE`: ACCEPT.
- T4 `R -> C(pathLenConstraint=2) -> S(pathLenConstraint=0) -> I_S -> EE`: REJECT at S.
- T5 `R -> C(pathLenConstraint=2) -> S(pathLenConstraint=1) -> I_S -> EE`: ACCEPT.

Normative basis: RFC 5280 6.1.1 (self-issued certificates are not counted), 6.1.4(l) (decrement only if not self-issued), 6.1.4(m) (clamp, no self-issued guard), 4.2.1.9. RFC 5280 6.2 permits stricter implementations, so stricter behavior is not automatically a conformance defect.

## Prior art

NIST PKITS test 4.6.15 already exercises the same self-issued counting exemption as T3.

## Toolchain pins

- Go 1.27.3 windows/arm64.
- OpenSSL 3.6.5 29 Sep 2026 (VC-WIN64-ARM).

## Raw output filename mapping

The OpenSSL raw files are cyclically shifted relative to their labels:

- raw/openssl_T1.txt -> T5 (EE_T5)
- raw/openssl_T2.txt -> T1 (EE_T1)
- raw/openssl_T3.txt -> T3 (EE_T3)
- raw/openssl_T4.txt -> T4 (EE_T4)
- raw/openssl_T5.txt -> T2 (EE_T2)

Use the EE target and chain in each file, not the filename, for attribution.

## Limitations

- Only Go and OpenSSL were executed.
- ECDSA signatures are non-deterministic, so regenerating changes DER hashes; manifest hashes pin the observed inputs.
- T3 is an implementation difference, not a demonstrated security issue or conformance violation.
- No independent upstream contact or finding promotion has been performed.
