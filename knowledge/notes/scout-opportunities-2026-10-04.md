# Opportunity scan, 2026-10-04 — post-X.509 dossier

Source: SCOUT-2, read-only scout. A first scout (SCOUT-1) ran 104 tool calls and
died before writing anything; this one was deliberately scoped to ~25 calls and
to writing incrementally. **That scoping was not needed** — the failure was an
infrastructure error, not verbosity — but the smaller dossier is more usable.

## Ground already covered (so none of these is a re-run)

X.509 pathLen (this session), ML-KEM/FIPS 203, HPKE + X-Wing, CBOR, COSE,
FROST, SSH hybrid KEX, C23 `#embed`, strict aliasing.

## Four candidates, ranked

### 1. DNSSEC RRSIG validation — RFC 4035 §5.3.1 / §5.3.2  ← top recommendation

**Decisive clause.** RFC 4035 §5.3.2 writes the signed-data reconstruction as an
executable production with a defined byte layout and sort order:

> `signed_data = RRSIG_RDATA | RR(1) | RR(2) ...`

with `rrsig_labels` / `fqdn_labels` cases, including an explicit
"rrsig_labels MUST NOT exceed fqdn_labels"-style rejection. *Verified by the
orchestrator: fetched RFC 4035 independently (130589 bytes, SHA-256
`8978b120636c69b2080b12768266ec48cd4c0879583310863a62f7c409908084`) and read
§5.3.2 directly; the production is present and quoted accurately.*

**Oracle.** A ~200-line reconstruction of the §5.3.2 byte layout plus the
§5.3.1 conjunct checks, validated against its own signatures before any adapter
is trusted.

**Cohort.** miekg/dns, hickory-dns, ldns, PowerDNS, Unbound — but see the
caveat below.

**Compute.** Lightweight. No toolchain. Reuses the CBOR/COSE cleanroom pattern.

### 2. QUIC packet protection — RFC 9001 §5.3 / §5.4

"The unprotected packet header is part of the associated data" settles AAD
normatively; §5.4 gives the 4-bit/5-bit mask split and the counter-intuitive
rule that the header-protection key does **not** change after a key update.

### 3. JOSE reject rules — RFC 8725 §3.3 / §3.4 / §3.11

§3.3's nested-JWT requirement is a concrete MUST a two-layer token can detect;
§3.4 delegates to a named NIST SP 800-56A routine.

### 4. TLS 1.3 `certificate_request_context` — RFC 8446 §4.4.2

Crispest clause of all (MUST be unique / SHALL be zero length), but ranked last
because lineage collapses: BoringSSL ≡ AWS-LC, and rustls vendors both `ring`
and `aws-lc-rs`.

## What the scout flagged against its own recommendation

This is the part worth keeping:

- **Candidate 1's independence is weaker than a headcount suggests.** `ldns`,
  Unbound and PowerDNS share Dutch academic / NLnet practice, so that is ~3–4
  families, not 5+. Recorded rather than letting the count flatter the case.
- Three lineage claims were explicitly marked **unverified** rather than
  asserted: the ngtcp2/quic-go non-relationship, the Go JOSE libraries'
  relationship, and "inherits the CBOR/COSE framework" (the code was not read).

## Not investigated (stated, not glossed)

RFC 4034, RFC 8446 §4.6.2, the RFC 751x set, RFC 9000's body, NIST SP 800-56A,
RFC 6960. Anything depending on those is unverified and unquoted in the dossier.

## Orchestrator's assessment

Candidate 1 is the strongest follow-on **if and only if** its independence is
re-derived before any finding is written. The §5.3.2 production is unusually
oracle-friendly — it is literally a byte-layout specification — which is the
property that made the X.509 work productive. The risk is that a 3-family cohort
produces correlated "agreement" that reads like independence; that exact failure
mode (BoringSSL/AWS-LC appearing as two votes) already occurred in the X.509
mission.

Recommended first step: build the cleanroom §5.3.2 oracle and check it against
DNSSEC's own published test vectors **before** writing a single adapter.
