# Reproducer: ML-KEM §7.2 differential characterization (msn-2026-0001)

Reproduces the executed differential table from committed commands. Every leg
is deterministic; verdicts must match `knowledge/observations/obs-*.yaml`.

## Stimuli

`stimuli/stimuli.tsv` (199 vectors) is generated deterministically by
`tools/gen_vectors.py` (fixed seeds inline per vector; Wycheproof
`ModulusOverflow` vectors pinned to C2SP wycheproof @ dac1dd47, files
`testvectors_v1/mlkem_{512,768,1024}_encaps_test.json`). Regenerate:

    python tools/gen_vectors.py --wycheproof-dir <wycheproof testvectors_v1> \
        --out stimuli.json && python tools/flatten_vectors.py stimuli.json stimuli.tsv

## Legs

| # | Implementation | Version | Command | Expected |
|---|----------------|---------|---------|----------|
| 1 | PQClean clean | master 0586a824 | see reproduce.ps1 leg 1 | all length-valid accepted (rc=0), wrong-length inexpressible |
| 2 | liboqs + mlkem-native | 0.16.0 / v1.2.0 | leg 2 | all non-canonical rejected (-1), canonical accepted |
| 3 | Go crypto/mlkem | go1.26.4 | leg 3 | malformed rejected with length/modulus error classes |
| 4 | RustCrypto ml-kem | 0.3.2 | leg 4 | all malformed import-rejected |
| 5 | OpenSSL | openssl-3.5.7 @ 8cf17aae | CI (.github/workflows/mlkem-diff.yml) | both checks at raw import |
| 6 | .NET MLKem | net10.0 | CI | recorded with runtime/backing metadata |

## Environment requirements

Windows host with MSVC 14.51 Build Tools + Windows SDK 10.0.26100.0 (legs 1-2),
Go >= 1.24 (leg 3), Rust >= 1.85 + network for crates.io fetch of declared
dependency (leg 4). All untrusted-code execution goes through
`frontier.execute.run_command` in a scratch workspace (env-scrubbed).

## Congruent-plant property (mission-novel family)

For every `congruent-plant` vector: ByteDecode12(ek'[0:384k]) equals
ByteDecode12(base[0:384k]) coefficient-wise while ByteEncode12 re-encodes
differently (planted = c_i + q at up to three positions). Verified by
`tools/gen_vectors.py` construction; the differential consequence is recorded
in obs-2026-0002.
