# ai-io/prompts — outbound external deep-research requests

One Markdown file per request: `aio-YYYY-NNNN.md` (IDs allocated via
`frontier.ids`). Front matter: `id`, `mission`, `status`
(`awaiting-output` / `answered` / `stale`), `angle`, `created_at`.

Generate several self-contained prompts at once with **distinct angles**;
near-duplicates are a defect. Deep, specific, technical. This channel is a last
resort — see `localdocs/external-research.md`.

Status: active. Prompts filed: aio-2026-0001 (ML-KEM encapsulation-key
validation prior art), aio-2026-0002, aio-2026-0003 (deployed-protocol placement
norms), aio-2026-0004 (pycose COSE protected-header key ordering: prior art and
normative text). Outputs for aio-2026-0001/0002/0003 are in `ai-io/outputs/`.
aio-2026-0004 remains `awaiting-output`; user-supplied Qwen transcripts are
preserved separately under `ai-io/pycose_deterministic_cbor/` and are not the
requested completed prompt response or verified evidence.
