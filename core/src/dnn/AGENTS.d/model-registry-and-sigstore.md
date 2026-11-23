---
paths:
  - model/tiny/registry.json
  - model/tiny/registry.schema.json
  - model/tiny/*.json
  - core/src/dnn/model_loader.c
  - core/src/dnn/signer_identity.c
  - core/src/dnn/signer_identity.h
  - core/test/dnn/test_signer_identity.c
  - core/test/dnn/signer_fixtures.h
  - ai/scripts/validate_model_registry.py
  - ai/src/aiutils/onnx_signature.py
invariant: Model registry entries must validate against schema and verify Sigstore bundles with cosign via posix_spawnp.
---
<!-- markdownlint-disable MD013 -->
# Model Registry Schema and Sigstore Verification

- **Registry schema = trust contract** (T6-9 / [ADR-0211](../../../../docs/adr/0211-model-registry-sigstore.md)).
  Every entry in [`model/tiny/registry.json`](../../../../model/tiny/registry.json)
  satisfies [`registry.schema.json`](../../../../model/tiny/registry.schema.json):
  required `id` / `kind` / `onnx` / `sha256`, plus `license` and
  `sigstore_bundle` for `schema_version: 1` entries. New fields
  added by extending schema first, then registry, then any
  consumers — never other way around. `--tiny-model-verify`
  path in `model_loader.c` parses registry inline (no JSON dep),
  spawns `cosign` via `posix_spawnp(3p)`; `system(3)` stays
  banned.

- **Model registry + Sigstore (T6-9, PR #199 open, ADR-0211
  placeholder)**: `--tiny-model-verify` flag wires through to
  `cosign verify-blob` against Sigstore bundle declared in
  registry. Pairs with `quant_mode` / `int8_sha256`
  fields from
  [ADR-0173](../../../../docs/adr/0173-ptq-int8-audit-impl.md) /
  [ADR-0174](../../../../docs/adr/0174-first-model-quantisation.md).
  On merge: every shipped tiny-AI model needs Sigstore bundle
  path in `model/tiny/registry.json`.

- **Metadata matches graph ([ADR-1546](../../../../docs/adr/1546-tiny-model-metadata-against-graphs.md))** —
  `ai/scripts/validate_model_registry.py` (required check "Tiny-Model
  Registry Validate") reads every registered graph and int8 sibling
  with `ai/src/aiutils/onnx_signature.py` (no `onnx` package); fails
  when registry `opset` or sidecar's `opset`, `sha256`,
  `input_names` / `output_names`, `input_name` / `output_name`,
  feature-list length, `encoder_vocab` (width + 2), `codec_block_dim` or
  `codec_block_layout` disagrees with graph. re-export updates
  sidecar and registry row with graph; exporters record opset
  file imports (torch raises requested 17 to 18). runtime never
  checks registry digests: only `--tiny-model-verify` reads
  registry, for bundle path.

- **Signer bound by owner ID ([ADR-2985](../../../../docs/adr/2985-signer-owner-id-binding.md))** —
  before cosign runs, `vmaf_dnn_signer_check_bundle()`
  (`signer_identity.c`) requires v0.3 Sigstore bundle allow-list structure
  (top-level `mediaType`, `verificationMaterial`, optional
  `messageSignature` or `dsseEnvelope`; `verificationMaterial` keys
  `certificate`, `tlogEntries`, `timestampVerificationData`; leaf at
  `verificationMaterial.certificate.rawBytes` only; no unknown, duplicate
  or case-variant keys, no `\u` escape; nested values of `messageSignature`,
  `dsseEnvelope`, `tlogEntries`, `timestampVerificationData` checked against
  the `k_schema` tables), full X.509 outer sequence
  (`TBSCertificate`, `signatureAlgorithm`, `signatureValue`), subject
  alternative name `supply-chain.yml` on `refs/tags/v<digit>...` or
  `refs/heads/master`, and Fulcio extension `.1.17` =
  `VMAF_DNN_SIGNER_OWNER_ID` (`340303765`). `resolve_bundle_abs()` confines
  `sigstore_bundle` relative path inside registry directory. Checked bytes
  copied into mode 0700 `mkdtemp(3)` directory (`bundle` opened inside with
  `O_EXCL|O_NOFOLLOW`) under validated `TMPDIR` or `/tmp` (base and
  ancestors up to `/` rejected when group- or other-writable without sticky
  bit), passed to cosign with anchored `VMAF_DNN_SIGNER_IDENTITY_REGEXP`; C
  grammar and expression change together. Never pass cosign registry bundle
  path, unanchored expression, or name-only check. `test_signer_identity`,
  `test_tiny_model_verify` (fake cosign records argv) and
  `test_signer_identity_regexp_contract.py` (every documented expression
  anchored) guard contract. Fixtures: `gen_signer_fixtures.py`, never
  hand-edited.
