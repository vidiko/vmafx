- **`--tiny-model-verify` accepts only the vidiko signer, by owner ID.** The
  identity expression libvmaf passed to `cosign verify-blob`
  (`https://github.com/VMAFx/vmafx/.github/workflows/.+`) was not anchored:
  cosign searches the identity for it, so an identity with text before or
  after it passed, and its dots matched any character. libvmaf now confines the
  registry's `sigstore_bundle` path to the registry directory (`-EINVAL`
  otherwise), validates the bundle against the Sigstore v0.3 field allow-list
  (accepting both `application/vnd.dev.sigstore.bundle.v0.3+json` and
  `application/vnd.dev.sigstore.bundle+json;version=0.3`), reads the leaf
  signing certificate at `verificationMaterial.certificate.rawBytes` and
  refuses the bundle (`-EPROTO`) unless its identity is the supply-chain
  workflow on a release tag or `master` and its Fulcio owner ID (extension
  `1.3.6.1.4.1.57264.1.17`) is `340303765`, the `vidiko` organisation's, which
  a later owner of the `vidiko` login cannot have. The owner before the move,
  `288567244`, is refused too; no model ships a bundle yet. cosign then
  verifies a private copy of those bytes
  in a mode 0700 `mkdtemp(3)` directory under `TMPDIR` (or `/tmp`), rejecting a
  base directory or ancestor up to `/` that is group- or other-writable without
  the sticky bit (`-EACCES`), with the expression anchored at both ends. The
  guides' identity expressions are anchored too, and
  [the release guide](docs/development/release.md#check-the-signers-owner-id)
  shows the owner-ID check with `gh attestation verify` and `jq`
  ([ADR-2985](docs/adr/2985-signer-owner-id-binding.md)).
