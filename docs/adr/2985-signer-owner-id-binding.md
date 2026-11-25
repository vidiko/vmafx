<!-- markdownlint-disable MD013 MD041 MD060 -->
# ADR-2985: A tiny model's signer is the vidiko owner ID, not only its name

- **Status**: Accepted
- **Date**: 2026-10-09
- **Deciders**: lusoris
- **Tags**: security, ai, supply-chain, dnn

## Context

`--tiny-model-verify` ([ADR-0211](0211-model-registry-sigstore.md)) runs
`cosign verify-blob` with `--certificate-identity-regexp
https://github.com/VMAFx/vmafx/.github/workflows/.+`. cosign searches the
certificate's identity for the expression (Go `regexp.MatchString`), so this
one accepted any identity that contains it: with text in front, after another
repository's path, and with any character where the dots are. Several guides
had the same flaw ([docs/ai/security.md](../ai/security.md), the u2netp mirror
pages, the operator and tester guides).

Even an anchored expression names the organisation only by its login. GitHub
frees a login when an organisation is renamed (GitHub docs, "Renaming an
organization"). Whoever takes the old login next can run a workflow at the same
path and get a Fulcio certificate with the same identity. Fulcio also writes the
organisation's numeric ID into extension `1.3.6.1.4.1.57264.1.17` (Source
Repository Owner Identifier), and a new owner of the name gets another ID. The
repository's first owner, `VMAFx`, had `288567244` (read from the v1.0.0-rc.3
release certificates). On 2026-11-20 the repository moved to the organisation
`vidiko`, whose ID is `340303765` (`gh api orgs/vidiko --jq .id`).
cosign 3.1.3, the release examined for this decision, has no option for that
extension; its certificate options are identity, issuer and five
`github-workflow-*` name fields
([research digest](../research/2985-signer-owner-id-binding.md)).

## Decision

libvmaf checks the signing certificate itself before it runs cosign
(`core/src/dnn/signer_identity.c`). First, `resolve_bundle_abs()` confines the
registry entry's `sigstore_bundle` path to the registry directory: it rejects
absolute paths, any `.`, `..` or empty component, backslashes, and any canonical
path (`vmaf_fullpath_utf8()`) that resolves outside the registry directory
(`-EINVAL`). Next, it reads the bundle once and accepts it only when:

- top-level keys belong to the Sigstore bundle v0.3 allow-list (`mediaType`,
  `verificationMaterial`, and at most one of `messageSignature` or
  `dsseEnvelope`), `verificationMaterial` keys belong to its allow-list
  (`certificate`, `tlogEntries`, `timestampVerificationData`), and
  `verificationMaterial.certificate` holds only `rawBytes`, and every value
  nested under `messageSignature`, `dsseEnvelope`, `tlogEntries` and
  `timestampVerificationData` matches the v0.3 schema: its keys, its value
  kinds, padded standard base64 for bytes fields, `int64` fields as a JSON
  number or decimal string of at most 18 digits without a leading zero,
  `HashAlgorithm` names, and well-formed UTF-8 in strings. Any unknown key,
  case-variant key, duplicate key, `\u` escape or other value is rejected
  (`-EBADMSG`). The walk keeps an explicit stack of at most three objects
  (`SIGNER_MAX_SCHEMA_DEPTH`) and takes at most 4096 steps per value
  (`SIGNER_MAX_SCHEMA_STEPS`), without recursion;
- `mediaType` equals `application/vnd.dev.sigstore.bundle.v0.3+json` or
  `application/vnd.dev.sigstore.bundle+json;version=0.3` in full;
- the leaf certificate at `verificationMaterial.certificate.rawBytes` is a DER
  `SEQUENCE` whose `TBSCertificate` (`SEQUENCE`), `signatureAlgorithm`
  (`SEQUENCE`) and `signatureValue` (`BIT STRING`) consume the outer sequence
  exactly;
- the certificate's subject alternative name is one URI of the form
  `https://github.com/vidiko/vmafx/.github/workflows/supply-chain.yml@refs/tags/v<digit>...`
  or `...@refs/heads/master`, and extension `.1.17` is the UTF8String
  `340303765` (`VMAF_DNN_SIGNER_OWNER_ID`); a certificate of the first owner,
  `288567244`, is refused like any other owner.

It then writes those checked bytes to `bundle` (`O_EXCL | O_NOFOLLOW`) inside a
mode 0700 directory (`mkdtemp(3)`) created under an existing absolute directory
in `TMPDIR` (or `/tmp` if unset or empty). The temporary-directory checks are
mandatory. `TMPDIR` is first resolved with `realpath(3)`, so a symbolic link is
judged by the directories it points into. The resolved path is then opened one
directory at a time from `/` with `O_NOFOLLOW`, and every directory from `/`
down to the base must be owned by root or the current user and must not be
group- or other-writable unless it has the sticky bit. No other user can then
rename or replace a directory on the path that cosign opens. If a directory
fails, verification logs it and fails with `-EACCES` before `mkdtemp(3)` or
cosign runs. The new directory is opened relative to the checked base, again
without following a symbolic link, and must be owned by the current user with no
group or other permission bits before `bundle` is created in it. It passes the
private file to cosign together with the same identity as an anchored
expression, `VMAF_DNN_SIGNER_IDENTITY_REGEXP`. A malformed bundle or a
certificate of any other identity or owner returns `-EPROTO`, as a signature
cosign rejects. Regular expressions in the workflows and current guides are
anchored with `^` and `$`, forbid top-level alternation outside parentheses, and
escape their dots; exact identity options use literal matching. The release
guide shows an owner-ID check for the separate GitHub provenance attestation.
Other cosign recipes still rely on the workflow identity alone.

**2026-11-25 clarification.** The verifier derives the bundle name by appending
`.sigstore.json` to the basename of the caller's ONNX path. It requires the
registry's `sigstore_bundle` to equal that name byte for byte (`-EINVAL` on
mismatch), then resolves the derived name within the registry directory.

## Alternatives considered

| Option | Pros | Cons | Why not chosen |
|---|---|---|---|
| Anchor the expression only | One-line change | Still trusts whoever holds the login after a rename | Leaves the rename hole open |
| Pin the owner ID in libvmaf (chosen) | A new owner of the name cannot pass; no new dependency | A small DER and base64 reader in C; the ID changes when the repository moves to another organisation, as it did to `vidiko`, and this constant changes with it | Smallest change that closes both holes |
| Pass `--certificate-github-workflow-repository vidiko/vmafx` | cosign supports it | Also a name (extension `.1.5`), freed by a rename like the login | Same hole as the expression |
| Trust the old name only for signatures logged before the rename (Rekor time) | No certificate parsing | Needs the rename date in the binary; new signatures under the new name still need a check; time handling in the verifier | More moving parts than an ID that never changes |
| Verify with `gh attestation verify` from libvmaf | gh reports the owner ID | Models are signed with `cosign sign-blob`, not attested; adds a second external tool | Wrong artefact type and a new dependency |
| Let cosign read the bundle file itself | No temporary file | The bundle can change between libvmaf's read and cosign's | The owner check must apply to the bytes cosign verifies |
| Skip nested values, as before | Less code | A malformed or unknown field under a checked key reached cosign unread | Every nested field stayed unchecked |
| Validate with the vendored parser `core/src/pdjson.c` | Existing code | Decodes `\u` escapes and allocates on the heap; still needs the schema tables | The check must refuse what a ProtoJSON decoder reads differently |

## Consequences

- **Positive**: a certificate for a squatted `VMAFx` or `vidiko` login cannot
  load a model; the anchored expression refuses prefixed, suffixed and
  look-alike identities; guides show a check a reader can run.
- **Negative**: the owner's organisation ID is a constant in libvmaf
  (`VMAF_DNN_SIGNER_OWNER_ID`); moving the repository to a new organisation
  (rather than renaming) needs a release with the new ID before models signed
  there load. The move to `vidiko` is such a case: libvmaf now carries
  `340303765`, and a bundle signed before the move no longer loads. Bundles
  with more than one certificate (Sigstore bundle v0.1
  chains) are refused; `cosign sign-blob` 3.x writes v0.3 bundles with one.
- **Neutral / follow-ups**: the rename itself changes the name in the
  expression, the guides and `VMAF_DNN_SIGNER_IDENTITY_REGEXP` to the new login,
  not the owner ID. No model ships a bundle yet
  (`T-AI-MODEL-SIGNING-BUNDLES-MISSING-2026-10-05`); the workflow that signs
  models must be `supply-chain.yml` on a tag or `master`, or the constant
  changes with it.

## References

- Source: the organisation-rename inventory of 2026-10-09 found the
  unanchored expressions and the name-only identity; hardening requested by
  the maintainer's rename-planning lane ahead of the rename.
- [ADR-0211](0211-model-registry-sigstore.md) (`--tiny-model-verify`),
  [research digest](../research/2985-signer-owner-id-binding.md).
- `core/test/dnn/test_signer_identity.c`, `core/test/dnn/test_tiny_model_verify.c`,
  `core/test/test_signer_identity_regexp_contract.py`.
