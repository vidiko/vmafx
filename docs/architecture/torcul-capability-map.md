<!-- markdownlint-disable MD013 MD060 -->
# VMAFx encode packages and torcul

torcul is the Vidiko video encode service, in its own repository
vidiko/torcul. The name comes from Latin *torcular*, a wine or oil press, and
is said TOR-kul. [ADR-3382](../adr/3382-encode-service-leaves-vmafx.md) moved
the encode service there while VMAFx keeps its scoring, `vmaf-tune auto` and
compare surfaces. As a consequence, five Go encode packages exist in both
trees until torcul reaches parity. This page is the VMAFx-side map and
retirement checklist; torcul's own design is in its ADR-0001 and ADR-0002.

## What VMAFx owes torcul

Issue [#2320](https://github.com/vidiko/vmafx/issues/2320) tracks a Rust crate
over `libvmafx.so.1` generated from
[`core/api/vmafx.toml`](../../core/api/vmafx.toml). Until that crate ships,
torcul may call the `vmaf` CLI instead
([ADR-3382](../adr/3382-encode-service-leaves-vmafx.md) decision 3).

## Capability map

| VMAFx package | What it does | VMAFx importers | torcul counterpart | Difference to plan for |
| --- | --- | --- | --- | --- |
| `pkg/hwdevice` | Intel QSV device chain for vmafx-tune encodes (VA-API + derived QSV); see `pkg/hwdevice/hwdevice.go` and [ADR-0601](../adr/0601-vmaftune-qsv-amf-hw-init-and-probe-fix.md) | `pkg/corpus`, `pkg/encoder`, `pkg/ffencode` | torcul issue 5 (hardware encoder probe), torcul issue 11 (Arc hardware encode/decode measurement) | VMAFx builds device arguments for the `ffmpeg` binary; torcul runs libav* in process and starts no `ffmpeg`/`ffprobe` at run time (torcul ADR-0002). |
| `pkg/ffencode` | Go port of `tools/vmaf-tune/src/vmaftune/encode.py`: shared FFmpeg encode driver for tuning subcommands | `cmd/vmafx-tune/cmd`, `pkg/corpus`, `pkg/corpusrow`, `pkg/encodeprofile`, `pkg/tune/executor` | torcul encode crate with one `Encoder` trait (torcul issue 13), encoder settings crate (torcul ADR-0002) | VMAFx builds an `ffmpeg` command line and runs the binary; torcul's encoder settings crate emits per-backend settings, not command lines. |
| `pkg/codecadapter` | Per-codec quality knob, range, defaults, encoder name, preset table; see `pkg/codecadapter/codecadapter.go` and [ADR-0237](../adr/0237-quality-aware-encode-automation.md), [ADR-0294](../adr/0294-vmaf-tune-codec-adapter-svtav1.md), [ADR-0326](../adr/0326-vmaf-tune-phase-b-bisect.md) | `cmd/vmafx-tune/cmd`, `pkg/corpus`, `pkg/encodeprofile`, `pkg/ffencode`, `pkg/predictor`, `pkg/tune/auto` | torcul issue 4 (codec tiering), encoder settings crate (torcul ADR-0002) | VMAFx adapters yield FFmpeg arguments; torcul's settings crate yields libavcodec options or SVT-AV1 fields. |
| `pkg/hdr` | HDR detection and codec-specific HDR encode flags; see `pkg/hdr/hdr.go` and [ADR-0300](../adr/0300-vmaf-tune-hdr-aware.md) | `pkg/corpus`, `pkg/ffencode`, `pkg/tune/auto` | torcul issue 8 | torcul issue 8 adds HDR10+ and Dolby Vision profile handling, which `pkg/hdr/hdr.go` does not have. |
| `pkg/tune/auto` | Phase F adaptive recipe-aware tuning tree; see `pkg/tune/auto/auto.go` and [ADR-0397](../adr/0397-vmaf-tune-phase-f-auto.md) | `cmd/vmafx-tune/cmd`, `pkg/tune/executor` | torcul issue 3 | Surface for `vmafx-tune auto` that [ADR-3382](../adr/3382-encode-service-leaves-vmafx.md) decision 2 keeps in VMAFx until explicitly moved. |

## Retirement conditions

These apply to every package in the table:

1. The torcul counterpart issue is **closed** with tests that cover the cases
   exercised by the VMAFx package's own tests (`pkg/<package>/*_test.go`).
2. Each listed VMAFx importer either calls the torcul crate or is removed from
   the tree.
3. The VMAFx package is deleted in one pull request with a
   `changelog.d/removed/` fragment, a `!` conventional-commit subject, and a
   `Migration:` footer, because external Go code may import these paths
   (HISS-14 append-only ABI).

**Open:** how Go code in VMAFx calls a Rust crate is not decided. torcul
ADR-0001 decision 4 defers that until a cgo-boundary measurement when torcul's
Go service layer is written. Until then, condition (2) cannot be satisfied by
calling the crate—only by removing or rewriting importers.

Per-package extras:

- **`pkg/tune/auto`:** retirement needs a record that supersedes ADR-3382
  decision 2 (which keeps the `vmafx-tune auto` CLI surface in VMAFx). Without
  it, only encode calls move; the auto command stays.
- **`pkg/ffencode`:** `pkg/encoder` (Stage-1 bisect) imports `pkg/hwdevice`
  only, not `pkg/ffencode`; it is out of scope for this package's retirement
  list.

## Re-check this page

The importer column was taken at commit `800122efd8`. Recompute it with the
commands below. Until #1249 removes the alias package `pkg/tune/codec`, the
`pkg/codecadapter` line also prints it; the table leaves it out.

```bash
grep -rln --include='*.go' '/pkg/hwdevice"' cmd pkg \
  | xargs -n1 dirname | sort -u | grep -v '^pkg/hwdevice$'
grep -rln --include='*.go' '/pkg/ffencode"' cmd pkg \
  | xargs -n1 dirname | sort -u | grep -v '^pkg/ffencode$'
grep -rln --include='*.go' '/pkg/codecadapter"' cmd pkg \
  | xargs -n1 dirname | sort -u | grep -v '^pkg/codecadapter$'
grep -rln --include='*.go' '/pkg/hdr"' cmd pkg \
  | xargs -n1 dirname | sort -u | grep -v '^pkg/hdr$'
grep -rln --include='*.go' '/pkg/tune/auto"' cmd pkg \
  | xargs -n1 dirname | sort -u | grep -v '^pkg/tune/auto$'
```
