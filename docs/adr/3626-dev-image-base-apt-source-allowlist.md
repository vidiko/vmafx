<!-- Copyright 2026 Lusoris -->
<!-- SPDX-License-Identifier: EUPL-1.2 -->

# ADR-3626: Allow only Ubuntu archive sources from development base images

- **Status**: Accepted
- **Date**: 2026-11-23
- **Deciders**: lusoris
- **Tags**: `ci`, `build`, `supply-chain`

## Context

On 2026-11-23, the first APT refresh in the SYCL development image received
HTTP 503 from the Kobuk Team Intel graphics PPA. Dev Container run
45132057436 failed, and the merge queue removed pull request 3621. The pinned
Intel oneAPI base image had configured both the PPA and
`apt.repos.intel.com/oneapi` to install its GPU runtime. The image inherited
both live sources, which the Ubuntu archive snapshot does not cover.

The SYCL image already has oneAPI and leaves `ENABLE_SYCL` at its default
of `false` in `scripts/setup/ubuntu.sh`. The CPU and CUDA development images
start from plain Ubuntu. The CUDA toolkit installer explicitly registers the
NVIDIA repository during the build.

## Decision

Before the certificate bootstrap, all three Ubuntu development Dockerfiles
keep `ubuntu.sources` in `/etc/apt/sources.list.d` and move all other entries
to `/etc/apt/vmafx-held-sources`. After the last package installer in the same
RUN, they restore the held entries. The helper refuses a missing archive
file, an active legacy `sources.list`, an existing holding directory, or a
restore destination that already exists.

## Alternatives considered

| Option | Pros | Cons | Why not chosen |
| --- | --- | --- | --- |
| Add retries | Helps brief outages. | Adds wait time. | Outages can outlast retries. |
| Delete sources | Avoids live fetches. | Alters the image. | Users lose vendor sources. |
| PPA snapshot only | Launchpad has PPA snapshots. | First refresh is live. | oneAPI stays live. |

APT already reads the PPA through `snapshot.ppa.launchpadcontent.net` once the
`APT::Snapshot` line is in place. The failing request came from the first
refresh, which runs before that line and reads the live PPA index. The
oneAPI repository has no snapshot service, so it stays live either way.

## Consequences

- The CPU and SYCL builds read the Ubuntu archive sources for the live
  certificate bootstrap and the pinned refreshes. An outage of either
  inherited Intel source no longer blocks the SYCL build.
- The CUDA installer installs the NVIDIA keyring after the hold, then refreshes
  APT with the NVIDIA source enabled. That source stays configured during the
  subsequent Ubuntu setup and in the finished image. Restore fails before
  moving any held entry if its destination is already occupied.
- The finished images retain inherited sources and gain no new dependencies.
  The SYCL sources can contact their live repositories when image users
  refresh APT. The build requires a readable `ubuntu.sources`, so a base
  image layout change can require an explicit update to the helper.
- The SYCL image now takes the VA-API runtime libraries that the FFmpeg
  development packages pull in (`libva2`, `libva-drm2`, `libva-x11-2`) from
  the Ubuntu archive snapshot. Before this change they came
  from the PPA build 2.24.1. The base image does not install them itself, and
  the build files declare no minimum libva version.
- The snapshot contract tests enforce the hold and restore ordering and
  exercise the helper against temporary APT directories.

## References

- [ADR-3541](3541-dev-image-apt-snapshot.md)
- [Ubuntu snapshot guide](../development/base-images.md#ubuntu-development-package-snapshot)
- Dev Container merge-group run 45132057436, job Ubuntu Dev Image (sycl).
- Dev Container pull-request run 45130121435, job Ubuntu Dev Image (sycl): the
  last green build before the outage, which unpacked `libva2` 2.24.1 from the
  PPA snapshot as a newly selected package.
