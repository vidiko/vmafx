<!-- Copyright 2026 Lusoris -->
<!-- SPDX-License-Identifier: EUPL-1.2 -->

- Ubuntu development builds hold inherited vendor APT sources during package installation and
  restore them before publishing the images. The SYCL build can proceed when its base image's
  Intel repositories are unavailable.
