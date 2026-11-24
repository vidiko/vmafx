- **`make pr-check` runs all three `rule-enforcement.yml` PR-body shell gates.**
  `scripts/ci/pr-body-gates.sh` runs `deliverables-check.sh`,
  `state-md-touch-check.sh` and `ffmpeg-patches-surface-check.sh` without early
  stop so a PR body that passes `make pr-check` locally cannot fail the
  `docs/state.md` or `ffmpeg-patches` surface gates in CI. `PR=<num>` fetches
  the title, body and revisions in one `gh pr view` call; `BODY=<file>` accepts
  `TITLE=<text>` and defaults to the `HEAD` commit subject when `TITLE` is
  empty. `make pr-check PR=<num>` now checks the PR's own base and head
  revisions, fetching missing commits from `origin` and failing if they cannot
  be obtained. `TITLE` and `BODY` are passed to the gates literally without
  `make` or shell expansion, and `PR` must be a positive decimal number.
