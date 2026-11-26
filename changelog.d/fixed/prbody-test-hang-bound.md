- Tests: under load, the PR-body input test reported a slow ffmpeg surface
  check as hung. Each gate now has 120 seconds to finish before the test
  reports a hang.
