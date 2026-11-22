# ADR-3624: Strip the release bot's own co-author line on landed commits

- **Status**: Accepted
- **Date**: 2026-11-22
- **Deciders**: Operator
- **Tags**: `ci`

## Context

Master commit `800122efd8` (PR #3613, the docs render commit) is authored by
`vmafx-release-bot[bot]` and carries exactly one `Co-authored-by:` trailer naming
that same bot. `scripts/ci/check-dco.py --landed` refuses it, so the workflow
`.github/workflows/landed-commit-messages.yml` is red on master (run 45030816200).
Every render commit has this shape:

```text
chore(docs): render generated changelog and ADR index (#3613)

Signed-off-by: vmafx-release-bot[bot] <340976456+vmafx-release-bot[bot]@users.noreply.github.com>
Co-authored-by: vmafx-release-bot[bot] <340976456+vmafx-release-bot[bot]@users.noreply.github.com>
```

## Decision

In `--landed` mode, when `(commit.author_name, commit.author_email.lower())`
matches the release bot identity, strip one line whose `.strip()` equals
`RELEASE_BOT_COAUTHOR` only when that line appears exactly once; zero or more
than one occurrence keeps the message unchanged for attribution. No path or
exception lookup applies. A foreign co-author on a release-bot commit, a second
self line, and the release-bot line on a commit by any other author stay refused.

## Alternatives considered

| Alternative | Benefit | Cost |
| --- | --- | --- |
| Strip the self line for the release-bot author only (chosen) | Matches forge squash behaviour without widening other identities | One more trailer shape in `landed_exempt_message` |
| Change squash landing so it never adds the self line | No DCO change | The forge adds the trailer when squashing a PR whose commits the bot authored, outside this repository's control |
| Add render paths to the `dco-landed-release-bot-coauthor` exception file | Reuses path grants | Path grants expire and the render commit touches many generated paths |

## Consequences

**Positive:** The landed commit message workflow accepts docs render commits on
master without operator intervention.

**Negative:** Landed mode recognises one more stripped `Co-authored-by:` trailer
shape.

**Neutral:** Renovate and Python lock refresh landed behaviour is unchanged.

## References

- [ADR-3389](3389-landed-commit-message-gate.md): landed commit message gate.
- [ADR-3555](3555-intel-neo-lock-file.md): Renovate landed co-author exemption.
- [ADR-3560](3560-python-lock-refresh.md): Python lock refresh landed exemption.
- `scripts/ci/check-dco.py`: `landed_exempt_message`, `RELEASE_BOT_COAUTHOR`.
