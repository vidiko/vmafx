#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Freeze existing Accepted, Superseded and Deprecated ADR bodies.

Allow status lines, References sections, appended dated status-update sections,
new supersession notes directly below the status block, link target repairs,
whole-line markdownlint directives, and whitespace-only reflow. An ADR-Body-Edit
trailer of at least 20 characters on a commit in the range overrides refusals only in
the ADRs whose ADR-NNNN id its reason names; a reason that names no ADR id is refused.
Compare ADR changes from the merge base of the supplied revisions.
"""

from __future__ import annotations

import argparse
import difflib
import importlib
import importlib.util
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
run = importlib.import_module("scripts.lib.safe_subprocess").run
GIT = shutil.which("git") or "git"
SECTION_LEVEL = 2
NOTE_MIN_LINES = 2
REASON_MIN_LENGTH = 20

spec = importlib.util.spec_from_file_location(
    "adr_status_drift", Path(__file__).with_name("check-adr-status-drift.py")
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load ADR status parser")
status_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status_module)
STATUS_RE = status_module.STATUS_RE
ADR = re.compile(r"^docs/adr/[0-9]{4}-[^/]*\.md$")
ADR_ID = re.compile(r"\bADR-([0-9]{4})\b")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
UPDATE = re.compile(r"^#{2,3} Status update \d{4}-\d{2}-\d{2}(?:\b|$)")
DIRECTIVE = re.compile(
    r"^<!--\s*markdownlint-"
    r"(?:disable|enable|disable-line|disable-next-line|capture|restore)\b[^>]*-->\s*$"
)
# CommonMark allows spaces or tabs between '(' and the destination; they stay in
# the preserved prefix so only the destination token is normalized.
# After the destination only an optional title and the closing parenthesis (or the
# line end of a definition) may follow, so link-like prose stays unnormalized.
# A title may contain its closing delimiter when backslash-escaped (CommonMark 0.31.2).
LINK_TITLE = (
    r"""(?:[ \t]+(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|\((?:[^()\\\n]|\\.)*\)))?[ \t]*"""
)
LINK = re.compile(r"(\[[^\]\n]*\]\([ \t]*)(?:<[^>\n]*>|[^\s)\n]*)(" + LINK_TITLE + r"\))")
REFERENCE_LINK = re.compile(r"^( {0,3}\[[^\]\n]+\]:\s*)(?:<[^>\n]*>|\S+)(" + LINK_TITLE + r")$")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
MESSAGE = (
    "body of an Accepted, Superseded or Deprecated ADR is frozen (docs/adr/README.md); "
    'append a dated "### Status update YYYY-MM-DD" section or supersede it with a new ADR'
)
RENAME_MESSAGE = (
    "Accepted, Superseded or Deprecated ADR cannot be renumbered or moved out of docs/adr/NNNN-*.md"
)


def git(*args: str) -> str:
    """Run a read-only Git command or report its failure."""
    result = run(
        [GIT, *args],
        allowed_executables=(GIT,),
        capture_output=True,
        text=True,
        timeout_seconds=120,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return str(result.stdout)


def status_index(lines: list[str]) -> int | None:
    """Find the first recognized status line."""
    return next((i for i, line in enumerate(lines) if STATUS_RE.match(line)), None)


def section(lines: list[str], index: int) -> str:
    """Find the nearest section heading outside code fences at a line or insertion point."""
    fenced = fenced_lines(lines)
    return next(
        (
            lines[i]
            for i in range(min(index, len(lines) - 1), -1, -1)
            if not fenced[i] and HEADING.match(lines[i])
        ),
        "(preamble)",
    )


def fenced_lines(lines: list[str]) -> list[bool]:
    """Mark fence delimiters and lines inside fenced blocks."""
    fence = ""
    fenced = []
    for line in lines:
        marker = FENCE.match(line)
        if marker and not fence and marker.group(1)[0] == "`" and "`" in marker.group(2):
            marker = None
        fenced.append(bool(fence) or marker is not None)
        if marker:
            token, tail = marker.groups()
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not tail.strip():
                fence = ""
    return fenced


def in_references(lines: list[str], index: int) -> bool:
    """Return whether a line lies in References before any peer or dated-update heading."""
    current = False
    for line, fenced in zip(lines[: index + 1], fenced_lines(lines), strict=False):
        if not fenced:
            match = HEADING.match(line)
            if match and (len(match.group(1)) <= SECTION_LEVEL or UPDATE.match(line)):
                current = line.strip() == "## References"
    return current


def content_lines(
    lines: list[str], fenced: list[bool], start: int, end: int
) -> list[tuple[int, str]]:
    """Keep fenced lines and unfenced non-directive lines in a slice."""
    return [
        (i, lines[i]) for i in range(start, end) if fenced[i] or not DIRECTIVE.fullmatch(lines[i])
    ]


def appended(old: list[str], fenced: list[bool], pos: int) -> bool:
    """Return whether only blank lines or unfenced directives follow pos."""
    return not any(line.strip() for _, line in content_lines(old, fenced, pos, len(old)))


def allowed_update(lines: list[str], start: int, end: int) -> bool:
    """Accept inserted dated sections, including their subordinate content."""
    level = 0
    fenced = fenced_lines(lines)
    for index in range(start, end):
        line = lines[index]
        match = None if fenced[index] else HEADING.match(line)
        if match and UPDATE.match(line):
            heading_level = len(match.group(1))
            if not level or heading_level <= level:
                level = heading_level
        elif match and level and len(match.group(1)) <= level:
            level = 0
        if not level and line.strip():
            return False
    return bool(level)


def allowed_note(old: list[str], pos: int, added: list[str], status: int) -> bool:
    """Accept a newly inserted note immediately after the status block."""
    if pos <= status or any(
        line.strip() and not re.match(r"^- \*\*[^*]+\*\*:", line) for line in old[status + 1 : pos]
    ):
        return False
    content = [line for line in added if line.strip()]
    return (
        len(content) >= NOTE_MIN_LINES
        and content[0].strip() == "> [!NOTE]"
        and re.match(r"^>\s*(?:\*\*)?(?:Superseded by|Status)\b", content[1]) is not None
        and all(line.startswith(">") for line in content)
    )


def link_repair(before: str, after: str) -> bool:
    """Permit only changes to Markdown link destinations."""

    def normalize(line: str) -> str:
        return REFERENCE_LINK.sub(r"\1DEST\2", LINK.sub(r"\1DEST\2", line))

    return before != after and normalize(before) == normalize(after)


def normalized_words(lines: list[str]) -> list[str]:
    """Normalize table spacing before comparing words."""
    normalized = []
    for original in lines:
        line = original
        if line.strip().startswith("|"):
            line = re.sub(r"\s*\|\s*", "|", line.strip())
            if re.fullmatch(r"[|:-]+", line):
                line = re.sub(r"-+", "-", line)
        normalized.append(line)
    return " ".join(normalized).split()


def formatting_only(tag: str, before: list[str], after: list[str], fenced: bool) -> bool:
    """Accept blank-only hunks and word-preserving prose replacements outside fences."""
    return all(not line.strip() for line in before + after) or (
        tag == "replace" and not fenced and normalized_words(before) == normalized_words(after)
    )


def references_tail(lines: list[str], start: int, end: int, at_end: bool) -> bool:
    """Accept References content, optionally followed by appended dated update sections."""
    fenced = fenced_lines(lines)
    heading = next((i for i in range(start, end) if not fenced[i] and HEADING.match(lines[i])), end)
    return heading == end or (at_end and allowed_update(lines, heading, end))


def references_edit(old: list[str], start: int, end: int) -> bool:
    """Return whether a changed range lies inside References and keeps its heading."""
    fenced = fenced_lines(old)
    return all(
        in_references(old, i) and (fenced[i] or old[i].strip() != "## References")
        for i in range(start, end)
    )


def allowed_replace(
    before: list[tuple[int, str]],
    after: list[tuple[int, str]],
    old: list[str],
    status: int,
    fenced: tuple[list[bool], list[bool]],
) -> bool:
    """Allow status changes with a note, or unfenced linewise status and link repairs."""
    if (
        len(before) == 1
        and len(after) > 1
        and before[0][0] == status
        and STATUS_RE.match(after[0][1])
        and allowed_note(old, status + 1, [line for _, line in after[1:]], status)
    ):
        return True
    return len(before) == len(after) and all(
        (i == status and STATUS_RE.match(new_line))
        or (not fenced[0][i] and not fenced[1][j] and link_repair(old_line, new_line))
        for (i, old_line), (j, new_line) in zip(before, after, strict=True)
    )


def allowed_insert(
    old: list[str], new: list[str], a: int, c: int, d: int, status: int, at_end: bool
) -> bool:
    """Accept inserted References lines, appended dated updates, or status notes."""
    if in_references(old, max(0, a - 1)) and references_tail(new, c, d, at_end):
        return True
    return (at_end and allowed_update(new, c, d)) or allowed_note(old, a, new[c:d], status)


def refused(old: list[str], new: list[str], status: int) -> list[tuple[int, str]]:
    """Return the location and section of each disallowed diff hunk."""
    failures: list[tuple[int, str]] = []
    old_fenced, new_fenced = fenced_lines(old), fenced_lines(new)
    for tag, a, b, c, d in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        before = content_lines(old, old_fenced, a, b)
        after = content_lines(new, new_fenced, c, d)
        fenced = any(old_fenced[a:b]) or any(new_fenced[c:d])
        at_end = appended(old, old_fenced, b)
        if formatting_only(tag, [line for _, line in before], [line for _, line in after], fenced):
            continue
        if tag == "insert" and allowed_insert(old, new, a, c, d, status, at_end):
            continue
        if tag != "insert" and references_edit(old, a, b) and references_tail(new, c, d, at_end):
            continue
        if tag == "replace" and allowed_replace(
            before, after, old, status, (old_fenced, new_fenced)
        ):
            continue
        failures.append((max(1, c + 1), section(old, a)))
    return failures


def file_problems(
    base: str, head: str, kind: str, path: str, target: str
) -> list[tuple[int, str, str]]:
    """Compare one existing ADR and its destination path against freeze rules."""
    old_text = git("show", f"{base}:{path}")
    new_text = "" if kind == "D" else git("show", f"{head}:{target}")
    old = old_text.splitlines()
    status = status_index(old)
    if status is None or STATUS_RE.match(old[status]).group(1).lower() not in {
        "accepted",
        "superseded",
        "deprecated",
    }:
        return []
    rename = (
        [(1, path, RENAME_MESSAGE)]
        if target != path
        and (not ADR.fullmatch(target) or Path(target).name[:4] != Path(path).name[:4])
        else []
    )
    return rename + [
        (line, heading, MESSAGE) for line, heading in refused(old, new_text.splitlines(), status)
    ]


class InvalidReason(Exception):
    """The override trailer does not explain its reason sufficiently."""


def override(base: str, head: str) -> dict[str, tuple[str, str]]:
    """Map each ADR number a trailer in the checked range names to its commit and reason."""
    output = git(
        "log", "--format=%H%x00%(trailers:key=ADR-Body-Edit,unfold=true)%x00", f"{base}..{head}"
    )
    fields = output.split("\0")
    waivers: dict[str, tuple[str, str]] = {}
    for index in range(0, len(fields) - 1, 2):
        sha, trailers = fields[index].strip(), fields[index + 1].strip()
        for trailer in trailers.splitlines():
            reason = trailer.partition(":")[2].strip()
            if len(reason) < REASON_MIN_LENGTH:
                raise InvalidReason("ADR-Body-Edit reason must contain at least 20 characters")
            numbers = ADR_ID.findall(reason)
            if not numbers:
                raise InvalidReason("ADR-Body-Edit reason must name each waived ADR as ADR-NNNN")
            for number in numbers:
                waivers.setdefault(number, (sha[:10], reason))
    return waivers


def check(base: str, head: str) -> int:
    """Check changed ADRs, including renames, against their base versions."""
    git("rev-parse", "--verify", f"{base}^{{commit}}")
    git("rev-parse", "--verify", f"{head}^{{commit}}")
    merge_base = git("merge-base", base, head).strip()
    if not merge_base:
        raise RuntimeError(f"no merge base for {base} and {head}")
    fields = git("diff", "--name-status", "-z", "-M", merge_base, head).split("\0")
    waivers = override(base, head)
    failures: list[tuple[str, str]] = []
    cursor = 0
    while cursor < len(fields) - 1:  # HISS-02 bound: len(fields)
        kind, path = fields[cursor : cursor + 2]
        cursor += 2
        target = path
        if kind.startswith(("R", "C")):
            target = fields[cursor]
            cursor += 1
        if not ADR.fullmatch(path) or path.endswith("/0000-template.md") or kind == "A":
            continue
        number = Path(path).name[:4]
        for line, heading, message in file_problems(merge_base, head, kind, path, target):
            failures.append((number, f"{target}:{line}: {heading}: {message}"))
    return report(failures, waivers)


def report(failures: list[tuple[str, str]], waivers: dict[str, tuple[str, str]]) -> int:
    """Print refusals and waived hunks; return 1 when a refusal has no waiver."""
    for number, failure in failures:
        print(f"note: {failure}" if number in waivers else failure)
    for number, (sha, reason) in sorted(waivers.items()):
        accepted = sum(1 for item, _ in failures if item == number)
        if accepted:
            print(
                f"ADR body freeze: ADR-{number}: {accepted} hunk(s) accepted under "
                f"ADR-Body-Edit in {sha}: {reason}"
            )
    return int(any(number not in waivers for number, _ in failures))


def main() -> int:
    """Parse CLI arguments and run the ADR body freeze check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        return check(args.base, args.head)
    except InvalidReason as exc:
        print(f"ADR body freeze: {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, OSError, TimeoutError, ValueError) as exc:
        print(f"ADR body freeze: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
