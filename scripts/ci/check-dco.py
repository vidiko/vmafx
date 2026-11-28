#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require DCO sign-offs and refuse model/tool attribution in PRs and landed commits.

ADR-2462 covers pull request sign-offs; ADR-3389 covers landed squash commits.
ADR-3531 covers identity and message attribution checks.
ADR-3544 refuses bot-authored PR/pre-push commits unless the bot is the branch opener.
ADR-3555 lifts only that PR-mode opener refusal for a signed release-bot commit on a
``renovate[bot]`` PR when every changed path is a live ``dco-bot-opener`` exception.
In ``--landed`` mode, ADR-3555 also strips a single exact ``vmafx-release-bot[bot]``
``Co-authored-by:`` line on a ``renovate[bot]`` squash commit that changes a live
``dco-landed-release-bot-coauthor`` exception path.
ADR-3560 adds a second class for the signed Python lock refresh commit with the exact
subject and author on a Renovate PR. Every changed path must have a live, path-exact
``dco-python-lock-refresh`` exception. In ``--landed`` mode the squash must change at
least one of the 30 live grant paths. Other paths must be manifest inputs, or the
manifest itself if valid parent and squash copies read from local Git objects
differ only in the top-level ``uv_version`` value. The new value must be an exact
release. Missing or invalid objects, malformed or duplicate-key JSON, and any
other manifest change keep the trailer.

ADR-3624 strips a single exact release-bot ``Co-authored-by:`` line in ``--landed`` mode
when the commit author is that same release bot. A second line and any bot or
coding-tool co-author keep the refusal; a human co-author passes, as on any commit.
Another author keeps the refusal unless a Renovate exemption above applies.

The forge must identify one PR with the squash SHA and a parseable ``merged_at``
timestamp. Its complete commit list must have fewer than 250 entries and include
a release-bot commit identified by normalized Git author name and email. Each
release-bot commit needs a nonempty file list shorter than one page (100 entries),
with valid filenames and only ``added``, ``removed``, ``modified``, ``renamed``,
``copied``, ``changed``, or ``unchanged`` statuses. A rename requires the previous
filename, and any supplied previous
filename is also checked. Every reported path needs a live grant. Missing forge
configuration, missing, ambiguous, malformed or incomplete forge evidence, and
``TierError``, ``OSError``, ``ValueError``, ``RecursionError``, ``KeyError``,
``TypeError``, or ``OverflowError`` from the forge read keep the trailer.

Every non-merge commit in ``BASE..HEAD`` must end with a ``Signed-off-by: Name
<email>`` trailer (what ``git commit -s`` writes), and the e-mail address of
the trailer must be the commit's author or committer address.  A sign-off in
the middle of the message, or one for somebody else, does not count.

On master (``--landed``), every commit must have
a sign-off matching the commit author or the designated landing identity
(``--landing-identity``).  Committer address is not accepted because GitHub is
committer on every squash. Commit author/committer identities must not name a
model or coding tool. Commit messages and pull request bodies must not carry
banned Co-authored-by lines or machine-generated attribution.

Sign-off exemptions for pull requests (attribution checks still run):

* a commit written by an allow-listed bot (``BOT_LOGINS``), in a pull request
  that GitHub itself reports as opened by that bot (``--author`` and
  ``--author-type Bot``).  A human commit pushed onto a bot branch is not
  exempt, and neither is a commit that merely names a bot as its author in a
  pull request opened by a person;
* the machine-generated release pull request, which the caller detects with
  ``scripts/ci/release-pr-exempt.sh`` and passes as ``--release-pr``;
* a pull request created before the cutoff in ``scripts/ci/dco-cutoff.txt``
  (``--created-at``, the rollout of ADR-2462).  Without ``--created-at``
  sign-offs are always enforced.

Usage::

    python3 scripts/ci/check-dco.py --base <sha> --head <sha> \\
        [--author <login> --author-type <User|Bot>] [--release-pr] \\
        [--created-at <ISO 8601>] [--cutoff-file <path>] \\
        [--exceptions-root <path>] [--pr-body-file <path> | --pr-body-from-event]

    python3 scripts/ci/check-dco.py --landed --landing-identity "Name <email>" \\
        --base <sha> --head <sha>

    python3 scripts/ci/check-dco.py --merge-base origin/master [--head <rev>]

    python3 scripts/ci/check-dco.py --message-file <path>

``--merge-base REF`` is the pre-push mode, named like the other pre-push hooks'
option: it checks the commits the push adds on top of ``REF``, those reachable
from the outgoing commit but not from ``REF``. The outgoing commit is
``--head``, else the ``PRE_COMMIT_TO_REF`` that pre-commit exports during a
push, else ``HEAD``. It catches commits that never passed the local commit-msg
hook, such as a review bot's commit pulled from the pull request branch.

``BASE_SHA``, ``HEAD_SHA``, ``PR_AUTHOR``, ``PR_AUTHOR_TYPE``,
``DCO_RELEASE_PR``, ``PR_CREATED_AT`` and ``LANDING_IDENTITY`` are read when the flags
are absent. ``--merge-base`` does not read ``HEAD_SHA``, so an inherited value
cannot replace the pushed commit. ``--pr-body-from-event`` reads ``GITHUB_EVENT_PATH`` JSON in CI.
Locally, ``--pr-body-file`` (alias ``--pr-body``) reads a UTF-8 file; otherwise
``PR_BODY`` supplies the body. Inputs exceeding named byte/line bounds are refused.
Exit status: 0 all checks pass, 1 attribution or sign-off fails, 2 usage or git error.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import shutil
import sys
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import check_python_dependency_locks, ci_tier, lint_exceptions
from scripts.lib.safe_subprocess import (
    CommandOutputLimitExceeded,
    CommandTimedOut,
    CommandValidationError,
    TextCommandResult,
    run,
)

GIT = shutil.which("git") or "/usr/bin/git"
GIT_TIMEOUT_S = 120
DEFAULT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CUTOFF_FILE = Path(__file__).resolve().parent / "dco-cutoff.txt"
MAX_COMMITS = 5000

# origin/master 20fa27ac625e, 6290 messages, measured 2026-11-11; 4x headroom.
MAX_COMMIT_MESSAGE_BYTES = 70_469 * 4
MAX_COMMIT_MESSAGE_LINES = 1_459 * 4
# Git's scissors line; in editor mode, a verbose diff follows comment lines below it.
SCISSORS_TAIL = b" ------------------------ >8 ------------------------"
VERBOSE_DIFF_HEAD = b"diff --git "
DIFF_EXTENDED_HEADERS = (
    b"old mode ",
    b"new mode ",
    b"deleted file mode ",
    b"new file mode ",
    b"copy from ",
    b"copy to ",
    b"rename from ",
    b"rename to ",
    b"similarity index ",
    b"dissimilarity index ",
    b"index ",
)
DIFF_NO_NEWLINE = b"\\ No newline at end of file"
DIFF_HUNK_RE = re.compile(rb"^@@ -[0-9]{1,9}(?:,([0-9]{1,9}))? \+[0-9]{1,9}(?:,([0-9]{1,9}))? @@")
DIFF_HUNK_DELTAS: dict[bytes, tuple[int, int]] = {
    b" ": (1, 1),
    b"-": (1, 0),
    b"+": (0, 1),
}
DIFF_LINE_ERE_SPECIAL = re.compile(r"([.\[\\()*+?{|^$])")
MAX_DIFF_ATTRIBUTION_LINES = 64
# Characters Git's core.commentChar=auto may pick (builtin/commit.c, git v2.56.1).
AUTO_COMMENT_CANDIDATES = tuple("#;@!$%^&|:")
# PRs 2906-3395, 300 bodies (corpus sha256 5a4d6f5c3cbf), measured 2026-11-11;
# largest 58,966 bytes (PR 3045) and 544 lines (PR 3041); 4x headroom.
MAX_PR_BODY_BYTES = 58_966 * 4
MAX_PR_BODY_LINES = 544 * 4
# JSON can escape each body byte as six ASCII bytes; allow 1 MiB event metadata.
MAX_PR_EVENT_BYTES = MAX_PR_BODY_BYTES * 6 + 1_048_576
# One commit per read; subject can repeat the message, plus bounded identity metadata.
MAX_COMMIT_LOG_BYTES = MAX_COMMIT_MESSAGE_BYTES * 2 + 65_536
# Changed path list for a single commit (NUL-delimited repository-relative paths).
MAX_COMMIT_PATHS_BYTES = 65_536

# GitHub logins (as the API reports them) whose commits are exempt.  Keep the
# list in docs/development/dco.md in step with this one.
BOT_LOGINS = ("renovate[bot]", "dependabot[bot]", "github-actions[bot]")
# Conditional PR-mode bot-opener and landed co-author exemptions (ADR-3555);
# keep docs/development/dco.md in step.
RENOVATE_BOT_LOGIN = "renovate[bot]"
RENOVATE_BOT_EMAIL = "29139614+renovate[bot]@users.noreply.github.com"
RELEASE_BOT_NAME = "vmafx-release-bot[bot]"
RELEASE_BOT_EMAIL = "340976456+vmafx-release-bot[bot]@users.noreply.github.com"
RELEASE_BOT_COAUTHOR = f"Co-authored-by: {RELEASE_BOT_NAME} <{RELEASE_BOT_EMAIL}>"
BOT_OPENER_EXCEPTION_RULE = "dco-bot-opener"
LANDED_COAUTHOR_EXCEPTION_RULE = "dco-landed-release-bot-coauthor"
# ADR-3560: each Python lock output has its own path-exact exception.
PYTHON_LOCK_EXCEPTION_RULE = "dco-python-lock-refresh"
PYTHON_LOCK_SUBJECT = "chore(deps): refresh Python dependency locks"
# GitHub caps the List commits on a pull request endpoint at 250 commits.
PULL_COMMIT_LIMIT = 250
FORGE_FILE_STATUSES = frozenset(
    {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"}
)

# All 13 tokens equal praetor tools/planning/commit_msg_check.py BANNED_COAUTHORS;
# both Python tuples use substring matching. Engine internal/forge/commit_message.go
# bannedCoauthorsRegex holds only the 11 word tokens, with word-boundary matching;
# the e-mail and [bot] entries are Python-only. Update both tuples together and
# synchronize word-token changes with the engine regex word list.
# On GitHub squash merges, GitHub (noreply@github.com) is the committer on every
# landed commit, so committer identity cannot authorize a commit sign-off; only
# the commit author or the designated landing identity is accepted.
BANNED_COAUTHOR_TOKENS = (
    "claude",
    "anthropic",
    "openai",
    "chatgpt",
    "gpt",
    "codex",
    "gemini",
    "copilot",
    "cursor",
    "opencode",
    "antigravity",
    "noreply@anthropic.com",
    "[bot]",
)

GENERATED_LINE_RE = re.compile(
    r"^(?:generated|created)\s+(?:with|by)\b",
    re.IGNORECASE,
)
ORDERED_MARKER_RE = re.compile(r"[0-9]{1,9}[.)]")
SIGNOFF_RE = re.compile(r"^signed-off-by:\s+(.+?)\s+<([^<>\s]+@[^<>\s]+)>\s*$", re.IGNORECASE)
FIELD_SEP = "\0"
LOG_FIELDS = 7  # sha, author name/e-mail, committer name/e-mail, subject, body
LOG_FORMAT = "%x00".join(["%H", "%an", "%ae", "%cn", "%ce", "%s", "%B"])


class UsageError(Exception):
    """Raised when git cannot answer; the gate must not read that as a pass."""


class InputBoundError(Exception):
    """Attribution input exceeds a named bound; refuse rather than truncate."""


@dataclass(frozen=True)
class Commit:
    sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    subject: str
    message: str


def run_git_result(
    args: list[str],
    stdin: str | None = None,
    max_output_bytes: int = MAX_COMMIT_LOG_BYTES,
    bound_name: str = "MAX_COMMIT_LOG_BYTES",
) -> TextCommandResult:
    """Run bounded Git and return the completed process without checking its exit status."""
    try:
        return run(
            [GIT, *args],
            allowed_executables=(GIT,),
            input_data=stdin,
            capture_output=True,
            text=True,
            check=False,
            timeout_seconds=GIT_TIMEOUT_S,
            max_output_bytes=max_output_bytes,
        )
    except CommandOutputLimitExceeded as exc:
        detail = (
            f"; MAX_COMMIT_MESSAGE_BYTES is {MAX_COMMIT_MESSAGE_BYTES}"
            if bound_name == "MAX_COMMIT_LOG_BYTES"
            else ""
        )
        raise InputBoundError(
            f"git output exceeds {bound_name} ({max_output_bytes}){detail}"
        ) from exc
    except (OSError, CommandTimedOut, CommandValidationError) as exc:
        raise UsageError(f"git {' '.join(args)}: {exc}") from exc


def run_git(
    args: list[str],
    stdin: str | None = None,
    max_output_bytes: int = MAX_COMMIT_LOG_BYTES,
    bound_name: str = "MAX_COMMIT_LOG_BYTES",
) -> str:
    """Run bounded Git; failure never becomes an empty successful answer."""
    done = run_git_result(
        args, stdin=stdin, max_output_bytes=max_output_bytes, bound_name=bound_name
    )
    if done.returncode != 0:
        raise UsageError(f"git {' '.join(args)} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def parse_commits(out: str) -> list[Commit]:
    """Parse NUL fields and git log -z's NUL record terminator."""
    if not out:
        return []
    fields = out.split(FIELD_SEP)
    if fields.pop() != "" or len(fields) % LOG_FIELDS:
        raise UsageError("unparseable NUL-terminated git log record")
    count = len(fields) // LOG_FIELDS
    if count > MAX_COMMITS:
        raise UsageError(f"{count} commits exceed the bound of {MAX_COMMITS}")
    return [Commit(*fields[i : i + LOG_FIELDS]) for i in range(0, len(fields), LOG_FIELDS)]


def list_commits(base: str, head: str) -> list[Commit]:
    """Read bounded metadata, then each non-merge commit separately, oldest first."""
    out = run_git(
        [
            "log",
            "--no-merges",
            "--reverse",
            f"--max-count={MAX_COMMITS + 1}",
            "--format=%H",
            f"{base}..{head}",
        ]
    )
    shas = out.splitlines()
    if len(shas) > MAX_COMMITS:
        raise UsageError(f"commits exceed the bound of {MAX_COMMITS}")
    commits = []
    for sha in shas:
        commits.extend(list_head_commit(sha))
    return commits


def list_head_commit(head: str) -> list[Commit]:
    """Read one commit, bounding captured bytes before parsing any message lines."""
    out = run_git(["log", "-z", "--no-merges", "-1", f"--format={LOG_FORMAT}", head])
    return parse_commits(out)


def is_ancestor(base: str, head: str) -> bool:
    """Return True if base is an ancestor of head, False if not or not a valid object."""
    done = run_git_result(["merge-base", "--is-ancestor", base, head])
    if done.returncode == 0:
        return True
    if done.returncode in (1, 128):
        return False
    raise UsageError(f"git merge-base exited {done.returncode}: {done.stderr.strip()}")


def trailer_lines(message: str) -> list[str]:
    """Return the trailer block of a commit message, as git parses it."""
    out = run_git(["interpret-trailers", "--parse", "--only-trailers"], stdin=message)
    return [line for line in out.splitlines() if line.strip()]


def signoff_emails(message: str) -> list[str]:
    """Return the e-mail addresses of the well-formed sign-off trailers."""
    found = []
    for line in trailer_lines(message):
        match = SIGNOFF_RE.match(line)
        if match:
            found.append(match.group(2).lower())
    return found


def bot_noreply_suffix(login: str) -> str:
    return f"+{login}@users.noreply.github.com".lower()


def is_exempt_bot_commit(commit: Commit, author: str, author_type: str) -> bool:
    """A bot commit is exempt only inside a pull request opened by that same bot."""
    if author_type != "Bot" or author not in BOT_LOGINS:
        return False
    return commit.author_email.lower().endswith(bot_noreply_suffix(author))


def commit_changed_paths(sha: str) -> list[str]:
    """Return the NUL-delimited repository-relative paths changed by one commit."""
    out = run_git(
        [
            "diff-tree",
            "-z",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            "--no-renames",
            "--end-of-options",
            sha,
        ],
        max_output_bytes=MAX_COMMIT_PATHS_BYTES,
        bound_name="MAX_COMMIT_PATHS_BYTES",
    )
    if not out:
        return []
    paths = out.split(FIELD_SEP)
    if paths.pop() != "":
        raise UsageError("unparseable NUL-terminated git diff-tree record")
    return paths


def is_exempt_opener_commit(
    sha: str,
    name: str,
    email: str,
    author: str,
    author_type: str,
    *,
    pre_push: bool = False,
    root: Path = DEFAULT_ROOT,
    subject: str = "",
) -> bool:
    """True when a Renovate PR commit is the release-bot refresh of excepted paths only.

    Two classes: every path a live ``dco-bot-opener`` exception (no subject check), or the
    exact ``PYTHON_LOCK_SUBJECT`` with every path covered by a live exception.
    """
    if pre_push or author != RENOVATE_BOT_LOGIN or author_type != "Bot":
        return False
    if (name, email) != NORMALIZED_RELEASE_BOT:
        return False
    paths = commit_changed_paths(sha)
    if not paths:
        return False
    if not lint_exceptions.still_read(BOT_OPENER_EXCEPTION_RULE, paths, root):
        return True
    return subject == PYTHON_LOCK_SUBJECT and not lint_exceptions.still_read(
        PYTHON_LOCK_EXCEPTION_RULE, paths, root
    )


def pr_attribution_reason(
    commit: Commit,
    author: str,
    author_type: str,
    opener: tuple[str, str] | None = None,
    *,
    pre_push: bool = False,
    root: Path = DEFAULT_ROOT,
) -> str | None:
    """Refuse bot authors outside their own branches, then apply shared attribution rules."""
    name = normalized_identity(commit.author_name)
    email = normalized_identity(commit.author_email)
    bot_author = is_bot_identity(name, email)
    if opener is not None:
        owns_branch = (name, email) == tuple(normalized_identity(part) for part in opener)
    else:
        owns_branch = author_type == "Bot" and email.endswith(bot_noreply_suffix(author))
    if (
        bot_author
        and not owns_branch
        and not is_exempt_opener_commit(
            commit.sha,
            name,
            email,
            author,
            author_type,
            pre_push=pre_push,
            root=root,
            subject=commit.subject,
        )
    ):
        return (
            f"bot author {commit.author_name} <{commit.author_email}> is not the branch opener; "
            "a squash landing would carry it as a Co-authored-by trailer that the landed gate "
            "refuses; re-author that commit with git commit --amend --reset-author --no-edit "
            "or drop it"
        )
    return commit_attribution_reason(commit)


def judge(
    commit: Commit,
    author: str,
    author_type: str,
    opener: tuple[str, str] | None = None,
    *,
    pre_push: bool = False,
    root: Path = DEFAULT_ROOT,
) -> str | None:
    """Return None when the commit passes, else the reason it does not."""
    reason = pr_attribution_reason(
        commit, author, author_type, opener, pre_push=pre_push, root=root
    )
    if reason:
        return reason
    if is_exempt_bot_commit(commit, author, author_type):
        return None
    return signoff_reason(commit)


def signoff_reason(commit: Commit) -> str | None:
    """Require a trailer matching the author or committer."""
    emails = signoff_emails(commit.message)
    if not emails:
        return "no 'Signed-off-by: Name <email>' trailer"
    own = {commit.author_email.lower(), commit.committer_email.lower()}
    if own.isdisjoint(emails):
        return (
            f"sign-off ({', '.join(emails)}) matches neither the author nor the committer address"
        )
    return None


def check_banned_coauthor(line: str) -> str | None:
    """Return the banned token if the line is a Co-authored-by with a forbidden token."""
    stripped = line.strip()
    if stripped.lower().startswith("co-authored-by:"):
        lower = stripped.lower()
        for token in BANNED_COAUTHOR_TOKENS:
            if token in lower:
                return token
    return None


def ordered_marker_end(line: str, start: int) -> int:
    """Return the end of a terminated ordered marker, or start when none matches."""
    # CommonMark 0.31.2 §5.2, List items: 1-9 ASCII digits followed by '.' or ')'.
    # https://spec.commonmark.org/0.31.2/#list-items
    match = ORDERED_MARKER_RE.match(line, start)
    if match is None:
        return start
    end = match.end()
    if end == len(line) or line[end].isspace() or unicodedata.category(line[end]) == "Cf":
        return end
    return start


def strip_attribution_prefix(line: str) -> str:
    """Remove leading comment, list, quote, heading, whitespace, and format prefixes linearly."""
    start = 0
    # Each iteration consumes at least one character: at most len(line) iterations.
    while start < len(line):
        if line.startswith("<!--", start):
            start += 4
        elif (
            line[start] in "-+*#>"
            or line[start].isspace()
            or unicodedata.category(line[start]) == "Cf"
        ):
            start += 1
        else:
            end = ordered_marker_end(line, start)
            if end == start:
                break
            start = end
    return line[start:]


def check_machine_attribution(line: str) -> bool:
    """Return True if line matches machine attribution patterns or contains robot emoji."""
    return bool(GENERATED_LINE_RE.match(strip_attribution_prefix(line)) or "\U0001f916" in line)


def normalize_attribution_text(text: str) -> str:
    """Normalize compatibility characters for both line and identity matching."""
    return unicodedata.normalize("NFKC", text)


def drop_format_characters(text: str) -> str:
    """Remove every Unicode format character for both line and identity matching."""
    return "".join(character for character in text if unicodedata.category(character) != "Cf")


def normalized_identity(text: str) -> str:
    """Share NFKC, format removal, whitespace and case normalization across identities."""
    return drop_format_characters(normalize_attribution_text(text)).strip().lower()


NORMALIZED_RELEASE_BOT = (
    normalized_identity(RELEASE_BOT_NAME),
    normalized_identity(RELEASE_BOT_EMAIL),
)


def is_bot_identity(name: str, email: str) -> bool:
    """Recognize bot suffixes in an already normalized name and email."""
    return name.endswith("[bot]") or email.endswith("[bot]@users.noreply.github.com")


def input_bound_reason(text: str, source: str, max_bytes: int, max_lines: int) -> str | None:
    """Reject UTF-8 byte/Unicode splitlines bounds before attribution scanning."""
    if len(text.encode("utf-8")) > max_bytes:
        return f"{source} exceeds MAX_{source}_BYTES ({max_bytes})"
    if len(text.splitlines()) > max_lines:
        return f"{source} exceeds MAX_{source}_LINES ({max_lines})"
    return None


def line_attribution_reason(line: str, source: str) -> str | None:
    """Apply shared message and PR body rules without exempting Markdown prefixes."""
    line = strip_attribution_prefix(normalize_attribution_text(line))
    line = drop_format_characters(line)
    token = check_banned_coauthor(line)
    if token:
        return f"disallowed Co-authored-by trailer ({token})"
    if check_machine_attribution(line):
        return f"{source} contains machine-generated attribution"
    return None


def commit_attribution_reason(commit: Commit) -> str | None:
    """Return the first forbidden identity or message attribution for a commit."""
    bound = input_bound_reason(
        commit.message, "COMMIT_MESSAGE", MAX_COMMIT_MESSAGE_BYTES, MAX_COMMIT_MESSAGE_LINES
    )
    if bound:
        return bound
    for role, name, email in (
        ("author", commit.author_name, commit.author_email),
        ("committer", commit.committer_name, commit.committer_email),
    ):
        identity = normalized_identity(f"{name} <{email}>")
        for candidate in BANNED_COAUTHOR_TOKENS:
            if candidate != "[bot]" and candidate in identity:
                return f"{role} identity names a model or coding tool ({candidate})"
    for line in commit.message.splitlines():
        reason = line_attribution_reason(line, "message")
        if reason:
            return reason
    return None


def landed_forge_fetch(env: Mapping[str, str]) -> ci_tier.Fetcher:
    """Build a repository-scoped getter whose configuration is checked on use."""

    def fetch(path: str) -> object:
        repo = env.get("GITHUB_REPOSITORY", "")
        if not repo:
            raise ci_tier.TierError("missing GITHUB_REPOSITORY")
        token = env.get("GH_TOKEN", "")
        if not token:
            raise ci_tier.TierError("missing GH_TOKEN")
        api_url = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
        return ci_tier.api_request("GET", f"{api_url}/repos/{repo}{path}", token)

    return fetch


def merged_pull_number(fetch: ci_tier.Fetcher, sha: str) -> int:
    """Read the single associated PR and verify that it merged as this squash."""
    pulls = ci_tier._paged(fetch, f"/commits/{sha}/pulls")
    if len(pulls) != 1:
        raise ci_tier.TierError(f"expected one associated pull request, found {len(pulls)}")
    pull = pulls[0]
    if not isinstance(pull, dict):
        raise ci_tier.TierError("malformed associated pull request")
    number = pull.get("number")
    if type(number) is not int or number <= 0:
        raise ci_tier.TierError("invalid associated pull request number")
    merged_at = pull.get("merged_at")
    if not isinstance(merged_at, str) or not merged_at or pull.get("merge_commit_sha") != sha:
        raise ci_tier.TierError(f"pull request {number} did not merge as this squash")
    parse_time(merged_at, f"pull request {number} merged_at")
    return number


def forge_commit_author(row: object) -> tuple[str, str, str]:
    """Return a PR commit's SHA, Git author name and Git author email."""
    if not isinstance(row, dict):
        raise ci_tier.TierError("malformed pull request commit")
    sha, commit = row.get("sha"), row.get("commit")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ci_tier.TierError("invalid pull request commit SHA")
    author = commit.get("author") if isinstance(commit, dict) else None
    if not isinstance(author, dict):
        raise ci_tier.TierError(f"commit {sha[:10]} has no Git author")
    name, email = author.get("name"), author.get("email")
    if not isinstance(name, str) or not isinstance(email, str):
        raise ci_tier.TierError(f"commit {sha[:10]} has an invalid Git author")
    return sha, name, email


def release_bot_commits(fetch: ci_tier.Fetcher, number: int) -> list[str]:
    """Find release-bot commits in a complete PR commit list using Git author identities."""
    rows = ci_tier._paged(fetch, f"/pulls/{number}/commits")
    if not rows or len(rows) >= PULL_COMMIT_LIMIT:
        raise ci_tier.TierError(f"pull request {number} has an empty or possibly truncated list")
    shas = []
    for row in rows:
        sha, name, email = forge_commit_author(row)
        if (normalized_identity(name), normalized_identity(email)) == NORMALIZED_RELEASE_BOT:
            shas.append(sha)
    if not shas:
        raise ci_tier.TierError(f"pull request {number} has no release-bot commit")
    return shas


def forge_file_paths(file: object, sha: str) -> list[str]:
    """Read a changed file, including the old path of a rename as PR mode does."""
    if not isinstance(file, dict):
        raise ci_tier.TierError(f"commit {sha[:10]} has a malformed file entry")
    path = file.get("filename")
    if not isinstance(path, str) or not path:
        raise ci_tier.TierError(f"commit {sha[:10]} has an invalid filename")
    status = file.get("status")
    if not isinstance(status, str) or status not in FORGE_FILE_STATUSES:
        raise ci_tier.TierError(f"commit {sha[:10]} has an invalid file status")
    if status != "renamed" and "previous_filename" not in file:
        return [path]
    previous = file.get("previous_filename")
    if not isinstance(previous, str) or not previous:
        raise ci_tier.TierError(f"commit {sha[:10]} has an invalid previous filename")
    return [path, previous]


def forge_commit_paths(fetch: ci_tier.Fetcher, sha: str) -> list[str]:
    """Read a release-bot commit's files, refusing a potentially truncated page."""
    response = fetch(f"/commits/{sha}?per_page={ci_tier.PAGE_SIZE}")
    files = response.get("files") if isinstance(response, dict) else None
    if not isinstance(files, list) or not 0 < len(files) < ci_tier.PAGE_SIZE:
        raise ci_tier.TierError(
            f"commit {sha[:10]} has a missing, empty or possibly truncated file list"
        )
    return [path for file in files for path in forge_file_paths(file, sha)]


def manifest_uv_version_only(sha: str) -> bool:
    """Prove the parent-to-squash manifest diff changes only the exact uv release."""
    manifest = check_python_dependency_locks.MANIFEST_PATH.as_posix()
    before, after = (
        check_python_dependency_locks.parse_manifest(
            run_git(["--no-lazy-fetch", "cat-file", "--", "blob", f"{rev}:{manifest}"]),
            parse_float=Decimal,
        )
        for rev in (f"{sha}^", sha)
    )
    old_version, new_version = before.pop("uv_version"), after.pop("uv_version")
    if old_version == new_version or before != after:
        return False
    # Equality checks Decimal values exactly. Serialization also distinguishes true from 1.
    return json.dumps(before, sort_keys=True, default=str) == json.dumps(
        after, sort_keys=True, default=str
    )


def python_lock_landed_exemption(
    sha: str, paths: list[str], root: Path, fetch: ci_tier.Fetcher | None
) -> bool:
    """Check the squash paths and prove the release bot stayed within its grant."""
    try:
        ungranted = set(lint_exceptions.still_read(PYTHON_LOCK_EXCEPTION_RULE, paths, root))
        if ungranted == set(paths):
            return False
        manifest = check_python_dependency_locks.MANIFEST_PATH.as_posix()
        if manifest in ungranted:
            if not manifest_uv_version_only(sha):
                return False
            ungranted.remove(manifest)
        if ungranted and not ungranted.issubset(
            check_python_dependency_locks.manifest_inputs(root)
        ):
            return False
        if fetch is None:
            fetch = landed_forge_fetch(os.environ)
        number = merged_pull_number(fetch, sha)
        for bot_sha in release_bot_commits(fetch, number):
            bot_paths = forge_commit_paths(fetch, bot_sha)
            if lint_exceptions.still_read(PYTHON_LOCK_EXCEPTION_RULE, bot_paths, root):
                raise ci_tier.TierError(
                    f"release-bot commit {bot_sha[:10]} touched an ungranted path"
                )
    except (
        ci_tier.TierError,
        check_python_dependency_locks.ContractError,
        InputBoundError,
        UsageError,
        OSError,
        ValueError,
        RecursionError,
        KeyError,
        TypeError,
        OverflowError,
    ) as error:
        print(f"dco: {sha[:10]} Python lock refresh exemption refused: {error}", file=sys.stderr)
        return False
    return True


def _drop_single_line(message: str, line: str) -> str | None:
    """Drop exactly one message line whose strip equals line, or return None."""
    lines = message.splitlines(keepends=True)
    kept = [item for item in lines if item.strip() != line]
    if len(lines) - len(kept) != 1:
        return None
    return "".join(kept)


def landed_exempt_message(
    commit: Commit, root: Path = DEFAULT_ROOT, *, fetch: ci_tier.Fetcher | None = None
) -> str:
    """Strip one release-bot co-author line for release-bot authors or Renovate grants.

    Covers any landed commit authored by the release bot (seen on render commit
    800122efd8) and Renovate commits matching ADR-3555 or ADR-3560 grants.
    """
    if input_bound_reason(
        commit.message, "COMMIT_MESSAGE", MAX_COMMIT_MESSAGE_BYTES, MAX_COMMIT_MESSAGE_LINES
    ):
        return commit.message
    if (commit.author_name, commit.author_email.lower()) == (
        RELEASE_BOT_NAME,
        RELEASE_BOT_EMAIL,
    ):
        stripped = _drop_single_line(commit.message, RELEASE_BOT_COAUTHOR)
        return commit.message if stripped is None else stripped
    if (commit.author_name, commit.author_email.lower()) != (
        RENOVATE_BOT_LOGIN,
        RENOVATE_BOT_EMAIL,
    ):
        return commit.message
    stripped = _drop_single_line(commit.message, RELEASE_BOT_COAUTHOR)
    if stripped is None:
        return commit.message
    paths = commit_changed_paths(commit.sha)
    unexcepted = lint_exceptions.still_read(LANDED_COAUTHOR_EXCEPTION_RULE, paths, root)
    if len(unexcepted) < len(paths) or python_lock_landed_exemption(commit.sha, paths, root, fetch):
        return stripped
    return commit.message


def judge_landed(
    commit: Commit,
    landing_email: str,
    root: Path = DEFAULT_ROOT,
    *,
    fetch: ci_tier.Fetcher | None = None,
) -> str | None:
    """Judge a commit on master: refuse bot co-authors, generated trailers, and bad sign-offs."""
    message = landed_exempt_message(commit, root, fetch=fetch)
    reason = commit_attribution_reason(replace(commit, message=message))
    if reason:
        return reason
    emails = signoff_emails(commit.message)
    if not emails:
        return "no 'Signed-off-by: Name <email>' trailer"
    allowed = {commit.author_email.lower(), landing_email.lower()}
    if allowed.isdisjoint(emails):
        return f"sign-off ({', '.join(emails)}) matches neither author nor landing identity"
    return None


def extract_email(identity: str) -> str:
    """Extract email address from an identity string like 'Name <email>' or 'email'."""
    match = re.search(r"<([^<>\s]+@[^<>\s]+)>", identity)
    if match:
        return match.group(1).lower()
    return identity.strip().lower()


def is_signoff_reason(reason: str) -> bool:
    """Distinguish sign-off failures from attribution failures for repair advice."""
    return reason.startswith(("no 'Signed-off-by:", "sign-off ("))


def report(failures: list[tuple[Commit, str]], landed: bool = False) -> None:
    """Print commit failures and repair advice appropriate to sign-off or attribution errors."""
    for commit, reason in failures:
        title = "DCO sign-off" if is_signoff_reason(reason) else "DCO attribution"
        print(f"::error title={title}::{commit.sha[:10]} {commit.subject}: {reason}")
    print("")
    signoff_failed = any(is_signoff_reason(reason) for _, reason in failures)
    attribution_failed = any(not is_signoff_reason(reason) for _, reason in failures)
    if landed:
        print(f"dco: {len(failures)} landed commit(s) refused.")
        if signoff_failed:
            print("  Landed commit check (ADR-3389): squash merge requires an explicit body file")
            print("  (--body-file / -F) containing commit body and sign-off.")
        print("  Alarm: commit already on master; published history is not rewritten.")
    else:
        print(f"dco: {len(failures)} commit(s) refused.")
        if signoff_failed:
            print("  Add the sign-off to each affected commit, then push again:")
            print("    git rebase --signoff $(git merge-base origin/master HEAD)")
            print("  New commits: git commit -s   (keep the trailers when squashing)")
    if attribution_failed and landed:
        print("  The squash body or author identity carried model/tool attribution;")
        print("  fix the landing tool's body file and author before the next merge.")
    elif attribution_failed:
        print("  Remove model/tool trailers or generated footers; re-author affected commits")
        print("  as yourself, and edit the pull request body to remove attribution.")
    if signoff_failed:
        print("  What the sign-off certifies: CONTRIBUTING.md#developer-certificate-of-origin")


def parse_time(text: str, what: str) -> datetime:
    """Parse an ISO 8601 timestamp; a naive one is read as UTC."""
    try:
        value = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise UsageError(f"{what}: not an ISO 8601 timestamp: {text.strip()!r}") from exc
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def read_cutoff(path: Path) -> datetime:
    """Return the rollout cutoff: the one non-comment line of the cutoff file."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UsageError(f"cutoff file {path}: {exc}") from exc
    values = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    if len(values) != 1:
        raise UsageError(f"cutoff file {path}: expected exactly one timestamp line")
    return parse_time(values[0], f"cutoff file {path}")


def grandfathered(created_at: str, cutoff_file: Path) -> bool:
    """True when the pull request was created strictly before the cutoff."""
    if not created_at:
        return False
    return parse_time(created_at, "created-at") < read_cutoff(cutoff_file)


def read_bounded_file(path: Path, max_bytes: int, bound: str) -> str:
    """Read at most bound+1 bytes; oversized files fail without truncation."""
    try:
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise InputBoundError(f"{path}: exceeds {bound} ({max_bytes})")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise UsageError(f"PR body file/event {path}: {exc}") from exc


def read_event_body() -> str:
    """Read the pull-request body from the file identified by GITHUB_EVENT_PATH."""
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        raise UsageError("PR body event: GITHUB_EVENT_PATH is required")
    text = read_bounded_file(Path(path), MAX_PR_EVENT_BYTES, "MAX_PR_EVENT_BYTES")
    try:
        payload = json.loads(text)
        body = payload["pull_request"]["body"]
    except (ValueError, KeyError, TypeError) as exc:
        raise UsageError(f"PR body event {path}: invalid pull_request.body") from exc
    if body is not None and not isinstance(body, str):
        raise UsageError(f"PR body event {path}: body must be a string or null")
    return body or ""


def read_pr_body(args: argparse.Namespace) -> str:
    """Explicit body file or event file, otherwise the local environment fallback."""
    if args.pr_body_file:
        return read_bounded_file(Path(args.pr_body_file), MAX_PR_BODY_BYTES, "MAX_PR_BODY_BYTES")
    if args.pr_body_from_event:
        return read_event_body()
    return str(args.pr_body)


def pr_body_attribution(body: str) -> list[tuple[int, str]]:
    """Return forbidden PR body lines with one-based line numbers."""
    bound = input_bound_reason(body, "PR_BODY", MAX_PR_BODY_BYTES, MAX_PR_BODY_LINES)
    if bound:
        return [(0, bound)]
    findings = []
    for number, line in enumerate(body.splitlines(), start=1):
        reason = line_attribution_reason(line, "PR body")
        if reason:
            findings.append((number, reason))
    return findings


def check_landed(args: argparse.Namespace, fetch: ci_tier.Fetcher | None = None) -> int:
    head, base = args.head, args.base
    run_git(["rev-parse", "--verify", f"{head}^{{commit}}"])
    is_zero_base = bool(re.fullmatch(r"0{40}", base))
    if is_zero_base or not is_ancestor(base, head):
        print(
            f"dco: base ({base[:10]}) is all-zero or not ancestor-reachable; judging head commit only."
        )
        commits = list_head_commit(head)
    else:
        commits = list_commits(base, head)
    landing_email = extract_email(args.landing_identity)
    if fetch is None:
        fetch = landed_forge_fetch(os.environ)
    failures = []
    for commit in commits:
        reason = judge_landed(commit, landing_email, fetch=fetch)
        if reason is not None:
            failures.append((commit, reason))
    if failures:
        report(failures, landed=True)
        return 1
    print(f"dco: PASS - {len(commits)} commit(s) verified on master.")
    return 0


def pr_signoff_exemption(args: argparse.Namespace) -> str | None:
    """Return the sign-off exemption notice when release or cutoff rules apply."""
    if args.release_pr:
        return "dco: machine-generated release pull request, exempt."
    if grandfathered(args.created_at, Path(args.cutoff_file)):
        return f"dco: pull request created {args.created_at}, before the cutoff; grandfathered."
    return None


def branch_opener(commits: list[Commit], pre_push: bool) -> tuple[str, str] | None:
    """Use the oldest pre-push author only if human or its normalized email matches BOT_LOGINS."""
    if not pre_push or not commits:
        return None
    name = normalized_identity(commits[0].author_name)
    email = normalized_identity(commits[0].author_email)
    if is_bot_identity(name, email) and not any(
        email.endswith(bot_noreply_suffix(login)) for login in BOT_LOGINS
    ):
        return None
    return commits[0].author_name, commits[0].author_email


def check_pr(args: argparse.Namespace) -> int:
    """Enforce commit and body attribution on every PR, and commit sign-offs unless exempt."""
    commits = list_commits(args.base, args.head)
    pre_push = bool(args.merge_base)
    opener = branch_opener(commits, pre_push)
    root = Path(args.exceptions_root)
    exemption = pr_signoff_exemption(args)
    judge_commit: Callable[[Commit], str | None]
    if exemption is not None:
        print(exemption)
        judge_commit = functools.partial(
            pr_attribution_reason,
            author=args.author,
            author_type=args.author_type,
            opener=opener,
            pre_push=pre_push,
            root=root,
        )
        kind = "release pull request" if args.release_pr else "grandfathered"
        summary = f" free of attribution; sign-off exempt ({kind})"
    else:
        judge_commit = functools.partial(
            judge,
            author=args.author,
            author_type=args.author_type,
            opener=opener,
            pre_push=pre_push,
            root=root,
        )
        summary = ", every one signed off or exempt"
    body_findings = pr_body_attribution(read_pr_body(args))
    failures = [(c, reason) for c in commits if (reason := judge_commit(c)) is not None]
    if failures:
        report(failures)
    for number, reason in body_findings:
        print(f"::error title=PR body attribution::line {number}: {reason}")
    if body_findings:
        print("  Edit the pull request body to remove model/tool attribution.")
    if failures or body_findings:
        return 1
    print(f"dco: PASS - {len(commits)} commit(s){summary}.")
    return 0


def resolve_push_range(args: argparse.Namespace) -> None:
    """Point ``--base`` at REF and ``--head`` at the outgoing commit.

    ``REF..head`` is the merge-base range without its criss-cross caveat: it
    leaves out every commit reachable from REF, including those a branch took
    in by merging REF.
    """
    if args.base:
        raise UsageError("--merge-base and --base (or BASE_SHA) are mutually exclusive")
    if args.landed:
        raise UsageError("--merge-base checks a branch before push; it cannot take --landed")
    head = args.head or os.environ.get("PRE_COMMIT_TO_REF", "") or "HEAD"
    args.head = run_git(["rev-parse", "--verify", "--end-of-options", f"{head}^{{commit}}"])
    args.head = args.head.strip()
    base = run_git(["rev-parse", "--verify", "--end-of-options", f"{args.merge_base}^{{commit}}"])
    args.base = base.strip()


def check(args: argparse.Namespace) -> int:
    if args.merge_base:
        resolve_push_range(args)
        # Pre-push ownership comes only from eligible outgoing authors.
        args.author_type = ""
    if args.landed:
        return check_landed(args)
    return check_pr(args)


def message_identity(kind: str) -> tuple[str, str]:
    """Read the identity Git will use for this commit."""
    identity = run_git(["var", f"GIT_{kind}_IDENT"]).strip()
    match = re.match(r"^(.*?)\s+<([^<>\s]+@[^<>\s]+)>\s+\d+\s+[+-]\d{4}$", identity)
    if not match:
        raise UsageError(f"git var GIT_{kind}_IDENT: unparseable identity")
    return match.group(1), match.group(2)


def report_message_failure(commit: Commit, reason: str) -> None:
    """Print advice for a commit that Git has not created yet."""
    signoff_failed = is_signoff_reason(reason)
    title = "DCO sign-off" if signoff_failed else "DCO attribution"
    print(f"::error title={title}::{commit.sha} {commit.subject}: {reason}")
    print("dco: the commit being made is refused.")
    if signoff_failed:
        print("  New commit: git commit -s")
        print("  Amend: git commit --amend -s --no-edit")
    else:
        print(
            "  Remove model/tool attribution from the message or author identity and commit again."
        )


def git_config_values(keys: tuple[str, ...]) -> dict[str, str]:
    """Return the last configured value for each matching Git config key."""
    wanted = {key.lower() for key in keys}
    values: dict[str, str] = {}
    # git config --list -z output is bounded by MAX_COMMIT_LOG_BYTES in run_git.
    for entry in run_git(["config", "--list", "-z"]).split("\0"):
        key, _, setting = entry.partition("\n")
        lower = key.lower()
        if lower in wanted:
            values.pop(lower, None)
            values[lower] = setting
    return values


def comment_prefixes() -> tuple[str, ...]:
    """Return Git's comment string, or every candidate when Git picks one itself."""
    values = git_config_values(("core.commentchar", "core.commentstring"))
    value = next(reversed(values.values()), "#")
    # Git matches core.commentChar/String "auto" without regard to case.
    if value.isascii() and value.lower() == "auto":
        return AUTO_COMMENT_CANDIDATES
    return (value,)


def cleanup_mode() -> str:
    """Return Git's configured commit.cleanup mode in lower case, or empty when unset."""
    return git_config_values(("commit.cleanup",)).get("commit.cleanup", "").lower()


def scissors_prefix(raw: bytes, prefixes: tuple[str, ...]) -> str | None:
    """Return the comment prefix of a Git scissors line, or None when raw is not one."""
    line = raw.rstrip(b"\r\n")
    # Bounded by len(prefixes), at most len(AUTO_COMMENT_CANDIDATES).
    for prefix in prefixes:
        if line == prefix.encode("utf-8") + SCISSORS_TAIL:
            return prefix
    return None


@dataclass
class _ScissorsBlock:
    start: int | None = None
    prefix: str = ""
    has_comment: bool = False


@dataclass
class _DiffState:
    phase: str = "start"
    old_rem: int = 0
    new_rem: int = 0
    can_noeol: bool = False
    pending_pos: int | None = None


def _is_diff_git_line(line: bytes) -> bool:
    """Match a non-empty 'diff --git ' file header line."""
    return line.startswith(VERBOSE_DIFF_HEAD) and len(line) > len(VERBOSE_DIFF_HEAD)


def _is_binary_diff_line(line: bytes) -> bool:
    """Match Git's 'Binary files <a-path> and <b-path> differ' summary line."""
    return (
        line.startswith(b"Binary files ")
        and line.endswith(b" differ")
        and len(line) > len(b"Binary files  differ")
    )


def _start_hunk(line: bytes, state: _DiffState, pos: int) -> bool:
    """Parse a unified-diff hunk header and initialize its expected line counts."""
    match = DIFF_HUNK_RE.match(line)
    if match is None:
        return False
    old_text, new_text = match.group(1), match.group(2)
    state.old_rem = 1 if old_text is None else int(old_text)
    state.new_rem = 1 if new_text is None else int(new_text)
    state.can_noeol = False
    if state.old_rem == 0 and state.new_rem == 0:
        state.phase = "after_hunk"
        state.pending_pos = None
    else:
        state.phase = "in_hunk"
        if state.pending_pos is None:
            state.pending_pos = pos
    return True


def _step_header_phase(line: bytes, state: _DiffState, pos: int) -> bool:
    """Advance from a 'diff --git ' or extended-header state."""
    if state.phase == "ext_header" and _is_diff_git_line(line):
        state.phase = "diff_head"
        state.pending_pos = pos
        return True
    if line.startswith(DIFF_EXTENDED_HEADERS):
        state.phase = "ext_header"
        state.pending_pos = None
        return True
    if line.startswith(b"--- "):
        state.phase = "need_plus"
        if state.pending_pos is None:
            state.pending_pos = pos
        return True
    if _is_binary_diff_line(line):
        state.phase = "after_binary"
        state.pending_pos = None
        return True
    return _start_hunk(line, state, pos)


def _step_hunk_line(line: bytes, state: _DiffState) -> bool:
    """Consume one counted hunk body line or a legal no-newline marker."""
    if line == DIFF_NO_NEWLINE:
        ok = state.can_noeol and 0 in (state.old_rem, state.new_rem)
        state.can_noeol = False
        return ok
    delta = DIFF_HUNK_DELTAS.get(line[:1])
    if delta is None or state.old_rem < delta[0] or state.new_rem < delta[1]:
        return False
    state.old_rem -= delta[0]
    state.new_rem -= delta[1]
    state.can_noeol = True
    if state.old_rem == 0 and state.new_rem == 0:
        state.phase = "after_hunk"
        state.pending_pos = None
    return True


def _step_after_hunk(line: bytes, state: _DiffState, pos: int) -> bool:
    """Advance from a completed hunk to no-newline, next hunk, or next file."""
    if line == DIFF_NO_NEWLINE and state.can_noeol:
        state.can_noeol = False
        return True
    if _is_diff_git_line(line):
        state.can_noeol = False
        state.phase = "diff_head"
        state.pending_pos = pos
        return True
    return _start_hunk(line, state, pos)


def _step_diff_line(raw: bytes, state: _DiffState, pos: int) -> bool:
    """Advance the diff grammar by one raw line; return False when the grammar breaks."""
    line = raw.removesuffix(b"\n").removesuffix(b"\r")
    if state.phase in ("start", "after_binary"):
        result = _is_diff_git_line(line)
        if result:
            state.phase = "diff_head"
            state.pending_pos = pos
    elif state.phase in ("diff_head", "ext_header"):
        result = _step_header_phase(line, state, pos)
    elif state.phase == "need_plus":
        state.phase = "need_hunk"
        result = line.startswith(b"+++ ")
    elif state.phase == "need_hunk":
        result = _start_hunk(line, state, pos)
    elif state.phase == "in_hunk":
        result = _step_hunk_line(line, state)
    else:
        result = _step_after_hunk(line, state, pos)
    return result


def _append_bounded(data: bytearray, chunk: bytes, path: Path) -> None:
    """Append chunk to data and enforce MAX_COMMIT_MESSAGE_BYTES."""
    data += chunk
    if len(data) > MAX_COMMIT_MESSAGE_BYTES:
        raise InputBoundError(
            f"{path}: exceeds MAX_COMMIT_MESSAGE_BYTES ({MAX_COMMIT_MESSAGE_BYTES})"
        )


def _read_tail_into(stream: BinaryIO, data: bytearray, path: Path) -> None:
    """Read every remaining byte after a broken diff suffix as message text."""
    remaining = MAX_COMMIT_MESSAGE_BYTES + 1 - len(data)
    if remaining > 0:
        _append_bounded(data, stream.read(remaining), path)
    if stream.read(1):
        raise InputBoundError(
            f"{path}: exceeds MAX_COMMIT_MESSAGE_BYTES ({MAX_COMMIT_MESSAGE_BYTES})"
        )


def _consume_diff_suffix(
    stream: BinaryIO, first_raw: bytes, first_pos: int, path: Path
) -> int | None:
    """Validate verbose diff lines to EOF; return None on full match or rewind offset."""
    state = _DiffState()
    if not _step_diff_line(first_raw, state, first_pos):
        return first_pos
    # HISS-02: bounded by MAX_COMMIT_MESSAGE_BYTES + 1 diff lines before refusing truncation.
    for _ in range(MAX_COMMIT_MESSAGE_BYTES + 1):
        pos = stream.tell()
        raw = stream.readline(MAX_COMMIT_LOG_BYTES + 1)
        if not raw:
            return state.pending_pos
        if len(raw) > MAX_COMMIT_LOG_BYTES:
            raise InputBoundError(
                f"{path}: diff line exceeds MAX_COMMIT_LOG_BYTES ({MAX_COMMIT_LOG_BYTES})"
            )
        if not _step_diff_line(raw, state, pos):
            return pos if state.pending_pos is None else state.pending_pos
    if stream.read(1):
        raise InputBoundError(
            f"{path}: exceeds MAX_COMMIT_MESSAGE_BYTES ({MAX_COMMIT_MESSAGE_BYTES})"
        )
    return state.pending_pos


def _git_exits_zero(args: list[str]) -> bool:
    """Return True only when bounded Git exits 0; errors and timeouts fail closed."""
    try:
        return run_git_result(args).returncode == 0
    except (InputBoundError, UsageError) as _:
        return False


def _commit_exists(rev: str) -> bool:
    """Return True when rev resolves to an existing commit object."""
    return _git_exits_zero(["rev-parse", "-q", "--verify", f"{rev}^{{commit}}"])


def _grep_whole_line(patterns: tuple[str, str], target: tuple[str, ...]) -> bool:
    """Return True only when git grep finds an exact whole-line match (exit 0)."""
    return _git_exits_zero(
        [
            "grep",
            "-E",
            "--no-ignore-case",
            "-q",
            "-e",
            patterns[0],
            "-e",
            patterns[1],
            *target,
            "--",
        ]
    )


def _line_in_repo(text: str, rev_cache: dict[str, bool]) -> bool:
    """Check index, HEAD, HEAD^, and tracked worktree files for whole-line text."""
    escaped = DIFF_LINE_ERE_SPECIAL.sub(r"\\\1", text)
    # git grep has no -x/--line-regexp switch; anchored POSIX ERE matches whole lines.
    patterns = (f"^{escaped}$", f"^{escaped}\r$")
    # GIT_INDEX_FILE set by commit -a or a pathspec commit is honoured by grep --cached
    # without extra code.
    if _grep_whole_line(patterns, ("--cached",)):
        return True
    # HISS-02: bounded by 2 revisions (HEAD and HEAD^).
    for rev in ("HEAD", "HEAD^"):
        exists = rev_cache.get(rev)
        if exists is None:
            exists = _commit_exists(rev)
            rev_cache[rev] = exists
        if exists and _grep_whole_line(patterns, (rev,)):
            return True
    return _grep_whole_line(patterns, ())


def _hunk_line_backed(
    line: str, in_hunk: bool, matched: set[str], rev_cache: dict[str, bool]
) -> bool:
    """Confirm one flagged diff line is a hunk body line present in the repository."""
    if not in_hunk or line[:1] not in ("+", "-", " "):
        return False
    text = line[1:]
    if text in matched:
        return True
    if not _line_in_repo(text, rev_cache):
        return False
    matched.add(text)
    return True


def _diff_region_backed(stream: BinaryIO, first_pos: int, end_pos: int | None) -> bool:
    """Verify attributed lines in an exempted diff region match repository content."""
    stream.seek(first_pos)
    state = _DiffState()
    rev_cache: dict[str, bool] = {}
    matched: set[str] = set()
    attributed = 0
    # HISS-02: _consume_diff_suffix bounded diff lines to MAX_COMMIT_MESSAGE_BYTES + 1.
    for _ in range(MAX_COMMIT_MESSAGE_BYTES + 2):
        pos = stream.tell()
        if pos == end_pos:
            return True
        raw = stream.readline(MAX_COMMIT_LOG_BYTES + 1)
        if not raw:
            return True
        in_hunk = state.phase == "in_hunk"
        if not _step_diff_line(raw, state, pos):
            return False
        # A verbose diff may show non-UTF-8 file bytes; a flagged line with a replacement
        # character never matches repository content, so the exemption fails closed.
        line = raw.removesuffix(b"\n").removesuffix(b"\r").decode("utf-8", errors="replace")
        if line_attribution_reason(line, "commit message") is None:
            continue
        attributed += 1
        if attributed > MAX_DIFF_ATTRIBUTION_LINES or not _hunk_line_backed(
            line, in_hunk, matched, rev_cache
        ):
            return False
    return False


def _finish_diff_or_tail(
    stream: BinaryIO,
    data: bytearray,
    block_start: int,
    block_prefix: str,
    first_raw: bytes,
    first_pos: int,
    path: Path,
) -> tuple[str, str]:
    """Return message before a valid diff suffix, or check remaining bytes on break."""
    if not first_raw.endswith(b"\n"):
        first_raw += stream.readline(MAX_COMMIT_LOG_BYTES + 1 - len(first_raw))
        if len(first_raw) > MAX_COMMIT_LOG_BYTES:
            raise InputBoundError(
                f"{path}: diff line exceeds MAX_COMMIT_LOG_BYTES ({MAX_COMMIT_LOG_BYTES})"
            )
    resume = _consume_diff_suffix(stream, first_raw, first_pos, path)
    if (resume is None or resume > first_pos) and not _diff_region_backed(
        stream, first_pos, resume
    ):
        resume = first_pos
    if resume is None:
        return data[:block_start].decode("utf-8"), block_prefix
    stream.seek(resume)
    _read_tail_into(stream, data, path)
    return data.decode("utf-8"), ""


def _step_scissors_block(
    raw: bytes, block: _ScissorsBlock, data_len: int, prefixes: tuple[str, ...]
) -> int | None:
    """Update scissors-block state; return block start when raw begins a verbose diff."""
    if block.start is not None:
        if block.has_comment and raw.startswith(VERBOSE_DIFF_HEAD):
            return block.start
        block.has_comment = True
        if not raw.startswith(block.prefix.encode("utf-8")):
            block.start = None
            block.prefix = ""
            block.has_comment = False
    matched = scissors_prefix(raw, prefixes)
    if matched is not None:
        block.start = data_len
        block.prefix = matched
        block.has_comment = False
    return None


def read_pending_message(path: Path, prefixes: tuple[str, ...], editor: bool) -> tuple[str, str]:
    """Read a pending message, exempting only proven verbose diff output in editor mode."""
    active_prefixes = prefixes if editor else ()
    data = bytearray()
    block = _ScissorsBlock()
    try:
        with path.open("rb") as stream:
            # HISS-02: each line adds at least one byte, so the byte bound ends the loop first.
            for _ in range(MAX_COMMIT_MESSAGE_BYTES + 1):
                line_pos = stream.tell()
                raw = stream.readline(MAX_COMMIT_MESSAGE_BYTES + 1)
                if not raw:
                    break
                cut_at = _step_scissors_block(raw, block, len(data), active_prefixes)
                if cut_at is not None:
                    return _finish_diff_or_tail(
                        stream, data, cut_at, block.prefix, raw, line_pos, path
                    )
                _append_bounded(data, raw, path)
        return data.decode("utf-8"), ""
    except (OSError, UnicodeError) as exc:
        raise UsageError(f"{path}: {exc}") from exc


def strip_comments(message: str, prefix: str) -> str:
    """Clean a message as Git does when it drops the lines starting with prefix."""
    args = ["-c", f"core.commentChar={prefix}", "stripspace", "--strip-comments"]
    return run_git(args, stdin=message)


def selected_comment(text: str, prefixes: tuple[str, ...], block_prefix: str) -> str:
    """Pick the single comment string Git uses for an edited commit message."""
    if len(prefixes) == 1:
        return prefixes[0]
    if block_prefix:
        return block_prefix
    lines = text.splitlines()
    # Bounded by len(lines) * len(prefixes) (within MAX_COMMIT_MESSAGE_BYTES).
    for line in reversed(lines):
        for prefix in prefixes:
            if line.startswith(prefix):
                return prefix
    return "#"


def editor_signoff_text(text: str, q: str, cleanup: str, truncate: bool) -> str:
    """Clean the sign-off portion Git keeps; scissors cuts only when truncate is set."""
    scissors = q + SCISSORS_TAIL.decode("utf-8")
    kept: list[str] = []
    lines = text.split("\n")
    # Bounded by len(lines) (at most MAX_COMMIT_MESSAGE_BYTES + 1).
    for line in lines:
        if truncate and line.rstrip("\r") == scissors:
            break
        kept.append(line)
    cut = "\n".join(kept)
    if cleanup in ("whitespace", "verbatim", "scissors"):
        return run_git(["stripspace"], stdin=cut)
    return strip_comments(cut, q)


def check_message_file(path: str) -> int:
    """Check a pending commit message with Git's effective identities."""
    editor = os.environ.get("GIT_EDITOR") != ":"
    prefixes = comment_prefixes() if editor else ()
    try:
        text, block_prefix = read_pending_message(Path(path), prefixes, editor)
    except UsageError as exc:
        raise UsageError(f"commit message file {path}: {exc}") from exc
    merge_path = Path(run_git(["rev-parse", "--git-path", "MERGE_HEAD"]).strip())
    if merge_path.is_file():
        print("dco: merge commit is exempt.")
        return 0
    author_name, author_email = message_identity("AUTHOR")
    committer_name, committer_email = message_identity("COMMITTER")
    message = run_git(["stripspace"], stdin=text)
    if editor:
        cleanup = cleanup_mode()
        q = selected_comment(text, prefixes, block_prefix)
        truncate = bool(block_prefix) or cleanup == "scissors"
        signoff_text = editor_signoff_text(text, q, cleanup, truncate)
    else:
        signoff_text = message
    stored = signoff_text.splitlines()
    subject = stored[0] if stored else ""
    commit = Commit(
        "(commit being made)",
        author_name,
        author_email,
        committer_name,
        committer_email,
        subject,
        message,
    )
    signoff_commit = replace(commit, message=signoff_text)
    reason = commit_attribution_reason(commit) or signoff_reason(signoff_commit)
    if reason:
        report_message_failure(commit, reason)
        return 1
    print("dco: PASS - commit message")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse revision, identity, body-source, and enforcement options with environment defaults."""
    env = os.environ.get
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base", default=env("BASE_SHA", ""))
    parser.add_argument("--head", default=None)
    parser.add_argument("--author", default=env("PR_AUTHOR", ""))
    parser.add_argument("--author-type", default=env("PR_AUTHOR_TYPE", ""))
    parser.add_argument("--created-at", default=env("PR_CREATED_AT", ""))
    parser.add_argument("--cutoff-file", default=str(DEFAULT_CUTOFF_FILE))
    parser.add_argument("--exceptions-root", default=str(DEFAULT_ROOT))
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--pr-body-file", "--pr-body", default="")
    body.add_argument("--pr-body-from-event", action="store_true")
    parser.set_defaults(pr_body=env("PR_BODY", ""))
    parser.add_argument(
        "--release-pr", action="store_true", default=env("DCO_RELEASE_PR", "") == "true"
    )
    parser.add_argument("--landed", action="store_true")
    parser.add_argument("--merge-base", default="", metavar="REF")
    parser.add_argument("--message-file", default=None, metavar="PATH")
    parser.add_argument("--landing-identity", default=env("LANDING_IDENTITY", ""))
    args = parser.parse_args(argv)
    if args.message_file == "":
        parser.error("--message-file needs a path")
    if args.head is None:
        # --merge-base names the pushed commit itself; HEAD_SHA must not replace it.
        args.head = "" if args.merge_base else env("HEAD_SHA", "")
    return args


def main(argv: list[str]) -> int:
    """Validate required inputs and return distinct statuses for policy and usage failures."""
    args = parse_args(argv)
    if args.message_file and any(
        arg == option or arg.startswith(option + "=")
        for arg in argv
        for option in (
            "--base",
            "--head",
            "--merge-base",
            "--landed",
            "--pr-body-file",
            "--pr-body",
            "--pr-body-from-event",
        )
    ):
        print(
            "check-dco: --message-file cannot be combined with range, landed or PR body options",
            file=sys.stderr,
        )
        return 2
    if not args.message_file and not args.merge_base and (not args.base or not args.head):
        print(
            "check-dco: --base and --head (or BASE_SHA and HEAD_SHA), or --merge-base,"
            " are required",
            file=sys.stderr,
        )
        return 2
    if args.landed and not args.landing_identity:
        print(
            "check-dco: --landing-identity (or LANDING_IDENTITY) is required with --landed",
            file=sys.stderr,
        )
        return 2
    try:
        return check_message_file(args.message_file) if args.message_file else check(args)
    except InputBoundError as exc:
        print(f"check-dco: {exc}", file=sys.stderr)
        return 1
    except UsageError as exc:
        print(f"check-dco: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
