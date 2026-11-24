#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require --no-install-recommends when apt-install-cached.sh installs driver-recommending libs.

Positive: checked-in tests-and-quality-gates.yml holds; a fixture with libcudart12 and
--no-install-recommends passes; a fixture without driver-recommending packages passes
without --no-install-recommends.
Negative: a fixture naming libcudart12 without --no-install-recommends fails.
Boundary: backslash-continued flags pass; flags after shell separators (&&) do not
exempt an earlier install call; missing apt list files fail closed.
"""

from __future__ import annotations

import os
import shlex
import tempfile
import unittest
from collections.abc import Set as AbstractSet
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests-and-quality-gates.yml"
DRIVER_RECOMMENDING: set[str] = {"libcudart12"}
SHELL_SEPARATORS: frozenset[str] = frozenset({"&&", "||", ";", "|"})


def workflow_under_test() -> Path:
    """Return WORKFLOW_UNDER_TEST when set, otherwise the tracked workflow."""
    override = os.environ.get("WORKFLOW_UNDER_TEST")
    return Path(override) if override else DEFAULT_WORKFLOW


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join shell backslash continuations while preserving starting line numbers."""
    joined: list[tuple[int, str]] = []
    buf = ""
    start = 1
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if not buf:
            start = lineno
        trimmed = raw.rstrip()
        if trimmed.endswith("\\"):
            buf += trimmed[:-1] + " "
        else:
            joined.append((start, buf + raw))
            buf = ""
    if buf:
        joined.append((start, buf))
    return joined


def parse_install_line(line: str) -> tuple[str, tuple[str, ...]] | None:
    """Extract (list_path, trailing_args) from an apt-install-cached.sh install line."""
    if "apt-install-cached.sh" not in line:
        return None
    tokens = shlex.split(line, comments=True)
    for idx, tok in enumerate(tokens):
        if tok != "apt-install-cached.sh" and not tok.endswith("/apt-install-cached.sh"):
            continue
        after = tokens[idx + 1 :]
        if not after or after[0] != "install":
            return None
        rest = after[1:]
        if not rest or rest[0] in SHELL_SEPARATORS:
            return ("", ())
        args: list[str] = []
        for arg in rest[1:]:
            if arg in SHELL_SEPARATORS:
                break
            args.append(arg)
        return (rest[0], tuple(args))
    return None


def extract_install_calls(text: str) -> list[tuple[int, str, tuple[str, ...]]]:
    """Find every (lineno, list_path, trailing_args) install call in workflow text."""
    calls: list[tuple[int, str, tuple[str, ...]]] = []
    for lineno, line in logical_lines(text):
        parsed = parse_install_line(line)
        if parsed is not None:
            calls.append((lineno, parsed[0], parsed[1]))
    return calls


def read_package_list(path: Path) -> set[str]:
    """Read package names from an apt list file, skipping '#' comments and blank lines."""
    packages: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        packages.update(stripped.split())
    return packages


def check_workflow_text(
    text: str,
    repo_root: Path = REPO_ROOT,
    source_name: str = ".github/workflows/tests-and-quality-gates.yml",
    driver_recommending: AbstractSet[str] = DRIVER_RECOMMENDING,
) -> list[str]:
    """Return findings where a DRIVER_RECOMMENDING list lacks --no-install-recommends."""
    findings: list[str] = []
    for lineno, list_rel, args in extract_install_calls(text):
        if not list_rel:
            findings.append(f"{source_name}:{lineno}: missing list path after install")
            continue
        list_path = repo_root / list_rel
        if not list_path.is_file():
            findings.append(f"{source_name}:{lineno}: missing apt list {list_rel}")
            continue
        flagged = sorted(read_package_list(list_path) & set(driver_recommending))
        if flagged and "--no-install-recommends" not in args:
            joined = ", ".join(flagged)
            findings.append(
                f"{source_name}:{lineno}: {list_rel} names {joined} without --no-install-recommends"
            )
    return findings


def check_workflow(
    workflow_path: Path | None = None,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """Check a workflow file on disk against DRIVER_RECOMMENDING apt package lists."""
    target = workflow_path if workflow_path is not None else workflow_under_test()
    text = target.read_text(encoding="utf-8")
    return check_workflow_text(text, repo_root=repo_root, source_name=str(target))


class AptInstallRecommendsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write_list(self, rel: str, content: str) -> None:
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    def test_checked_in_workflow_holds(self) -> None:
        target = workflow_under_test()
        calls = extract_install_calls(target.read_text(encoding="utf-8"))
        self.assertTrue(calls, f"no apt-install-cached.sh install calls in {target}")
        self.assertEqual(check_workflow(target, repo_root=REPO_ROOT), [])

    def test_driver_recommending_package_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "# comment\n\nninja-build\nlibcudart12\n")
        snippet = (
            "jobs:\n  cov:\n    steps:\n"
            "      - run: |\n"
            "          bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
        )
        findings = check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("libcudart12", findings[0])
        self.assertIn("--no-install-recommends", findings[0])

    def test_driver_recommending_package_with_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "# comment\n\nninja-build\nlibcudart12\n")
        snippet = (
            "jobs:\n  cov:\n    steps:\n"
            "      - run: |\n"
            "          bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_list_without_driver_recommending_package_passes_without_flag(self) -> None:
        self._write_list(
            ".github/apt/plain.txt",
            "# libcudart12 mentioned in comment only\n\nninja-build\nlibzimg-dev\n",
        )
        snippet = (
            "jobs:\n  build:\n    steps:\n"
            "      - run: |\n"
            "          bash scripts/ci/apt-install-cached.sh install .github/apt/plain.txt\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_boundary_continuations_chaining_and_missing_list(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        continued = (
            "          bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt \\\n"
            "            --no-install-recommends\n"
        )
        self.assertEqual(check_workflow_text(continued, repo_root=self.root), [])
        chained = (
            "          bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt"
            " && echo --no-install-recommends\n"
        )
        self.assertEqual(len(check_workflow_text(chained, repo_root=self.root)), 1)
        missing = "          bash scripts/ci/apt-install-cached.sh install .github/apt/nope.txt\n"
        missing_findings = check_workflow_text(missing, repo_root=self.root)
        self.assertEqual(len(missing_findings), 1)
        self.assertIn("missing apt list", missing_findings[0])


if __name__ == "__main__":
    unittest.main()
