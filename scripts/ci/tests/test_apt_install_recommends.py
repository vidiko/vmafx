#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require --no-install-recommends when apt-install-cached.sh installs driver-recommending libs.

Positive: checked-in tests-and-quality-gates.yml holds; a fixture with libcudart12 and
--no-install-recommends passes; a fixture without driver-recommending packages passes
without --no-install-recommends; multiple flagged installs on one line pass when all carry
--no-install-recommends.
Negative: a fixture naming libcudart12 without --no-install-recommends fails; chained
subcommands (refresh && install, refresh&&install) and multiple installs on one line fail
when any flagged install omits --no-install-recommends. An install line ending with
backslash-space or backslash-tab before --no-install-recommends on the next line also fails
because bash does not continue past escaped trailing blanks.
Boundary: backslash-continued flags pass; continuations over MAX_CONTINUATION_LINES fail
closed; flags after shell separators (&&) do not exempt an earlier install call; missing apt
list files, oversize workflow/list inputs (MAX_WORKFLOW_BYTES, MAX_LIST_BYTES), and excess
install calls (MAX_INSTALL_CALLS) fail closed; fixtures at each byte cap still parse.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from collections.abc import Set as AbstractSet
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from scripts.ci.test_fail_closed_ci import (  # noqa: E402
    MAX_CONTINUATION_LINES,
    _logical_ci_lines,
    _split_shell_clauses,
    _tokenise_shell_item,
)

DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests-and-quality-gates.yml"
DRIVER_RECOMMENDING: set[str] = {"libcudart12"}
# Largest tracked workflow .github/workflows/required-aggregator.yml is 65,234 bytes (wc -c); fourfold.
MAX_WORKFLOW_BYTES = 262_144
# Largest .github/apt/*.txt is tidy-ratchet.txt at 810 bytes (wc -c).
MAX_LIST_BYTES = 16_384
# git grep -c 'apt-install-cached.sh install' -- .github/workflows/ counts 8 calls.
MAX_INSTALL_CALLS = 64


def workflow_under_test() -> Path:
    """Return WORKFLOW_UNDER_TEST when set, otherwise the tracked workflow."""
    override = os.environ.get("WORKFLOW_UNDER_TEST")
    return Path(override) if override else DEFAULT_WORKFLOW


def read_bounded_utf8(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    """Read path once up to max_bytes + 1 bytes; return (text, oversize_finding)."""
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return (None, f"{path}: exceeds {max_bytes} bytes")
    return (raw.decode("utf-8"), None)


def parse_install_calls(line: str) -> list[tuple[str, tuple[str, ...]]]:
    """Extract every (list_path, trailing_args) install call from one logical shell line."""
    if "apt-install-cached.sh" not in line:
        return []
    calls: list[tuple[str, tuple[str, ...]]] = []
    for clause in _split_shell_clauses(_tokenise_shell_item(line)):
        script_idx = next(
            (
                idx
                for idx, tok in enumerate(clause)
                if tok == "apt-install-cached.sh" or tok.endswith("/apt-install-cached.sh")
            ),
            None,
        )
        if script_idx is None:
            continue
        after = clause[script_idx + 1 :]
        if not after or after[0] != "install":
            continue
        rest = after[1:]
        calls.append((rest[0], tuple(rest[1:])) if rest else ("", ()))
    return calls


def scan_install_calls(
    text: str,
    source_name: str,
) -> tuple[list[tuple[int, str, tuple[str, ...]]], list[str]]:
    """Scan workflow text for bounded install calls, continuation overflows, and call-cap hits."""
    calls: list[tuple[int, str, tuple[str, ...]]] = []
    findings: list[str] = []
    for lineno, line, overflowed in _logical_ci_lines(text):
        if overflowed:
            findings.append(
                f"{source_name}:{lineno}: continuation exceeds"
                f" {MAX_CONTINUATION_LINES} physical lines"
            )
            continue
        parsed = parse_install_calls(line)
        if not parsed:
            continue
        for list_rel, args in parsed:
            if len(calls) >= MAX_INSTALL_CALLS:
                findings.append(
                    f"{source_name}:{lineno}: exceeds {MAX_INSTALL_CALLS} install calls"
                )
                return (calls, findings)
            calls.append((lineno, list_rel, args))
    return (calls, findings)


def extract_install_calls(text: str) -> list[tuple[int, str, tuple[str, ...]]]:
    """Find every (lineno, list_path, trailing_args) install call in workflow text."""
    calls, _ = scan_install_calls(text, "<workflow>")
    return calls


def read_package_list(path: Path) -> set[str] | str:
    """Read package names from a bounded apt list file, or return an oversize finding."""
    text, err = read_bounded_utf8(path, MAX_LIST_BYTES)
    if err is not None or text is None:
        return err if err is not None else f"{path}: exceeds {MAX_LIST_BYTES} bytes"
    packages: set[str] = set()
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        packages.update(stripped.split())
    return packages


def load_cached_packages(
    list_path: Path,
    list_rel: str,
    source_name: str,
    lineno: int,
    cache: dict[Path, set[str] | str],
) -> set[str] | str:
    """Read an apt package list at most once per workflow check; return packages or finding."""
    if list_path not in cache:
        if not list_path.is_file():
            return f"{source_name}:{lineno}: missing apt list {list_rel}"
        cache[list_path] = read_package_list(list_path)
    return cache[list_path]


def check_workflow_text(
    text: str,
    repo_root: Path = REPO_ROOT,
    source_name: str = ".github/workflows/tests-and-quality-gates.yml",
    driver_recommending: AbstractSet[str] = DRIVER_RECOMMENDING,
) -> list[str]:
    """Return findings where a DRIVER_RECOMMENDING list lacks --no-install-recommends."""
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        return [f"{source_name}: exceeds {MAX_WORKFLOW_BYTES} bytes"]
    calls, findings = scan_install_calls(text, source_name)
    cache: dict[Path, set[str] | str] = {}
    drivers = set(driver_recommending)
    for lineno, list_rel, args in calls:
        if not list_rel:
            findings.append(f"{source_name}:{lineno}: missing list path after install")
            continue
        loaded = load_cached_packages(repo_root / list_rel, list_rel, source_name, lineno, cache)
        if isinstance(loaded, str):
            if loaded not in findings:
                findings.append(loaded)
            continue
        flagged = sorted(loaded & drivers)
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
    text, err = read_bounded_utf8(target, MAX_WORKFLOW_BYTES)
    if err is not None or text is None:
        return [err] if err is not None else []
    return check_workflow_text(text, repo_root=repo_root, source_name=str(target))


class AptInstallRecommendsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write_list(self, rel: str, content: str) -> Path:
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return dest

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

    def test_backslash_space_does_not_continue_to_flag_line(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt \\ \n"
            "--no-install-recommends\n"
        )
        findings = check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml")
        self.assertEqual(
            findings,
            [
                "fixture.yml:1: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_backslash_tab_does_not_continue_to_flag_line(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt \\\t\n"
            "--no-install-recommends\n"
        )
        findings = check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml")
        self.assertEqual(
            findings,
            [
                "fixture.yml:1: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_chained_refresh_then_install_with_spaces_fails(self) -> None:
        self._write_list(".github/apt/coverage.txt", "libcudart12\n")
        snippet = (
            "          bash scripts/ci/apt-install-cached.sh refresh"
            " && bash scripts/ci/apt-install-cached.sh install .github/apt/coverage.txt\n"
        )
        findings = check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("libcudart12", findings[0])

    def test_chained_refresh_then_install_without_spaces_fails(self) -> None:
        self._write_list(".github/apt/coverage.txt", "libcudart12\n")
        snippet = (
            "          bash scripts/ci/apt-install-cached.sh refresh"
            "&&bash scripts/ci/apt-install-cached.sh install .github/apt/coverage.txt\n"
        )
        findings = check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("libcudart12", findings[0])

    def test_two_installs_on_one_line_second_without_flag_fails(self) -> None:
        self._write_list(".github/apt/first.txt", "libcudart12\n")
        self._write_list(".github/apt/second.txt", "libcudart12\n")
        snippet = (
            "          bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/first.txt --no-install-recommends"
            " && bash scripts/ci/apt-install-cached.sh install .github/apt/second.txt\n"
        )
        findings = check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn(".github/apt/second.txt", findings[0])

    def test_two_installs_on_one_line_both_with_flag_passes(self) -> None:
        self._write_list(".github/apt/first.txt", "libcudart12\n")
        self._write_list(".github/apt/second.txt", "libcudart12\n")
        snippet = (
            "          bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/first.txt --no-install-recommends"
            " && bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/second.txt --no-install-recommends\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_workflow_byte_cap_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        call_line = "bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
        exact_size = 262_144
        exact_wf = self.root / "exact.yml"
        exact_wf.write_text(
            call_line + "#" * (exact_size - len(call_line) - 1) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(exact_wf.stat().st_size, exact_size)
        exact_findings = check_workflow(exact_wf, repo_root=self.root)
        self.assertEqual(len(exact_findings), 1)
        self.assertIn("libcudart12", exact_findings[0])

        oversize_size = 262_145
        oversize_wf = self.root / "oversize.yml"
        oversize_wf.write_text(
            call_line + "#" * (oversize_size - len(call_line) - 1) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(oversize_wf.stat().st_size, oversize_size)
        self.assertEqual(
            check_workflow(oversize_wf, repo_root=self.root),
            [f"{oversize_wf}: exceeds {MAX_WORKFLOW_BYTES} bytes"],
        )

    def test_list_byte_cap_boundary(self) -> None:
        head = "libcudart12\n"
        exact_size = 16_384
        exact_list = self._write_list(
            ".github/apt/exact.txt",
            head + "#" * (exact_size - len(head) - 1) + "\n",
        )
        self.assertEqual(exact_list.stat().st_size, exact_size)
        exact_snippet = "bash scripts/ci/apt-install-cached.sh install .github/apt/exact.txt\n"
        exact_findings = check_workflow_text(exact_snippet, repo_root=self.root)
        self.assertEqual(len(exact_findings), 1)
        self.assertIn("libcudart12", exact_findings[0])

        oversize_size = 16_385
        oversize_list = self._write_list(
            ".github/apt/oversize.txt",
            head + "#" * (oversize_size - len(head) - 1) + "\n",
        )
        self.assertEqual(oversize_list.stat().st_size, oversize_size)
        oversize_snippet = (
            "bash scripts/ci/apt-install-cached.sh install .github/apt/oversize.txt\n"
        )
        self.assertEqual(
            check_workflow_text(oversize_snippet, repo_root=self.root),
            [f"{oversize_list}: exceeds {MAX_LIST_BYTES} bytes"],
        )

    def test_continuation_line_cap_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        head = "bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt \\\n"
        at_cap = head + "  \\\n" * 198 + "  --no-install-recommends\n"
        self.assertEqual(len(at_cap.splitlines()), 200)
        self.assertEqual(
            check_workflow_text(at_cap, repo_root=self.root, source_name="fixture.yml"),
            [],
        )
        over_cap = head + "  \\\n" * 199 + "  --no-install-recommends\n"
        self.assertEqual(len(over_cap.splitlines()), 201)
        self.assertEqual(
            check_workflow_text(over_cap, repo_root=self.root, source_name="fixture.yml"),
            [f"fixture.yml:1: continuation exceeds {MAX_CONTINUATION_LINES} physical lines"],
        )

    def test_install_call_cap_boundary(self) -> None:
        self._write_list(".github/apt/plain.txt", "ninja-build\n")
        one_call = "bash scripts/ci/apt-install-cached.sh install .github/apt/plain.txt\n"
        self.assertEqual(
            check_workflow_text(one_call * 64, repo_root=self.root),
            [],
        )
        over_findings = check_workflow_text(
            one_call * 65,
            repo_root=self.root,
            source_name="fixture.yml",
        )
        self.assertEqual(
            over_findings,
            [f"fixture.yml:65: exceeds {MAX_INSTALL_CALLS} install calls"],
        )


if __name__ == "__main__":
    unittest.main()
