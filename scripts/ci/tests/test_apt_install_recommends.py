#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Check physical workflow lines that mention apt-install-cached.

Plain configure and install calls pass. Lists naming a driver-recommending package
require --no-install-recommends. Other forms and missing lists produce findings.
Workflow bytes, list bytes and accepted install calls have inclusive bounds.
A variable, concatenation or folded YAML scalar that splits the script name can
avoid writing apt-install-cached on any one line. Such calls go unseen.
Anchors and merge keys need no expansion: aliases reuse lines already checked.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from collections.abc import Set as AbstractSet
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests-and-quality-gates.yml"
DRIVER_RECOMMENDING: set[str] = {"libcudart12"}
# Largest tracked workflow .github/workflows/required-aggregator.yml is 65,234 bytes (wc -c); fourfold.
MAX_WORKFLOW_BYTES = 262_144
# Largest .github/apt/*.txt is tidy-ratchet.txt at 810 bytes (wc -c).
MAX_LIST_BYTES = 16_384
# git grep -c 'apt-install-cached.sh install' -- .github/workflows/ counts 8 calls.
MAX_INSTALL_CALLS = 64

APT_QUALIFIER_RE = re.compile(r"[:=/]")
COMMAND_PREFIX = r"[ \t]*(?:- run: |run: )?bash scripts/ci/apt-install-cached\.sh "
CONFIGURE_FORM = re.compile(COMMAND_PREFIX + r"configure *")
INSTALL_FORM = re.compile(
    COMMAND_PREFIX + r"install (?P<list_path>\.github/apt/[a-z0-9][a-z0-9-]*\.txt)"
    r"(?P<flag> --no-install-recommends)? *"
)
UNSUPPORTED_FORM = (
    "unsupported apt-install-cached.sh form; write it as one plain line "
    "(see scripts/ci/tests/test_apt_install_recommends.py)"
)


def workflow_under_test() -> Path:
    """Return WORKFLOW_UNDER_TEST when set, otherwise the tracked workflow."""
    override = os.environ.get("WORKFLOW_UNDER_TEST")
    return Path(override) if override else DEFAULT_WORKFLOW


def read_bounded_utf8(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    """Read at most max_bytes + 1 bytes and report an oversized file."""
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return None, f"{path}: exceeds {max_bytes} bytes"
    return raw.decode("utf-8"), None


def _apt_package_base(token: str) -> str:
    """Return the apt package base name for driver matching, or '' for a removal token."""
    if token.endswith("-"):
        return ""
    head = APT_QUALIFIER_RE.split(token, maxsplit=1)[0]
    return head.removesuffix("+")


def read_package_list(path: Path) -> set[str] | str:
    """Read package names from a bounded apt list file, or return an oversize finding."""
    text, err = read_bounded_utf8(path, MAX_LIST_BYTES)
    if text is None:
        assert err is not None
        return err
    packages: set[str] = set()
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            packages.update(stripped.split())
    return packages


def _install_problem(
    install: re.Match[str], repo_root: Path, driver_recommending: AbstractSet[str]
) -> str | None:
    list_path = install["list_path"]
    try:
        packages = read_package_list(repo_root / list_path)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return f"missing apt list {list_path}"
    if isinstance(packages, str):
        return packages
    if install["flag"] is None:
        drivers = sorted(pkg for pkg in packages if _apt_package_base(pkg) in driver_recommending)
        if drivers:
            return f"{list_path} names {', '.join(drivers)} without --no-install-recommends"
    return None


def check_workflow_text(
    text: str,
    repo_root: Path = REPO_ROOT,
    source_name: str = ".github/workflows/tests-and-quality-gates.yml",
    driver_recommending: AbstractSet[str] = DRIVER_RECOMMENDING,
) -> list[str]:
    """Check workflow or shell text one physical line at a time."""
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        return [f"{source_name}: exceeds {MAX_WORKFLOW_BYTES} bytes"]
    findings: list[str] = []
    install_count = 0
    # Each physical line consumes at least one byte, so at most MAX_WORKFLOW_BYTES lines.
    for lineno, raw in enumerate(StringIO(text.replace("\r\n", "\n")), start=1):
        line = raw.removesuffix("\n")
        if "apt-install-cached" not in line or CONFIGURE_FORM.fullmatch(line):
            continue
        location = f"{source_name}:{lineno}"
        install = INSTALL_FORM.fullmatch(line)
        if install is None:
            findings.append(f"{location}: {UNSUPPORTED_FORM}")
            continue
        install_count += 1
        if install_count > MAX_INSTALL_CALLS:
            findings.append(f"{location}: exceeds {MAX_INSTALL_CALLS} install calls")
            break
        problem = _install_problem(install, repo_root, driver_recommending)
        if problem is not None:
            findings.append(f"{location}: {problem}")
    return findings


def check_workflow(workflow_path: Path | None = None, repo_root: Path = REPO_ROOT) -> list[str]:
    """Check a workflow file on disk against driver-recommending apt package lists."""
    target = workflow_path if workflow_path is not None else workflow_under_test()
    text, err = read_bounded_utf8(target, MAX_WORKFLOW_BYTES)
    if text is None:
        assert err is not None
        return [err]
    return check_workflow_text(text, repo_root=repo_root, source_name=str(target))


class AptInstallRecommendsTest(unittest.TestCase):
    install = "bash scripts/ci/apt-install-cached.sh install"
    list_rel = ".github/apt/cov-12.txt"
    call = f"{install} {list_rel}"
    configure = "bash scripts/ci/apt-install-cached.sh configure"

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.list_path = self.root / self.list_rel
        self.list_path.parent.mkdir(parents=True)
        self.list_path.write_text("libcudart12\n", encoding="utf-8")

    def check(self, text: str) -> list[str]:
        return check_workflow_text(text, self.root, "fixture.yml")

    def test_checked_in_workflow_holds(self) -> None:
        target = workflow_under_test()
        self.assertEqual(check_workflow(target), [])
        text, _ = read_bounded_utf8(target, MAX_WORKFLOW_BYTES)
        self.assertIn(self.install, text or "")

    def test_driver_package_requires_flag_at_install_line(self) -> None:
        for token in ("libcudart12", "libcudart12:amd64", "libcudart12=12", "libcudart12/stable"):
            with self.subTest(token=token):
                self.list_path.write_text(token, encoding="utf-8")
                self.assertEqual(
                    self.check(f"- run: |\n    {self.call}\n"),
                    [
                        f"fixture.yml:2: {self.list_rel} names {token} without --no-install-recommends"
                    ],
                )

    def test_flagged_install_and_run_prefixes_pass(self) -> None:
        for prefix in ("", "  run: ", "  - run: "):
            with self.subTest(prefix=prefix):
                self.assertEqual(
                    self.check(f"{prefix}{self.call} --no-install-recommends  \r\n"), []
                )

    def test_list_without_driver_passes_without_flag(self) -> None:
        self.list_path.write_text("# libcudart12\n\nninja-build libcudart12-\n", encoding="utf-8")
        self.assertEqual(self.check(self.call), [])

    def test_configure_passes(self) -> None:
        self.assertEqual(self.check(f"  - run: {self.configure}"), [])

    def test_unsupported_forms_report_source_line(self) -> None:
        for line in (
            f"{self.call} # comment",
            f'{self.install} "{self.list_rel}"',
            f'run: "{self.call}"',
            self.call + " \\" + "\n  --no-install-recommends",
            f"bash -c '{self.call}'",
            f"{self.call} && true",
            f"{self.call}; true",
            f"{self.call} | cat",
            f"{self.call} &",
            f"{self.call} `true`",
            f"{self.call}\vignored",
            f"{self.call} --no-install-recommends --no-install-recommends",
            f"{self.install} $VAR",
            f"{self.install} .github/apt/Cov.txt",
            f"{self.install} .github/apt/../cov.txt",
            f"# {self.call}",
            "# apt-install-cached",
            f"{self.configure} # comment",
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    self.check(f"steps:\n{line}\n"), [f"fixture.yml:2: {UNSUPPORTED_FORM}"]
                )

    def test_workflow_byte_cap(self) -> None:
        path = self.root / "workflow.yml"
        prefix = f"{self.call}\n#é".encode()
        exact = prefix.ljust(MAX_WORKFLOW_BYTES, b" ")
        path.write_bytes(exact)
        self.assertEqual(
            check_workflow(path, self.root),
            [f"{path}:1: {self.list_rel} names libcudart12 without --no-install-recommends"],
        )
        path.write_bytes(exact + b" ")
        self.assertEqual(
            check_workflow(path, self.root), [f"{path}: exceeds {MAX_WORKFLOW_BYTES} bytes"]
        )
        self.assertEqual(
            self.check(exact.decode() + " "), [f"fixture.yml: exceeds {MAX_WORKFLOW_BYTES} bytes"]
        )

    def test_list_byte_cap(self) -> None:
        exact = b"libcudart12\n#".ljust(MAX_LIST_BYTES, b" ")
        self.list_path.write_bytes(exact)
        self.assertEqual(
            self.check(self.call),
            [f"fixture.yml:1: {self.list_rel} names libcudart12 without --no-install-recommends"],
        )
        self.list_path.write_bytes(exact + b" ")
        self.assertEqual(
            self.check(self.call + " --no-install-recommends"),
            [f"fixture.yml:1: {self.list_path}: exceeds {MAX_LIST_BYTES} bytes"],
        )

    def test_install_cap_stops_at_first_excess_line(self) -> None:
        exact = (self.call + " --no-install-recommends\n") * MAX_INSTALL_CALLS
        self.assertEqual(self.check(exact), [])
        prefix = f"{self.configure}\n# apt-install-cached\n{self.call}\n"
        self.assertEqual(
            self.check(prefix + exact + "# apt-install-cached"),
            [
                f"fixture.yml:2: {UNSUPPORTED_FORM}",
                f"fixture.yml:3: {self.list_rel} names libcudart12 without --no-install-recommends",
                f"fixture.yml:{MAX_INSTALL_CALLS + 3}: exceeds {MAX_INSTALL_CALLS} install calls",
            ],
        )

    def test_missing_list(self) -> None:
        missing = ".github/apt/missing.txt"
        self.assertEqual(
            self.check(f"{self.install} {missing} --no-install-recommends"),
            [f"fixture.yml:1: missing apt list {missing}"],
        )

    def test_script_name_built_from_variable_goes_unseen(self) -> None:
        # Documented gap: no physical line spells the script name.
        self.assertEqual(
            self.check(
                'name=apt-install\nbash scripts/ci/"${name}-cached.sh" install ' + self.list_rel
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
