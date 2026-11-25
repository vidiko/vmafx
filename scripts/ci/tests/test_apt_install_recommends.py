#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Check plain bash scripts/ci/apt-install-cached.sh calls at literal run block indentation.
Allow configure, refresh, or install .github/apt/<list>.txt [--no-install-recommends].
Driver-recommending packages require the flag. Only column-zero # starts a list comment.
Tokens match [a-z0-9][a-z0-9+.-]* with one optional suffix drawn from
:[a-z0-9]+, =[A-Za-z0-9.+~:-]+ or /[a-z0-9.-]+.
Caps cover YAML file count, workflow and list bytes, and install calls per workflow.
Calls that never write apt-install-cached on one line go unseen. Inside a literal block,
a form in a Bash quoted string, heredoc or continued command passes with the arguments shown.
A more-indented literal line fails closed.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from collections.abc import Iterator
from collections.abc import Set as AbstractSet
from io import StringIO
from itertools import chain, islice
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

# Measured 55 workflows + 7 composite actions. Allow growth up to twice that total.
MAX_YAML_FILES = 124

APT_QUALIFIER_RE = re.compile(r"[:=/]")
PACKAGE_TOKEN = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+|=[A-Za-z0-9.+~:-]+|/[a-z0-9.-]+)?")
LITERAL_HEADER = re.compile(r" *(?:- )?(?P<key>run): \|[-+]?[ \t]*")
COMMAND_PREFIX = r"bash scripts/ci/apt-install-cached\.sh "
NO_INSTALL_FORM = re.compile(COMMAND_PREFIX + r"(?:configure|refresh)[ \t]*")
INSTALL_FORM = re.compile(
    COMMAND_PREFIX + r"install (?P<list_path>\.github/apt/[a-z0-9][a-z0-9-]*\.txt)"
    r"(?P<flag> --no-install-recommends)?[ \t]*"
)
UNSUPPORTED_FORM = (
    "unsupported apt-install-cached.sh form; write a plain command at literal run block "
    "indentation (see scripts/ci/tests/test_apt_install_recommends.py)"
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


def read_package_list(path: Path) -> tuple[set[str], list[str]]:
    """Read a bounded apt list, reporting unsupported tokens at their source lines."""
    text, err = read_bounded_utf8(path, MAX_LIST_BYTES)
    if text is None:
        assert err is not None
        return set(), [err]
    packages: set[str] = set()
    problems: list[str] = []
    for lineno, raw in enumerate(StringIO(text), start=1):
        if raw.startswith("#"):
            continue
        for token in raw.split():
            if not PACKAGE_TOKEN.fullmatch(token):
                problems.append(f"{path}:{lineno}: invalid package token {token!r}")
            else:
                packages.add(token)
    return packages, problems


def _install_problems(
    install: re.Match[str], repo_root: Path, driver_recommending: AbstractSet[str]
) -> list[str]:
    list_path = install["list_path"]
    try:
        packages, problems = read_package_list(repo_root / list_path)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return [f"missing apt list {list_path}"]
    if install["flag"] is None:
        drivers = sorted(pkg for pkg in packages if _apt_package_base(pkg) in driver_recommending)
        if drivers:
            problems.append(
                f"{list_path} names {', '.join(drivers)} without --no-install-recommends"
            )
    return problems


def _mentioned_commands(text: str) -> Iterator[tuple[int, str, bool]]:
    """Yield each mention and whether it starts at a literal run block's body indentation."""
    header_indent: int | None = None
    body_indent: int | None = None
    # The caller bounds the text by MAX_WORKFLOW_BYTES before this pass.
    for lineno, raw in enumerate(StringIO(text.replace("\r\n", "\n")), start=1):
        line = raw.removesuffix("\n")
        if not line.strip(" \t"):
            continue
        command = line.lstrip(" ")
        indent = len(line) - len(command)
        if header_indent is None or indent <= header_indent:
            header = LITERAL_HEADER.fullmatch(line)
            header_indent = header.start("key") if header else None
            body_indent = None
        elif body_indent is None:
            body_indent = indent
        if "apt-install-cached" in command:
            yield lineno, command, indent == body_indent


def check_workflow_text(
    text: str,
    repo_root: Path = REPO_ROOT,
    source_name: str = ".github/workflows/tests-and-quality-gates.yml",
    driver_recommending: AbstractSet[str] = DRIVER_RECOMMENDING,
) -> list[str]:
    """Check apt installer mentions in one bounded workflow or composite action."""
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        return [f"{source_name}: exceeds {MAX_WORKFLOW_BYTES} bytes"]
    findings: list[str] = []
    install_count = 0
    for lineno, command, at_block_indent in _mentioned_commands(text):
        if at_block_indent and NO_INSTALL_FORM.fullmatch(command):
            continue
        location = f"{source_name}:{lineno}"
        install = INSTALL_FORM.fullmatch(command) if at_block_indent else None
        if install is None:
            findings.append(f"{location}: {UNSUPPORTED_FORM}")
            continue
        install_count += 1
        if install_count > MAX_INSTALL_CALLS:
            findings.append(f"{location}: exceeds {MAX_INSTALL_CALLS} install calls")
            break
        problems = _install_problems(install, repo_root, driver_recommending)
        findings.extend(f"{location}: {problem}" for problem in problems)
    return findings


def check_workflow(workflow_path: Path | None = None, repo_root: Path = REPO_ROOT) -> list[str]:
    """Check a workflow file on disk against driver-recommending apt package lists."""
    target = workflow_path if workflow_path is not None else workflow_under_test()
    text, err = read_bounded_utf8(target, MAX_WORKFLOW_BYTES)
    if text is None:
        assert err is not None
        return [err]
    return check_workflow_text(text, repo_root=repo_root, source_name=str(target))


def check_yaml_files(repo_root: Path) -> list[str]:
    """Check workflow and composite action files in path order, up to the shared limit."""
    github = repo_root / ".github"
    paths = chain(github.glob("workflows/*.yml"), github.glob("actions/*/action.yml"))
    files = sorted(islice(paths, MAX_YAML_FILES + 1))
    if len(files) > MAX_YAML_FILES:
        return [f"exceeds {MAX_YAML_FILES} YAML files"]
    return [finding for path in files for finding in check_workflow(path, repo_root)]


class AptInstallRecommendsTest(unittest.TestCase):
    install = "bash scripts/ci/apt-install-cached.sh install"
    list_rel = ".github/apt/cov-12.txt"
    call = f"{install} {list_rel}"
    configure = "bash scripts/ci/apt-install-cached.sh configure"
    refresh = "bash scripts/ci/apt-install-cached.sh refresh"

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

    def test_accepted_literal_forms(self) -> None:
        self.list_path.write_text("pkg:arm64 pkg=1:2.3~rc1-4+A pkg/stable-1.0", encoding="utf-8")
        for header in ("run: |", "run: |-", "run: |+", "- run: |"):
            for call in (
                self.call,
                self.call + " --no-install-recommends",
                self.configure,
                self.refresh,
            ):
                with self.subTest(header=header, call=call):
                    self.assertEqual(self.check(f"  {header}\r\n\n      {call} \t\r\n"), [])

    def test_list_without_driver_passes_without_flag(self) -> None:
        self.list_path.write_text("# libcudart12\n\nninja-build libcudart12-\n", encoding="utf-8")
        self.assertEqual(self.check(f"run: |\n  {self.call}"), [])

    def test_invalid_package_token_reports_both_lines(self) -> None:
        for entry, token in (
            ('"libcudart12"', '"libcudart12"'),
            ("libcudart12\\", "libcudart12\\"),
            ("$PKG", "$PKG"),
            ("Libcudart12", "Libcudart12"),
            ("  # indented comment", "#"),
            ("pkg:amd64/stable", "pkg:amd64/stable"),
        ):
            with self.subTest(entry=entry):
                self.list_path.write_text(f"# comment\nninja-build\n{entry}\n", encoding="utf-8")
                self.assertEqual(
                    self.check(f"run: |\n  {self.call} --no-install-recommends"),
                    [f"fixture.yml:2: {self.list_path}:3: invalid package token {token!r}"],
                )

    def test_all_invalid_tokens_reported(self) -> None:
        self.list_path.write_text("ok BAD\n# ignored\npkg:s390x $PKG", encoding="utf-8")
        self.assertEqual(
            self.check(f"run: |\n  {self.call}"),
            [
                f"fixture.yml:2: {self.list_path}:1: invalid package token 'BAD'",
                f"fixture.yml:2: {self.list_path}:3: invalid package token '$PKG'",
            ],
        )

    def test_unsupported_context_reports_source_line(self) -> None:
        for lineno, text in (
            (1, f"- run: {self.call} --no-install-recommends"),
            (2, f"steps:\n  run: {self.call} --no-install-recommends\n    --install-recommends"),
            (2, f"run: >\n  {self.call} --no-install-recommends\n  --install-recommends"),
            (4, f"- run: |\n    {self.configure}\n  name: next\n    {self.refresh}"),
            (2, f"- run: |\n  {self.configure}"),
            (2, f"run: |\n  \t{self.configure}"),
            (3, f"run: |\n  true\n    {self.configure}"),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.check(text), [f"fixture.yml:{lineno}: {UNSUPPORTED_FORM}"])

    def test_adjacent_literal_headers(self) -> None:
        self.assertEqual(
            self.check(f"- run: |\n    {self.refresh}\n- run: |-\n    {self.configure}"), []
        )

    def test_tracked_workflows_and_actions(self) -> None:
        self.assertEqual(check_yaml_files(REPO_ROOT), [])

    def test_yaml_file_cap(self) -> None:
        workflows = self.root / ".github/workflows"
        workflows.mkdir()
        for index in range(MAX_YAML_FILES):
            (workflows / f"{index}.yml").touch()
        self.assertEqual(check_yaml_files(self.root), [])
        action = self.root / ".github/actions/extra/action.yml"
        action.parent.mkdir(parents=True)
        action.touch()
        self.assertEqual(check_yaml_files(self.root), [f"exceeds {MAX_YAML_FILES} YAML files"])

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
                    self.check(f"run: |\n  {line}\n"), [f"fixture.yml:2: {UNSUPPORTED_FORM}"]
                )

    def test_workflow_byte_cap(self) -> None:
        path = self.root / "workflow.yml"
        prefix = f"run: |\n  {self.call}\n#é".encode()
        exact = prefix.ljust(MAX_WORKFLOW_BYTES, b" ")
        path.write_bytes(exact)
        self.assertEqual(
            check_workflow(path, self.root),
            [f"{path}:2: {self.list_rel} names libcudart12 without --no-install-recommends"],
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
            self.check(f"run: |\n  {self.call}"),
            [f"fixture.yml:2: {self.list_rel} names libcudart12 without --no-install-recommends"],
        )
        self.list_path.write_bytes(exact + b" ")
        self.assertEqual(
            self.check(f"run: |\n  {self.call} --no-install-recommends"),
            [f"fixture.yml:2: {self.list_path}: exceeds {MAX_LIST_BYTES} bytes"],
        )

    def test_install_cap_stops_at_first_excess_line(self) -> None:
        exact = ("  " + self.call + " --no-install-recommends\n") * MAX_INSTALL_CALLS
        self.assertEqual(self.check("run: |\n" + exact), [])
        prefix = f"run: |\n  {self.configure}\n  # apt-install-cached\n  {self.call}\n"
        self.assertEqual(
            self.check(prefix + exact + "# apt-install-cached"),
            [
                f"fixture.yml:3: {UNSUPPORTED_FORM}",
                f"fixture.yml:4: {self.list_rel} names libcudart12 without --no-install-recommends",
                f"fixture.yml:{MAX_INSTALL_CALLS + 4}: exceeds {MAX_INSTALL_CALLS} install calls",
            ],
        )

    def test_missing_list(self) -> None:
        missing = ".github/apt/missing.txt"
        self.assertEqual(
            self.check(f"run: |\n  {self.install} {missing} --no-install-recommends"),
            [f"fixture.yml:2: missing apt list {missing}"],
        )

    def test_script_name_built_from_variable_goes_unseen(self) -> None:
        # Documented gap: no physical line spells the script name.
        self.assertEqual(
            self.check(
                'run: |\n  name=apt-install\n  bash scripts/ci/"${name}-cached.sh" install '
                + self.list_rel
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
