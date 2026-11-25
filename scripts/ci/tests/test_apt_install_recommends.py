#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require --no-install-recommends when apt-install-cached.sh installs driver-recommending libs.

Positive: check effective job and composite action steps, including inherited steps and runs.
Shell and literal runs follow Bash quote, comment and escape rules across physical lines.
Negative: ignore metadata, shadowed steps and runs, and steps on non-composite actions.
Flagged installs, unrelated packages and removal tokens produce no missing-flag finding.
Boundary: charge expanded widths on every merge path before flattening. Reject malformed,
deep or oversized input, invalid merges, non-mapping roots, missing lists and excess continuations.
Scan aliased runs once and stop lexing at the first excess install. Sort findings in source order.
Literal runs report body lines relative to the block header, other styles the scalar start.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from collections.abc import Iterable, Iterator
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from itertools import chain, groupby
from pathlib import Path
from unittest.mock import patch

import yaml  # type: ignore[import-untyped]  # no PyYAML stubs in the hook environment, as in scripts/ci/check_composite_actions.py

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from scripts.ci.test_fail_closed_ci import (  # noqa: E402
    APT_UNBALANCED_QUOTE_MESSAGE,
    HOSTED_YAML_NODE_BOUND_MESSAGE,
    HOSTED_YAML_PARSE_MESSAGE,
    MAX_CONTINUATION_LINES,
    MAX_YAML_NODES,
    _is_operator_token,
    _iter_shell_tokens,
    _logical_ci_lines,
    _push_child_collections,
    _yaml_error_line,
)

InstallCall = tuple[int, str, tuple[str, ...]]
YAML_MERGE_TAG = "tag:yaml.org,2002:merge"
APT_QUALIFIER_RE = re.compile(r"[:=/]")
# PyYAML's scalar start may include tag/anchor properties and intervening comment lines.
_LITERAL_PREFIX_TOKEN = re.compile(
    r"[&!][^ \t\r\n\x85\u2028\u2029]*|#[^\r\n\x85\u2028\u2029]*|[ \t]+|\r\n|[\r\n\x85\u2028\u2029|]"
)

DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests-and-quality-gates.yml"
DRIVER_RECOMMENDING: set[str] = {"libcudart12"}
# Largest tracked workflow .github/workflows/required-aggregator.yml is 65,234 bytes (wc -c); fourfold.
MAX_WORKFLOW_BYTES = 262_144
# Largest .github/apt/*.txt is tidy-ratchet.txt at 810 bytes (wc -c).
MAX_LIST_BYTES = 16_384
# git grep -c 'apt-install-cached.sh install' -- .github/workflows/ counts 8 calls.
MAX_INSTALL_CALLS = 64
# Tracked .github/{workflows,actions} YAML files have 0 `<<` merge keys; 8 covers fixture mixin chains.
MAX_STEP_MERGE_DEPTH = 8


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


def _at_install_args(clause: Iterator[str]) -> bool:
    """Advance past the first installer and its verb, leaving the arguments unread."""
    for token in clause:
        if token.rsplit("/", 1)[-1] == "apt-install-cached.sh":
            return next(clause, None) == "install"
    return False


def parse_install_calls(
    line: str, *, limit: int | None = None
) -> list[tuple[str, tuple[str, ...]]]:
    """Extract installs, stopping at the limit's install verb (an excess-call sentinel)."""
    if "apt-install-cached.sh" not in line:
        return []
    calls: list[tuple[str, tuple[str, ...]]] = []
    for operator, clause in groupby(_iter_shell_tokens(line), _is_operator_token):
        args = iter(clause)
        if operator or not _at_install_args(args):
            continue
        if len(calls) + 1 == limit:
            calls.append(("", ()))
            break
        calls.append((next(args, ""), tuple(args)))
    return calls


def _apt_package_base(token: str) -> str:
    """Return the apt package base name for driver matching, or '' for a removal token."""
    if token.endswith("-"):
        return ""
    head = APT_QUALIFIER_RE.split(token, maxsplit=1)[0]
    return head.removesuffix("+")


def _mapping_value(mapping: yaml.MappingNode, name: str) -> yaml.Node | None:
    """Return the last explicit value of a scalar key."""
    for key, value in reversed(mapping.value):
        if isinstance(key, yaml.ScalarNode) and key.value == name:
            return value
    return None


def _step_owners(root: yaml.MappingNode) -> dict[yaml.MappingNode, bool]:
    """Only workflow jobs and the composite action's runs mapping own executable steps."""
    jobs = _mapping_value(root, "jobs")
    owners: dict[yaml.MappingNode, bool] = {}
    if isinstance(jobs, yaml.MappingNode):
        owners.update(
            (job, False)
            for key, job in jobs.value
            if isinstance(key, yaml.ScalarNode)
            and key.tag != YAML_MERGE_TAG
            and isinstance(job, yaml.MappingNode)
        )
    runs = _mapping_value(root, "runs")
    if isinstance(runs, yaml.MappingNode):
        owners.setdefault(runs, True)  # Only runs requires the composite discriminator.
    return owners


def _within_collection_bound(root: yaml.MappingNode) -> bool:
    stack: list[yaml.Node] = [root]
    seen = {id(root)}
    for _ in range(MAX_YAML_NODES):
        _push_child_collections(stack.pop(), stack, seen)
        if not stack:
            return True
    return False


def _merge_edges(mapping: yaml.MappingNode) -> Iterator[tuple[int, yaml.MappingNode]]:
    """Yield merge edges for bounds checking. PyYAML validates their types during flattening."""
    for key, value in mapping.value:
        if key.tag == YAML_MERGE_TAG:
            line = int(key.start_mark.line) + 1
            if isinstance(value, yaml.MappingNode):
                yield line, value
            elif isinstance(value, yaml.SequenceNode):
                for child in reversed(value.value):
                    if isinstance(child, yaml.MappingNode):
                        yield line, child


def _merge_pair_charge(
    work: list[tuple[yaml.MappingNode, int]],
    widths: dict[yaml.MappingNode, int],
    edges: dict[yaml.MappingNode, list[tuple[int, yaml.MappingNode]]],
) -> int:
    """Pop the bounded visit stack deepest first. Charge each incoming edge, even on aliases."""
    charge = 0
    for _ in range(len(work)):
        child, depth = work.pop()
        if child not in widths:
            own = sum(key.tag != YAML_MERGE_TAG for key, _ in child.value)
            widths[child] = own + sum(widths[merged] for _, merged in edges[child])
        if depth:
            charge += widths[child]
    return charge


def _merge_bound_error(roots: Iterable[yaml.MappingNode]) -> tuple[int, str] | None:
    """Check depth on every path, with one visit and copy budget across owners and steps."""
    visits = copied_pairs = 0
    widths: dict[yaml.MappingNode, int] = {}
    edges: dict[yaml.MappingNode, list[tuple[int, yaml.MappingNode]]] = {}
    for root in roots:
        work = [(root, 0)]
        visits += 1
        if visits > MAX_YAML_NODES:
            return 1, HOSTED_YAML_NODE_BOUND_MESSAGE
        for mapping, depth in work:
            if mapping not in edges:
                edges[mapping] = list(_merge_edges(mapping))
            for line, child in edges[mapping]:
                if depth >= MAX_STEP_MERGE_DEPTH:
                    return line, f"step merge depth exceeds {MAX_STEP_MERGE_DEPTH}"
                visits += 1
                if visits > MAX_YAML_NODES:
                    return 1, HOSTED_YAML_NODE_BOUND_MESSAGE
                work.append((child, depth + 1))
        copied_pairs += _merge_pair_charge(work, widths, edges)
        if copied_pairs > MAX_YAML_NODES:
            return 1, HOSTED_YAML_NODE_BOUND_MESSAGE
    return None


def _effective_value(owner: yaml.MappingNode, name: str) -> yaml.Node | None:
    """Resolve a key on a checked merge graph without mutating anchors during preflight."""
    stack = [owner]
    while stack:
        mapping = stack.pop()
        value = _mapping_value(mapping, name)
        if value is not None:
            return value
        # Pop the last merge key first, and the first mapping in a merge sequence first.
        stack.extend(child for _, child in _merge_edges(mapping))
    return None


def _workflow_steps(owners: dict[yaml.MappingNode, bool]) -> Iterator[yaml.MappingNode]:
    seen: set[yaml.Node] = set()
    for owner, requires_composite in owners.items():
        if requires_composite:
            using = _effective_value(owner, "using")
            if not (
                isinstance(using, yaml.ScalarNode)
                and using.tag == "tag:yaml.org,2002:str"
                and using.value == "composite"
            ):
                continue
        steps = _effective_value(owner, "steps")
        if isinstance(steps, yaml.SequenceNode) and steps not in seen:
            seen.add(steps)
            yield from (step for step in steps.value if isinstance(step, yaml.MappingNode))


def _yaml_run_scalars(text: str) -> tuple[list[yaml.ScalarNode], tuple[int, str] | None]:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        if not isinstance(root, yaml.MappingNode):
            return [], (1, "workflow root is not a YAML mapping")
        if not _within_collection_bound(root):
            return [], (1, HOSTED_YAML_NODE_BOUND_MESSAGE)
        owners = _step_owners(root)
        # Check the owners before following their merges to discover the step roots.
        error = _merge_bound_error(chain(owners, _workflow_steps(owners)))
        if error:
            return [], error
        scalars: dict[yaml.ScalarNode, None] = {}
        loader = yaml.SafeLoader("")
        try:
            for owner in owners:
                loader.flatten_mapping(owner)
            for step in _workflow_steps(owners):
                loader.flatten_mapping(step)
                run = _mapping_value(step, "run")
                if isinstance(run, yaml.ScalarNode):
                    scalars[run] = None
        finally:
            loader.dispose()
    except RecursionError:
        return [], (1, HOSTED_YAML_NODE_BOUND_MESSAGE)
    except yaml.YAMLError as error_detail:
        return [], (_yaml_error_line(error_detail), HOSTED_YAML_PARSE_MESSAGE)
    return sorted(scalars, key=lambda run: (run.start_mark.line, run.start_mark.column)), None


@dataclass
class _InstallScan:
    calls: list[tuple[int, InstallCall]] = field(default_factory=list)
    findings: list[tuple[int, int, str]] = field(default_factory=list)

    def next_order(self) -> int:
        return len(self.calls) + len(self.findings)

    def problem(self, line: int, message: str) -> None:
        self.findings.append((line, self.next_order(), message))


def _scan_shell_text(
    text: str,
    source_name: str,
    *,
    scan: _InstallScan,
    fixed_lineno: int | None = None,
    line_offset: int = 0,
) -> None:
    """Scan shell text for install calls and per-line continuation or quote findings."""
    for lineno, line, overflowed in _logical_ci_lines(text):
        report_line = fixed_lineno if fixed_lineno is not None else lineno + line_offset
        if overflowed:
            msg = (
                f"{source_name}:{report_line}: continuation exceeds"
                f" {MAX_CONTINUATION_LINES} physical lines"
            )
            scan.problem(report_line, msg)
            continue
        try:
            parsed = parse_install_calls(line, limit=MAX_INSTALL_CALLS + 1 - len(scan.calls))
        except ValueError:
            scan.problem(
                report_line, f"{source_name}:{report_line}: {APT_UNBALANCED_QUOTE_MESSAGE}"
            )
            continue
        for list_rel, args in parsed:
            scan.calls.append((scan.next_order(), (report_line, list_rel, args)))
        if len(scan.calls) > MAX_INSTALL_CALLS:
            return


def _literal_header_line(text: str, run: yaml.ScalarNode) -> int:
    line = int(run.start_mark.line) + 1
    for match in _LITERAL_PREFIX_TOKEN.finditer(text, run.start_mark.index, run.end_mark.index):
        if match[0] == "|":
            return line
        if match[0][0] in "\r\n\x85\u2028\u2029":
            line += 1
    raise AssertionError("composed literal scalar has no block header")


def _scan_yaml_text(text: str, source_name: str, *, scan: _InstallScan) -> None:
    scalars, error = _yaml_run_scalars(text)
    if error is not None:
        line, message = error
        scan.problem(line, f"{source_name}:{line}: {message}")
        return
    for run in scalars:
        start = int(run.start_mark.line) + 1
        _scan_shell_text(
            run.value,
            source_name,
            fixed_lineno=None if run.style == "|" else start,
            line_offset=_literal_header_line(text, run) if run.style == "|" else 0,
            scan=scan,
        )
        if len(scan.calls) > MAX_INSTALL_CALLS:
            return


def _validate_mode(mode: str) -> None:
    if mode not in ("yaml", "shell"):
        raise ValueError(f"unknown scan mode: {mode!r}")


def _scan_install_calls(text: str, source_name: str, mode: str) -> _InstallScan:
    _validate_mode(mode)
    scan = _InstallScan()
    scan_text = _scan_yaml_text if mode == "yaml" else _scan_shell_text
    scan_text(text, source_name, scan=scan)
    if len(scan.calls) > MAX_INSTALL_CALLS:
        order, (line, _, _) = scan.calls.pop()
        scan.findings.append(
            (line, order, f"{source_name}:{line}: exceeds {MAX_INSTALL_CALLS} install calls")
        )
    return scan


def scan_install_calls(
    text: str, source_name: str, *, mode: str = "yaml"
) -> tuple[list[InstallCall], list[str]]:
    """Scan a workflow's effective run scalars or a standalone shell script in source order."""
    scan = _scan_install_calls(text, source_name, mode)
    return [call for _, call in scan.calls], [message for _, _, message in scan.findings]


def extract_install_calls(text: str, *, mode: str = "yaml") -> list[InstallCall]:
    """Find every (lineno, list_path, trailing_args) install call, up to MAX_INSTALL_CALLS."""
    calls, _ = scan_install_calls(text, "<workflow>", mode=mode)
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
    *,
    mode: str = "yaml",
) -> list[str]:
    """Return findings where a DRIVER_RECOMMENDING list lacks --no-install-recommends."""
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        _validate_mode(mode)
        return [f"{source_name}: exceeds {MAX_WORKFLOW_BYTES} bytes"]
    scan = _scan_install_calls(text, source_name, mode)
    cache: dict[Path, set[str] | str] = {}
    drivers = set(driver_recommending)
    reported_errors: set[str] = set()
    for order, (lineno, list_rel, args) in scan.calls:
        if not list_rel:
            scan.findings.append(
                (lineno, order, f"{source_name}:{lineno}: missing list path after install")
            )
            continue
        loaded = load_cached_packages(repo_root / list_rel, list_rel, source_name, lineno, cache)
        if isinstance(loaded, str):
            if loaded not in reported_errors:
                scan.findings.append((lineno, order, loaded))
                reported_errors.add(loaded)
            continue
        flagged = sorted(token for token in loaded if _apt_package_base(token) in drivers)
        if flagged and "--no-install-recommends" not in args:
            joined = ", ".join(flagged)
            message = (
                f"{source_name}:{lineno}: {list_rel} names {joined} without --no-install-recommends"
            )
            scan.findings.append((lineno, order, message))
    return [message for _, _, message in sorted(scan.findings)]


def check_workflow(
    workflow_path: Path | None = None,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """Check a workflow file on disk against DRIVER_RECOMMENDING apt package lists."""
    target = workflow_path if workflow_path is not None else workflow_under_test()
    text, err = read_bounded_utf8(target, MAX_WORKFLOW_BYTES)
    if err is not None or text is None:
        return [err] if err is not None else []
    return check_workflow_text(text, repo_root=repo_root, source_name=str(target), mode="yaml")


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
        self.assertEqual(check_workflow_text(continued, repo_root=self.root, mode="shell"), [])
        chained = (
            "          bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt"
            " && echo --no-install-recommends\n"
        )
        self.assertEqual(len(check_workflow_text(chained, repo_root=self.root, mode="shell")), 1)
        missing = "          bash scripts/ci/apt-install-cached.sh install .github/apt/nope.txt\n"
        missing_findings = check_workflow_text(missing, repo_root=self.root, mode="shell")
        self.assertEqual(len(missing_findings), 1)
        self.assertIn("missing apt list", missing_findings[0])

    def test_backslash_space_does_not_continue_to_flag_line(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt \\ \n"
            "--no-install-recommends\n"
        )
        findings = check_workflow_text(
            snippet, repo_root=self.root, source_name="fixture.yml", mode="shell"
        )
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
        findings = check_workflow_text(
            snippet, repo_root=self.root, source_name="fixture.yml", mode="shell"
        )
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
        findings = check_workflow_text(
            snippet, repo_root=self.root, source_name="fixture.yml", mode="shell"
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("libcudart12", findings[0])

    def test_chained_refresh_then_install_without_spaces_fails(self) -> None:
        self._write_list(".github/apt/coverage.txt", "libcudart12\n")
        snippet = (
            "          bash scripts/ci/apt-install-cached.sh refresh"
            "&&bash scripts/ci/apt-install-cached.sh install .github/apt/coverage.txt\n"
        )
        findings = check_workflow_text(
            snippet, repo_root=self.root, source_name="fixture.yml", mode="shell"
        )
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
        findings = check_workflow_text(
            snippet, repo_root=self.root, source_name="fixture.yml", mode="shell"
        )
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
            check_workflow_text(
                snippet, repo_root=self.root, source_name="fixture.yml", mode="shell"
            ),
            [],
        )

    def test_merge_copied_pair_boundary(self) -> None:
        width = 128
        count, remainder = divmod(MAX_YAML_NODES, width)
        self.assertEqual(remainder, 0)
        fields = ", ".join(f"k{i}: value" for i in range(width))
        base = f"fields: &fields {{{fields}}}\nextra: &extra {{name: action}}\nruns:\n  using: composite\n"
        steps = "  steps:\n" + "  - <<: *fields\n" * count
        self.assertEqual(scan_install_calls(base + steps, "wf"), ([], []))
        # One additional pair inherited by runs shares the budget with its steps.
        with patch.object(yaml.SafeLoader, "flatten_mapping") as flatten:
            self.assertEqual(
                scan_install_calls(base + "  <<: *extra\n" + steps, "wf"),
                ([], [f"wf:1: {HOSTED_YAML_NODE_BOUND_MESSAGE}"]),
            )
            flatten.assert_not_called()

    def test_transitive_merge_copy_boundary(self) -> None:
        width, remainder = divmod(MAX_YAML_NODES, MAX_STEP_MERGE_DEPTH)
        self.assertEqual(remainder, 0)
        chain = "".join(f"m{i}: &m{i} {{<<: *m{i - 1}}}\n" for i in range(1, MAX_STEP_MERGE_DEPTH))
        owner = f"jobs: {{a: {{steps: [{{<<: *m{MAX_STEP_MERGE_DEPTH - 1}}}]}}}}"
        for n, errors in ((width, []), (width + 1, [f"wf:1: {HOSTED_YAML_NODE_BOUND_MESSAGE}"])):
            fields = ", ".join(f"k{i}: x" for i in range(n))
            with self.subTest(width=n):
                self.assertEqual(
                    scan_install_calls(f"leaf: &m0 {{{fields}}}\n" + chain + owner, "wf"),
                    ([], errors),
                )

    def test_charge_bounds_flattened_pair_copies(self) -> None:
        original_charge = _merge_pair_charge
        original_flatten = yaml.SafeLoader.flatten_mapping
        charged = copied = 0

        def charge(
            work: list[tuple[yaml.MappingNode, int]],
            widths: dict[yaml.MappingNode, int],
            edges: dict[yaml.MappingNode, list[tuple[int, yaml.MappingNode]]],
        ) -> int:
            nonlocal charged
            result = original_charge(work, widths, edges)
            charged += result
            return result

        def flatten(loader: yaml.SafeLoader, node: yaml.MappingNode) -> None:
            nonlocal copied
            own = sum(key.tag != YAML_MERGE_TAG for key, _ in node.value)
            original_flatten(loader, node)
            copied += len(node.value) - own

        base = "a: &a {x: x, y: y, z: z}\nb: &b {<<: *a, w: w}\n"
        for steps in ("[{<<: *b}]", "[{<<: [*a, *b]}, {<<: *b}, {<<: *b}]"):
            charged = copied = 0
            with (
                self.subTest(steps=steps),
                patch.object(sys.modules[__name__], "_merge_pair_charge", side_effect=charge),
                patch.object(yaml.SafeLoader, "flatten_mapping", flatten),
            ):
                self.assertEqual(
                    scan_install_calls(base + f"jobs: {{a: {{steps: {steps}}}}}", "wf"), ([], [])
                )
                self.assertGreater(copied, 0)
                self.assertGreaterEqual(charged, copied)

    def test_bash_physical_lines_in_shell_and_literal_run(self) -> None:
        self._write_list("cov.txt", "libcudart12\n")
        install = "apt-install-cached.sh install cov.txt"
        for script, line in (
            ("echo a # ignored \\\n" + install, 2),
            ("echo a\\\\\n" + install, 2),
            ("echo 'x\\\ny'\n" + install, 3),
            ("apt-install-cached.sh in\\\nstall cov.txt --no-install-recommends", 0),
        ):
            literal = "jobs:\n  j:\n    steps:\n    - run: |\n" + "".join(
                f"        {raw}\n" for raw in script.splitlines()
            )
            for mode, text, offset in (("shell", script, 0), ("yaml", literal, 4)):
                with self.subTest(script=script, mode=mode):
                    expected = (
                        [
                            f"wf:{line + offset}: cov.txt names libcudart12 without --no-install-recommends"
                        ]
                        if line
                        else []
                    )
                    self.assertEqual(
                        check_workflow_text(text, self.root, "wf", mode=mode), expected
                    )

    def test_excess_install_stops_lexer_before_quote(self) -> None:
        install = "apt-install-cached.sh install cov.txt"
        original = _iter_shell_tokens
        reads = 0

        def counted(text: str) -> Iterator[str]:
            nonlocal reads
            for token in original(text):
                reads += 1
                yield token

        for tail in ("; echo '", " '"):
            reads = 0
            with (
                self.subTest(tail=tail),
                patch.object(sys.modules[__name__], "_iter_shell_tokens", counted),
            ):
                calls, findings = scan_install_calls(
                    "; ".join([install] * (MAX_INSTALL_CALLS + 1)) + tail, "wf", mode="shell"
                )
                self.assertEqual(findings, [f"wf:1: exceeds {MAX_INSTALL_CALLS} install calls"])
                self.assertEqual(len(calls), MAX_INSTALL_CALLS)
                self.assertEqual(reads, 4 * MAX_INSTALL_CALLS + 2)

    def test_composite_discriminator(self) -> None:
        for using, expected in (
            ("using: node24, main: index.js, ", []),
            ("", []),
            ("using: composite, ", [(2, "cov.txt", ())]),
            ("<<: *base, ", [(2, "cov.txt", ())]),
            ("<<: *base, using: node24, ", []),
        ):
            text = (
                "base: &base {using: composite}\nruns: {"
                + using
                + "steps: [{run: apt-install-cached.sh install cov.txt}]}"
            )
            with self.subTest(using=using):
                self.assertEqual(scan_install_calls(text, "wf"), (expected, []))

    def test_package_and_scan_findings_in_source_order(self) -> None:
        self._write_list("cov.txt", "libcudart12\n")
        install = "apt-install-cached.sh install cov.txt"
        for mode, text, bad_line in (
            ("shell", install + "\n" + install + " '", 2),
            ("yaml", f'jobs: {{a: {{steps: [{{run: "{install}"}}, {{run: "{install} \'"}}]}}}}', 1),
        ):
            with self.subTest(mode=mode):
                self.assertEqual(
                    check_workflow_text(text, self.root, "wf", mode=mode),
                    [
                        "wf:1: cov.txt names libcudart12 without --no-install-recommends",
                        f"wf:{bad_line}: {APT_UNBALANCED_QUOTE_MESSAGE}",
                    ],
                )

    def test_split_install_token(self) -> None:
        self._write_list("cov.txt", "libcudart12\n")
        for flag in ("", " --no-install-recommends"):
            shell = f"apt-install-cached.sh in\\\nstall cov.txt{flag}\n"
            literal = "jobs:\n  cov:\n    steps:\n    - run: |\n" + "".join(
                f"        {line}\n" for line in shell.splitlines()
            )
            for mode, text, line in (("shell", shell, 1), ("yaml", literal, 5)):
                with self.subTest(mode=mode, flag=flag):
                    expected = (
                        []
                        if flag
                        else [
                            f"wf:{line}: cov.txt names libcudart12 without --no-install-recommends"
                        ]
                    )
                    self.assertEqual(
                        check_workflow_text(text, self.root, "wf", mode=mode), expected
                    )

    def test_only_effective_workflow_and_composite_steps(self) -> None:
        template = "template: &job {using: composite, steps: [{run: apt-install-cached.sh install cov.txt}]}\n"
        matrix = (
            "jobs:\n  test:\n    strategy:\n      matrix:\n"
            "        steps: [{run: apt-install-cached.sh install cov.txt}]"
        )
        self.assertEqual(scan_install_calls(matrix, "wf"), ([], []))
        self.assertEqual(scan_install_calls(template + "jobs: {<<: *job}", "wf"), ([], []))
        for path in ("jobs: {test: {<<: *job}}", "runs: {<<: *job}"):
            self.assertEqual(scan_install_calls(template + path, "wf"), ([(1, "cov.txt", ())], []))
        for path in ("jobs: {test: {<<: *job, steps: []}}", "runs: {<<: *job, steps: []}"):
            self.assertEqual(scan_install_calls(template + path, "wf"), ([], []))

    def test_deep_flow_nesting_fails_closed(self) -> None:
        snippet = "a: " + "[" * 1000 + "]" * 1000
        self.assertEqual(
            scan_install_calls(snippet, "wf"), ([], [f"wf:1: {HOSTED_YAML_NODE_BOUND_MESSAGE}"])
        )

    def test_stop_parsing_at_first_excess_install(self) -> None:
        install = "apt-install-cached.sh install cov.txt"
        literal = f"runs:\n  using: composite\n  steps:\n  - run: {install}\n  - run: |\n"
        original_parse = parse_install_calls
        parsed_count: int

        def counted(line: str, *, limit: int | None = None) -> list[tuple[str, tuple[str, ...]]]:
            nonlocal parsed_count
            parsed = original_parse(line, limit=limit)
            parsed_count += len(parsed)
            return parsed

        for mode, text, excess_line in (
            ("yaml", literal + f"      {install}\n" * 100, 5 + MAX_INSTALL_CALLS),
            ("yaml", literal + "      " + " && ".join([install] * 100), 6),
            ("shell", (install + "\n") * 100, MAX_INSTALL_CALLS + 1),
        ):
            parsed_count = 0
            with (
                self.subTest(mode=mode),
                patch.object(sys.modules[__name__], "parse_install_calls", side_effect=counted),
            ):
                calls, findings = scan_install_calls(text, "wf", mode=mode)
                self.assertEqual(len(calls), MAX_INSTALL_CALLS)
                self.assertEqual(
                    findings, [f"wf:{excess_line}: exceeds {MAX_INSTALL_CALLS} install calls"]
                )
                self.assertEqual(parsed_count, MAX_INSTALL_CALLS + 1)

    def test_same_line_anchors_at_install_cap(self) -> None:
        install = "apt-install-cached.sh install"
        prefix = " && ".join([f"{install} prefix.txt"] * (MAX_INSTALL_CALLS - 1))
        text = (
            f"prefix: &prefix '{prefix}'\n"
            f"commands: [&first '{install} first.txt', &second '{install} second.txt']\n"
            "runs: {using: composite, steps: [{run: *prefix}, {run: *second}, {run: *first}]}\n"
        )
        calls, findings = scan_install_calls(text, "wf")
        self.assertEqual(
            calls, [(1, "prefix.txt", ())] * (MAX_INSTALL_CALLS - 1) + [(2, "first.txt", ())]
        )
        self.assertEqual(findings, [f"wf:2: exceeds {MAX_INSTALL_CALLS} install calls"])

    def test_literal_body_line_after_anchor(self) -> None:
        for properties in ("&cmd\n", "&cmd # ignore | here\n          !!str\n          # |\n"):
            text = (
                f"jobs:\n  test:\n    steps:\n      - run: {properties}"
                "          |-\n            apt-install-cached.sh install cov.txt\n"
            )
            self.assertEqual(
                scan_install_calls(text, "wf"), ([(len(text.splitlines()), "cov.txt", ())], [])
            )

    def test_workflow_byte_cap_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        call_line = "runs:\n  using: composite\n  steps:\n  - run: bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
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
        exact_findings = check_workflow_text(exact_snippet, repo_root=self.root, mode="shell")
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
            check_workflow_text(oversize_snippet, repo_root=self.root, mode="shell"),
            [f"{oversize_list}: exceeds {MAX_LIST_BYTES} bytes"],
        )

    def test_continuation_line_cap_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        head = "bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt \\\n"
        at_cap = head + "  \\\n" * 198 + "  --no-install-recommends\n"
        self.assertEqual(len(at_cap.splitlines()), 200)
        self.assertEqual(
            check_workflow_text(
                at_cap, repo_root=self.root, source_name="fixture.yml", mode="shell"
            ),
            [],
        )
        over_cap = head + "  \\\n" * 199 + "  --no-install-recommends\n"
        self.assertEqual(len(over_cap.splitlines()), 201)
        self.assertEqual(
            check_workflow_text(
                over_cap, repo_root=self.root, source_name="fixture.yml", mode="shell"
            ),
            [f"fixture.yml:1: continuation exceeds {MAX_CONTINUATION_LINES} physical lines"],
        )

    def test_install_call_cap_boundary(self) -> None:
        self._write_list(".github/apt/plain.txt", "ninja-build\n")
        one_call = "bash scripts/ci/apt-install-cached.sh install .github/apt/plain.txt\n"
        self.assertEqual(
            check_workflow_text(one_call * 64, repo_root=self.root, mode="shell"),
            [],
        )
        over_findings = check_workflow_text(
            one_call * 65,
            repo_root=self.root,
            source_name="fixture.yml",
            mode="shell",
        )
        self.assertEqual(
            over_findings,
            [f"fixture.yml:65: exceeds {MAX_INSTALL_CALLS} install calls"],
        )

    def test_quoted_run_without_flag_fails_at_run_line(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        expected = [
            "fixture.yml:4: .github/apt/cov.txt names libcudart12 without --no-install-recommends"
        ]
        for quote in ("'", '"'):
            snippet = (
                "jobs:\n  cov:\n    steps:\n"
                f"      - run: {quote}bash scripts/ci/apt-install-cached.sh"
                f" install .github/apt/cov.txt{quote}\n"
            )
            self.assertEqual(
                check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
                expected,
            )

    def test_split_plain_multiline_run_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n  cov:\n    steps:\n"
            "      - run: bash scripts/ci/apt-install-cached.sh\n"
            "          install .github/apt/cov.txt\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:4: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_literal_continuation_stops_at_step_boundary(self) -> None:
        self._write_list("cov.txt", "libcudart12\n")
        for next_run in ("echo ok", "|\n      echo ok", "|\n      echo --no-install-recommends"):
            with self.subTest(next_run=next_run):
                snippet = (
                    "runs:\n  using: composite\n  steps:\n"
                    "  - run: |\n"
                    "      apt-install-cached.sh install cov.txt \\\n"
                    "  - name: --no-install-recommends\n"
                    f"    run: {next_run}\n"
                )
                self.assertEqual(
                    check_workflow_text(snippet, self.root, "wf"),
                    ["wf:5: cov.txt names libcudart12 without --no-install-recommends"],
                )

    def test_merge_sequence_uses_first_mapping_with_run(self) -> None:
        self._write_list("cov.txt", "libcudart12\n")
        install = "apt-install-cached.sh install cov.txt"
        flagged = install + " --no-install-recommends"
        missing = ["wf:2: cov.txt names libcudart12 without --no-install-recommends"]
        for a, b, expected in ((flagged, install, []), (install, flagged, missing)):
            snippet = f"a: &a\n  run: {a}\nb: &b\n  run: {b}\nruns:\n  using: composite\n  steps:\n  - <<: [*a, *b]\n"
            self.assertEqual(check_workflow_text(snippet, self.root, "wf"), expected)

    def test_shared_leaf_over_merge_depth(self) -> None:
        chain = "leaf: &m0 {run: echo ok}\n" + "".join(
            f"anchor{depth}: &m{depth} {{<<: *m{depth - 1}}}\n"
            for depth in range(1, MAX_STEP_MERGE_DEPTH + 1)
        )
        # A preceding step can also reference the chain before the over-depth step.
        for prefix in ("", "  - <<: *m1\n"):
            snippet = (
                chain
                + f"runs:\n  using: composite\n  steps:\n{prefix}  - <<: [*m0, *m{MAX_STEP_MERGE_DEPTH}]\n"
            )
            self.assertEqual(
                check_workflow_text(snippet, self.root, "wf"),
                [f"wf:2: step merge depth exceeds {MAX_STEP_MERGE_DEPTH}"],
            )

    def test_merge_path_visit_bound(self) -> None:
        chain = "leaf: &m0 {run: echo ok}\n"
        for depth in range(1, MAX_STEP_MERGE_DEPTH):
            aliases = ", ".join([f"*m{depth - 1}"] * 5)
            chain += f"anchor{depth}: &m{depth} {{<<: [{aliases}]}}\n"
        snippet = (
            chain + f"runs:\n  using: composite\n  steps:\n  - <<: *m{MAX_STEP_MERGE_DEPTH - 1}\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, self.root, "wf"),
            [f"wf:1: {HOSTED_YAML_NODE_BOUND_MESSAGE}"],
        )
        self.assertEqual(
            check_workflow_text(
                "runs:\n  using: composite\n  steps:\n  - &step {<<: *step}\n", self.root, "wf"
            ),
            [f"wf:4: step merge depth exceeds {MAX_STEP_MERGE_DEPTH}"],
        )

    def test_invalid_merge_and_non_scalar_override(self) -> None:
        base = "base: &a {run: apt-install-cached.sh install missing.txt}\nruns:\n  using: composite\n  steps:\n"
        self.assertEqual(
            check_workflow_text(base + "  - <<: [*a, 1]\n", self.root, "wf"),
            [f"wf:5: {HOSTED_YAML_PARSE_MESSAGE}"],
        )
        self.assertEqual(check_workflow_text(base + "  - <<: *a\n    run: []\n"), [])

    def test_shell_and_yaml_modes(self) -> None:
        self._write_list("cov.txt", "libcudart12\n")
        snippet = "echo status: ready\n  apt-install-cached.sh install cov.txt\n"
        self.assertEqual(
            check_workflow_text(snippet, self.root, "wf", mode="shell"),
            ["wf:2: cov.txt names libcudart12 without --no-install-recommends"],
        )
        self.assertEqual(extract_install_calls(snippet, mode="shell"), [(2, "cov.txt", ())])
        self.assertEqual(check_workflow_text(snippet, self.root, "wf", mode="yaml"), [])
        for document in ("echo ok", "[]", ""):
            self.assertEqual(
                check_workflow_text(document, self.root, "wf"),
                ["wf:1: workflow root is not a YAML mapping"],
            )
        self.assertEqual(
            check_workflow_text("'unterminated", self.root, "wf"),
            [f"wf:1: {HOSTED_YAML_PARSE_MESSAGE}"],
        )
        with self.assertRaises(ValueError):
            check_workflow_text(snippet, mode="auto")

    def test_qualified_driver_tokens_without_flag_fail(self) -> None:
        snippet = (
            "jobs:\n  cov:\n    steps:\n"
            "      - run: bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
        )
        for token in ("libcudart12:amd64", "libcudart12=12.0.146-1", "libcudart12/noble"):
            self._write_list(".github/apt/cov.txt", f"ninja-build\n{token}\n")
            self.assertEqual(
                check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
                [
                    f"fixture.yml:4: .github/apt/cov.txt names {token}"
                    " without --no-install-recommends"
                ],
            )

    def test_quoted_run_with_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        for quote in ("'", '"'):
            snippet = (
                "jobs:\n  cov:\n    steps:\n"
                f"      - run: {quote}bash scripts/ci/apt-install-cached.sh"
                f" install .github/apt/cov.txt --no-install-recommends{quote}\n"
            )
            self.assertEqual(
                check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
                [],
            )

    def test_non_driver_qualified_and_removal_tokens_pass(self) -> None:
        snippet = (
            "jobs:\n  cov:\n    steps:\n"
            "      - run: bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
        )
        for token in ("libcudart12-dev:amd64", "libcudart12-"):
            self._write_list(".github/apt/cov.txt", f"{token}\n")
            self.assertEqual(
                check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
                [],
            )

    def test_single_line_plain_run_not_duplicated(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n  cov:\n    steps:\n"
            "      - run: bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        self.assertEqual(
            extract_install_calls(snippet),
            [(4, ".github/apt/cov.txt", ("--no-install-recommends",))],
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_invalid_yaml_with_collection_line_fails_closed(self) -> None:
        snippet = "jobs:\n  cov:\n    steps: [\n"
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [f"fixture.yml:4: {HOSTED_YAML_PARSE_MESSAGE}"],
        )

    def test_quoted_scalar_install_call_cap_boundary(self) -> None:
        self._write_list(".github/apt/plain.txt", "ninja-build\n")
        one = "bash scripts/ci/apt-install-cached.sh install .github/apt/plain.txt"
        at_cap = "jobs:\n  cov:\n    steps:\n      - run: '" + " && ".join([one] * 64) + "'\n"
        self.assertEqual(
            check_workflow_text(at_cap, repo_root=self.root, source_name="fixture.yml"),
            [],
        )
        over_cap = "jobs:\n  cov:\n    steps:\n      - run: '" + " && ".join([one] * 65) + "'\n"
        self.assertEqual(
            check_workflow_text(over_cap, repo_root=self.root, source_name="fixture.yml"),
            [f"fixture.yml:4: exceeds {MAX_INSTALL_CALLS} install calls"],
        )

    def test_install_call_cap_across_scalars_in_source_order(self) -> None:
        call = "apt-install-cached.sh install cov.txt"
        snippet = (
            f"command: &first '{call}'\nruns:\n  using: composite\n  steps:\n"
            + f"  - run: |\n      {call}\n" * MAX_INSTALL_CALLS
            + "  - run: *first\n"
        )
        calls, findings = scan_install_calls(snippet, "wf")
        lines = [1, *range(6, 2 * MAX_INSTALL_CALLS + 3, 2)]
        self.assertEqual([line for line, _, _ in calls], lines)
        overflow_line = 4 + 2 * MAX_INSTALL_CALLS
        self.assertEqual(
            findings, [f"wf:{overflow_line}: exceeds {MAX_INSTALL_CALLS} install calls"]
        )

    def test_job_env_quoted_run_without_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n"
            "  cov:\n"
            "    env:\n"
            "      run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "    steps:\n"
            "      - run: bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_step_env_quoted_run_without_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - env:\n"
            "          run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "        run: bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_job_env_unquoted_run_without_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n"
            "  cov:\n"
            "    env:\n"
            "      run: bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
            "    steps:\n"
            "      - run: bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_step_env_unquoted_run_without_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - env:\n"
            "          run: bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
            "        run: bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_non_run_env_cmd_plain_value_without_flag_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n"
            "  cov:\n"
            "    env: {CMD: bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt }\n"
            "    steps:\n"
            "      - run: echo ok\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [],
        )

    def test_top_level_anchored_step_alias_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "x-step: &step\n"
            "  run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - *step\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:2: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_step_merge_key_quoted_run_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        single_merge = (
            "x-step: &step\n"
            "  run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - <<: *step\n"
        )
        expected = [
            "fixture.yml:2: .github/apt/cov.txt names libcudart12 without --no-install-recommends"
        ]
        self.assertEqual(
            check_workflow_text(single_merge, repo_root=self.root, source_name="fixture.yml"),
            expected,
        )
        seq_merge = (
            "x-meta: &meta\n"
            "  name: install\n"
            "x-step: &step\n"
            "  run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - <<: [*meta, *step]\n"
        )
        self.assertEqual(
            check_workflow_text(seq_merge, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:4: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_step_merge_key_literal_run_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "x-step: &step\n"
            "  run: |\n"
            "    bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n"
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - <<: *step\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:3: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_step_merge_key_overridden_by_own_flagged_run_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        for merged_run in (
            "  run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n",
            "  run: |\n    bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt\n",
        ):
            snippet = (
                "x-step: &step\n" + merged_run + "jobs:\n"
                "  cov:\n"
                "    steps:\n"
                "      - <<: *step\n"
                "        run: bash scripts/ci/apt-install-cached.sh install"
                " .github/apt/cov.txt --no-install-recommends\n"
            )
            self.assertEqual(
                check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
                [],
            )

    def test_aliased_run_scalar_dedup_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "x-cmd: &cmd 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "jobs:\n"
            "  cov:\n"
            "    steps:\n"
            "      - run: *cmd\n"
            "      - run: *cmd\n"
        )
        self.assertEqual(len(extract_install_calls(snippet)), 1)
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:1: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_step_merge_depth_cap_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        leaf = (
            f"x-m{MAX_STEP_MERGE_DEPTH}: &m{MAX_STEP_MERGE_DEPTH}\n"
            "  run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
        )
        chain_at_cap = leaf + "".join(
            f"x-m{depth}: &m{depth}\n  <<: *m{depth + 1}\n"
            for depth in range(MAX_STEP_MERGE_DEPTH - 1, 0, -1)
        )
        at_cap = chain_at_cap + "jobs:\n  cov:\n    steps:\n      - <<: *m1\n"
        self.assertEqual(
            check_workflow_text(at_cap, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:2: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )
        over_leaf = (
            f"x-m{MAX_STEP_MERGE_DEPTH + 1}: &m{MAX_STEP_MERGE_DEPTH + 1}\n"
            "  run: bash scripts/ci/apt-install-cached.sh install"
            " .github/apt/cov.txt --no-install-recommends\n"
        )
        chain_over_cap = over_leaf + "".join(
            f"x-m{depth}: &m{depth}\n  <<: *m{depth + 1}\n"
            for depth in range(MAX_STEP_MERGE_DEPTH, 0, -1)
        )
        over_cap = chain_over_cap + "jobs:\n  cov:\n    steps:\n      - <<: *m1\n"
        self.assertEqual(
            check_workflow_text(over_cap, repo_root=self.root, source_name="fixture.yml"),
            [f"fixture.yml:4: step merge depth exceeds {MAX_STEP_MERGE_DEPTH}"],
        )

    def test_workflow_step_quoted_run_without_flag_fails_at_run_line(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "jobs:\n"
            "  cov:\n"
            "    env:\n"
            "      run: 'echo setup'\n"
            "    steps:\n"
            "      - run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:6: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_composite_action_quoted_run_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        snippet = (
            "runs:\n"
            "  using: composite\n"
            "  steps:\n"
            "    - run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
        )
        self.assertEqual(
            check_workflow_text(snippet, repo_root=self.root, source_name="action.yml"),
            ["action.yml:4: .github/apt/cov.txt names libcudart12 without --no-install-recommends"],
        )

    def test_anchored_env_aliased_as_step_without_flag_fails(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        expected = [
            "fixture.yml:5: .github/apt/cov.txt names libcudart12 without --no-install-recommends"
        ]
        for quote in ("", "'"):
            snippet = (
                "jobs:\n"
                "  a:\n"
                "    runs-on: ubuntu-latest\n"
                "    env: &step\n"
                f"      run: {quote}bash scripts/ci/apt-install-cached.sh"
                f" install .github/apt/cov.txt{quote}\n"
                "    steps:\n"
                "      - run: echo ok\n"
                "  b:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - *step\n"
            )
            self.assertEqual(
                check_workflow_text(snippet, repo_root=self.root, source_name="fixture.yml"),
                expected,
            )

    def test_aliased_step_mapping_dedup_boundary(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        two_step_aliases = (
            "jobs:\n"
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "    env: &step\n"
            "      run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "    steps:\n"
            "      - run: echo ok\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - *step\n"
            "  c:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - *step\n"
        )
        expected = [
            "fixture.yml:5: .github/apt/cov.txt names libcudart12 without --no-install-recommends"
        ]
        self.assertEqual(
            check_workflow_text(two_step_aliases, repo_root=self.root, source_name="fixture.yml"),
            expected,
        )
        step_then_env = (
            "jobs:\n"
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - &step\n"
            "        run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    env: *step\n"
            "    steps:\n"
            "      - run: echo ok\n"
        )
        self.assertEqual(
            check_workflow_text(step_then_env, repo_root=self.root, source_name="fixture.yml"),
            [
                "fixture.yml:6: .github/apt/cov.txt names libcudart12"
                " without --no-install-recommends"
            ],
        )

    def test_anchored_env_without_step_alias_passes(self) -> None:
        self._write_list(".github/apt/cov.txt", "libcudart12\n")
        unaliased = (
            "jobs:\n"
            "  a:\n"
            "    runs-on: ubuntu-latest\n"
            "    env: &step\n"
            "      run: 'bash scripts/ci/apt-install-cached.sh install .github/apt/cov.txt'\n"
            "    steps:\n"
            "      - run: echo ok\n"
        )
        self.assertEqual(
            check_workflow_text(unaliased, repo_root=self.root, source_name="fixture.yml"),
            [],
        )
        env_only_alias = (
            unaliased
            + "  b:\n"
            + "    runs-on: ubuntu-latest\n"
            + "    env: *step\n"
            + "    steps:\n"
            + "      - run: echo ok\n"
        )
        self.assertEqual(
            check_workflow_text(env_only_alias, repo_root=self.root, source_name="fixture.yml"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
