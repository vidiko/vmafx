#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require --no-install-recommends when apt-install-cached.sh installs driver-recommending libs.

Positive: checked-in tests-and-quality-gates.yml holds; quoted (`'`, `"`), split plain, and
literal-block `run` steps fail without --no-install-recommends and pass with it; workflow and
composite-action step `run` scalars report missing flags at their `run:` line; anchored mappings
aliased (`- *step`) or merged (`- <<: *step`, `- <<: [*a, *b]`) into `steps` report missing flags
at the anchored `run` scalar or literal install line; qualified apt tokens (`:arch`, `=version`,
`/release`, trailing `+`) match their base package name.
Negative: non-driver packages, `-dev:arch` packages, and trailing-`-` removal tokens pass without
--no-install-recommends; collection YAML raw scans allow-list only literal-block (`|`) step `run`
spans, so quoted or plain `run` and non-`run` values outside step `run` (`env.run`,
`steps[*].env.run`, `env.CMD`) and unreferenced anchored mappings pass without findings;
single-line plain `run` steps are recorded once across raw and YAML scans; chained subcommands and
multiple installs on one line fail when any flagged install omits the flag.
Boundary: YAML decoding scans only `MappingNode` items of `steps` sequences and their `<<` merged
mappings (unless overridden by the step's own `run`); aliased step mappings, merged mappings, and
shared `run: *cmd` scalars deduplicate by node id; backslash-continued flags pass;
backslash-space/tab do not continue; continuations over MAX_CONTINUATION_LINES, step merges over
MAX_STEP_MERGE_DEPTH, invalid collection YAML, YAML over MAX_YAML_NODES, missing apt lists,
oversize workflow/list inputs, and excess install calls (MAX_INSTALL_CALLS) fail closed.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from collections.abc import Set as AbstractSet
from pathlib import Path

import yaml  # type: ignore[import-untyped]  # no PyYAML stubs in the hook environment, as in scripts/ci/check_composite_actions.py

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from scripts.ci.test_fail_closed_ci import (  # noqa: E402
    APT_UNBALANCED_QUOTE_MESSAGE,
    HOSTED_YAML_NODE_BOUND_MESSAGE,
    HOSTED_YAML_PARSE_MESSAGE,
    MAX_CONTINUATION_LINES,
    MAX_YAML_NODES,
    _logical_ci_lines,
    _push_child_collections,
    _split_shell_clauses,
    _tokenise_shell_item,
    _yaml_error_line,
)

InstallCall = tuple[int, str, tuple[str, ...]]
Span = tuple[int, int]
RunScalar = tuple[int, int, str]
YAML_MERGE_TAG = "tag:yaml.org,2002:merge"
COLLECTION_LINE_RE = re.compile(r"^(?:---(?:\s+|$))?(?:[-?](?=\s|$)|[\[{])|:(?=\s|$)")
APT_QUALIFIER_RE = re.compile(r"[:=/]")

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


def _has_collection_line(text: str) -> bool:
    """Return True when text contains a non-comment YAML mapping or sequence line."""
    for raw in text.splitlines():
        stripped = raw.lstrip()
        if stripped and not stripped.startswith("#") and COLLECTION_LINE_RE.search(stripped):
            return True
    return False


def _apt_package_base(token: str) -> str:
    """Return the apt package base name for driver matching, or '' for a removal token."""
    if token.endswith("-"):
        return ""
    head = APT_QUALIFIER_RE.split(token, maxsplit=1)[0]
    return head.removesuffix("+")


def _literal_scalar_span(node: yaml.ScalarNode) -> Span | None:
    """Return inclusive 1-based body `(start_line, end_line)` for a literal `|` scalar."""
    start_line = int(node.start_mark.line) + 2
    end_line = int(node.end_mark.line) + (1 if int(node.end_mark.column) > 0 else 0)
    return (start_line, end_line) if start_line <= end_line else None


def _collect_direct_run_scalars(
    mapping: yaml.MappingNode,
    scalar_ids: set[int],
    scalars: list[RunScalar],
    literal_spans: list[Span],
) -> bool:
    """Record unseen direct `run` scalars from `mapping`; return True if `mapping` sets `run`."""
    has_run = False
    for key_node, val_node in mapping.value:
        if not (isinstance(key_node, yaml.ScalarNode) and key_node.value == "run"):
            continue
        has_run = True
        if not isinstance(val_node, yaml.ScalarNode) or id(val_node) in scalar_ids:
            continue
        scalar_ids.add(id(val_node))
        if val_node.style == "|":
            span = _literal_scalar_span(val_node)
            if span is not None:
                literal_spans.append(span)
        else:
            scalars.append(
                (
                    int(val_node.start_mark.line) + 1,
                    int(val_node.end_mark.line) + 1,
                    str(val_node.value),
                )
            )
    return has_run


def _merged_child_mappings(mapping: yaml.MappingNode) -> list[tuple[int, yaml.MappingNode]]:
    """Return `(merge_key_line, child_mapping)` pairs from `<<` keys on `mapping`."""
    merged: list[tuple[int, yaml.MappingNode]] = []
    for key_node, val_node in mapping.value:
        if not (isinstance(key_node, yaml.ScalarNode) and key_node.tag == YAML_MERGE_TAG):
            continue
        key_line = int(key_node.start_mark.line) + 1
        if isinstance(val_node, yaml.MappingNode):
            merged.append((key_line, val_node))
        elif isinstance(val_node, yaml.SequenceNode):
            merged.extend(
                (key_line, item) for item in val_node.value if isinstance(item, yaml.MappingNode)
            )
    return merged


def _mapping_run_scalars(
    mapping: yaml.MappingNode,
    source_name: str,
    scalar_ids: set[int],
    scalars: list[RunScalar],
    literal_spans: list[Span],
) -> str | None:
    """Collect step `run` scalars and literal spans across `<<` merges; return bound error."""
    work: list[tuple[yaml.MappingNode, int]] = [(mapping, 0)]
    seen_merged: set[int] = {id(mapping)}
    for index in range(MAX_YAML_NODES):
        if index >= len(work):
            return None
        current, depth = work[index]
        if _collect_direct_run_scalars(current, scalar_ids, scalars, literal_spans):
            continue
        for key_line, child in _merged_child_mappings(current):
            if id(child) in seen_merged:
                continue
            if depth >= MAX_STEP_MERGE_DEPTH:
                return f"{source_name}:{key_line}: step merge depth exceeds {MAX_STEP_MERGE_DEPTH}"
            seen_merged.add(id(child))
            work.append((child, depth + 1))
    return f"{source_name}:1: {HOSTED_YAML_NODE_BOUND_MESSAGE}"


def _record_step_mapping_ids(
    mapping: yaml.MappingNode,
    step_ids: set[int],
) -> list[yaml.MappingNode]:
    """Register new `MappingNode` items in `steps` sequences on `mapping` and return them."""
    new_steps: list[yaml.MappingNode] = []
    for key_node, val_node in mapping.value:
        if not (isinstance(key_node, yaml.ScalarNode) and key_node.value == "steps"):
            continue
        if not isinstance(val_node, yaml.SequenceNode):
            continue
        for item in val_node.value:
            if isinstance(item, yaml.MappingNode) and id(item) not in step_ids:
                step_ids.add(id(item))
                new_steps.append(item)
    return new_steps


def _compose_collection_root(
    text: str,
    source_name: str,
) -> tuple[yaml.CollectionNode | None, str | None]:
    """Compose `text` when it is a YAML collection; return `(root, yaml_finding)`."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        if not _has_collection_line(text):
            return (None, None)
        return (None, f"{source_name}:{_yaml_error_line(error)}: {HOSTED_YAML_PARSE_MESSAGE}")
    if isinstance(root, yaml.CollectionNode):
        return (root, None)
    return (None, None)


def _yaml_run_scalars(
    text: str,
    source_name: str,
) -> tuple[list[RunScalar], list[Span] | None, str | None]:
    """Compose YAML with bounded walk; return `(scalars, literal_spans, yaml_finding)`."""
    root, yaml_error = _compose_collection_root(text, source_name)
    if root is None or yaml_error is not None:
        return ([], None, yaml_error)
    scalars: list[RunScalar] = []
    literal_spans: list[Span] = []
    scalar_ids: set[int] = set()
    step_ids: set[int] = set()
    stack: list[yaml.Node] = [root]
    seen: set[int] = {id(root)}
    for _ in range(MAX_YAML_NODES):
        if not stack:
            return (scalars, literal_spans, None)
        current = stack.pop()
        if isinstance(current, yaml.MappingNode):
            for step in _record_step_mapping_ids(current, step_ids):
                merge_err = _mapping_run_scalars(
                    step, source_name, scalar_ids, scalars, literal_spans
                )
                if merge_err is not None:
                    return ([], None, merge_err)
        _push_child_collections(current, stack, seen)
    return ([], None, f"{source_name}:1: {HOSTED_YAML_NODE_BOUND_MESSAGE}")


def _scan_shell_text(
    text: str,
    source_name: str,
    fixed_lineno: int | None = None,
) -> tuple[list[InstallCall], list[tuple[int, str]]]:
    """Scan shell text for install calls and per-line continuation or quote findings."""
    calls: list[InstallCall] = []
    findings: list[tuple[int, str]] = []
    for lineno, line, overflowed in _logical_ci_lines(text):
        report_line = fixed_lineno if fixed_lineno is not None else lineno
        if overflowed:
            msg = (
                f"{source_name}:{report_line}: continuation exceeds"
                f" {MAX_CONTINUATION_LINES} physical lines"
            )
            findings.append((report_line, msg))
            continue
        try:
            parsed = parse_install_calls(line)
        except ValueError:
            findings.append(
                (report_line, f"{source_name}:{report_line}: {APT_UNBALANCED_QUOTE_MESSAGE}")
            )
            continue
        for list_rel, args in parsed:
            calls.append((report_line, list_rel, args))
            if fixed_lineno is not None and len(calls) > MAX_INSTALL_CALLS:
                return (calls, findings)
    return (calls, findings)


def _yaml_run_pass(
    scalars: list[tuple[int, int, str]],
    source_name: str,
) -> tuple[list[tuple[int, int]], list[InstallCall], list[str]]:
    """Scan non-literal YAML `run` scalars; return (spans, decoded_calls, findings)."""
    spans = [(start_line, end_line) for start_line, end_line, _ in scalars]
    calls: list[InstallCall] = []
    findings: list[str] = []
    for start_line, _, value in scalars:
        scalar_calls, scalar_findings = _scan_shell_text(
            value, source_name, fixed_lineno=start_line
        )
        findings.extend(msg for _, msg in scalar_findings)
        for call in scalar_calls:
            calls.append(call)
            if len(calls) > MAX_INSTALL_CALLS:
                return (spans, calls, findings)
    return (spans, calls, findings)


def _in_any_span(lineno: int, spans: list[Span]) -> bool:
    """Return True when lineno lies within any inclusive (start_line, end_line) span."""
    return any(start <= lineno <= end for start, end in spans)


def _keep_raw_line(
    lineno: int,
    literal_spans: list[Span] | None,
    non_literal_spans: list[Span],
) -> bool:
    """Return True when raw scan keeps `lineno` under collection allow-list and span exclusion."""
    if literal_spans is not None and not _in_any_span(lineno, literal_spans):
        return False
    return not (non_literal_spans and _in_any_span(lineno, non_literal_spans))


def scan_install_calls(
    text: str,
    source_name: str,
) -> tuple[list[InstallCall], list[str]]:
    """Scan workflow text for bounded install calls, continuation overflows, and call-cap hits."""
    scalars, literal_spans, yaml_error = _yaml_run_scalars(text, source_name)
    if yaml_error is not None:
        return ([], [yaml_error])
    raw_calls, raw_findings = _scan_shell_text(text, source_name)
    spans, yaml_calls, yaml_findings = _yaml_run_pass(scalars, source_name)
    raw_calls = [call for call in raw_calls if _keep_raw_line(call[0], literal_spans, spans)]
    raw_findings = [item for item in raw_findings if _keep_raw_line(item[0], literal_spans, spans)]
    findings = [*(msg for _, msg in raw_findings), *yaml_findings]
    merged = sorted([*raw_calls, *yaml_calls], key=lambda call: call[0])
    if len(merged) > MAX_INSTALL_CALLS:
        over_line = merged[MAX_INSTALL_CALLS][0]
        findings.append(f"{source_name}:{over_line}: exceeds {MAX_INSTALL_CALLS} install calls")
        return (merged[:MAX_INSTALL_CALLS], findings)
    return (merged, findings)


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
        flagged = sorted(token for token in loaded if _apt_package_base(token) in drivers)
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
