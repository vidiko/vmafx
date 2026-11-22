#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""ADR-2985: every Sigstore identity expression VMAFx passes or documents is anchored.

cosign and gh search the certificate identity for the expression (Go's
regexp.MatchString), so an expression without `^` and `$` also accepts an
identity with text before or after it, and an unescaped `.` in the host or
path accepts any character there. The test reads the expression libvmaf passes
to cosign (core/src/dnn/signer_identity.h) and every
`--certificate-identity-regexp` / `--cert-identity-regex` in the workflows and
the current guides, checks each one's form, and runs the library's expression
against identities it must accept and refuse. Python's `re.search` has Go's
semantics for the constructs these expressions use (`^ \\. ( | ) [...] *`)
except `$`, which in Python also matches before a final newline; go_regexp()
spells Go's `$` as `\\Z`.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = ROOT / "core" / "src" / "dnn" / "signer_identity.h"
LOADER = ROOT / "core" / "src" / "dnn" / "model_loader.c"
# Records of past decisions and findings keep the expressions they quoted.
HISTORY = ("docs/research/", "docs/adr/", "docs/changelog-archive/")
FLAG_OCCURRENCE = re.compile(
    r"(?:--certificate-identity-regexp|--cert-identity-regex)(?=[= ]\s*[^\s`…])"
)
FLAG = re.compile(r"(?:--certificate-identity-regexp|--cert-identity-regex)[= ]\s*(['\"])(.+?)\1")
# Documents whose expression must be the library's (release files of supply-chain.yml).
SUPPLY_CHAIN_DOCS = (
    "docs/ai/security.md",
    "docs/ai/u2netp-mirror.md",
    "docs/ai/models/u2netp_mirror_card.md",
)
WORKFLOW = "https://github.com/vidiko/vmafx/.github/workflows/supply-chain.yml"


def header_expression() -> str:
    text = HEADER.read_text(encoding="utf-8")
    block = re.search(r"#define VMAF_DNN_SIGNER_IDENTITY_REGEXP((?:[^\n]*\\\n)+[^\n]*)", text)
    if block is None:
        raise AssertionError(f"{HEADER}: VMAF_DNN_SIGNER_IDENTITY_REGEXP not found")
    pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', block.group(1))
    return "".join(pieces).replace("\\\\", "\\")


def go_regexp(expr: str) -> re.Pattern[str]:
    """Compile @p expr with Go's meaning of a final `$` (end of text only)."""
    return re.compile(expr[:-1] + r"\Z" if expr.endswith("$") else expr)


def scan_line_expressions(line: str) -> list[str | None]:
    """Extract every identity-regexp flag value on @p line, or None when unparseable."""
    results: list[str | None] = []
    for occ in FLAG_OCCURRENCE.finditer(line):
        match = FLAG.match(line, occ.start())
        results.append(match.group(2) if match is not None else None)
    return results


def documented_expressions() -> list[tuple[str, int, str | None]]:
    files = [
        *sorted((ROOT / ".github" / "workflows").glob("*.y*ml")),
        *sorted((ROOT / "docs").rglob("*.md")),
        ROOT / "README.md",
        ROOT / "SECURITY.md",
    ]
    found: list[tuple[str, int, str | None]] = []
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(HISTORY) or not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            found += [(rel, lineno, expr) for expr in scan_line_expressions(line)]
    return found


def has_top_level_alternation(expr: str) -> bool:
    escaped = False
    in_class = False
    paren_depth = 0
    for ch in expr:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_class:
            if ch == "]":
                in_class = False
            continue
        if ch == "[":
            in_class = True
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            if paren_depth == 0:
                return True
            paren_depth -= 1
        elif ch == "|" and paren_depth == 0:
            return True
    return paren_depth != 0 or in_class


def form_errors(expr: str | None) -> list[str]:
    if expr is None:
        return ["flag value is not a quoted expression"]
    errors = []
    if not expr.startswith("^") or not expr.endswith("$"):
        errors.append("not anchored with ^ and $")
    if has_top_level_alternation(expr):
        errors.append("top-level alternation outside parentheses")
    outside_classes = re.sub(r"\[[^\]]*\]", "", expr)
    if ".*" in outside_classes or ".+" in outside_classes:
        errors.append("unbounded .* or .+")
    head = expr.split("@", 1)[0]
    if re.search(r"(?<!\\)\.", head):
        errors.append("unescaped '.' before '@'")
    return errors


class SignerIdentityExpressionTest(unittest.TestCase):
    def test_library_expression_accepts_release_identities(self) -> None:
        expr = go_regexp(header_expression())
        for ref in ("refs/tags/v1.0.0", "refs/tags/v1.0.0-rc.3", "refs/heads/master"):
            self.assertIsNotNone(expr.search(f"{WORKFLOW}@{ref}"), ref)

    def test_library_expression_refuses_other_identities(self) -> None:
        expr = go_regexp(header_expression())
        refused = (
            f"https://evil.example/{WORKFLOW}@refs/tags/v1.0.0",  # prefix
            f"{WORKFLOW}@refs/heads/master/evil",  # suffix
            f"{WORKFLOW}@refs/tags/v1.0.0\n",  # trailing newline
            WORKFLOW.replace("github.com", "githubXcom") + "@refs/tags/v1",  # dot as wildcard
            WORKFLOW.replace("vmafx/.github", "vmafx-evil/.github") + "@refs/tags/v1",
            WORKFLOW.replace("supply-chain", "evil") + "@refs/heads/master",
            f"{WORKFLOW}@refs/heads/evil",
            f"{WORKFLOW}@refs/tags/vx",
        )
        for identity in refused:
            self.assertIsNone(expr.search(identity), identity)

    def test_library_passes_the_header_expression(self) -> None:
        text = LOADER.read_text(encoding="utf-8")
        self.assertRegex(
            text, r'"--certificate-identity-regexp",\s*\(char \*\)VMAF_DNN_SIGNER_IDENTITY_REGEXP,'
        )

    def test_every_documented_expression_is_anchored(self) -> None:
        found = documented_expressions()
        self.assertTrue(found, "no identity expression found: the scan is broken")
        problems = [
            f"{rel}:{line}: {expr}: {', '.join(errs)}"
            for rel, line, expr in found
            if (errs := form_errors(expr))
        ]
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_supply_chain_documents_use_the_library_expression(self) -> None:
        want = header_expression()
        for rel in SUPPLY_CHAIN_DOCS:
            exprs = [e for r, _, e in documented_expressions() if r == rel]
            self.assertTrue(exprs, f"{rel}: no identity expression")
            for expr in exprs:
                self.assertEqual(expr, want, rel)

    def test_form_check_refuses_planted_defects(self) -> None:
        for planted in (
            WORKFLOW + "@.*",
            "^https://github\\.com/vidiko/vmafx",
            "^https://github.com/vidiko/vmafx/\\.github/workflows/x\\.yml@refs/heads/master$",
        ):
            self.assertTrue(form_errors(planted), planted)

    def test_scanner_rejects_unquoted_flag_value(self) -> None:
        line = (
            "cosign verify-blob --certificate-identity-regexp ^https://github\\.com/vidiko/vmafx$"
        )
        extracted = scan_line_expressions(line)
        self.assertEqual(extracted, [None])
        self.assertTrue(form_errors(extracted[0]))

    def test_form_check_rejects_top_level_alternation(self) -> None:
        ungrouped = (
            "^https://github\\.com/vidiko/vmafx/\\.github/workflows/a\\.yml@refs/heads/master|"
            "https://github\\.com/vidiko/vmafx/\\.github/workflows/b\\.yml@refs/heads/master$"
        )
        grouped = (
            "^https://github\\.com/vidiko/vmafx/\\.github/workflows/(a|b)\\.yml@refs/heads/master$"
        )
        self.assertIn("top-level alternation outside parentheses", form_errors(ungrouped))
        self.assertEqual(form_errors(grouped), [])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
