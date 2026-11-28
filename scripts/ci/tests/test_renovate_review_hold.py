#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Reviewed Renovate rules carry hold unless a later rule can automerge them.

The catch-all minor/patch rule is the one exception: its mergeable addLabels
would also hold updates that later rules explicitly automerge.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any, ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from scripts.lib.renovate_regex import to_python

ROOT = Path(__file__).resolve().parents[3]
HOLD = "hold"
GLOB_METACHARACTERS = frozenset("*?[]{}()\\")
DIMENSIONS = (
    "matchManagers",
    "matchUpdateTypes",
    "matchPackageNames",
    "matchDepNames",
    "matchDatasources",
    "matchFileNames",
    "matchDepTypes",
    "matchCurrentValue",
)
# Pin independently of packageRules so deletion or disabling cannot erase the expectation.
REQUIRED_HOLD_RULES = {
    "CI Node.js",
    "Cargo deps (major)",
    "GitHub Actions (major)",
    "Go deps (major)",
    "Intel NEO compute stack (matched set)",
    "OpenSSF Scorecard action (gate identity)",
    "Python (minor)",
    "ROCm (hip runtime)",
    "Renovate self-hosted action",
    "Rust toolchain",
    "dev-image pinned deps",
    "numpy (all managers)",
    "CUDA_VERSION resolves from NVIDIA's official redist HTML index, which exposes versions "
    "but no release timestamps. Keep the global three-day age policy for timestamped "
    "dependencies, but permit this manually reviewed source to update instead of leaving "
    "every CUDA release pending forever.",
    "Propose seven-day-old Ubuntu archive dates weekly; image rebuild and manual review "
    "required (ADR-3541).",
}
Rule = dict[str, Any]


def values(value: str | list[str]) -> list[str]:
    """Normalize the scalar matchCurrentValue form to a value list."""
    return [value] if isinstance(value, str) else value


# https://docs.renovatebot.com/configuration-options/#packagerulesmatchpackagenames
# https://docs.renovatebot.com/string-pattern-matching/ (regex flags and case-insensitive globs)
def regex(value: str) -> re.Pattern[str] | None:
    """Compile Renovate's slash-delimited regex, including its optional i flag."""
    if not value.startswith("/"):
        return None
    if value.endswith("/i"):
        return re.compile(to_python(value[1:-2]), re.IGNORECASE)
    if value.endswith("/"):
        return re.compile(to_python(value[1:-1]))
    return None


def concrete(value: str) -> bool:
    """Only exact positive strings can prove coverage by a later rule."""
    return (
        not value.startswith("!")
        and regex(value) is None
        and not any(char in GLOB_METACHARACTERS for char in value)
    )


def matches(pattern: str, value: str) -> bool:
    """Prove a concrete value belongs to an exact string or a regex."""
    if pattern.startswith("!"):
        return False
    expression = regex(pattern)
    if expression is not None:
        return bool(expression.search(value)) and (
            bool(expression.flags & re.IGNORECASE) or value.lower() == value.upper()
        )
    return concrete(pattern) and pattern.casefold() == value.casefold()


def pair_overlap(left: str, right: str) -> bool:
    """Unknown pattern intersections conservatively count as overlapping."""
    if concrete(left) and concrete(right):
        return left.casefold() == right.casefold()
    for pattern, value in ((left, right), (right, left)):
        expression = regex(pattern)
        if concrete(value) and expression is not None:
            if expression.search(value):
                return True
            if expression.flags & re.IGNORECASE or value.lower() == value.upper():
                return False
            # A literal anchored prefix rules out every spelling with a different prefix.
            prefix = re.fullmatch(r"\^([A-Za-z0-9]+)", expression.pattern)
            return prefix is None or value.casefold().startswith(prefix[1].casefold())
    return True


def may_overlap(a: list[str], b: list[str]) -> bool:
    """At least one pair can match within this dimension."""
    return any(pair_overlap(left, right) for left in a for right in b)


def dimension_overlap(key: str, a: list[str], b: list[str]) -> bool:
    # https://docs.renovatebot.com/configuration-options/#packagerulesmatchdeptypes
    # https://docs.renovatebot.com/configuration-options/#packagerulesmatchfilenames
    # An update may carry multiple dep types or involve both a manifest and a lock file.
    if key in ("matchFileNames", "matchDepTypes"):
        return True
    # https://docs.renovatebot.com/configuration-options/#packagerulesmatchupdatetypes
    # A bump can match both "bump" and its ordinary update type.
    if key == "matchUpdateTypes" and (may_overlap(a, ["bump"]) or may_overlap(b, ["bump"])):
        return True
    return may_overlap(a, b)


def co_match(r1: Rule, r2: Rule) -> bool:
    """A single disjoint dimension suffices to rule out a shared update."""
    return all(
        dimension_overlap(key, values(r1[key]), values(r2[key]))
        for key in DIMENSIONS
        if key in r1 and key in r2
    )


def unsupported_selectors(rule: Rule) -> list[str]:
    return [key for key in rule if key.startswith(("match", "exclude")) and key not in DIMENSIONS]


def dimension_covers(patterns: list[str], reviewed: list[str]) -> bool:
    for value in reviewed:
        if not concrete(value) or not any(matches(p, value) for p in patterns):
            return False
        if any(pair_overlap(p[1:], value) for p in patterns if p.startswith("!")):
            return False
    return True


def covers(k: Rule, r: Rule) -> bool:
    """Prove every selector on k covers the reviewed rule r."""
    return not unsupported_selectors(k) and all(
        key in r and dimension_covers(values(k[key]), values(r[key]))
        for key in DIMENSIONS
        if key in k
    )


State = tuple[bool, bool]


def initial_state(config: Rule) -> State:
    return config.get("enabled") is not False, config.get("automerge") is True


def apply_rule(state: State, rule: Rule) -> State:
    enabled, automerge = state
    if isinstance(rule.get("enabled"), bool):
        enabled = rule["enabled"]
    if isinstance(rule.get("automerge"), bool):
        automerge = rule["automerge"]
    return enabled, automerge


def outcomes(rules: list[Rule], i: int, initial: State = (True, False)) -> set[State]:
    """Trace reachable (enabled, automerge) states across matching rules in order."""
    target = rules[i]
    states = {initial}
    for k, other in enumerate(rules):
        if k == i or covers(other, target):
            states = {apply_rule(state, other) for state in states}
        elif co_match(target, other):
            states = states | {apply_rule(state, other) for state in states}
    return states


def is_active(states: set[State]) -> bool:
    return any(enabled for enabled, _ in states)


def leaks(rules: list[Rule], i: int, initial: State = (True, False)) -> bool:
    """An enabled automerged state remains reachable after all matching rules."""
    return (True, True) in outcomes(rules, i, initial)


def name(rule: Rule, index: int) -> str:
    """Use the human-readable group, description, or position in diagnostics."""
    return str(rule.get("groupName", rule.get("description", index)))


def rule_findings(rules: list[Rule], i: int, initial: State = (True, False)) -> list[str]:
    rule = rules[i]
    label = name(rule, i)
    reviewed = rule.get("automerge") is False
    errors: list[str] = []
    if "automerge" in rule:
        errors.extend(
            f"unsupported selector {key} on {label}" for key in unsupported_selectors(rule)
        )
    # https://docs.renovatebot.com/configuration-options/#labels replaces earlier labels.
    # https://docs.renovatebot.com/configuration-options/#addlabels accumulates across rules.
    added = HOLD in rule.get("addLabels", [])
    held = added or HOLD in rule.get("labels", [])
    if held and not reviewed:
        errors.append(f"hold outside a reviewed rule: {label}")
    states = outcomes(rules, i, initial)
    leaking = (True, True) in states
    if reviewed and (True, False) in states and not leaking and not added:
        errors.append(f"reviewed rule {label} lacks addLabels hold")
    if held and leaking:
        errors.append(f"hold on {label} reaches an automerged update")
    return errors


def policy_findings(config: Rule) -> list[str]:
    errors = [
        f"hold in top-level {key}" for key in ("labels", "addLabels") if HOLD in config.get(key, [])
    ]
    initial = initial_state(config)
    rules = config["packageRules"]
    for i in range(len(rules)):
        errors.extend(rule_findings(rules, i, initial))
    return errors


def findings(config: Rule) -> list[str]:
    """Check label policy and the repository's inventory of reviewed rules carrying hold."""
    initial = initial_state(config)
    rules = config["packageRules"]
    held = {
        name(rule, i)
        for i, rule in enumerate(rules)
        if rule.get("automerge") is False
        and HOLD in rule.get("addLabels", [])
        and is_active(outcomes(rules, i, initial))
    }
    errors = policy_findings(config)
    errors.extend(
        f"missing reviewed hold rule: {label}" for label in sorted(REQUIRED_HOLD_RULES - held)
    )
    errors.extend(
        f"unexpected reviewed hold rule: {label}" for label in sorted(held - REQUIRED_HOLD_RULES)
    )
    return errors


def leak_exempt(config: dict[str, Any]) -> list[str]:
    """Name active reviewed rules where adding hold would reach automerge."""
    initial = initial_state(config)
    rules = config["packageRules"]
    return [
        name(rule, i)
        for i, rule in enumerate(rules)
        if rule.get("automerge") is False and leaks(rules, i, initial)
    ]


class ReviewedRulesCarryHold(unittest.TestCase):
    config: ClassVar[dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))

    def test_checked_in_rules(self) -> None:
        self.assertEqual(findings(self.config), [])

    def test_only_catch_all_is_exempt(self) -> None:
        self.assertEqual(leak_exempt(self.config), ["Other dependencies (minor + patch)"])

    def test_ci_node_carries_hold(self) -> None:
        rule = next(r for r in self.config["packageRules"] if r.get("groupName") == "CI Node.js")
        self.assertIn(HOLD, rule.get("addLabels", []))

    def test_missing_ci_node_hold_fails(self) -> None:
        config = copy.deepcopy(self.config)
        rule = next(r for r in config["packageRules"] if r.get("groupName") == "CI Node.js")
        rule.pop("addLabels", None)
        self.assertIn("reviewed rule CI Node.js lacks addLabels hold", findings(config))

    def test_catch_all_hold_leaks(self) -> None:
        config = copy.deepcopy(self.config)
        config["packageRules"][0]["addLabels"] = [HOLD]
        self.assertIn(
            "hold on Other dependencies (minor + patch) reaches an automerged update",
            findings(config),
        )

    def test_separate_label_only_rule_fails(self) -> None:
        config = copy.deepcopy(self.config)
        config["packageRules"].append({"matchPackageNames": ["numpy"], "addLabels": [HOLD]})
        index = len(config["packageRules"]) - 1
        self.assertIn(f"hold outside a reviewed rule: {index}", findings(config))

    def test_automerge_rule_with_hold_fails(self) -> None:
        config = copy.deepcopy(self.config)
        rule = next(
            r
            for r in config["packageRules"]
            if r.get("groupName") == "GitHub Actions (minor + patch)"
        )
        rule["addLabels"] = [HOLD]
        self.assertIn(
            "hold outside a reviewed rule: GitHub Actions (minor + patch)", findings(config)
        )

    def test_regex_negated_range_overlaps_literal(self) -> None:
        for left, right in (
            ("/^foo[^A-Z]$/", "foob"),
            ("foob", "/^foo[^A-Z]$/"),
            ("/^fo[^O]$/", "foo"),
            ("foo", "/^fo[^O]$/"),
            ("/^fo[^O]$/", "FOO"),
            ("FOO", "/^fo[^O]$/"),
        ):
            with self.subTest(left=left, right=right):
                self.assertTrue(pair_overlap(left, right))
        for package in ("foo", "FOO"):
            with self.subTest(package=package):
                rules: list[Rule] = [
                    {
                        "matchManagers": ["npm"],
                        "matchDatasources": ["npm"],
                        "matchPackageNames": ["/^fo[^O]$/"],
                        "automerge": False,
                        "addLabels": [HOLD],
                    },
                    {
                        "matchManagers": ["npm"],
                        "matchDatasources": ["npm"],
                        "matchPackageNames": [package],
                        "automerge": True,
                    },
                ]
                self.assertEqual(
                    policy_findings({"packageRules": rules}),
                    ["hold on 0 reaches an automerged update"],
                )
                config = copy.deepcopy(self.config)
                index = len(config["packageRules"])
                config["packageRules"].extend(rules)
                self.assertIn(f"hold on {index} reaches an automerged update", findings(config))

    def test_unknown_selectors_name_the_rule_and_key(self) -> None:
        for label, key in (
            ("CI Node.js", "matchNewValue"),
            ("GitHub Actions (minor + patch)", "excludePackageNames"),
        ):
            with self.subTest(label=label, key=key):
                config = copy.deepcopy(self.config)
                rule = next(r for r in config["packageRules"] if r.get("groupName") == label)
                rule[key] = "/^99[.]/" if key == "matchNewValue" else ["foo"]
                self.assertIn(f"unsupported selector {key} on {label}", findings(config))

    def test_top_level_hold_fails(self) -> None:
        for key in ("labels", "addLabels"):
            with self.subTest(key=key):
                config = {**self.config, key: [HOLD]}
                self.assertIn(f"hold in top-level {key}", findings(config))

    def test_automerge_labels_hold_fails(self) -> None:
        config = copy.deepcopy(self.config)
        label = "GitHub Actions (minor + patch)"
        rule = next(r for r in config["packageRules"] if r.get("groupName") == label)
        rule["labels"] = [HOLD]
        self.assertIn(f"hold outside a reviewed rule: {label}", findings(config))

    def test_pre_commit_labels_hold_and_reviewed_labels_only_fail(self) -> None:
        config = copy.deepcopy(self.config)
        config["packageRules"].append({"matchManagers": ["pre-commit"], "labels": [HOLD]})
        index = len(config["packageRules"]) - 1
        self.assertIn(f"hold outside a reviewed rule: {index}", findings(config))

        reviewed_config = copy.deepcopy(self.config)
        rule = next(
            r for r in reviewed_config["packageRules"] if r.get("groupName") == "CI Node.js"
        )
        rule.pop("addLabels", None)
        rule["labels"] = [HOLD]
        errors = findings(reviewed_config)
        self.assertIn("reviewed rule CI Node.js lacks addLabels hold", errors)
        self.assertIn("missing reviewed hold rule: CI Node.js", errors)

    def test_bump_overlaps_version_update_types(self) -> None:
        bump = {"matchUpdateTypes": ["bump"]}
        for version in ("major", "minor", "patch"):
            with self.subTest(version=version):
                update = {"matchUpdateTypes": [version]}
                self.assertTrue(co_match(bump, update))
                self.assertTrue(co_match(update, bump))

    def test_distinct_dep_types_can_co_match(self) -> None:
        self.assertTrue(co_match({"matchDepTypes": ["dependencies"]}, {"matchDepTypes": ["dev"]}))

    def test_missing_reviewed_rule_fails(self) -> None:
        config = copy.deepcopy(self.config)
        label = "Renovate self-hosted action"
        config["packageRules"] = [r for r in config["packageRules"] if r.get("groupName") != label]
        self.assertIn(f"missing reviewed hold rule: {label}", findings(config))

    def test_review_after_automerge_wins(self) -> None:
        rules = [
            {"matchPackageNames": ["foo"], "automerge": True},
            {"matchPackageNames": ["foo"], "automerge": False, "addLabels": [HOLD]},
        ]
        self.assertFalse(leaks(rules, 1))
        self.assertEqual(policy_findings({"packageRules": rules}), [])

    def test_later_reviewed_superset_settles_overlap(self) -> None:
        rules = [
            {"matchPackageNames": ["foo"], "automerge": False, "addLabels": [HOLD]},
            {"matchManagers": ["custom.regex"], "automerge": True},
            {"matchPackageNames": ["foo", "bar"], "automerge": False, "addLabels": [HOLD]},
        ]
        self.assertFalse(leaks(rules, 0))
        self.assertEqual(policy_findings({"packageRules": rules}), [])

    def test_disjoint_update_types(self) -> None:
        self.assertFalse(co_match({"matchUpdateTypes": ["major"]}, {"matchUpdateTypes": ["minor"]}))

    def test_regex_against_concrete(self) -> None:
        for pattern, value, expected in (
            ("/^foo/", "foobar", True),
            ("/^foo/", "barfoo", False),
            ("/^foo/i", "barfoo", False),
            ("/^foo/i", "FOObar", True),
            ("/(?<prefix>foo)/", "foobar", True),
        ):
            with self.subTest(pattern=pattern, value=value):
                left = {"matchPackageNames": [pattern]}
                right = {"matchPackageNames": [value]}
                self.assertEqual(co_match(left, right), expected)
                self.assertEqual(co_match(right, left), expected)

    def test_current_value_accepts_a_string(self) -> None:
        rule = {"matchCurrentValue": "24.04"}
        self.assertTrue(co_match(rule, {"matchCurrentValue": ["24.04"]}))
        self.assertFalse(co_match(rule, {"matchCurrentValue": "26.04"}))
        self.assertTrue(covers({"matchCurrentValue": "/^24/"}, rule))

    def test_unknown_pattern_overlap_is_conservative(self) -> None:
        for left, right in (("foo*", "bar"), ("!foo", "foo"), ("/^foo/", "/^bar/")):
            with self.subTest(left=left, right=right):
                self.assertTrue(may_overlap([left], [right]))
                self.assertTrue(may_overlap([right], [left]))

    def test_glob_metacharacters_cannot_hide_leaks(self) -> None:
        for pattern, value in (("foo?", "fooa"), ("foo[ab]", "fooa"), ("{foo,bar}", "foo")):
            with self.subTest(pattern=pattern):
                rules = [
                    {"matchPackageNames": [pattern], "automerge": False, "addLabels": [HOLD]},
                    {"matchPackageNames": [value], "automerge": True},
                ]
                self.assertTrue(pair_overlap(pattern, value))
                self.assertIn(
                    "hold on 0 reaches an automerged update",
                    policy_findings({"packageRules": rules}),
                )

    def test_case_insensitive_exact_overlap_and_coverage(self) -> None:
        self.assertTrue(pair_overlap("numpy", "NumPy"))
        self.assertTrue(pair_overlap("/^NUMPY$/", "numpy"))
        rules = [
            {"matchPackageNames": ["numpy"], "automerge": False, "addLabels": [HOLD]},
            {"matchPackageNames": ["NumPy"], "automerge": True},
        ]
        self.assertIn(
            "hold on 0 reaches an automerged update", policy_findings({"packageRules": rules})
        )
        self.assertFalse(covers({"matchPackageNames": ["/^numpy$/"]}, rules[0]))
        self.assertTrue(covers({"matchPackageNames": ["/^numpy$/i"]}, rules[0]))
        self.assertTrue(covers({"matchPackageNames": ["NumPy"]}, rules[0]))

    def test_later_review_exclusions_control_settlement(self) -> None:
        rules = [
            {"matchPackageNames": ["foo"], "automerge": False, "addLabels": [HOLD]},
            {"matchManagers": ["custom.regex"], "automerge": True},
            {"matchPackageNames": ["foo", "bar", "!foo"], "automerge": False, "addLabels": [HOLD]},
        ]
        self.assertIn(
            "hold on 0 reaches an automerged update", policy_findings({"packageRules": rules})
        )
        rules[2]["matchPackageNames"] = ["foo", "bar", "!baz"]
        self.assertFalse(leaks(rules, 0))

    def test_coverage_requires_proof_in_every_dimension(self) -> None:
        reviewed = {"matchPackageNames": ["foo", "bar"]}
        self.assertFalse(covers({"matchPackageNames": ["foo"]}, reviewed))
        self.assertFalse(covers({"matchManagers": ["npm"]}, reviewed))
        self.assertFalse(covers({"matchPackageNames": ["*"]}, reviewed))
        self.assertFalse(covers({"matchPackageNames": ["!baz"]}, reviewed))
        self.assertTrue(covers({}, {"matchPackageNames": ["/^foo/"]}))
        self.assertFalse(covers(reviewed, {"matchPackageNames": ["/^foo/"]}))
        self.assertTrue(covers({"matchPackageNames": ["/^(foo|bar)$/i"]}, reviewed))

    def test_enabled_trace_follows_matching_rules_in_order(self) -> None:
        stay_disabled: list[Rule] = [
            {
                "matchManagers": ["npm"],
                "matchDatasources": ["npm"],
                "matchPackageNames": ["foo"],
                "enabled": False,
                "automerge": False,
                "addLabels": [HOLD],
            },
            {
                "matchManagers": ["npm"],
                "matchDatasources": ["npm"],
                "matchPackageNames": ["foo"],
                "automerge": True,
            },
        ]
        reenabled = copy.deepcopy(stay_disabled)
        reenabled[1]["enabled"] = True
        self.assertTrue(leaks(reenabled, 0))
        self.assertEqual(
            policy_findings({"packageRules": reenabled}),
            ["hold on 0 reaches an automerged update"],
        )
        config = copy.deepcopy(self.config)
        index = len(config["packageRules"])
        config["packageRules"].extend(copy.deepcopy(reenabled))
        self.assertIn(f"hold on {index} reaches an automerged update", findings(config))

        self.assertFalse(leaks(stay_disabled, 0))
        self.assertEqual(policy_findings({"packageRules": stay_disabled}), [])
        config["packageRules"][-1].pop("enabled")
        self.assertEqual(findings(config), [])

    def test_later_disabled_or_reenabled_rules_control_settlement(self) -> None:
        rules: list[Rule] = [
            {"matchPackageNames": ["foo"], "automerge": False, "addLabels": [HOLD]},
            {"matchPackageNames": ["foo"], "automerge": True, "enabled": False},
        ]
        self.assertFalse(leaks(rules, 0))
        self.assertEqual(policy_findings({"packageRules": rules}), [])
        rules.append({"matchPackageNames": ["foo"], "enabled": True})
        self.assertTrue(leaks(rules, 0))
        self.assertEqual(
            policy_findings({"packageRules": rules}), ["hold on 0 reaches an automerged update"]
        )
        rules.append({"matchPackageNames": ["foo"], "automerge": False, "enabled": False})
        self.assertFalse(leaks(rules, 0))
        self.assertEqual(policy_findings({"packageRules": rules}), [])

        disabled_required = copy.deepcopy(self.config)
        disabled_required["packageRules"].append(
            {"matchManagers": ["custom.regex"], "matchDepNames": ["node"], "enabled": False}
        )
        self.assertIn("missing reviewed hold rule: CI Node.js", findings(disabled_required))

    def test_disjoint_file_names_still_co_match(self) -> None:
        rules: list[Rule] = [
            {"matchFileNames": ["package.json"], "automerge": False, "addLabels": [HOLD]},
            {"matchFileNames": ["package-lock.json"], "automerge": True},
        ]
        self.assertEqual(
            policy_findings({"packageRules": rules}), ["hold on 0 reaches an automerged update"]
        )
        self.assertTrue(co_match(rules[0], rules[1]))
        self.assertTrue(covers({"matchFileNames": ["package.json"]}, rules[0]))
        self.assertFalse(covers({"matchFileNames": ["package-lock.json"]}, rules[0]))

    def test_unmodeled_match_or_exclude_blocks_coverage(self) -> None:
        rules: list[Rule] = [
            {"matchPackageNames": ["foo"], "automerge": False, "addLabels": [HOLD]},
            {"matchManagers": ["custom.regex"], "automerge": True},
            {
                "matchPackageNames": ["foo"],
                "matchNewValue": "/^2\\./",
                "automerge": False,
                "addLabels": [HOLD],
            },
        ]
        self.assertEqual(
            policy_findings({"packageRules": rules}),
            ["hold on 0 reaches an automerged update", "unsupported selector matchNewValue on 2"],
        )
        self.assertFalse(
            covers({"matchPackageNames": ["foo"], "excludePackageNames": ["bar"]}, rules[0])
        )
        self.assertTrue(covers(rules[0], rules[2]))


if __name__ == "__main__":
    unittest.main()
