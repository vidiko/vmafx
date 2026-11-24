#!/usr/bin/env python3
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Tests for scripts/ci/pr-body-gates.sh and rule-enforcement.yml body-gate parity."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # no PyYAML stubs in the hook environment

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "rule-enforcement.yml"
DEFAULT_WRAPPER = ROOT / "scripts" / "ci" / "pr-body-gates.sh"
BASH = shutil.which("bash") or "/bin/bash"
GIT = shutil.which("git") or "/usr/bin/git"
SUBPROCESS_TIMEOUT_S = 60
RC_OK = 0
RC_FAIL = 1
RC_USAGE = 2
STUB_EXIT_THREE = 3
BODY_STEP_SCRIPT_RE = re.compile(r"\bbash\s+scripts/ci/([A-Za-z0-9_.-]+\.sh)\b")
GATES_ARRAY_RE = re.compile(r"(?m)^GATES=\(([^)]*)\)")
CLEAN_ENV = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}


def _isolated_env() -> dict[str, str]:
    env: dict[str, str] = {
        **CLEAN_ENV,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for key in ("PR_TITLE", "PR_BODY", "BASE_SHA", "HEAD_SHA", "PR_BODY_GATES_DIR"):
        env.pop(key, None)
    return env


def _head_sha() -> str:
    done = subprocess.run(  # noqa: S603  # nosec B603
        [GIT, "rev-parse", "HEAD"],
        cwd=ROOT,
        env=_isolated_env(),
        capture_output=True,
        text=True,
        check=True,
        timeout=SUBPROCESS_TIMEOUT_S,
    )
    return done.stdout.strip()


def _wrapper_path() -> Path:
    override = os.environ.get("PR_BODY_GATES_WRAPPER")
    return Path(override) if override else DEFAULT_WRAPPER


def _run_wrapper(
    *,
    title: str | None,
    body: str | None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    gates_dir: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = _isolated_env()
    if title is not None:
        env["PR_TITLE"] = title
    if body is not None:
        env["PR_BODY"] = body
    if base_sha is not None:
        env["BASE_SHA"] = base_sha
    if head_sha is not None:
        env["HEAD_SHA"] = head_sha
    if gates_dir is not None:
        env["PR_BODY_GATES_DIR"] = str(gates_dir)
    return subprocess.run(  # noqa: S603  # nosec B603
        [BASH, str(_wrapper_path())],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=SUBPROCESS_TIMEOUT_S,
    )


def _step_body_gates(step: object, job_env: dict[str, Any]) -> list[str]:
    if not isinstance(step, dict):
        return []
    raw_env = step.get("env")
    step_env = raw_env if isinstance(raw_env, dict) else {}
    merged_env = {**job_env, **step_env}
    run_cmd = step.get("run")
    if "PR_BODY" in merged_env and isinstance(run_cmd, str):
        return BODY_STEP_SCRIPT_RE.findall(run_cmd)
    return []


def collect_workflow_body_gates(workflow_doc: dict[str, Any]) -> set[str]:
    """Collect scripts/ci/<name>.sh steps whose env defines PR_BODY."""
    found: set[str] = set()
    jobs = workflow_doc.get("jobs")
    if not isinstance(jobs, dict):
        return found
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        raw_job_env = job.get("env")
        job_env = raw_job_env if isinstance(raw_job_env, dict) else {}
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                found.update(_step_body_gates(step, job_env))
    return found


def parse_wrapper_gates(wrapper_text: str) -> list[str]:
    """Read the fixed GATES=(...) array from scripts/ci/pr-body-gates.sh."""
    match = GATES_ARRAY_RE.search(wrapper_text)
    assert match is not None, "GATES=(...) array missing in pr-body-gates.sh"
    return shlex.split(match.group(1), comments=True)


def _write_stubs(directory: Path, codes: dict[str, int]) -> None:
    for name, code in codes.items():
        script = directory / name
        script.write_text(
            f"#!/usr/bin/env bash\necho {name}\nexit {code}\n",
            encoding="utf-8",
        )
        script.chmod(0o755)


def test_t1_workflow_parity() -> None:
    """Every rule-enforcement.yml PR_BODY shell gate has a local mirror in GATES."""
    workflow_doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow_doc, dict)
    workflow_gates = collect_workflow_body_gates(workflow_doc)
    wrapper_gates = parse_wrapper_gates(DEFAULT_WRAPPER.read_text(encoding="utf-8"))
    assert len(wrapper_gates) == len(set(wrapper_gates))
    assert workflow_gates == set(wrapper_gates)

    synthetic_doc: dict[str, Any] = {
        "jobs": {
            "unmirrored": {
                "steps": [
                    {
                        "env": {"PR_BODY": "${{ github.event.pull_request.body }}"},
                        "run": "bash scripts/ci/unmirrored-body-gate.sh",
                    }
                ]
            }
        }
    }
    assert collect_workflow_body_gates(synthetic_doc) | workflow_gates != set(wrapper_gates)


def test_t2_planted_bug_shaped_pr_without_state_delta_fails() -> None:
    """Real wrapper runs state-md-touch-check.sh and reports rc 1 on fix: without state delta."""
    sha = _head_sha()
    res = _run_wrapper(
        title="fix: planted",
        body="planted body",
        base_sha=sha,
        head_sha=sha,
    )
    assert res.returncode != RC_OK
    assert "pr-body-gates: state-md-touch-check.sh rc 1" in res.stdout.splitlines()


def test_t3_negative_control_state_md_passes() -> None:
    """Real wrapper reports state-md-touch-check.sh rc 0 when title is ci: with opt-out."""
    sha = _head_sha()
    res = _run_wrapper(
        title="ci: planted",
        body="no state delta: planted",
        base_sha=sha,
        head_sha=sha,
    )
    assert "pr-body-gates: state-md-touch-check.sh rc 0" in res.stdout.splitlines()


def test_t4_no_early_stop_runs_all_gates(tmp_path: Path) -> None:
    """First stub gate exiting 1 does not stop subsequent gates; wrapper exits 1."""
    _write_stubs(
        tmp_path,
        {
            "deliverables-check.sh": RC_FAIL,
            "state-md-touch-check.sh": RC_OK,
            "ffmpeg-patches-surface-check.sh": RC_OK,
        },
    )
    res = _run_wrapper(title="ci: stub", body="stub", gates_dir=tmp_path)
    lines = res.stdout.splitlines()
    assert res.returncode == RC_FAIL
    for echoed in (
        "deliverables-check.sh",
        "state-md-touch-check.sh",
        "ffmpeg-patches-surface-check.sh",
        "pr-body-gates: deliverables-check.sh rc 1",
        "pr-body-gates: state-md-touch-check.sh rc 0",
        "pr-body-gates: ffmpeg-patches-surface-check.sh rc 0",
    ):
        assert echoed in lines


def test_t5_boundary_exit_codes_and_missing_title(tmp_path: Path) -> None:
    """Stub gate exiting >2 maps to wrapper rc 2; unset PR_TITLE exits 2; empty PR_BODY works."""
    _write_stubs(
        tmp_path,
        {
            "deliverables-check.sh": RC_FAIL,
            "state-md-touch-check.sh": STUB_EXIT_THREE,
            "ffmpeg-patches-surface-check.sh": RC_OK,
        },
    )
    high_rc = _run_wrapper(title="ci: stub", body="stub", gates_dir=tmp_path)
    assert high_rc.returncode == RC_USAGE
    assert "pr-body-gates: state-md-touch-check.sh rc 3" in high_rc.stdout.splitlines()

    missing_title = _run_wrapper(title=None, body="stub", gates_dir=tmp_path)
    assert missing_title.returncode == RC_USAGE
    assert "Usage:" in missing_title.stderr

    missing_body = _run_wrapper(title="ci: stub", body=None, gates_dir=tmp_path)
    assert missing_body.returncode == RC_USAGE

    _write_stubs(
        tmp_path,
        {
            "deliverables-check.sh": RC_OK,
            "state-md-touch-check.sh": RC_OK,
            "ffmpeg-patches-surface-check.sh": RC_OK,
        },
    )
    empty_body = _run_wrapper(title="ci: stub", body="", gates_dir=tmp_path)
    assert empty_body.returncode == RC_OK
