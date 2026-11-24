# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Tests for scripts/ci/ffmpeg-patches-surface-check.sh (Issue #2435, ADR-2166)."""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]  # PyYAML ships no stubs in the hook env, as in test_clang_format_scope.py

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from scripts.lib.safe_subprocess import TextCommandResult  # noqa: E402
from scripts.lib.safe_subprocess import run as run_command  # noqa: E402

SCRIPT = ROOT / "scripts" / "ci" / "ffmpeg-patches-surface-check.sh"
HOOK_ID = "ffmpeg-patches-surface-docs"
SURFACE_ONLY_DONE_LINE = "--surface-only: tree checks passed"
GIT_TIMEOUT_S = 60
SCRIPT_TIMEOUT_S = 300
PROBE_SYMBOL = "vmaf_fixture_surface_probe"
PROBE_HEADER_REL = "core/include/libvmaf/fixture_probe.h"
PROBE_PATCH_REL = "ffmpeg-patches/0001-pass-autotune-cli-glue.patch"
PROBE_HEADER_WITH_SYM = (
    "#ifndef VMAF_FIXTURE_PROBE_H_\n"
    "#define VMAF_FIXTURE_PROBE_H_\n"
    f"int {PROBE_SYMBOL}(void);\n"
    "#endif\n"
)
PROBE_HEADER_WITHOUT_SYM = "#ifndef VMAF_FIXTURE_PROBE_H_\n#define VMAF_FIXTURE_PROBE_H_\n#endif\n"


def _clean_env(**extra: str) -> dict[str, str]:
    """Return the caller environment without GIT_* and with a fixture-only identity."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    env.update(extra)
    return env


def _tool(name: str) -> str:
    """Return the absolute path of a tool, or skip when it is absent."""
    path = shutil.which(name)
    if path is None:
        raise unittest.SkipTest(f"{name} is not on PATH")
    return path


def _git(repo: Path, *args: str) -> None:
    """Run git in a fixture repository with the clean environment."""
    git = _tool("git")
    run_command(
        [git, "-C", str(repo), *args],
        allowed_executables=[git],
        check=True,
        env=_clean_env(),
        capture_output=True,
        timeout_seconds=GIT_TIMEOUT_S,
    )


def _rev_parse(repo: Path, rev: str) -> str:
    """Resolve a git revision in a fixture repository."""
    git = _tool("git")
    res = run_command(
        [git, "-C", str(repo), "rev-parse", rev],
        allowed_executables=[git],
        check=True,
        env=_clean_env(),
        capture_output=True,
        text=True,
        timeout_seconds=GIT_TIMEOUT_S,
    )
    return res.stdout.strip()


def _run_script(script: Path, cwd: Path, *args: str, **extra: str) -> TextCommandResult:
    """Run the surface check script with bash, the only executable allowed."""
    bash = _tool("bash")
    return run_command(
        [bash, str(script), *args],
        allowed_executables=[bash],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=_clean_env(**extra),
        timeout_seconds=SCRIPT_TIMEOUT_S,
    )


class _FixtureTree:
    """Build the temporary fixture repository both test classes run the script in."""

    def _prepare_temp_worktree(self, temp_dir: Path, *, origin_master: bool = True) -> Path:
        """Stage a minimal fixture tree with the three surfaces and script."""
        # Copy ffmpeg-patches
        shutil.copytree(ROOT / "ffmpeg-patches", temp_dir / "ffmpeg-patches")
        # Copy scripts/ci needed by script
        (temp_dir / "scripts" / "ci").mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPT, temp_dir / "scripts" / "ci" / SCRIPT.name)
        for helper in ("pr-body-input.sh", "pr-diff-base.sh"):
            src = ROOT / "scripts" / "ci" / helper
            if src.is_file():
                shutil.copy(src, temp_dir / "scripts" / "ci" / helper)
        # Copy allow-listed build configs
        for rel in (
            "Containerfile.vmafx",
            "Dockerfile",
            "Dockerfile.ffmpeg",
            "dev/Containerfile",
            "docker/Dockerfile.node",
            "scripts/test/sycl-dev-container.sh",
            ".github/workflows/ffmpeg-patch-stack.yml",
            "scripts/ci/tidy-integrations-build.sh",
        ):
            src = ROOT / rel
            if src.is_file():
                dst = temp_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, dst)
        # Copy allow-listed doc files
        for rel in (
            "README.md",
            "docs/reference/faq.md",
            "docs/adr/0000-template.md",
            "docs/usage/ffmpeg.md",
            "docs/usage/vmaf-tune-ffmpeg.md",
            "docs/usage/vmaf-tune-codec-adapters.md",
            "docs/usage/vmaf-vpl.md",
            "docs/development/sycl-zerocopy-testing.md",
            "docs/ai/inference.md",
            "docs/ai/model-registry.md",
            "docs/ai/roadmap.md",
            "docs/ai/models/fastdvdnet_pre.md",
            "docs/ai/models/learned_filter_v1.md",
            "docs/api/dnn.md",
            "docs/api/models-and-features.md",
        ):
            src = ROOT / rel
            if src.is_file():
                dst = temp_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, dst)

        # A fixture repository so origin/master exists for diff base resolution.
        _git(temp_dir, "init", "-q", "-b", "master")
        _git(temp_dir, "add", ".")
        _git(temp_dir, "commit", "-q", "-m", "init")
        if origin_master:
            _git(temp_dir, "update-ref", "refs/remotes/origin/master", "HEAD")
        return temp_dir


class FfmpegPatchesSurfaceCheckTests(_FixtureTree, unittest.TestCase):
    """Verify surface invariant checks on series, build configs, and docs."""

    def test_positive_on_clean_tree(self) -> None:
        """On clean worktree, surface checks and public-surface gate pass."""
        res = _run_script(SCRIPT, ROOT)
        self.assertEqual(
            res.returncode,
            0,
            f"Expected exit 0 on clean tree, got {res.returncode}.\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}",
        )
        self.assertIn("series surface: zero vmaf-named filters/options", res.stdout)
        self.assertIn("fork build configs: zero retired filters/options", res.stdout)
        self.assertIn("docs examples: zero retired filters/options", res.stdout)
        self.assertIn("patch tests: zero retired filters/options", res.stdout)
        self.assertRegex(res.stdout, r"across [1-9][0-9]* scanned doc files")

    def test_planted_negative_series_surface(self) -> None:
        """Planted vmaf_pre in a patch causes series surface check failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td))
            target_patch = tmp / "ffmpeg-patches" / "0004-add-vmafx-pre-filter.patch"
            with target_patch.open("a", encoding="utf-8") as fp:
                fp.write("\n+/* planted defect: vmaf_pre filter */\n")

            res = _run_script(tmp / "scripts" / "ci" / SCRIPT.name, tmp, REPO_ROOT=str(tmp))
            self.assertNotEqual(res.returncode, 0, "Expected non-zero exit code")
            self.assertIn("patch carries retired vmaf filter/option", res.stderr)

    def test_planted_negative_fork_build_config_surface(self) -> None:
        """Planted vmaf_pre in a build config causes config check failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td))
            target_cfg = tmp / "Containerfile.vmafx"
            with target_cfg.open("a", encoding="utf-8") as fp:
                fp.write("\n# planted defect: enable vmaf_pre filter\n")

            res = _run_script(tmp / "scripts" / "ci" / SCRIPT.name, tmp, REPO_ROOT=str(tmp))
            self.assertNotEqual(res.returncode, 0, "Expected non-zero exit code")
            self.assertIn("fork build config references retired filter/option", res.stderr)

    def test_planted_negative_docs_examples_surface(self) -> None:
        """Planted vmaf_pre in docs outside migration guide causes doc check failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td))
            target_doc = tmp / "docs" / "usage" / "vmaf-tune-ffmpeg.md"
            with target_doc.open("a", encoding="utf-8") as fp:
                fp.write("\nPlanted defect: use vmaf_pre in the graph.\n")

            res = _run_script(tmp / "scripts" / "ci" / SCRIPT.name, tmp, REPO_ROOT=str(tmp))
            self.assertNotEqual(res.returncode, 0, "Expected non-zero exit code")
            self.assertIn("retired filter/option in doc", res.stderr)

    def test_planted_doc_outside_old_list_fails(self) -> None:
        """Planted libvmaf_cuda in a doc outside old allow-list fails check."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td))
            target_doc = tmp / "docs" / "reference" / "faq.md"
            with target_doc.open("a", encoding="utf-8") as fp:
                fp.write("\nPlanted defect: run libvmaf_cuda filter here.\n")

            res = _run_script(tmp / "scripts" / "ci" / SCRIPT.name, tmp, REPO_ROOT=str(tmp))
            self.assertNotEqual(res.returncode, 0, "Expected non-zero exit code")
            self.assertIn("retired filter/option in doc", res.stderr)

    def test_planted_doc_in_adr_passes(self) -> None:
        """Planted libvmaf_cuda in docs/adr is excluded and passes check."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td))
            target_adr = tmp / "docs" / "adr" / "0000-template.md"
            with target_adr.open("a", encoding="utf-8") as fp:
                fp.write("\nHistorical context: libvmaf_cuda filter was used previously.\n")

            res = _run_script(tmp / "scripts" / "ci" / SCRIPT.name, tmp, REPO_ROOT=str(tmp))
            self.assertEqual(
                res.returncode,
                0,
                f"Expected exit 0 for docs/adr, got {res.returncode}.\nstderr:\n{res.stderr}",
            )
            self.assertIn("docs examples: zero retired filters/options", res.stdout)

    def test_planted_negative_patch_test_surface(self) -> None:
        """Planted libvmaf_sycl= filter in a patch test script fails surface check."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td))
            target_script = tmp / "ffmpeg-patches" / "test" / "check-sycl-feature-routing.sh"
            with target_script.open("a", encoding="utf-8") as fp:
                fp.write(
                    "\n# planted defect:\n# -filter_complex '[0:v][1:v]libvmaf_sycl=threads=1'\n"
                )

            res = _run_script(tmp / "scripts" / "ci" / SCRIPT.name, tmp, REPO_ROOT=str(tmp))
            self.assertNotEqual(res.returncode, 0, "Expected non-zero exit code")
            self.assertIn("patch test carries retired filter/option", res.stderr)


class SurfaceOnlyModeTests(_FixtureTree, unittest.TestCase):
    """Verify the --surface-only mode the pre-commit hook runs."""

    def test_surface_only_passes_without_origin_master(self) -> None:
        """A checkout without origin/master passes the tree checks; the full gate cannot."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            script = tmp / "scripts" / "ci" / SCRIPT.name

            res = _run_script(script, tmp, "--surface-only", REPO_ROOT=str(tmp))
            self.assertEqual(res.returncode, 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn(SURFACE_ONLY_DONE_LINE, res.stdout)
            self.assertNotIn("tree checks read HEAD_SHA", res.stdout)
            self.assertNotIn("PR body from", res.stdout)

            full = _run_script(script, tmp, REPO_ROOT=str(tmp))
            self.assertEqual(full.returncode, 2, f"stderr:\n{full.stderr}")
            self.assertIn("origin/master not found", full.stderr)

    def test_surface_only_fails_on_planted_doc(self) -> None:
        """A retired filter in a doc fails the tree checks in --surface-only mode too."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            target_doc = tmp / "docs" / "usage" / "vmaf-tune-ffmpeg.md"
            with target_doc.open("a", encoding="utf-8") as fp:
                fp.write("\nPlanted defect: use vmaf_pre in the graph.\n")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name, tmp, "--surface-only", REPO_ROOT=str(tmp)
            )
            self.assertEqual(res.returncode, 1, f"stderr:\n{res.stderr}")
            self.assertIn("retired filter/option in doc", res.stderr)
            self.assertNotIn(SURFACE_ONLY_DONE_LINE, res.stdout)

    def test_surface_only_fails_on_planted_patch_test(self) -> None:
        """Planted libvmaf_sycl= in patch test fails in --surface-only mode."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            target_script = tmp / "ffmpeg-patches" / "test" / "check-sycl-feature-routing.sh"
            with target_script.open("a", encoding="utf-8") as fp:
                fp.write(
                    "\n# planted defect:\n# -filter_complex '[0:v][1:v]libvmaf_sycl=threads=1'\n"
                )

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name, tmp, "--surface-only", REPO_ROOT=str(tmp)
            )
            self.assertEqual(res.returncode, 1, f"stderr:\n{res.stderr}")
            self.assertIn("patch test carries retired filter/option", res.stderr)
            self.assertNotIn(SURFACE_ONLY_DONE_LINE, res.stdout)

    def test_surface_only_fails_when_zero_docs_scanned(self) -> None:
        """Zero doc files scanned in fixture tree fails surface check."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            shutil.rmtree(tmp / "docs", ignore_errors=True)
            (tmp / "README.md").unlink(missing_ok=True)
            (tmp / "ffmpeg-patches" / "README.md").unlink(missing_ok=True)
            _git(tmp, "add", "-A")
            _git(tmp, "commit", "-q", "-m", "remove docs")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name, tmp, "--surface-only", REPO_ROOT=str(tmp)
            )
            self.assertEqual(res.returncode, 1, f"stderr:\n{res.stderr}")
            self.assertIn("zero doc files scanned", res.stderr)
            self.assertNotIn(SURFACE_ONLY_DONE_LINE, res.stdout)

    def test_surface_only_fails_when_doc_listing_fails(self) -> None:
        """A git ls-files failure (corrupt index) is named, never read as an empty doc list."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            (tmp / ".git" / "index").write_bytes(b"not an index")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name, tmp, "--surface-only", REPO_ROOT=str(tmp)
            )
            self.assertEqual(res.returncode, 1, f"stderr:\n{res.stderr}")
            self.assertIn("[FAIL] cannot list docs", res.stderr)
            self.assertNotIn("zero doc files scanned", res.stderr)
            self.assertNotIn(SURFACE_ONLY_DONE_LINE, res.stdout)

    def test_surface_only_fails_when_find_listing_fails_outside_git(self) -> None:
        """Outside a git tree, a find error on one doc root fails closed, not as a partial list."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            shutil.rmtree(tmp / ".git")
            (tmp / "ffmpeg-patches" / "README.md").unlink()

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name, tmp, "--surface-only", REPO_ROOT=str(tmp)
            )
            self.assertEqual(res.returncode, 1, f"stderr:\n{res.stderr}")
            self.assertIn("[FAIL] cannot list docs", res.stderr)
            self.assertNotIn(SURFACE_ONLY_DONE_LINE, res.stdout)

    def test_bash_32_contract_no_mapfile_or_readarray(self) -> None:
        """Script must not use mapfile or readarray because macOS bash 3.2 lacks them."""
        content = SCRIPT.read_text(encoding="utf-8")
        for lineno, line in enumerate(content.splitlines(), start=1):
            code_only = line.split("#", 1)[0]
            for token in ("mapfile", "readarray"):
                self.assertNotIn(
                    token,
                    code_only,
                    f"Line {lineno} violates bash 3.2 compatibility by using '{token}': {line}",
                )

    def test_bash_32_contract_array_loops_survive_empty_arrays(self) -> None:
        """Bash 3.2 under set -u aborts on "${a[@]}" when a is empty, so every loop is guarded."""
        content = SCRIPT.read_text(encoding="utf-8")
        loops = re.findall(r'for \w+ in "\$\{(\w+)\[@\]\}"', content)
        self.assertTrue(loops, "no array loops found; the pattern no longer matches the script")
        for name in loops:
            count_guard = f'"${{#{name}[@]}}" -eq 0'
            # A quoted first element followed by whitespace or ")" is a literal, never a glob.
            literal_list = re.search(rf'\b{name}=\(\s*"[^"]*"(?=[\s)])', content)
            self.assertTrue(
                count_guard in content or literal_list,
                f'loop over "${{{name}[@]}}" has no empty-array guard; use ${{{name}[@]+"${{{name}[@]}}"}}',
            )

    def test_bad_arguments_exit_two(self) -> None:
        """An unknown option or a second argument is a usage error, never a pass."""
        cases = {
            "unknown option": ("--surface",),
            "second argument": ("--surface-only", "--surface-only"),
        }
        for label, args in cases.items():
            with self.subTest(label):
                res = _run_script(SCRIPT, ROOT, *args)
                self.assertEqual(res.returncode, 2, f"stderr:\n{res.stderr}")
                self.assertIn("the only option is --surface-only", res.stderr)
                self.assertNotIn("[PASS]", res.stdout)

    def test_hook_runs_surface_only_on_every_tree_check_input(self) -> None:
        """The hook runs --surface-only, and its files pattern covers every path the checks read."""
        config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
        hooks = [
            hook
            for repo in config.get("repos") or []
            for hook in repo.get("hooks") or []
            if hook.get("id") == HOOK_ID
        ]
        self.assertEqual(len(hooks), 1, f"expected one {HOOK_ID} hook")
        hook = hooks[0]
        self.assertEqual(
            hook["entry"], "bash scripts/ci/ffmpeg-patches-surface-check.sh --surface-only"
        )
        files = re.compile(hook["files"])

        body = SCRIPT.read_text(encoding="utf-8")
        block = re.search(r"^FORK_BUILD_CONFIGS=\(\n(.*?)\n\)", body, re.M | re.S)
        self.assertIsNotNone(block, "configs=( ... ) list not found in the script")
        assert block is not None
        configs = re.findall(r'"([^"]+)"', block.group(1))
        self.assertGreaterEqual(len(configs), 9)
        read_paths = [
            *configs,
            "README.md",
            "docs/usage/ffmpeg.md",
            "ffmpeg-patches/README.md",
            "ffmpeg-patches/0001-example.patch",
            "ffmpeg-patches/test/build-and-run.sh",
            "scripts/ci/ffmpeg-patches-surface-check.sh",
        ]
        for path in read_paths:
            with self.subTest(read=path):
                self.assertIsNotNone(files.search(path), f"{path} does not trigger {HOOK_ID}")
        for path in ("core/src/libvmaf.c", "docs/usage/ffmpeg.txt", "Dockerfile.node"):
            with self.subTest(unread=path):
                self.assertIsNone(files.search(path), f"{path} triggers {HOOK_ID}")


class HeadRevisionConsumedSetTests(_FixtureTree, unittest.TestCase):
    """Verify section 4 builds the consumed symbol set from HEAD_SHA, not the checkout."""

    def _stage_probe_base(self, td: str) -> tuple[Path, Path, Path, str, str]:
        """Create a base commit whose public header declares a symbol a patch consumes."""
        tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
        header = tmp / PROBE_HEADER_REL
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(PROBE_HEADER_WITH_SYM, encoding="utf-8")
        patch = tmp / PROBE_PATCH_REL
        orig_patch = patch.read_text(encoding="utf-8")
        patch.write_text(f"{orig_patch}\n+    ret = {PROBE_SYMBOL}();\n", encoding="utf-8")
        _git(tmp, "add", ".")
        _git(tmp, "commit", "-q", "-m", "base with probe symbol")
        return tmp, header, patch, orig_patch, _rev_parse(tmp, "HEAD")

    def test_consumed_set_reads_head_sha_not_working_tree(self) -> None:
        """Uncommitted working-tree patch edit cannot hide a symbol still consumed at HEAD_SHA."""
        with tempfile.TemporaryDirectory() as td:
            tmp, header, patch, orig_patch, base_sha = self._stage_probe_base(td)
            header.write_text(PROBE_HEADER_WITHOUT_SYM, encoding="utf-8")
            _git(tmp, "add", PROBE_HEADER_REL)
            _git(tmp, "commit", "-q", "-m", "remove probe declaration without patch update")
            head_sha = _rev_parse(tmp, "HEAD")
            patch.write_text(orig_patch, encoding="utf-8")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name,
                tmp,
                REPO_ROOT=str(tmp),
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
            )
            self.assertEqual(res.returncode, 1, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn("::error title=Agent hard rule 11::", res.stdout)
            self.assertIn(PROBE_SYMBOL, res.stdout)

    def test_consumed_set_boundary_head_commit_updates_patch(self) -> None:
        """Removing the header declaration passes when the head commit also edits the patch."""
        with tempfile.TemporaryDirectory() as td:
            tmp, header, patch, orig_patch, base_sha = self._stage_probe_base(td)
            header.write_text(PROBE_HEADER_WITHOUT_SYM, encoding="utf-8")
            patch.write_text(orig_patch, encoding="utf-8")
            _git(tmp, "add", PROBE_HEADER_REL, PROBE_PATCH_REL)
            _git(tmp, "commit", "-q", "-m", "remove probe declaration and update patch")
            head_sha = _rev_parse(tmp, "HEAD")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name,
                tmp,
                REPO_ROOT=str(tmp),
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
            )
            self.assertEqual(res.returncode, 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")

    def test_consumed_set_zero_patches_at_head_sha(self) -> None:
        """Zero patches at HEAD: HEAD_SHA set fails sec 0; HEAD_SHA unset hits sec 4 exit 0."""
        with tempfile.TemporaryDirectory() as td:
            tmp, header, _patch, _orig_patch, base_sha = self._stage_probe_base(td)
            _git(tmp, "update-ref", "refs/remotes/origin/master", base_sha)
            header.write_text(PROBE_HEADER_WITHOUT_SYM, encoding="utf-8")
            for p in (tmp / "ffmpeg-patches").glob("*.patch"):
                p.unlink()
            _git(tmp, "add", "-A")
            _git(tmp, "commit", "-q", "-m", "drop patches at head")
            head_sha = _rev_parse(tmp, "HEAD")
            for src in (ROOT / "ffmpeg-patches").glob("*.patch"):
                shutil.copy(src, tmp / "ffmpeg-patches" / src.name)
            script = tmp / "scripts" / "ci" / SCRIPT.name

            with self.subTest(mode="head_sha_set"):
                res = _run_script(
                    script,
                    tmp,
                    REPO_ROOT=str(tmp),
                    BASE_SHA=base_sha,
                    HEAD_SHA=head_sha,
                    PR_BODY="",
                )
                self.assertEqual(res.returncode, 1, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
                self.assertIn("no patches found", res.stderr)
                self.assertNotIn("[PASS]", res.stdout)

            with self.subTest(mode="head_sha_unset"):
                res = _run_script(
                    script,
                    tmp,
                    REPO_ROOT=str(tmp),
                    BASE_SHA=base_sha,
                    PR_BODY="",
                )
                self.assertEqual(res.returncode, 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
                self.assertIn("missing; nothing to check", res.stderr)

    def test_consumed_set_from_subdirectory_exits_one(self) -> None:
        """Running from a subdirectory still reads patches and header diff from tree root."""
        with tempfile.TemporaryDirectory() as td:
            tmp, header, patch, orig_patch, base_sha = self._stage_probe_base(td)
            header.write_text(PROBE_HEADER_WITHOUT_SYM, encoding="utf-8")
            _git(tmp, "add", PROBE_HEADER_REL)
            _git(tmp, "commit", "-q", "-m", "remove probe declaration without patch update")
            head_sha = _rev_parse(tmp, "HEAD")
            patch.write_text(orig_patch, encoding="utf-8")
            subdir = tmp / "core"
            script = (tmp / "scripts" / "ci" / SCRIPT.name).resolve()
            self.assertTrue(subdir.is_dir())
            self.assertTrue(script.is_absolute())

            res = _run_script(
                script,
                subdir,
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
            )
            self.assertEqual(res.returncode, 1, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn("::error title=Agent hard rule 11::", res.stdout)
            self.assertIn(PROBE_SYMBOL, res.stdout)

    def test_consumed_set_negative_missing_head_or_blob_exits_two(self) -> None:
        """With HEAD_SHA set, missing HEAD_SHA or missing patch blob/tree fails in section 0."""
        with tempfile.TemporaryDirectory() as td:
            tmp, header, _patch, _orig_patch, base_sha = self._stage_probe_base(td)
            script = tmp / "scripts" / "ci" / SCRIPT.name
            missing_sha = "deadbeef" * 5
            with self.subTest(expected="cannot resolve HEAD_SHA"):
                res = _run_script(
                    script,
                    tmp,
                    REPO_ROOT=str(tmp),
                    BASE_SHA=base_sha,
                    HEAD_SHA=missing_sha,
                    PR_BODY="",
                )
                self.assertEqual(res.returncode, 2, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
                self.assertEqual(len(res.stderr.splitlines()), 1, f"stderr:\n{res.stderr}")
                self.assertIn("ffmpeg-patches-surface-check: cannot resolve HEAD_SHA", res.stderr)
                self.assertIn(missing_sha, res.stderr)

            header.write_text(PROBE_HEADER_WITHOUT_SYM, encoding="utf-8")
            _git(tmp, "add", PROBE_HEADER_REL)
            _git(tmp, "commit", "-q", "-m", "remove probe declaration")
            head_sha = _rev_parse(tmp, "HEAD")
            tree_sha = _rev_parse(tmp, f"{head_sha}:ffmpeg-patches")
            self.assertEqual(tree_sha, _rev_parse(tmp, f"{base_sha}:ffmpeg-patches"))
            blob_sha = _rev_parse(tmp, f"{head_sha}:{PROBE_PATCH_REL}")

            for obj_sha, expected_msg in (
                (blob_sha, "cannot extract surface inputs at"),
                (tree_sha, "cannot list surface inputs at"),
            ):
                with self.subTest(expected=expected_msg):
                    (tmp / ".git" / "objects" / obj_sha[:2] / obj_sha[2:]).unlink()
                    bad = _run_script(
                        script,
                        tmp,
                        REPO_ROOT=str(tmp),
                        BASE_SHA=base_sha,
                        HEAD_SHA=head_sha,
                        PR_BODY="",
                    )
                    self.assertEqual(
                        bad.returncode, 2, f"stdout:\n{bad.stdout}\nstderr:\n{bad.stderr}"
                    )
                    err_lines = bad.stderr.strip().splitlines()
                    self.assertEqual(len(err_lines), 1, f"stderr:\n{bad.stderr}")
                    self.assertTrue(err_lines[0].startswith("ffmpeg-patches-surface-check:"))
                    self.assertIn(expected_msg, err_lines[0])
                    self.assertIn(head_sha, err_lines[0])

    def test_consumed_set_negative_sec4_without_head_sha_exits_two(self) -> None:
        """With HEAD_SHA unset, missing patch blob or tree fails in section 4 (exit 2)."""
        with tempfile.TemporaryDirectory() as td:
            tmp, header, _patch, _orig_patch, base_sha = self._stage_probe_base(td)
            _git(tmp, "update-ref", "refs/remotes/origin/master", base_sha)
            header.write_text(PROBE_HEADER_WITHOUT_SYM, encoding="utf-8")
            _git(tmp, "add", PROBE_HEADER_REL)
            _git(tmp, "commit", "-q", "-m", "drop probe symbol on head branch")
            blob_sha = _rev_parse(tmp, f"HEAD:{PROBE_PATCH_REL}")
            tree_sha = _rev_parse(tmp, "HEAD:ffmpeg-patches")
            script = tmp / "scripts" / "ci" / SCRIPT.name

            for label, missing_oid, sec4_msg in (
                ("blob", blob_sha, "cannot read ffmpeg-patches/"),
                ("tree", tree_sha, "cannot list ffmpeg-patches/ at HEAD"),
            ):
                with self.subTest(deleted=label):
                    (tmp / ".git" / "objects" / missing_oid[:2] / missing_oid[2:]).unlink()
                    res = _run_script(script, tmp, REPO_ROOT=str(tmp), PR_BODY="")
                    self.assertEqual(
                        res.returncode, 2, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
                    )
                    stderr_lines = res.stderr.splitlines()
                    self.assertEqual(len(stderr_lines), 1, f"stderr:\n{res.stderr}")
                    self.assertTrue(stderr_lines[0].startswith("ffmpeg-patches-surface-check:"))
                    self.assertIn(sec4_msg, stderr_lines[0])
                    self.assertIn("at HEAD.", stderr_lines[0])


class HeadRevisionTreeChecksTests(_FixtureTree, unittest.TestCase):
    """Verify section 0 reads the HEAD_SHA tree (not checkout) when HEAD_SHA is set."""

    def test_head_tree_retired_doc_fails_when_checkout_restored(self) -> None:
        """Retired filter at HEAD_SHA fails section 0 even when checkout restores clean doc."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            base_sha = _rev_parse(tmp, "HEAD")
            faq = tmp / "docs" / "reference" / "faq.md"
            base_text = faq.read_text(encoding="utf-8")
            faq.write_text(
                f"{base_text}\nPlanted retired option: libvmaf_tune.\n",
                encoding="utf-8",
            )
            _git(tmp, "add", "docs/reference/faq.md")
            _git(tmp, "commit", "-q", "-m", "add retired filter to faq")
            head_sha = _rev_parse(tmp, "HEAD")
            faq.write_text(base_text, encoding="utf-8")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name,
                tmp,
                REPO_ROOT=str(tmp),
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
            )
            self.assertEqual(res.returncode, 1, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn("tree checks read HEAD_SHA", res.stdout)
            self.assertIn(head_sha, res.stdout)
            self.assertIn(
                "ffmpeg-patches-surface-check: [FAIL] retired filter/option in doc docs/reference/faq.md:",
                res.stderr,
            )
            self.assertIn("libvmaf_tune", res.stderr)

    def test_head_tree_clean_passes_with_uncommitted_checkout_defect(self) -> None:
        """Uncommitted retired filter in checkout does not fail when HEAD_SHA tree is clean."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            base_sha = _rev_parse(tmp, "HEAD")
            readme = tmp / "README.md"
            readme.write_text(
                f"{readme.read_text(encoding='utf-8')}\nHarmless README note.\n",
                encoding="utf-8",
            )
            _git(tmp, "add", "README.md")
            _git(tmp, "commit", "-q", "-m", "harmless readme update")
            head_sha = _rev_parse(tmp, "HEAD")
            faq = tmp / "docs" / "reference" / "faq.md"
            faq.write_text(
                f"{faq.read_text(encoding='utf-8')}\nUncommitted: libvmaf_tune.\n",
                encoding="utf-8",
            )

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name,
                tmp,
                REPO_ROOT=str(tmp),
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
            )
            self.assertEqual(res.returncode, 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn(
                "ffmpeg-patches-surface-check: [PASS] docs examples: zero retired filters/options",
                res.stdout,
            )

    def test_head_tree_boundary_deleted_build_config_passes(self) -> None:
        """Deleting an allow-listed fork build config at HEAD_SHA skips it on export and passes."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            base_sha = _rev_parse(tmp, "HEAD")
            _git(tmp, "rm", "-q", "Dockerfile.ffmpeg")
            _git(tmp, "commit", "-q", "-m", "remove Dockerfile.ffmpeg")
            head_sha = _rev_parse(tmp, "HEAD")

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name,
                tmp,
                REPO_ROOT=str(tmp),
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
            )
            self.assertEqual(res.returncode, 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn("fork build configs: zero retired filters/options", res.stdout)

    def test_head_tree_tmpdir_inside_worktree_uses_find(self) -> None:
        """Temp export dir under TMPDIR inside a git worktree still lists docs via find."""
        with tempfile.TemporaryDirectory() as td:
            tmp = self._prepare_temp_worktree(Path(td), origin_master=False)
            base_sha = _rev_parse(tmp, "HEAD")
            readme = tmp / "README.md"
            readme.write_text(
                f"{readme.read_text(encoding='utf-8')}\nHarmless note.\n",
                encoding="utf-8",
            )
            _git(tmp, "add", "README.md")
            _git(tmp, "commit", "-q", "-m", "readme note")
            head_sha = _rev_parse(tmp, "HEAD")
            nested_tmpdir = tmp / "nested-tmp"
            nested_tmpdir.mkdir()

            res = _run_script(
                tmp / "scripts" / "ci" / SCRIPT.name,
                tmp,
                REPO_ROOT=str(tmp),
                BASE_SHA=base_sha,
                HEAD_SHA=head_sha,
                PR_BODY="",
                TMPDIR=str(nested_tmpdir),
            )
            self.assertEqual(res.returncode, 0, f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}")
            self.assertIn(
                "ffmpeg-patches-surface-check: [PASS] docs examples: zero retired filters/options",
                res.stdout,
            )


if __name__ == "__main__":
    unittest.main()
