# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Pending commit message checks and the commit-msg hook contract."""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
import io
import os
import shlex
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

yaml = importlib.import_module("yaml")

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "scripts/ci/check-dco.py"
sys.path.insert(0, str(ROOT))
run = importlib.import_module("scripts.lib.safe_subprocess").run
GIT = shutil.which("git") or "/usr/bin/git"
spec = importlib.util.spec_from_file_location("dco_message_gate", GATE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)
SIGNED = "fix: example\n\nSigned-off-by: Ada <ada@example.org>\n"


class CommitMessageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        for key in ("BASE_SHA", "HEAD_SHA", "PR_BODY", "DCO_RELEASE_PR"):
            self.env.pop(key, None)
        self.env.update(
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
            GIT_AUTHOR_NAME="Ada",
            GIT_AUTHOR_EMAIL="ada@example.org",
            GIT_COMMITTER_NAME="Ada",
            GIT_COMMITTER_EMAIL="ada@example.org",
        )
        self.git("init", "-q")
        self.message = self.root / "message"

    def git(self, *args: str) -> Any:
        return run(
            [GIT, *args],
            allowed_executables=(GIT,),
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=True,
            timeout_seconds=30,
        )

    def run_gate(self, text: str, *args: str, editor: bool = False) -> Any:
        """Run --message-file with GIT_EDITOR=':' unless editor leaves GIT_EDITOR unset."""
        self.message.write_text(text, encoding="utf-8", newline="")
        env = dict(self.env)
        if not editor:
            env["GIT_EDITOR"] = ":"
        return run(
            [sys.executable, str(GATE), "--message-file", str(self.message), *args],
            allowed_executables=(sys.executable,),
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout_seconds=30,
        )

    def install_hook(self) -> None:
        hook = self.root / ".git/hooks/commit-msg"
        hook.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{GATE}" --message-file "$1"\n', encoding="utf-8"
        )
        hook.chmod(0o755)

    def commit_both_ways(
        self, args: list[str], env: dict[str, str], staged: str = "next\n"
    ) -> tuple[int, int, str]:
        """Run git commit with the hook, store the message if refused, and run range check."""
        tracked = self.root / "file"
        tracked.write_text("base\n", encoding="utf-8")
        self.git("add", "file")
        self.git("commit", "-q", "-s", "-m", "chore: base")
        base = self.git("rev-parse", "HEAD").stdout.strip()
        tracked.write_text(staged, encoding="utf-8")
        self.git("add", "file")
        self.install_hook()
        hook_done = run(
            [GIT, "commit", *args],
            allowed_executables=(GIT,),
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout_seconds=30,
        )
        if hook_done.returncode != 0:
            (self.root / ".git/hooks/commit-msg").unlink()
            run(
                [GIT, "commit", *args],
                allowed_executables=(GIT,),
                cwd=self.root,
                env=env,
                text=True,
                capture_output=True,
                check=True,
                timeout_seconds=30,
            )
        stored = self.git("log", "-1", "--format=%B").stdout
        range_done = run(
            [sys.executable, "-I", str(GATE), "--base", base, "--head", "HEAD"],
            allowed_executables=(sys.executable,),
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout_seconds=30,
        )
        return hook_done.returncode, range_done.returncode, stored

    def test_signed_and_committer_signoff(self) -> None:
        result = self.run_gate(SIGNED)
        self.assertEqual(result.returncode, 0)
        self.assertIn("dco: PASS - commit message", result.stdout)
        self.env["GIT_AUTHOR_EMAIL"] = "author@example.org"
        self.assertEqual(self.run_gate(SIGNED).returncode, 0)

    def test_comment_and_scissors(self) -> None:
        scissors = "# ------------------------ >8 ------------------------\n"
        tail = "# Generated by Codex\ndiff --git a/f b/f\n+Generated by Codex\n"
        result = self.run_gate(SIGNED + scissors + tail)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        result = self.run_gate(SIGNED + scissors + tail, editor=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        help_tail = (
            "# Do not modify or remove the line above.\n"
            "# Everything below it will be ignored.\n"
            "diff --git a/f b/f\n+Generated by Codex\n"
        )
        result = self.run_gate(SIGNED + scissors + help_tail, editor=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_gate(SIGNED + scissors + help_tail)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        diff = "diff --git a/f b/f\n" + "+" * (gate.MAX_COMMIT_MESSAGE_BYTES + 1) + "\n"
        result = self.run_gate(SIGNED + scissors + diff, editor=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_gate(SIGNED + scissors + diff)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        line = "not a cut ------------------------ >8 ------------------------\n"
        fake = "not-a-cut ------------------------ >8 ------------------------\n"
        # Bounded by 2 editor modes.
        for editor in (False, True):
            result = self.run_gate(SIGNED + "\n" + line, editor=editor)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            result = self.run_gate(SIGNED + fake + "Generated by Codex\n", editor=editor)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.git("config", "core.commentChar", ";")
        hashed = SIGNED + "# ------------------------ >8 ------------------------\n"
        message = (
            SIGNED + "; ------------------------ >8 ------------------------\n"
            "diff --git a/f b/f\n+x\n"
        )
        result = self.run_gate(message, editor=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Bounded by 2 editor modes.
        for editor in (False, True):
            result = self.run_gate(hashed + "Generated by Codex\n", editor=editor)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_unedited_scissors_suffix_is_checked(self) -> None:
        scissors = "# ------------------------ >8 ------------------------\n"
        result = self.run_gate(SIGNED + scissors + "Generated by Codex\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error title=DCO attribution::", result.stdout)
        result = self.run_gate(SIGNED + "diff --git a/f b/f\nGenerated by Codex\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error title=DCO attribution::", result.stdout)
        result = self.run_gate(SIGNED + scissors + "#\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_gate(SIGNED + scissors + "Generated by Codex\n", editor=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_no_trailer(self) -> None:
        result = self.run_gate("fix: example\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("no 'Signed-off-by:", result.stdout)
        self.assertIn("(commit being made) fix: example", result.stdout)
        self.assertIn("dco: the commit being made is refused.", result.stdout)
        self.assertIn("  New commit: git commit -s", result.stdout)
        self.assertIn("  Amend: git commit --amend -s --no-edit", result.stdout)
        self.assertNotIn("(commit be ", result.stdout)
        self.assertNotIn("rebase --signoff", result.stdout)
        self.assertNotIn("push again", result.stdout)

    def test_attribution_advice(self) -> None:
        result = self.run_gate(SIGNED + "Generated by Codex\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error title=DCO attribution::", result.stdout)
        self.assertIn("(commit being made) fix: example", result.stdout)
        self.assertIn("dco: the commit being made is refused.", result.stdout)
        self.assertIn(
            "  Remove model/tool attribution from the message or author identity and commit again.",
            result.stdout,
        )
        self.assertNotIn("New commit: git commit -s", result.stdout)
        self.assertNotIn("Amend: git commit --amend -s --no-edit", result.stdout)
        self.assertNotIn("rebase --signoff", result.stdout)

    def test_other_address_and_prose_and_attribution(self) -> None:
        for message in (
            SIGNED.replace("ada@example.org", "other@example.org"),
            SIGNED + "\nmore prose\n",
            SIGNED + "Generated by Codex\n",
        ):
            with self.subTest(message=message):
                self.assertEqual(self.run_gate(message).returncode, 1)

    def test_invalid_options_and_missing_file(self) -> None:
        self.assertEqual(self.run_gate(SIGNED, "--merge-base", "main").returncode, 2)
        self.message.unlink()
        result = run(
            [sys.executable, str(GATE), "--message-file", str(self.message)],
            allowed_executables=(sys.executable,),
            cwd=self.root,
            env=self.env,
            capture_output=True,
            check=False,
            timeout_seconds=30,
        )
        self.assertEqual(result.returncode, 2)

    def test_excluded_options_and_empty_path(self) -> None:
        self.message.write_text(SIGNED, encoding="utf-8")
        path = str(self.message)
        for extra in (
            ["--base", "x"],
            ["--base=x"],
            ["--head", "x"],
            ["--head=x"],
            ["--merge-base=x"],
            ["--landed"],
            ["--pr-body-file", "x"],
            ["--pr-body=x"],
            ["--pr-body-from-event"],
        ):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(gate.main(["--message-file", path, *extra]), 2)
                self.assertIn("cannot be combined", err.getvalue())
        self.env.update(BASE_SHA="HEAD", HEAD_SHA="HEAD")
        result = run(
            [sys.executable, str(GATE), "--message-file="],
            allowed_executables=(sys.executable,),
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout_seconds=30,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--message-file needs a path", result.stderr)

    def test_line_bound_identity_and_empty_message(self) -> None:
        signoff = SIGNED.split("\n\n", 1)[1]
        lines = gate.MAX_COMMIT_MESSAGE_LINES
        result = self.run_gate("fix: example\n\n" + "x\n" * (lines - 4) + "\n" + signoff)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_gate("fix: example\n\n" + "x\n" * (lines - 3) + "\n" + signoff)
        self.assertEqual(result.returncode, 1)
        self.assertIn("MAX_COMMIT_MESSAGE_LINES", result.stdout)
        self.env["GIT_AUTHOR_EMAIL"] = "no-at-sign"
        result = self.run_gate(SIGNED)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("GIT_AUTHOR_IDENT: unparseable identity", result.stderr)
        self.env["GIT_AUTHOR_EMAIL"] = "ada@example.org"
        result = self.run_gate("# only a comment\n", editor=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("(commit being made) : no 'Signed-off-by:", result.stdout)

    def test_merge_and_bounds(self) -> None:
        (self.root / ".git/MERGE_HEAD").write_text("a" * 40, encoding="utf-8")
        self.assertEqual(self.run_gate("fix: unsigned\n").returncode, 0)
        (self.root / ".git/MERGE_HEAD").unlink()
        message = (
            "fix: example\n\n"
            + "x" * (gate.MAX_COMMIT_MESSAGE_BYTES - len(SIGNED) - 2)
            + "\n\n"
            + SIGNED[len("fix: example\n\n") :]
        )
        self.assertEqual(len(message.encode()), gate.MAX_COMMIT_MESSAGE_BYTES)
        self.assertEqual(self.run_gate(message).returncode, 0)
        result = self.run_gate(message + "x")
        self.assertEqual(result.returncode, 1)
        self.assertIn("MAX_COMMIT_MESSAGE_BYTES", result.stderr)

    def test_main_and_author_override_during_commit(self) -> None:
        self.message.write_text(SIGNED, encoding="utf-8")
        with mock.patch.dict(os.environ, self.env, clear=True):
            old = Path.cwd()
            os.chdir(self.root)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.main(["--message-file", str(self.message)]), 0)
            finally:
                os.chdir(old)
        self.install_hook()
        (self.root / "file").write_text("content", encoding="utf-8")
        self.git("add", "file")
        self.env["GIT_AUTHOR_EMAIL"] = "author@example.org"
        self.git("commit", "-q", "-s", "-m", "fix: example")
        self.assertEqual(self.git("log", "-1", "--format=%ae").stdout.strip(), "author@example.org")
        (self.root / "file").write_text("another", encoding="utf-8")
        self.git("add", "file")
        self.git(
            "commit",
            "-q",
            "--author=Other <other@example.org>",
            "-m",
            "fix: next\n\nSigned-off-by: Other <other@example.org>",
        )
        self.assertEqual(self.git("log", "-1", "--format=%ae").stdout.strip(), "other@example.org")

    def test_auto_comment_character(self) -> None:
        body = "fix: example\n\n#123 issue reference\n\nSigned-off-by: Ada <ada@example.org>\n\n"
        footer = "; Please enter the commit message for your changes.\n;\n; On branch master\n"
        hash_footer = footer.replace(";", "#")
        cut = (
            "; ------------------------ >8 ------------------------\n"
            "diff --git a/f b/f\n+Generated by Codex\n"
        )
        bad_tail = "; ------------------------ >8 ------------------------\nGenerated by Codex\n"
        for key, value in (
            ("core.commentChar", "auto"),
            ("core.commentChar", "AUTO"),
            ("core.commentString", "Auto"),
        ):
            with self.subTest(key=key, value=value):
                self.git("config", key, value)
                result = self.run_gate(body + footer, editor=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = self.run_gate(body + footer + cut, editor=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = self.run_gate(SIGNED + bad_tail + hash_footer, editor=True)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("::error title=DCO attribution::", result.stdout)
                if value == "AUTO":
                    result = self.run_gate(body + footer + bad_tail, editor=True)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_unedited_message_keeps_comment_lines(self) -> None:
        self.install_hook()
        (self.root / "file").write_text("content", encoding="utf-8")
        self.git("add", "file")
        signoff = "Signed-off-by: Ada <ada@example.org>"
        self.git("commit", "-q", "-m", "fix: example", "-m", "#123 issue reference", "-m", signoff)
        self.assertIn("#123 issue reference", self.git("log", "-1", "--format=%B").stdout)
        (self.root / "file").write_text("another", encoding="utf-8")
        self.git("add", "file")
        result = run(
            [GIT, "commit", "-q", "-m", "fix: next", "-m", "# Generated by Codex", "-m", signoff],
            allowed_executables=(GIT,),
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout_seconds=30,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("machine-generated attribution", result.stdout + result.stderr)
        self.assertEqual(self.git("log", "-1", "--format=%s").stdout.strip(), "fix: example")

    def test_auto_unedited_signoff_matches_range_check(self) -> None:
        self.git("config", "core.commentChar", "auto")
        signoff_body = "Signed-off-by: Ada <ada@example.org>\n; ordinary text"
        args = ["-q", "-m", "feat: sample", "-m", signoff_body]
        hook_rc, range_rc, stored = self.commit_both_ways(args, self.env)
        self.assertEqual(hook_rc == 0, range_rc == 0, stored)
        self.assertEqual(hook_rc, 0, stored)
        self.assertEqual(range_rc, 0, stored)

    def test_auto_editor_scissors_candidate_is_text(self) -> None:
        self.git("config", "core.commentChar", "auto")
        script = self.root / "editor.py"
        script.write_text(
            "import pathlib, sys\n"
            "path = pathlib.Path(sys.argv[1])\n"
            "out = []\n"
            "for line in path.read_text(encoding='utf-8').splitlines(keepends=True):\n"
            "    out.append(line)\n"
            "    if line.startswith('Signed-off-by:'):\n"
            "        out.append('; ------------------------ >8 ------------------------\\n')\n"
            "        out.append('Generated by Codex\\n')\n"
            "path.write_text(''.join(out), encoding='utf-8')\n",
            encoding="utf-8",
        )
        env = {**self.env, "GIT_EDITOR": f'"{sys.executable}" "{script}"'}
        args = [
            "-q",
            "-e",
            "--cleanup=scissors",
            "-m",
            "fix: example",
            "-m",
            "Signed-off-by: Ada <ada@example.org>",
        ]
        hook_rc, range_rc, stored = self.commit_both_ways(args, env)
        self.assertEqual(hook_rc, 1, stored)
        self.assertIn("Generated by Codex", stored)
        self.assertEqual(range_rc, 1, stored)

    def test_unedited_file_diff_line_is_text(self) -> None:
        msg = self.root / "input.txt"
        msg.write_text(
            "test: example\n\n"
            "Signed-off-by: Ada <ada@example.org>\n"
            "# ------------------------ >8 ------------------------\n"
            "diff --git a/example b/example\n"
            "Generated by Codex\n",
            encoding="utf-8",
        )
        hook_rc, range_rc, stored = self.commit_both_ways(["-q", "-F", str(msg)], self.env)
        self.assertEqual(hook_rc, 1, stored)
        self.assertIn("Generated by Codex", stored)
        self.assertEqual(range_rc, 1, stored)

    def test_verbose_diff_stays_exempt(self) -> None:
        env = {**self.env, "GIT_EDITOR": f'"{sys.executable}" -c pass'}
        args = [
            "-q",
            "-v",
            "-e",
            "-m",
            "fix: example",
            "-m",
            "Signed-off-by: Ada <ada@example.org>",
        ]
        hook_rc, range_rc, stored = self.commit_both_ways(args, env, staged="Generated by Codex\n")
        self.assertEqual(hook_rc, 0, stored)
        self.assertNotIn("Generated by Codex", stored)
        self.assertEqual(range_rc, 0, stored)


class HookContractTest(unittest.TestCase):
    def test_commit_msg_hook(self) -> None:
        config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
        hooks = {h["id"]: h for repo in config["repos"] for h in repo["hooks"]}
        hook = hooks["dco-sign-off-commit-msg"]
        self.assertEqual(hook["stages"], ["commit-msg"])
        self.assertEqual(
            shlex.split(hook["entry"]), ["python3", "scripts/ci/check-dco.py", "--message-file"]
        )
        self.assertEqual(hook["language"], "system")
        self.assertTrue(hook["always_run"])
        self.assertTrue(hook.get("pass_filenames", True))


if __name__ == "__main__":
    unittest.main()
