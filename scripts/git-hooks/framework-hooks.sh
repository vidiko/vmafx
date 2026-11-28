#!/usr/bin/env bash
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
#
# framework-hooks.sh — hand one lefthook stage to the pre-commit framework
# (ADR-1249, ADR-2012). lefthook.yml calls this file from a one-line `run:`.
#
# Why a file and not an inline `run: |` block: on Windows, lefthook v2.1.14
# starts `sh -c` through a hand-built command line and does not escape the
# script (internal/run/controller/exec/exec_windows.go builds
# `"<sh>" -c "<run>"`). The first double quote inside the script therefore
# ends the `-c` argument. The inline block failed with "unexpected end of file
# from `if' command", and a one-line command silently lost every word after
# its first quoted string. Keep double quotes out of every lefthook `run:`
# value; scripts/githooks/tests/test_install.py enforces that.
#
# Usage: framework-hooks.sh pre-commit
#        framework-hooks.sh commit-msg [MESSAGE_FILE]
#        framework-hooks.sh pre-push REMOTE URL   (push refs on stdin)
set -euo pipefail

# Force UTF-8 on Windows where cp1252 is default, avoiding charmap decode errors
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

find_framework() {
  # A repository virtualenv wins over PATH: bin/ is the POSIX layout and
  # Scripts/ the one `python -m venv` creates on Windows.
  local candidate
  for candidate in .venv/bin/pre-commit .venv/Scripts/pre-commit.exe; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  command -v pre-commit
}

if ! fw=$(find_framework); then
  echo "VMAFx hooks: pre-commit is missing; activate the environment used by make install-hooks." >&2
  exit 1
fi
case "$fw" in
  .venv/*)
    # Same effect as activating the virtualenv. The `language: system` hooks
    # it serves, such as reuse-lint, come from the same hash lock
    # (requirements/locks/pre-commit.txt), so they resolve from here too.
    tools="$PWD/${fw%/*}"
    if command -v cygpath >/dev/null 2>&1; then
      # Under lefthook, Git Bash reports PWD as C:/...; its colon would split
      # the PATH entry in two.
      tools=$(cygpath -u "$tools")
    fi
    # On Windows, python -m venv creates python.exe in Scripts/ but not python3.exe.
    # Provide python3.exe if missing so system hooks invoking python3 resolve to .venv.
    if [ -x "$tools/python.exe" ] && [ ! -e "$tools/python3.exe" ]; then
      cp "$tools/python.exe" "$tools/python3.exe"
    fi
    PATH="$tools:$PATH"
    export PATH
    ;;
esac

# Git exports GIT_DIR (and in some versions GIT_WORK_TREE) to every hook. A hook
# entry that runs `git init` or `git config` in a scratch directory with them set
# writes into this repository instead: a test fixture set core.bare=true in the
# main checkout on 2026-11-03. Neither stage needs them, since pre-commit finds the
# repository from the working directory, which Git sets to the top level. The other
# repository-locating variables go too. Keep GIT_INDEX_FILE: a partial commit
# (`git commit <path>`) names its temporary index there, and pre-commit lists the
# staged files from it. GIT_CONFIG_PARAMETERS stays: it carries the operator's own
# `git -c` settings, which the hooks are meant to see.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

physical_dir() {
  # A final marker keeps command substitution from trimming newlines in a path.
  CDPATH='' cd -P -- "$1" && pwd -P && printf .
}

resolve_commit_msg_file() {
  # lefthook v2.2.2 cannot pass {1} safely: run templates {0}/{1} join unescaped
  # (internal/run/controller/command/replacer/replacer.go:75,:192, escaping file
  # templates only), scripts: appends git args unescaped (command/build_script.go),
  # exec_unix.go:81 runs `sh -c cmdstr`, exec_windows.go builds `"<sh>" -c "<cmdstr>"`
  # by hand, env: values are not templated (job.go:128 copies job.Env; exec_unix.go:52
  # applies only os.ExpandEnv), and test_run_values_survive_the_windows_command_line
  # forbids block scalars and double quotes in `run:`.
  # Git 2.56.1 commit-msg probe + git/git master source:
  # - `merge --no-edit` / `merge -e`: arg .git/MERGE_MSG, GIT_REFLOG_ACTION="merge
  #   <side>", MERGE_HEAD present, COMMIT_EDITMSG older/stale (builtin/merge.c:978,
  #   :1590 setenv overwrite=0).
  # - `pull --no-rebase --no-edit`: arg .git/MERGE_MSG, GIT_REFLOG_ACTION="pull ..."
  #   kept from builtin/pull.c:160; MERGE_HEAD and MERGE_MSG share identical ns mtime.
  # - `commit`, `--amend`, `commit` after `merge --no-commit` or conflicted merge,
  #   `merge --continue`: arg .git/COMMIT_EDITMSG, no GIT_REFLOG_ACTION (last three
  #   keep MERGE_HEAD and MERGE_MSG).
  # - `rebase -i` reword: arg .git/COMMIT_EDITMSG, GIT_REFLOG_ACTION="rebase (reword)"
  #   (sequencer.c:1170); `rebase --rebase-merges` writes MERGE_HEAD then runs commit;
  #   `cherry-pick`, `cherry-pick -e`, `revert --no-edit`, `pull --rebase=merges`
  #   merge/pick steps do not invoke commit-msg.
  # Rule: pick MERGE_MSG iff GIT_REFLOG_ACTION starts with word `merge` or `pull`,
  # MERGE_HEAD verifies, MERGE_MSG is a regular file in git-dir, and neither
  # rebase-merge nor rebase-apply exists there; else COMMIT_EDITMSG if regular; else
  # exit 2. Limit: pre-setting GIT_REFLOG_ACTION to another word before `merge`
  # checks COMMIT_EDITMSG; the PR DCO range check still reads the stored message.
  local git_output git_dir edit_msg merge_msg
  if ! git_output=$(git rev-parse --absolute-git-dir 2>/dev/null && printf .); then
    echo "framework-hooks.sh: commit-msg needs the message file" >&2
    exit 2
  fi
  git_dir=${git_output%$'\n.'}
  edit_msg="$git_dir/COMMIT_EDITMSG"
  merge_msg="$git_dir/MERGE_MSG"
  case ${GIT_REFLOG_ACTION:-} in
    merge | 'merge '* | $'merge\t'* | pull | 'pull '* | $'pull\t'*)
      if [[ -f "$merge_msg" &&
        ! -e "$git_dir/rebase-merge" && ! -L "$git_dir/rebase-merge" &&
        ! -e "$git_dir/rebase-apply" && ! -L "$git_dir/rebase-apply" ]] &&
        git rev-parse -q --verify MERGE_HEAD >/dev/null 2>&1; then
        msg_file=$merge_msg
        return 0
      fi
      ;;
  esac
  if [ -f "$edit_msg" ]; then
    msg_file=$edit_msg
  else
    echo "framework-hooks.sh: commit-msg needs the message file" >&2
    exit 2
  fi
}

validate_commit_msg_file() {
  local name parent git_output expected received git_dir
  if [ -z "$1" ]; then
    echo "framework-hooks.sh: commit-msg needs the message file" >&2
    exit 2
  fi
  # Git supplies one of two files in this worktree's git dir. Compare physical
  # directories so a Git for Windows drive path and its MSYS spelling agree.
  name=${1##*/}
  parent=${1%"$name"}
  if ! git_output=$(git rev-parse --absolute-git-dir 2>/dev/null && printf .) ||
    ! expected=$(physical_dir "${git_output%$'\n.'}" 2>/dev/null) ||
    ! received=$(physical_dir "${parent:-.}" 2>/dev/null) ||
    [[ $received != "$expected" || ! -f $1 ||
      ($name != COMMIT_EDITMSG && $name != MERGE_MSG) ]]; then
    git_dir=${git_output%$'\n.'}
    git_dir=${git_dir:-current worktree git dir (unavailable)}
    printf 'framework-hooks.sh: invalid commit-msg file "%s", expected COMMIT_EDITMSG or MERGE_MSG in "%s"\n' \
      "${1//$'\n'/\\n}" "${git_dir//$'\n'/\\n}" >&2
    exit 2
  fi
  msg_file=$1
}

msg_file=
stage=${stage:-${1:-}}
if [ "$stage" = commit-msg ]; then
  if [ "$#" -gt 0 ]; then
    shift
  fi
  if [ "$#" -eq 0 ]; then
    resolve_commit_msg_file
  elif [ "$#" -eq 1 ]; then
    validate_commit_msg_file "$1"
  else
    echo "framework-hooks.sh: commit-msg takes one message file, got $#" >&2
    exit 2
  fi
fi

# Installing hook environments also drops GIT_INDEX_FILE (pre-commit/pre-commit#3609).
env -u GIT_INDEX_FILE -u GIT_DIR -u GIT_WORK_TREE -u GIT_OBJECT_DIRECTORY "$fw" install-hooks || exit 1

case "$stage" in
  pre-commit)
    exec "$fw" run
    ;;
  commit-msg)
    exec "$fw" hook-impl --config=.pre-commit-config.yaml --hook-type=commit-msg \
      --hook-dir "$(git rev-parse --git-path hooks)" -- "$msg_file"
    ;;
  pre-push)
    if [ "$#" -gt 0 ]; then
      shift
    fi
    # hook-impl needs Git's remote arguments and the push-ref stdin to compute
    # the pushed range (ADR-1241); exec keeps stdin attached.
    exec "$fw" hook-impl --config=.pre-commit-config.yaml --hook-type=pre-push \
      --hook-dir "$(git rev-parse --git-path hooks)" -- "$@"
    ;;
  *)
    echo "framework-hooks.sh: unknown stage '$stage'; expected pre-commit, commit-msg or pre-push" >&2
    exit 2
    ;;
esac
