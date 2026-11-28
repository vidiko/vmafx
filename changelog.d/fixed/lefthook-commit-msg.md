- **Hooks:** run the Conventional Commits `commit-msg` stage from
  `lefthook.yml` through `scripts/git-hooks/framework-hooks.sh`, so a
  lefthook-only checkout refuses a non-conventional subject locally
  (issue 3638). Because lefthook does not shell-escape Git hook arguments in
  custom templates, `lefthook.yml` omits `{1}` and the bridge picks
  `MERGE_MSG` in the worktree's Git directory when `GIT_REFLOG_ACTION` starts
  with `merge` or `pull`, `MERGE_HEAD` resolves, and no rebase directory is
  present, or `COMMIT_EDITMSG` otherwise (still validating an explicit
  message-file argument for direct callers). The job times out after 300
  seconds.
