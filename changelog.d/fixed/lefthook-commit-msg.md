- **Hooks:** run the Conventional Commits `commit-msg` stage from
  `lefthook.yml` through `scripts/git-hooks/framework-hooks.sh`, so a
  lefthook-only checkout refuses a non-conventional subject locally
  (issue 3638). The bridge checks that the message file belongs to the
  current worktree's Git directory. The job times out after 300 seconds.
