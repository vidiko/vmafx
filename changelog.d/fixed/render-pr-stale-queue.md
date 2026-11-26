- **CI:** The `docs-render-pr` workflow now refreshes stale queued renders before
  they fail merge-queue checks. A failed queue query stops the push. When
  master's render is already current, it closes the stale render pull request
  instead of pushing an empty commit.
