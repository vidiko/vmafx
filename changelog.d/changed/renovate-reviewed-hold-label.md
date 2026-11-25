- Reviewed Renovate updates now carry `hold`. The catch-all rule omits the label
  so automerged updates can land. Regression tests detect missing reviewed rules,
  missing or misplaced holds, holds that can reach automerged updates, and
  unsupported selectors on review or automerge rules.
