#!/usr/bin/env bash
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2

set -euo pipefail
shopt -s dotglob nullglob

readonly max_entries=256

fail() {
  printf 'apt-source-allowlist: %s\n' "$1" >&2
  exit 1
}

path_exists() {
  [[ -e "$1" || -L "$1" ]]
}

check_legacy_sources() {
  local legacy="$1" status=0
  if ! path_exists "$legacy"; then
    return
  fi
  [[ -f "$legacy" && -r "$legacy" ]] || fail "cannot read $legacy"
  grep -aE '^[[:space:]]*[^[:space:]#]' -- "$legacy" >/dev/null || status=$?
  case "$status" in
    0) fail "active entry in $legacy" ;;
    1) ;;
    *) fail "cannot read $legacy" ;;
  esac
}

move_sources() {
  local destination="$1" entry target
  shift
  (($# <= max_entries)) || fail "more than $max_entries entries to move"
  # Check at most max_entries destinations before moving any entry.
  for entry in "$@"; do
    target="$destination/${entry##*/}"
    if path_exists "$target"; then
      fail "refusing to overwrite $target"
    fi
  done
  # Move at most max_entries entries and fail if mv skips a newly occupied name.
  for entry in "$@"; do
    if ! mv -n -- "$entry" "$destination/" || path_exists "$entry"; then
      fail "could not move $entry to $destination"
    fi
  done
}

hold_sources() {
  local archive="$sources_dir/ubuntu.sources" entry
  local -a entries=("$sources_dir"/*) held=()
  [[ -f "$archive" && -r "$archive" && ! -L "$archive" ]] ||
    fail "missing or unreadable $archive"
  check_legacy_sources "$apt_dir/sources.list"
  ((${#entries[@]} <= max_entries)) || fail "more than $max_entries entries in $sources_dir"
  # Consider at most max_entries entries, including hidden entries.
  for entry in "${entries[@]}"; do
    if [[ "$entry" != "$archive" ]]; then
      held+=("$entry")
    fi
  done
  mkdir -- "$holding_dir" || fail "cannot create holding directory $holding_dir"
  if ((${#entries[@]} > 1)); then
    move_sources "$holding_dir" "${held[@]}"
  fi
}

restore_sources() {
  [[ -d "$holding_dir" && -r "$holding_dir" && -x "$holding_dir" && ! -L "$holding_dir" ]] ||
    fail "missing or unreadable holding directory $holding_dir"
  move_sources "$sources_dir" "$holding_dir"/*
  rmdir -- "$holding_dir"
}

(($# == 1 || $# == 2)) || fail "usage: $0 {hold|restore} [apt-directory]"
readonly apt_dir="${2-/etc/apt}"
[[ -n "$apt_dir" ]] || fail "APT directory must be non-empty"
readonly sources_dir="$apt_dir/sources.list.d"
readonly holding_dir="$apt_dir/vmafx-held-sources"
[[ -d "$sources_dir" && -r "$sources_dir" && -x "$sources_dir" ]] ||
  fail "missing or unreadable source directory $sources_dir"
case "$1" in
  hold) hold_sources ;;
  restore) restore_sources ;;
  *) fail "usage: $0 {hold|restore} [apt-directory]" ;;
esac
