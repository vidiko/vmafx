#!/usr/bin/env bash
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2

# scripts/ci/check-toolchain-claims.sh — gate for PR-body toolchain absence claims.
#
# Enforces that any claim asserting a toolchain is missing or that a GPU backend
# was not compiled is backed by evidence from `scripts/dev/toolchain-probe.sh`.
#
# Refuses (exit 1, message naming line) when:
#   1. Body contains a missing-toolchain claim and lacks a `toolchain-probe v1` block.
#   2. Body claims a toolchain is missing/not compiled, but the pasted probe output
#      reports that toolchain was `found` on the host.
#
# Checks prose in fences and skips the probe's header and result lines.
#
# Reads PR body from $PR_BODY env var or stdin via scripts/ci/pr-body-input.sh.
#
# Exit codes:
#   0 — pass (claims justified by probe, or no claims made).
#   1 — claim violation (missing probe evidence or contradicted by probe).
#   2 — usage error (no body supplied).

set -euo pipefail

_check_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/pr-body-input.sh
. "${_check_dir}/pr-body-input.sh"

if [ -n "${PR_BODY+x}" ]; then
  body_text="${PR_BODY}"
else
  pr_body_classify_stdin
  if [ "${PR_BODY_STDIN_KIND}" = "stream" ]; then
    body_text="$(pr_body_read_stdin)"
    pr_body_close_stdin
  else
    echo "check-toolchain-claims: no PR body supplied — $(pr_body_stdin_reason)" >&2
    echo "  Set PR_BODY env var, OR pipe body on stdin." >&2
    exit 2
  fi
fi

# Empty or blank body: no claims to evaluate.
if [ -z "$(printf '%s' "${body_text}" | tr -d '[:space:]')" ]; then
  exit 0
fi

# Probe name; explicit compiler aliases; other absence aliases; compile-only aliases.
# Use this map for claim vocabulary, accepted probe names and evidence lookup.
toolchain_map=(
  "icpx;;oneapi;sycl"
  "icx;;;"
  "nvcc;;cuda[[:space:]]+toolkit;cuda"
  "hipcc;hip[[:space:]]+cc;rocm;hip"
  "glslc;;;vulkan"
  "glslangValidator;;;"
  "metal;;;"
  "x86_64-w64-mingw32-gcc;;;"
)

wb_l='(^|[^a-zA-Z0-9_])'
wb_r='([^a-zA-Z0-9_]|$)'
claim_words=''
compile_words=''
probe_names=''
for spec in "${toolchain_map[@]}"; do
  IFS=';' read -r name compiler_alias absence_alias compile_alias <<<"${spec}"
  probe_names+="${probe_names:+|}${name}"
  claim_words+="${claim_words:+|}${name}${compiler_alias:+|${compiler_alias}}${absence_alias:+|${absence_alias}}"
  compile_words+="${compile_alias:+|${compile_alias}}"
done
compile_words="${claim_words}${compile_words}"

space='[[:space:]]+'
token='[^[:space:]]+'
probe_header="^[[:space:]]*toolchain-probe v1 host=${token} os=${token} date=${token}[[:space:]]*$"
probe_result="^[[:space:]]*toolchain-probe: (${probe_names}) (found ${token}|absent searched=${token})(${space}.*)?$"
fence_open='^[[:space:]]*(`{3,}|~{3,})'
blank='^[[:space:]]*$'

# Probe lines store the opening fence's line number, or zero for raw output
# and fence markers. Only fences with a strict header exempt their probe rows.
declare -a lines=() probe_lines=() fence_headers=()
declare -A probed_tools=() found_tools=()
fence_start=0
fence_close=''
after_header=0
has_probe_header=0

# Opening and closing fences reset the evidence scope. A shorter or
# different fence marker inside a block is content.
is_fence_marker() {
  local line="$1" idx="$2" marker
  if [ "${fence_start}" -eq 0 ]; then
    [[ "${line}" =~ ${fence_open} ]] || return 1
    marker="${BASH_REMATCH[1]}"
    fence_start="${idx}"
    fence_close="^[[:space:]]*${marker:0:1}{${#marker},}[[:space:]]*$"
  else
    [[ "${line}" =~ ${fence_close} ]] || return 1
    fence_start=0
  fi
  after_header=0
}

read_probe_line() {
  local line="$1" idx="$2" name status
  if is_fence_marker "${line}" "${idx}"; then
    probe_lines[idx]=0
  elif [[ "${line}" =~ ${blank} ]]; then
    if [ "${fence_start}" -eq 0 ]; then
      after_header=0
    fi
  elif [[ "${line}" =~ ${probe_header} ]]; then
    has_probe_header=1
    after_header=1
    fence_headers[fence_start]=1
    probe_lines[idx]="${fence_start}"
  elif [[ "${line}" =~ ${probe_result} ]]; then
    name="${BASH_REMATCH[1]}"
    status="${BASH_REMATCH[2]}"
    probe_lines[idx]="${fence_start}"
    if [ "${after_header}" -eq 1 ]; then
      probed_tools["${name}"]=1
      if [[ "${status}" == 'found '* ]]; then
        found_tools["${name}"]=1
      fi
    fi
  fi
}

idx=0
while IFS= read -r line; do
  idx=$((idx + 1))
  lines[idx]="${line}"
  read_probe_line "${line}" "${idx}"
done <<<"${body_text}"

p_no="${wb_l}no${space}\`?(${claim_words})\`?${wb_r}"
p_status="${wb_l}\`?(${claim_words})\`?(${space}(is|was|were))?${space}(not${space}(installed|found)|missing|unavailable|absent)${wb_r}"
p_without="${wb_l}without${space}\`?(${claim_words})\`?${wb_r}"
p_host="${wb_l}(on${space}this${space}host|here|locally)${wb_r}"
p_compile="${wb_l}(not${space}compiled|(was|were)${space}not${space}built|compilation(${space}(was|were))?${space}skipped)${wb_r}"

classify_claim() {
  local line="$1"
  host_claim=0
  if [[ "${line}" =~ ${p_no} || "${line}" =~ ${p_status} ]] ||
    [[ "${line}" =~ ${p_without} && "${line}" =~ ${p_host} ]]; then
    host_claim=1
  elif [[ "${line}" =~ ${p_compile} && "${line}" =~ ${wb_l}(${compile_words})${wb_r} ]]; then
    # A compilation claim can describe a build configuration. Toolchain
    # presence contradicts it only if it describes the build host.
    if [[ "${line}" =~ ${p_host} || "${line}" =~ ${wb_l}(this${space}host|on${space}the${space}host)${wb_r} ]]; then
      host_claim=1
    fi
  else
    return 1
  fi
}

claim_tools() {
  local line="$1" spec name compiler_alias absence_alias compile_alias aliases
  local -a explicit=() backends=()
  for spec in "${toolchain_map[@]}"; do
    IFS=';' read -r name compiler_alias absence_alias compile_alias <<<"${spec}"
    aliases="${absence_alias}${compile_alias:+${absence_alias:+|}${compile_alias}}"
    if [[ "${line}" =~ ${wb_l}(${name}${compiler_alias:+|${compiler_alias}})${wb_r} ]]; then
      explicit+=("${name}")
    elif [ -n "${aliases}" ] && [[ "${line}" =~ ${wb_l}(${aliases})${wb_r} ]]; then
      backends+=("${name}")
    fi
  done
  if [ "${#explicit[@]}" -gt 0 ]; then
    printf '%s\n' "${explicit[@]}"
  else
    printf '%s\n' "${backends[@]}"
  fi
}

check_claim() {
  local idx="$1" line="$2" tool missing='' contradicted=''
  if [ "${has_probe_header}" -eq 0 ]; then
    echo "::error file=PR_BODY,line=${idx},title=Missing toolchain probe::no 'toolchain-probe v1' block" >&2
    echo "check-toolchain-claims: line ${idx}: missing-toolchain claim without 'toolchain-probe v1' block in PR body:" >&2
    echo "  ${line}" >&2
    echo "  Hint: run scripts/dev/toolchain-probe.sh on the build host and paste its fenced output into the PR description." >&2
    return 1
  fi

  while IFS= read -r tool; do
    if [ "${probed_tools[${tool}]:-0}" -eq 0 ]; then
      missing="${missing:+${missing}, }${tool}"
    elif [ "${host_claim}" -eq 1 ] && [ "${found_tools[${tool}]:-0}" -eq 1 ]; then
      contradicted="${contradicted:+${contradicted}, }${tool}"
    fi
  done < <(claim_tools "${line}")

  if [ -n "${missing}" ]; then
    echo "::error file=PR_BODY,line=${idx},title=Missing toolchain probe results::missing probe results for claimed toolchains: ${missing}" >&2
    echo "check-toolchain-claims: line ${idx}: missing probe results for claimed toolchains: ${missing}" >&2
    echo "  ${line}" >&2
    echo "  Hint: paste complete output from scripts/dev/toolchain-probe.sh into the PR description covering every claimed toolchain." >&2
    return 1
  fi
  if [ -n "${contradicted}" ]; then
    echo "::error file=PR_BODY,line=${idx},title=Contradicted toolchain claim::line ${idx} claims '${contradicted}' is missing/not compiled, but probe reports it found on host:" >&2
    echo "check-toolchain-claims: line ${idx}: PR body claims '${contradicted}' is missing/not compiled, but probe reports it found on host:" >&2
    echo "  ${line}" >&2
    return 1
  fi
}

# Check claims after collecting evidence from the entire description.
shopt -s nocasematch
fail=0
for idx in "${!lines[@]}"; do
  scope="${probe_lines[idx]:-}"
  if [[ "${scope}" == 0 ]] || [[ -n "${scope}" && "${fence_headers[scope]:-0}" == 1 ]]; then
    continue
  fi
  if classify_claim "${lines[idx]}"; then
    check_claim "${idx}" "${lines[idx]}" || fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  exit 1
fi

echo "check-toolchain-claims: PASS — toolchain claims verified against probe."
exit 0
