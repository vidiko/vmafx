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
  body_src="env"
else
  pr_body_classify_stdin
  if [ "${PR_BODY_STDIN_KIND}" = "stream" ]; then
    body_text="$(pr_body_read_stdin)"
    pr_body_close_stdin
    body_src="stdin"
  else
    echo "check-toolchain-claims: no PR body supplied — $(pr_body_stdin_reason)" >&2
    echo "  Set PR_BODY env var, OR pipe body on stdin." >&2
    exit 2
  fi
fi

# An open stdin stream carrying no bytes fails closed (producer sent nothing);
# an explicitly set blank $PR_BODY makes no claims and exits 0.
if [ -z "$(printf '%s' "${body_text}" | tr -d '[:space:]')" ]; then
  if [ "${body_src}" = "stdin" ]; then
    echo "check-toolchain-claims: nothing arrived on stdin." >&2
    echo "  The pipe was open and carried no bytes." >&2
    echo "  Set PR_BODY env var, OR pipe body on stdin." >&2
    exit 2
  fi
  exit 0
fi

# Family; probe name; explicit compiler aliases; backend aliases.
# Single source for claim vocabulary, accepted probe names and evidence lookup.
toolchain_map=(
  "sycl;icpx;;oneapi|sycl"
  "sycl;icx;;"
  "cuda;nvcc;;cuda[[:space:]]+toolkit|cuda"
  "hip;hipcc;hip[[:space:]]+cc;rocm|hip"
  "vulkan;glslc;;vulkan"
  "vulkan;glslangValidator;;"
  "metal;metal;;"
  "mingw;x86_64-w64-mingw32-gcc;;"
)

wb_l='(^|[^a-zA-Z0-9_-])'
wb_r='([^a-zA-Z0-9_-]|$)'
wb_tok_l='(^|[^a-zA-Z0-9_`-])'
wb_tok_r='([^a-zA-Z0-9_`-]|$)'
claim_words=''
probe_names=''
for spec in "${toolchain_map[@]}"; do
  IFS=';' read -r _family name compiler_alias backend_alias <<<"${spec}"
  probe_names+="${probe_names:+|}${name}"
  claim_words+="${claim_words:+|}${name}${compiler_alias:+|${compiler_alias}}${backend_alias:+|${backend_alias}}"
done

space='[[:space:]]+'
token='[^[:space:]]+'
# Accepted scripts/dev/toolchain-probe.sh stdout shapes:
#   - line 74: `toolchain-probe v1 host=<token> os=<token> date=<token>`
#   - lines 144,157,167,198,206,217,236,244,255,274,281,304,310,317,488:
#     `toolchain-probe: <name> found <path>[ <version>]`
#   - lines 175,227,265,290,320,484: `toolchain-probe: <name> absent searched=<dirs>`
#   - line 295: `toolchain-probe: metal absent searched=none os=<os>`
#   - lines 403,421,425,430,434,438,490,493,500,505,517,519,524:
#     `x86_64-w64-mingw32-gcc` detail rows (`dumpversion`, `thread-model`,
#     `runtime`, `runtime-unresolved`, `pairing ok`, `pairing-mismatch`,
#     `pairing-unverified`).
probe_header="^[[:space:]]*toolchain-probe v1 host=${token} os=${token} date=${token}[[:space:]]*$"
probe_found="^[[:space:]]*toolchain-probe: (${probe_names}) found ${token}(${space}.*)?$"
probe_absent="^[[:space:]]*toolchain-probe: ((${probe_names}) absent searched=${token}|metal absent searched=none os=${token})[[:space:]]*$"
mingw_name='x86_64-w64-mingw32-gcc'
mingw_rt_unres='\(gcc -print-file-name answered no absolute path; refusing instead of staging green\)'
mingw_opt_unres='unresolved \(evidence only; not every flavour ships it\)'
mingw_pair_ok="pairing ok thread-model (win32, ${token} imports no libwinpthread|posix, ${token} imports libwinpthread)"
mingw_pair_bad="pairing-mismatch thread-model (win32 but ${token} imports libwinpthread \(B24: a posix runtime next to a win32-model driver deadlocks on the target\)|posix but ${token} imports no libwinpthread \(B24 inverse: a win32 runtime next to a posix-model driver\))"
mingw_pair_unv="pairing-unverified (${token}: objdump -p exited [0-9]+|thread-model unknown \(${token} imports (libwinpthread|none)\); refusing instead of guessing a flavour|no objdump found \(target-prefixed or plain\); refusing to pass an unasserted stage)"
probe_mingw_detail="^[[:space:]]*toolchain-probe: ${mingw_name} (dumpversion ${token}|thread-model ${token}|runtime (libstdc\+\+-6\.dll|libgcc_s_seh-1\.dll|libwinpthread-1\.dll)=${token}|runtime libwinpthread-1\.dll ${mingw_opt_unres}|runtime-unresolved ${token} ${mingw_rt_unres}|${mingw_pair_ok}|${mingw_pair_bad}|${mingw_pair_unv})[[:space:]]*$"
tick='`'
fence_tick="^[[:space:]]*(${tick}{3,})[^${tick}]*\$"
fence_tilde='^[[:space:]]*(~{3,})'
blank='^[[:space:]]*$'

# Only fence markers, valid headers, and probe rows inside a strict header
# block (`after_header=1`) are exempt from prose claim checking.
declare -a lines=() exempt_lines=()
declare -A probed_tools=() found_tools=()
fence_start=0
fence_close=''
after_header=0
has_probe_header=0

# Opening and closing fences reset the evidence scope. Under CommonMark, a
# backtick fence info string cannot contain a backtick (same-line spans pass).
is_fence_marker() {
  local line="$1" idx="$2" marker
  if [ "${fence_start}" -eq 0 ]; then
    if [[ "${line}" =~ ${fence_tick} || "${line}" =~ ${fence_tilde} ]]; then
      marker="${BASH_REMATCH[1]}"
      fence_start="${idx}"
      fence_close="^[[:space:]]*${marker:0:1}{${#marker},}[[:space:]]*$"
    else
      return 1
    fi
  else
    [[ "${line}" =~ ${fence_close} ]] || return 1
    fence_start=0
  fi
  after_header=0
}

record_probe_row() {
  local line="$1" idx="$2" name
  if [[ "${line}" =~ ${probe_found} ]]; then
    name="${BASH_REMATCH[1]}"
    probed_tools["${name}"]=1
    found_tools["${name}"]=1
    exempt_lines[idx]=1
  elif [[ "${line}" =~ ${probe_absent} ]]; then
    name="${BASH_REMATCH[2]:-metal}"
    probed_tools["${name}"]=1
    exempt_lines[idx]=1
  elif [[ "${line}" =~ ${probe_mingw_detail} ]]; then
    exempt_lines[idx]=1
  fi
}

read_probe_line() {
  local line="$1" idx="$2"
  if is_fence_marker "${line}" "${idx}"; then
    exempt_lines[idx]=1
  elif [[ "${line}" =~ ${blank} ]]; then
    if [ "${fence_start}" -eq 0 ]; then
      after_header=0
    fi
  elif [[ "${line}" =~ ${probe_header} ]]; then
    has_probe_header=1
    after_header=1
    exempt_lines[idx]=1
  elif [ "${after_header}" -eq 1 ]; then
    record_probe_row "${line}" "${idx}"
  fi
}

idx=0
while IFS= read -r line; do
  idx=$((idx + 1))
  lines[idx]="${line}"
  read_probe_line "${line}" "${idx}"
done <<<"${body_text}"

p_no="${wb_l}no${space}\`*(${claim_words})\`*${wb_tok_r}"
# Allow-list change-scope `no <tool>` phrases in two shapes:
#   (a) change word follows directly or after one word (`no SYCL changes`, `no nvcc flags changed`);
#   (b) change verb directly precedes `no <tool>` (`Touches no CUDA`, `changes no HIP`).
p_scope_word="\`*[a-zA-Z0-9][a-zA-Z0-9_-]*\`*"
p_no_scope_after="no${space}\`*(${claim_words})\`*${space}(${p_scope_word}${space})?(change|changes|changed|edit|edits|edited|touched|modified)${wb_r}"
p_no_scope_before="(touch|touches|touched|change|changes|changed|edit|edits|edited|modify|modifies|modified)${space}no${space}\`*(${claim_words})\`*${wb_tok_r}"
p_no_scope="${wb_l}(${p_no_scope_after}|${p_no_scope_before})"
p_lacks="${wb_l}(lacks|lacking)${space}((a|an|the)${space})?\`*(${claim_words})\`*${wb_tok_r}"
p_status="${wb_tok_l}\`*(${claim_words})\`*(${space}(is|are|was|were))?${space}(not${space}(installed|found|available)|missing|unavailable|absent)${wb_r}"
p_absence="(${p_no}|${p_lacks}|${p_status})"
p_without="${wb_l}without${space}\`*(${claim_words})\`*${wb_tok_r}"
p_host="${wb_l}(on${space}(this|the)${space}host|this${space}host|here|locally)${wb_r}"
p_nonhost="${wb_l}(ci|runners?|images?|containers?|golden(${space}|-)builds?)${wb_r}"
p_compile="${wb_l}(not${space}compiled|(was|were)${space}not${space}built|did${space}not${space}(compile|build)|compilation(${space}(was|were))?${space}skipped)${wb_r}"
p_any_tool="${wb_tok_l}\`*(${claim_words})\`*${wb_tok_r}"

split_clauses() {
  local s="$1"
  s="${s//;/$'\n'}"
  s="${s//.[[:space:]]/$'\n'}"
  s="${s//![[:space:]]/$'\n'}"
  s="${s//\?[[:space:]]/$'\n'}"
  printf '%s\n' "${s}"
}

is_nonhost_scope() {
  local clause="$1" line="$2"
  [[ "${clause}" =~ ${p_host} ]] && return 1
  [[ "${clause}" =~ ${p_nonhost} ]] && return 0
  [[ "${line}" =~ ${p_nonhost} && ! "${line}" =~ ${p_host} ]]
}

classify_claim() {
  local clause="$1" line="$2"
  host_claim=0
  if [[ "${clause}" =~ ${p_absence} ]] ||
    [[ "${clause}" =~ ${p_without} && "${clause}" =~ ${p_host} ]]; then
    is_nonhost_scope "${clause}" "${line}" || host_claim=1
    return 0
  fi
  if [[ "${clause}" =~ ${p_compile} && "${clause}" =~ ${p_any_tool} ]]; then
    [[ "${clause}" =~ ${p_host} ]] && host_claim=1
    return 0
  fi
  return 1
}

claim_tools() {
  local clause="$1" spec family name compiler_alias backend_alias
  local -A family_explicit=()
  local -a tools=()
  for spec in "${toolchain_map[@]}"; do
    IFS=';' read -r family name compiler_alias _ <<<"${spec}"
    if [[ "${clause}" =~ ${wb_tok_l}\`*(${name}${compiler_alias:+|${compiler_alias}})\`*${wb_tok_r} ]]; then
      family_explicit["${family}"]=1
      tools+=("${name}")
    fi
  done
  for spec in "${toolchain_map[@]}"; do
    IFS=';' read -r family name _ backend_alias <<<"${spec}"
    if [ -n "${backend_alias}" ] && [ "${family_explicit[${family}]:-0}" -eq 0 ] &&
      [[ "${clause}" =~ ${wb_tok_l}\`*(${backend_alias})\`*${wb_tok_r} ]]; then
      tools+=("${name}")
    fi
  done
  if [ "${#tools[@]}" -gt 0 ]; then
    printf '%s\n' "${tools[@]}"
  fi
}

emit_missing_probe() {
  local idx="$1" line="$2"
  echo "::error file=PR_BODY,line=${idx},title=Missing toolchain probe::no 'toolchain-probe v1' block" >&2
  echo "check-toolchain-claims: line ${idx}: missing-toolchain claim without 'toolchain-probe v1' block in PR body:" >&2
  echo "  ${line}" >&2
  echo "  Hint: run scripts/dev/toolchain-probe.sh on the build host and paste its fenced output into the PR description." >&2
}

emit_claim_errors() {
  local idx="$1" line="$2" missing="$3" contradicted="$4" rc=0
  if [ -n "${missing}" ]; then
    echo "::error file=PR_BODY,line=${idx},title=Missing toolchain probe results::missing probe results for claimed toolchains: ${missing}" >&2
    echo "check-toolchain-claims: line ${idx}: missing probe results for claimed toolchains: ${missing}" >&2
    echo "  ${line}" >&2
    echo "  Hint: paste complete output from scripts/dev/toolchain-probe.sh into the PR description covering every claimed toolchain." >&2
    rc=1
  fi
  if [ -n "${contradicted}" ]; then
    echo "::error file=PR_BODY,line=${idx},title=Contradicted toolchain claim::line ${idx} claims '${contradicted}' is missing/not compiled, but probe reports it found on host:" >&2
    echo "check-toolchain-claims: line ${idx}: PR body claims '${contradicted}' is missing/not compiled, but probe reports it found on host:" >&2
    echo "  ${line}" >&2
    rc=1
  fi
  return "${rc}"
}

check_clause_tools() {
  local clause="$1" tool
  while IFS= read -r tool; do
    if [ "${probed_tools[${tool}]:-0}" -eq 0 ]; then
      if [ "${seen_miss[${tool}]:-0}" -eq 0 ]; then
        missing="${missing:+${missing}, }${tool}"
        seen_miss["${tool}"]=1
      fi
    elif [ "${host_claim}" -eq 1 ] && [ "${found_tools[${tool}]:-0}" -eq 1 ]; then
      if [ "${seen_contra[${tool}]:-0}" -eq 0 ]; then
        contradicted="${contradicted:+${contradicted}, }${tool}"
        seen_contra["${tool}"]=1
      fi
    fi
  done < <(claim_tools "${clause}")
}

strip_scoped_no() {
  local rem="$1" i
  for ((i = 0; i < 32; i++)); do
    if [[ ! "${rem}" =~ ${p_no_scope} ]]; then
      stripped_clause="${rem}"
      return 0
    fi
    rem="${rem/"${BASH_REMATCH[0]}"/ , }"
  done
  if [[ "${rem}" =~ ${p_no_scope} ]]; then
    stripped_clause="$1"
  else
    stripped_clause="${rem}"
  fi
}

check_claim() {
  local idx="$1" line="$2" clause stripped_clause='' missing='' contradicted=''
  local -A seen_miss=() seen_contra=()
  while IFS= read -r clause; do
    strip_scoped_no "${clause}"
    classify_claim "${stripped_clause}" "${line}" || continue
    if [ "${has_probe_header}" -eq 0 ]; then
      emit_missing_probe "${idx}" "${line}"
      return 1
    fi
    check_clause_tools "${stripped_clause}"
  done < <(split_clauses "${line}")
  emit_claim_errors "${idx}" "${line}" "${missing}" "${contradicted}"
}

# Check claims after collecting evidence from the entire description.
shopt -s nocasematch
fail=0
for idx in "${!lines[@]}"; do
  if [ "${exempt_lines[idx]:-0}" -eq 1 ]; then
    continue
  fi
  check_claim "${idx}" "${lines[idx]}" || fail=1
done

if [ "${fail}" -ne 0 ]; then
  exit 1
fi

echo "check-toolchain-claims: PASS — toolchain claims verified against probe."
exit 0
