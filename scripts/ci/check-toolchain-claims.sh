#!/usr/bin/env bash
# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2

# scripts/ci/check-toolchain-claims.sh — gate for PR-body toolchain absence claims.
#
# Enforces that any claim asserting a toolchain is missing or that a GPU backend
# was not compiled is backed by evidence from `scripts/dev/toolchain-probe.sh`.
#
# A claim requires one block covering every tool. A host claim also requires
# a covering block with no claimed tool found. Pasted output is unauthenticated:
# the checker detects missing or contradictory evidence, not forged blocks.
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
# shellcheck source=scripts/dev/toolchain-probe-format.sh
. "${_check_dir}/../dev/toolchain-probe-format.sh"

# Bash 3.2 has no {variable} fd allocation. Use a scoped duplicate for the
# stdin read on that shell. Redirection on the function restores fd 9 on return.
read_legacy_stdin() {
  PR_BODY_STDIN_FD=9
  if [ -t 9 ]; then
    PR_BODY_STDIN_KIND="tty"
  elif [ -e /dev/fd/9 ] && [ ! -f /dev/fd/9 ] && [ ! -p /dev/fd/9 ] && [ ! -S /dev/fd/9 ]; then
    PR_BODY_STDIN_KIND=unreadable
  else
    PR_BODY_STDIN_KIND=stream
    body_text="$(pr_body_read_stdin)"
  fi
}

if [ -n "${PR_BODY+x}" ]; then
  body_text="${PR_BODY}"
  body_src="env"
else
  body_src="stdin"
  if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] == 0))); then
    if ! { : 9<&0; } 2>/dev/null; then
      PR_BODY_STDIN_KIND=closed
    else
      read_legacy_stdin 9<&0
    fi
  else
    pr_body_classify_stdin
    if [ "${PR_BODY_STDIN_KIND}" = "stream" ]; then
      body_text="$(pr_body_read_stdin)"
      pr_body_close_stdin
    fi
  fi
  if [ "${PR_BODY_STDIN_KIND}" != "stream" ]; then
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
probe_result_patterns "${probe_names}"
tick='`'
fence_tick="^[[:space:]]*(${tick}{3,})[^${tick}]*\$"
fence_tilde='^[[:space:]]*(~{3,})'
blank='^[[:space:]]*$'

# Only fence markers, valid headers, and probe rows inside a strict header
# block (`after_header=1`) are exempt from prose claim checking.
declare -a lines=() exempt_lines=()
# Each indexed entry is a space-delimited set of canonical probe names.
declare -a probed_tools=() found_tools=()
block_count=0
fence_start=0
fence_close=''
after_header=0

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
    probed_tools[block_count]+=" ${name} "
    found_tools[block_count]+=" ${name} "
    exempt_lines[idx]=1
  elif [[ "${line}" =~ ${probe_absent} ]]; then
    name="${BASH_REMATCH[2]:-metal}"
    probed_tools[block_count]+=" ${name} "
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
    block_count=$((block_count + 1))
    probed_tools[block_count]=''
    found_tools[block_count]=''
    after_header=1
    exempt_lines[idx]=1
  elif [[ "${line}" =~ ^[[:space:]]*toolchain-probe[[:space:]]+v[0-9]+([[:space:]]|$) ]]; then
    after_header=0
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
#   (a) change word follows after zero to three change objects (`no SYCL changes`, `no nvcc flags changed`);
#   (b) change verb directly precedes `no <tool>` (`Touches no CUDA`, `changes no HIP`).
change_objects='build|flag|flags|option|options|code|source|sources|file|files|path|paths|kernel|kernels|backend|test|tests|config|setting|settings|dependency|dependencies'
p_scope_object="\`*(${change_objects})\`*"
p_no_scope_after="no${space}\`*(${claim_words})\`*${space}(${p_scope_object}${space}){0,3}(change|changes|changed|edit|edits|edited|touched|modified)${wb_r}"
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

p_absence_or_without="(${p_absence}|${p_without})"
# Subject suffix stops exactly where the absence predicate starts.
p_subject_action="((has|have)${space}no|lacks)${space}((a|an|the)${space})?\`*(${claim_words})\`*${wb_tok_r}$"
p_nonhost_subject="${wb_l}(ci|runners?|images?|containers?|golden(${space}|-)builds?)${space}${p_subject_action}"
p_host_subject="${wb_l}((this|the)${space}host|(this|my)${space}machine)${space}${p_subject_action}"
word='[[:alnum:]_-]+'
sep='[^[:alnum:]_-]+'
left_window="(${word}${sep}){0,3}${word}[^[:alnum:]_-]*$"
right_window="^[^[:alnum:]_-]*${word}(${sep}${word}){0,3}"

split_clauses() {
  local s="$1"
  s="${s//;/$'\n'}"
  s="${s//.[[:space:]]/$'\n'}"
  s="${s//![[:space:]]/$'\n'}"
  s="${s//\?[[:space:]]/$'\n'}"
  printf '%s\n' "${s}"
}

near_host() {
  local left="$1" match="$2" right="$3" window=''
  if [[ "${left}" =~ ${left_window} ]]; then window="${BASH_REMATCH[0]}"; fi
  window+="${match}"
  if [[ "${right}" =~ ${right_window} ]]; then window+="${BASH_REMATCH[0]}"; fi
  [[ "${window}" =~ ${p_host} ]]
}

absence_is_host() {
  local clause="$1" left="$2" match="$3" right="$4"
  [[ "${left}${match}" =~ ${p_nonhost_subject} ]] && return 1
  [[ "${left}${match}" =~ ${p_host_subject} ]] && return 0
  near_host "${left}" "${match}" "${right}" && return 0
  [[ ! "${clause}" =~ ${p_nonhost} ]]
}

claim_tools() {
  local clause="$1" spec family name compiler_alias backend_alias families=' '
  tools=()
  for spec in "${toolchain_map[@]}"; do
    IFS=';' read -r family name compiler_alias _ <<<"${spec}"
    if [[ "${clause}" =~ ${wb_tok_l}\`*(${name}${compiler_alias:+|${compiler_alias}})\`*${wb_tok_r} ]]; then
      families+="${family} "
      tools+=("${name}")
    fi
  done
  for spec in "${toolchain_map[@]}"; do
    IFS=';' read -r family name _ backend_alias <<<"${spec}"
    if [[ -n "${backend_alias}" && "${families}" != *" ${family} "* &&
      "${clause}" =~ ${wb_tok_l}\`*(${backend_alias})\`*${wb_tok_r} ]]; then
      tools+=("${name}")
    fi
  done
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

# Keep the first closest block for diagnostics. A complete block takes
# precedence over partial blocks, and any agreeing complete block suffices.
check_evidence() {
  local clause="$1" host_tools="$2" block tool missing contradicted count
  local best_count=$((${#toolchain_map[@]} + 1)) best_missing='' best_contradicted=''
  local -a tools=()
  if ((block_count == 0)); then
    emit_missing_probe "${idx}" "${line}"
    return 1
  fi
  claim_tools "${clause}"
  for ((block = 1; block <= block_count; block++)); do
    missing='' contradicted='' count=0
    for tool in ${tools[@]+"${tools[@]}"}; do
      if [[ "${probed_tools[block]}" != *" ${tool} "* ]]; then
        missing+="${missing:+, }${tool}"
        count=$((count + 1))
      elif [[ ("${host_tools}" == all || "${host_tools}" == *" ${tool} "*) &&
        "${found_tools[block]}" == *" ${tool} "* ]]; then
        contradicted+="${contradicted:+, }${tool}"
      fi
    done
    if [[ -z "${missing}${contradicted}" ]]; then return 0; fi
    if ((count < best_count)); then
      best_count=${count}
      best_missing="${missing}"
      best_contradicted="${contradicted}"
    fi
  done
  if ((best_count > 0)); then best_contradicted=''; fi
  emit_claim_errors "${idx}" "${line}" "${best_missing}" "${best_contradicted}"
}

# One absence can name several tools ("no nvcc or hipcc"). A new absence
# predicate starts a new phrase and gets its own subject and qualifier window.
check_clause() {
  local clause="$1" tail="$1" left='' match before after phrase
  local offset=0 saw_absence=0 host_tools=' '
  local -a tools=()
  while ((offset < ${#clause})) && [[ "${tail}" =~ ${p_absence_or_without} ]]; do
    match="${BASH_REMATCH[0]}"
    before="${tail%%"${match}"*}"
    left="${clause:0:offset}${before}"
    after="${tail#*"${match}"}"
    phrase="${match}"
    if ((offset == 0)); then phrase="${before}${match}"; fi
    if [[ "${after}" =~ ${p_absence_or_without} ]]; then
      phrase+="${after%%"${BASH_REMATCH[0]}"*}"
    else
      phrase+="${after}"
    fi
    tail="${after}"
    offset=$((${#clause} - ${#tail}))
    if [[ "${match}" =~ ${p_without} ]] && ! near_host "${left}" "${match}" "${after}"; then
      continue
    fi
    saw_absence=1
    if absence_is_host "${clause}" "${left}" "${match}" "${after}"; then
      claim_tools "${phrase}"
      host_tools+="${tools[*]-} "
    fi
  done
  if ((saw_absence == 0)); then
    [[ "${clause}" =~ ${p_compile} && "${clause}" =~ ${p_any_tool} ]] || return 0
    if [[ "${clause}" =~ ${p_host} ]]; then host_tools=all; fi
  fi
  check_evidence "${clause}" "${host_tools}"
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
  local idx="$1" line="$2" clause stripped_clause='' rc=0
  while IFS= read -r clause; do
    strip_scoped_no "${clause}"
    check_clause "${stripped_clause}" || rc=1
    if ((rc != 0 && block_count == 0)); then return 1; fi
  done < <(split_clauses "${line}")
  return "${rc}"
}

# Check claims after collecting evidence from the entire description.
shopt -s nocasematch
fail=0
for ((idx = 1; idx <= ${#lines[@]}; idx++)); do
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
