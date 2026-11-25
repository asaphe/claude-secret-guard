#!/usr/bin/env bash
# Shared utility: reads a Bash hook payload once, with one jq, for the scripts that run on every Bash call — see README § Process launches per call.

# The scripts' own $(cat), by builtin: a NUL ends the read, and only then does $(cat) take the rest, NULs dropped and bash 5's warning printed as $(cat) did.
sg_read_payload() {
  # TMOUT emptied: read honors an inherited one, and $(cat) never timed out.
  if TMOUT='' IFS= read -r -d '' SGA_INPUT; then SGA_INPUT+=$(printf '\0'; cat); fi
  # A substitution strips trailing newlines in one pass; trimming them one at a time took 14 s for 20,000 of them on bash 3.2.
  [ "${SGA_INPUT: -1}" != $'\n' ] || SGA_INPUT=$(printf '%s' "$SGA_INPUT")
}

# Only one JSON value in which each script's own `$(jq -r '.x // empty')` yields a plain string with no NUL (which bash would drop), trailing newlines trimmed as that substitution trims them: anything else returns 1, and the caller parses it the way it always did.
sg_parse_payload() {
  local _assign
  # Options a stage inherits (errexit, posix, pipefail from SHELLOPTS or POSIXLY_CORRECT, nocasematch from BASHOPTS) act on the code that changed, so only the defaults take this route.
  [ "$-" = hB ] && ! shopt -oq posix && ! shopt -oq pipefail && ! shopt -q nocasematch 2>/dev/null || return 1
  [ -n "$SGA_INPUT" ] || return 1
  # The eval reads jq's quotes as jq meant only in UTF-8 (— is one character) or where bytes 80–ff are one character each: an EUC decoder can take a quote as a later byte.
  _assign=$'\xe2\x80\x94'; [ ${#_assign} -eq 1 ] || { printf -v _assign '\\x%x' {128..255}; printf -v _assign '%b' "$_assign"; [ ${#_assign} -eq 128 ]; } || return 1
  # The newlines are counted from the end in one pass: trimming them one at a time copied the string each time, 27 s for 60,000 of them on bash 5.
  _assign=$(printf '%s' "$SGA_INPUT" | jq -rs 'def plain: . == null or . == false or (type == "string" and (test("\u0000") | not));
    def field: . // "" | if endswith("\n") then explode | .[:length - ((reverse | map(. == 10) | index(false)) // length)] | implode else . end | @sh;
    if length == 1 and (.[0] | type == "object" and (.tool_input == null or (.tool_input | type) == "object")
       and (.tool_input.command | plain) and (.hook_event_name | plain) and (.session_id | plain) and (.cwd | plain))
    then .[0] | "SGA_CMD=\(.tool_input.command | field) SGA_EVENT=\(.hook_event_name | field) SGA_SESSION=\(.session_id | field) SGA_CWD=\(.cwd | field)"
    else empty end' 2>/dev/null) || return 1
  [ "${_assign:0:8}" = "SGA_CMD=" ] || return 1
  eval "$_assign" || return 1
  # Without a session id the duplicate-read tracker is named after $PPID, which is the authority's parent once a stage is sourced rather than run.
  [ -n "$SGA_SESSION" ] || [ -n "${CLAUDE_CODE_SESSION_ID:-}" ] || return 1
  # shellcheck disable=SC2034  # read by the scripts that source this
  SGA_PREPARSED=1
}
