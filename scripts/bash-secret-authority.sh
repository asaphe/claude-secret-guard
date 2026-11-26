#!/usr/bin/env bash
# Single PreToolUse Bash authority for this plugin's block/ask stages — see README § Why one Bash authority script, not several parallel hooks.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
[ "${LC_ALL:-}" = C ] || unset SG_ASCII_TRAIL; _sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }

# Every verdict below is a grep, and a grep that cannot run matches nothing, which reads as safe - see README § Failing closed.
command -v grep >/dev/null 2>&1 || { echo "SECRET GUARD: grep is not on PATH. Blocking: the guard cannot confirm this command is safe." >&2; exit 2; }

# Inherited from the environment, these would tell a stage that a payload nobody parsed was already parsed.
unset SGA_PREPARSED SG_NC_PRIMED SGA_HAVE SGA_LOADING
HOOKS_DIR=${BASH_SOURCE[0]%/*}; [ "$HOOKS_DIR" != "${BASH_SOURCE[0]}" ] || HOOKS_DIR=.
# Checked first: in posix mode a . that cannot open its file exits the shell.
# shellcheck source-path=SCRIPTDIR
{ [ -f "$HOOKS_DIR/hook-payload.sh" ] && [ -r "$HOOKS_DIR/hook-payload.sh" ] && . "$HOOKS_DIR/hook-payload.sh" 2>/dev/null && sg_read_payload; } || SGA_INPUT=$(cat)

# Each stage runs in a fork of this process: BASH_ENV (read by every exec'd bash) or FUNCNEST (sg_stage adds levels) keeps each stage its own bash.
if [ -z "${BASH_ENV:-}" ] && [ -z "${FUNCNEST:-}" ] && sg_parse_payload 2>/dev/null; then
  # Loaded here rather than in each fork, which an endpoint agent can hold ~250 ms per process it starts once it has opened a script - see README § Process launches per call.
  SGA_HAVE=" "
  # A helper not listed in SGA_HAVE is sourced by each stage itself, which then fails exactly as it did.
  # shellcheck source=/dev/null
  for _sg_f in strip-cmd.sh secret-shapes.sh session-namespace.sh; do { [ -f "$HOOKS_DIR/$_sg_f" ] && [ -r "$HOOKS_DIR/$_sg_f" ] && . "$HOOKS_DIR/$_sg_f"; } 2>/dev/null && SGA_HAVE+="$_sg_f "; done
  # One sed for the call instead of one per stage.
  [ -z "$SGA_CMD" ] || [[ $SGA_HAVE != *" strip-cmd.sh "* ]] || normalize_cmd_prime "$SGA_CMD" 2>/dev/null
  # shellcheck disable=SC2034  # read by each stage file's dispatch line
  SGA_LOADING=1
  # shellcheck source=/dev/null
  for _sg_f in secret-mask-guard.sh write-secret-guard-bash.sh op-read-guard.sh read-secret-guard-bash.sh; do { [ -f "$HOOKS_DIR/$_sg_f" ] && [ -r "$HOOKS_DIR/$_sg_f" ] && . "$HOOKS_DIR/$_sg_f"; } 2>/dev/null; done
  unset SGA_LOADING
  # The comsub is the fork; a stage that did not load is sourced there, and one that cannot be read is exec'd, so bash reports either as it always did.
  # shellcheck source=/dev/null
  sg_stage() {
    local _sg_fn=sg_${1%.sh}; _sg_fn=${_sg_fn//-/_}
    if declare -F "$_sg_fn" >/dev/null; then SECONDS=0; "$_sg_fn" "$@"
    elif [ -f "$HOOKS_DIR/$1" ] && [ -r "$HOOKS_DIR/$1" ]; then ( SECONDS=0; . "$HOOKS_DIR/$1" )
    else printf '%s' "$SGA_INPUT" | bash "$HOOKS_DIR/$1"; fi
  }
else
  # Any payload the one-jq parse does not take is piped to each stage exactly as before, so each refuses or reads it with its own parse.
  sg_stage() { printf '%s' "$SGA_INPUT" | bash "$HOOKS_DIR/$1"; }
fi

BLOCK_OUT=$(sg_stage secret-mask-guard.sh)
BLOCK_CODE=$?
if [ "$BLOCK_CODE" -ne 0 ]; then
  [ -n "$BLOCK_OUT" ] && printf '%s\n' "$BLOCK_OUT" >&2
  exit "$BLOCK_CODE"
fi

WRITE_BLOCK_OUT=$(sg_stage write-secret-guard-bash.sh)
WRITE_BLOCK_CODE=$?
if [ "$WRITE_BLOCK_CODE" -ne 0 ]; then
  [ -n "$WRITE_BLOCK_OUT" ] && printf '%s\n' "$WRITE_BLOCK_OUT" >&2
  exit "$WRITE_BLOCK_CODE"
fi

DUP_OUT=$(sg_stage op-read-guard.sh)
DUP_CODE=$?
if [ "$DUP_CODE" -ne 0 ]; then
  [ -n "$DUP_OUT" ] && printf '%s\n' "$DUP_OUT" >&2
  exit "$DUP_CODE"
fi

ASK_OUT=$(sg_stage read-secret-guard-bash.sh)
ASK_CODE=$?
# Without this the reader's own fail-closed branch is inert on the wired path: only its stdout was read, so a non-zero exit reached the caller as a plain allow.
if [ "$ASK_CODE" -ne 0 ]; then
  [ -n "$ASK_OUT" ] && printf '%s\n' "$ASK_OUT" >&2
  exit "$ASK_CODE"
fi
if [ -n "$ASK_OUT" ]; then
  printf '%s\n' "$ASK_OUT"
  exit 0
fi

exit 0
