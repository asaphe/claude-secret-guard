#!/usr/bin/env bash
# Single PreToolUse Bash authority for this plugin's block/ask stages — see README § Why one Bash authority script, not several parallel hooks.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
_sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }

# Every verdict below is a grep, and a grep that cannot run matches nothing, which reads as safe - see README § Failing closed.
command -v grep >/dev/null 2>&1 || { echo "SECRET GUARD: grep is not on PATH. Blocking: the guard cannot confirm this command is safe." >&2; exit 2; }

# Inherited from the environment, these would tell a stage that a payload nobody parsed was already parsed.
unset SGA_PREPARSED SG_NC_PRIMED
HOOKS_DIR=${BASH_SOURCE[0]%/*}; [ "$HOOKS_DIR" != "${BASH_SOURCE[0]}" ] || HOOKS_DIR=.
# Checked first: in posix mode a . that cannot open its file exits the shell.
# shellcheck source-path=SCRIPTDIR
{ [ -f "$HOOKS_DIR/hook-payload.sh" ] && [ -r "$HOOKS_DIR/hook-payload.sh" ] && . "$HOOKS_DIR/hook-payload.sh" 2>/dev/null && sg_read_payload; } || SGA_INPUT=$(cat)

# Each stage is sourced in a subshell, a fork: BASH_ENV (read by every exec'd bash) or FUNCNEST (sg_stage adds a level) keeps each stage its own bash.
if [ -z "${BASH_ENV:-}" ] && [ -z "${FUNCNEST:-}" ] && sg_parse_payload 2>/dev/null; then
  # One sed for the call instead of one per stage; a stage that cannot source this fails exactly as it did, since each still sources it itself.
  # shellcheck source-path=SCRIPTDIR
  [ -z "$SGA_CMD" ] || { . "$HOOKS_DIR/strip-cmd.sh" && normalize_cmd_prime "$SGA_CMD"; } 2>/dev/null
  # A stage file that cannot be sourced is exec'd, so bash reports it as it always did.
  # shellcheck source=/dev/null
  sg_stage() { if [ -f "$HOOKS_DIR/$1" ] && [ -r "$HOOKS_DIR/$1" ]; then ( SECONDS=0; . "$HOOKS_DIR/$1" ); else printf '%s' "$SGA_INPUT" | bash "$HOOKS_DIR/$1"; fi; }
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
