#!/usr/bin/env bash
# Single PreToolUse Bash authority for this plugin's block/ask stages — see README § Why one script, not several parallel hooks.

HOOKS_DIR="$(dirname "${BASH_SOURCE[0]}")"
INPUT=$(cat)

BLOCK_OUT=$(printf '%s' "$INPUT" | bash "$HOOKS_DIR/secret-mask-guard.sh")
BLOCK_CODE=$?
if [ "$BLOCK_CODE" -ne 0 ]; then
  [ -n "$BLOCK_OUT" ] && echo "$BLOCK_OUT" >&2
  exit "$BLOCK_CODE"
fi

WRITE_BLOCK_OUT=$(printf '%s' "$INPUT" | bash "$HOOKS_DIR/write-secret-guard-bash.sh")
WRITE_BLOCK_CODE=$?
if [ "$WRITE_BLOCK_CODE" -ne 0 ]; then
  [ -n "$WRITE_BLOCK_OUT" ] && echo "$WRITE_BLOCK_OUT" >&2
  exit "$WRITE_BLOCK_CODE"
fi

DUP_OUT=$(printf '%s' "$INPUT" | bash "$HOOKS_DIR/op-read-guard.sh")
DUP_CODE=$?
if [ "$DUP_CODE" -ne 0 ]; then
  [ -n "$DUP_OUT" ] && echo "$DUP_OUT" >&2
  exit "$DUP_CODE"
fi

ASK_OUT=$(printf '%s' "$INPUT" | bash "$HOOKS_DIR/read-secret-guard-bash.sh")
if [ -n "$ASK_OUT" ]; then
  echo "$ASK_OUT"
  exit 0
fi

exit 0
