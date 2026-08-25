#!/usr/bin/env bash
# PreToolUse hook (Write|Edit|MultiEdit). Content-scans the new text for the same near-zero-FP shapes as the prompt guard, before it lands in a file.

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/secret-shapes.sh"
# An unset pattern makes grep match every byte, so the guard would block all content while looking like it found a secret in it.
[ -n "${SECRET_PATTERN:-}" ] || { echo "WRITE-SECRET GUARD: could not load scripts/secret-shapes.sh — blocking, because the guard has no shapes to check against." >&2; exit 2; }

INPUT=$(cat)
# Blocks rather than allows: jq failing here yields empty content, which the check below reads as "nothing to inspect".
if ! TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null); then
  echo "WRITE-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this call is free of secret-shaped literals." >&2
  exit 2
fi

CONTENT=""
case "$TOOL" in
  Write)     CONTENT=$(printf '%s' "$INPUT" | jq -r '.tool_input.content // empty') ;;
  Edit)      CONTENT=$(printf '%s' "$INPUT" | jq -r '.tool_input.new_string // empty') ;;
  MultiEdit) CONTENT=$(printf '%s' "$INPUT" | jq -r '[.tool_input.edits[]?.new_string // empty] | join("\n")') ;;
esac

[ -z "$CONTENT" ] && exit 0

# A secret scanner's allowlist has to name the fixture literals it exempts, so these shapes are its legitimate content.
FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')
case "${FILE_PATH##*/}" in
  .gitleaks.toml|gitleaks.toml|.gitleaksignore|.secretsignore) exit 0 ;;
esac

if printf '%s' "$CONTENT" | grep -qE -- "$SECRET_PATTERN"; then
  if fixture_exempt "$CONTENT"; then
    echo "WRITE-SECRET GUARD: allowed — every matched literal is a sanctioned fixture in fixtures.allow: $SECRET_GUARD_EXEMPTED" >&2
    exit 0
  fi
  echo "WRITE-SECRET GUARD: this $TOOL call would write a raw secret-shaped literal (private key / AWS access key / Slack bot token / GitLab PAT) into a file. Use a reference (env var, masked-cache path) instead of the literal value — never hardcode it into code." >&2
  exit 2
fi

exit 0
