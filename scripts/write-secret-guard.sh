#!/usr/bin/env bash
# PreToolUse hook (Write|Edit|MultiEdit). Content-scans the new text for the same near-zero-FP shapes as the prompt guard, before it lands in a file.

PATTERN='-----BEGIN[ A-Z0-9]*PRIVATE KEY-----|\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16}\b|\bxoxb-[0-9]{10,13}-[0-9]{10,13}|\bglpat-[A-Za-z0-9_-]{20,}'

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')

CONTENT=""
case "$TOOL" in
  Write)     CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty') ;;
  Edit)      CONTENT=$(echo "$INPUT" | jq -r '.tool_input.new_string // empty') ;;
  MultiEdit) CONTENT=$(echo "$INPUT" | jq -r '[.tool_input.edits[]?.new_string // empty] | join("\n")') ;;
esac

[ -z "$CONTENT" ] && exit 0

if echo "$CONTENT" | grep -qE -- "$PATTERN"; then
  echo "WRITE-SECRET GUARD: this $TOOL call would write a raw secret-shaped literal (private key / AWS access key / Slack bot token / GitLab PAT) into a file. Use a reference (env var, masked-cache path) instead of the literal value — never hardcode it into code." >&2
  exit 2
fi

exit 0
