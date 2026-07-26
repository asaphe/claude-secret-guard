#!/usr/bin/env bash
# 1Password duplicate-read guard — detects repeated `op read` calls within a session and blocks with a reminder to reuse the cached value instead of re-triggering a biometric prompt.

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty')

if [ -z "$CMD" ]; then
  exit 0
fi

if ! echo "$CMD" | grep -qE 'op[[:space:]]([^|;&]* )?read([[:space:]]|$)'; then
  if ! echo "$CMD" | grep -qE 'op[[:space:]]([^|;&]* )?item +get([[:space:]]|$)'; then
    exit 0
  fi
fi

SECRET_REF=$(echo "$CMD" | grep -oE 'op://[^ "'"'"']+' | head -1)
if [ -z "$SECRET_REF" ]; then
  SECRET_REF=$(echo "$CMD" | grep -oE "op +item +get +['\"]?[^'\"]+['\"]?" | head -1)
fi

if [ -z "$SECRET_REF" ]; then
  exit 0
fi

TRACK_FILE="/tmp/claude-op-reads-${SESSION_ID:-shared}"

if [ -f "$TRACK_FILE" ] && grep -qF "$SECRET_REF" "$TRACK_FILE"; then
  echo "Duplicate op read for $SECRET_REF. You already read this secret earlier in this session. Reuse the value you got before — each op read triggers a biometric prompt." >&2
  exit 2
fi

echo "$SECRET_REF" >> "$TRACK_FILE"
exit 0
