#!/usr/bin/env bash
# UserPromptSubmit hook. Tiny high-confidence block-list only: a false positive here erases the whole prompt, so this must never grow beyond near-zero-FP shapes.

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty')
[ -z "$PROMPT" ] && exit 0

if echo "$PROMPT" | grep -qE -- '-----BEGIN[ A-Z0-9]*PRIVATE KEY-----|\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16}\b|\bxoxb-[0-9]{10,13}-[0-9]{10,13}|\bglpat-[A-Za-z0-9_-]{20,}'; then
  jq -n '{decision: "block", reason: "PASTE-SECRET GUARD: this prompt looks like it contains a raw secret (AWS key / Slack bot token / GitLab PAT / private key). Blocked before it enters history/paste-cache. Use a masked wrapper (see README) if this needs to reach a command, or resend without the literal value."}'
  exit 0
fi

exit 0
