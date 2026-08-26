#!/usr/bin/env bash
# UserPromptSubmit hook. Tiny high-confidence block-list only: a false positive here erases the whole prompt, so this must never grow beyond near-zero-FP shapes.

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/secret-shapes.sh"
# An unset pattern makes grep match every byte, so the guard would block all content while looking like it found a secret in it.
[ -n "${SECRET_PATTERN:-}" ] || { echo "PASTE-SECRET GUARD: could not load scripts/secret-shapes.sh — blocking, because the guard has no shapes to check against." >&2; exit 2; }

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "PASTE-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this prompt is free of secret-shaped literals." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty prompt, which the check below reads as "nothing to inspect".
if ! PROMPT=$(printf '%s' "$INPUT" | jq -r '.prompt // empty' 2>/dev/null); then
  echo "PASTE-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this prompt is free of secret-shaped literals." >&2
  exit 2
fi
[ -z "$PROMPT" ] && exit 0

if printf '%s' "$PROMPT" | grep -qE -- "$SECRET_PATTERN"; then
  if fixture_exempt "$PROMPT"; then
    echo "PASTE-SECRET GUARD: allowed — every matched literal is a sanctioned fixture in fixtures.allow: $SECRET_GUARD_EXEMPTED" >&2
    exit 0
  fi
  jq -n '{decision: "block", reason: "PASTE-SECRET GUARD: this prompt looks like it contains a raw secret (AWS key / Slack bot token / GitLab PAT / private key). Blocked before it enters history/paste-cache. Use a masked wrapper (see README) if this needs to reach a command, or resend without the literal value."}'
  exit 0
fi

exit 0
