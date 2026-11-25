#!/usr/bin/env bash
# UserPromptSubmit hook. Tiny high-confidence block-list only: a false positive here erases the whole prompt, so this must never grow beyond near-zero-FP shapes.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
_sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }

# Every verdict below is a grep, and a grep that cannot run matches nothing, which reads as safe - see README § Failing closed.
command -v grep >/dev/null 2>&1 || { echo "PASTE-SECRET GUARD: grep is not on PATH. Blocking: the guard cannot confirm this prompt is free of secret-shaped literals." >&2; exit 2; }

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
# Blocks rather than allows: an unparseable payload cannot be shown to be safe, and jq failing here would otherwise exit 0 on every prompt and disarm the guard silently.
if ! PROMPT=$(printf '%s' "$INPUT" | jq -r '.prompt // empty' 2>/dev/null); then
  echo "PASTE-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this prompt is free of secret-shaped literals. Install jq, or disable the secret-guard plugin deliberately." >&2
  exit 2
fi
[ -z "$PROMPT" ] && exit 0

if printf '%s\n' "$PROMPT" | grep -qE -- "$SECRET_PATTERN"; then
  # Notice goes to stderr: on exit 0 this hook's stdout is appended to the model's context.
  if fixture_exempt "$PROMPT"; then
    echo "PASTE-SECRET GUARD: allowed — every matched literal is a sanctioned fixture in fixtures.allow: $SECRET_GUARD_EXEMPTED" >&2
    exit 0
  fi
  jq -n '{decision: "block", reason: "PASTE-SECRET GUARD: this prompt looks like it contains a raw secret (AWS key / Slack bot token / GitLab PAT / private key). Blocked before it enters history/paste-cache. Use a masked wrapper (see README) if this needs to reach a command, or resend without the literal value. If it is a sanctioned test fixture, its exact value belongs in the plugin fixtures.allow; otherwise reference the value rather than pasting it."}'
  exit 0
fi

exit 0
