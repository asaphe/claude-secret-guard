#!/usr/bin/env bash
# PreToolUse Bash-side counterpart to write-secret-guard.sh. Blocks a command that both writes to a file (redirect/heredoc/tee) and embeds a matching secret shape — narrower than "any command containing the pattern" to keep the same false-positive posture as the prompt guard.

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/secret-shapes.sh"
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
# An unset pattern makes grep match every byte, so the guard would block all content while looking like it found a secret in it.
[ -n "${SECRET_PATTERN:-}" ] || { echo "WRITE-SECRET GUARD: could not load scripts/secret-shapes.sh — blocking, because the guard has no shapes to check against." >&2; exit 2; }

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "WRITE-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is free of secret-shaped literals." >&2
  exit 2
fi
# Blocks rather than allows: an unparseable payload cannot be shown to be safe, and jq failing here would otherwise exit 0 on every call and disarm the guard silently.
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "WRITE-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is free of secret-shaped literals. Install jq, or disable the secret-guard plugin deliberately." >&2
  exit 2
fi
[ -z "$CMD" ] && exit 0

# normalize_cmd only, never strip_cmd: this is the one guard whose payload IS the heredoc body, so masking it would hide the very text being written.
# Both spellings are scanned as two lines rather than the normalized one alone: the raw line is where an escape is part of the secret's own boundary, and normalization widens most of these predicates but narrows the two that require a quote character, open('f','w') and git commit -m"…".
WRITE_SCAN=$(printf '%s\n%s' "$CMD" "$(normalize_cmd "$CMD")")

IS_WRITE=0
# A backslash quotes the delimiter exactly like '' or "", so <<\EOF is a heredoc the earlier quote-only form skipped.
printf '%s\n' "$WRITE_SCAN" | grep -qE '(^|[^<])<<[-~]?[[:space:]]*(\\|"|'"'"')?[A-Za-z_]' && IS_WRITE=1
printf '%s\n' "$WRITE_SCAN" | grep -qE '\btee\b' && IS_WRITE=1
# Writers that never spell a redirect. Each needs its writing form, not just its name: a bare `install` matches `npm install`, which writes no file the guard cares about.
printf '%s\n' "$WRITE_SCAN" | grep -qE '\b(dd|truncate)\b|\b(sed|perl|ruby)\b[^|;&]*([[:space:]]-[A-Za-z]*i|--in-place)|(^|[;&|])[[:space:]]*(sudo[[:space:]]+)?([A-Za-z0-9_.-]*/)*install[[:space:]]|\b(curl|wget)\b[^|;&]*([[:space:]]-[A-Za-z]*[oO]|--output)' && IS_WRITE=1
# The mode argument, not any w/a in the path: open('data.json') is a read.
printf '%s\n' "$WRITE_SCAN" | grep -qE "\bopen\([^)]*,[^)]*['\"][wax]" && IS_WRITE=1
# A commit or tag message persists to disk in git history, which is why this guard alone does not strip_cmd the way the fetch-detecting guards do.
printf '%s\n' "$WRITE_SCAN" | grep -qE '\bgit\b[^|;&]*[[:space:]](commit|tag)\b[^|;&]*([[:space:]]-[A-Za-z]*[mF]([[:space:]]|=|"|'"'"')|--message|--file)' && IS_WRITE=1
# An fd prefix is part of the operator; >& reaches a file unless its target is a digit or -, which is duplication; >( is a write-side substitution.
printf '%s\n' "$WRITE_SCAN" | grep -qE '[0-9&]?>>?[[:space:]]*([^&>[:space:]]|&[[:space:]]*[^0-9>&[:space:]-])' && IS_WRITE=1
[ "$IS_WRITE" -eq 0 ] && exit 0

# No generator bail-out on any surface: the generator's output never appears in the command text, so piping it was never blocked and the exemption only ever served text that merely named the path.
# The same two lines the writer test used: quoting AKIA''XT… out of one shape is exactly how a literal reaches a file unseen, and exempting on the raw text alone would clear a split key that sat beside a listed fixture.
if printf '%s\n' "$WRITE_SCAN" | grep -qE -- "$SECRET_PATTERN"; then
  if fixture_exempt "$WRITE_SCAN"; then
    echo "WRITE-SECRET GUARD: allowed — every matched literal is a sanctioned fixture in fixtures.allow: $SECRET_GUARD_EXEMPTED" >&2
    exit 0
  fi
  echo "WRITE-SECRET GUARD: this command writes to a file and embeds a raw secret-shaped literal (private key / AWS access key / Slack bot token / GitLab PAT). Use a reference (env var, masked-cache path) instead of the literal value — never hardcode it into a script. If it is a test fixture, add its exact value to the plugin's fixtures.allow, or pipe scripts/fixture-value.sh — do not assemble it from fragments to get past this guard." >&2
  exit 2
fi

exit 0
