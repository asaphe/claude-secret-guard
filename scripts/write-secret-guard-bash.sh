#!/usr/bin/env bash
# PreToolUse Bash-side counterpart to write-secret-guard.sh. Blocks a command that both writes to a file (redirect/heredoc/tee) and embeds a matching secret shape — narrower than "any command containing the pattern" to keep the same false-positive posture as the prompt guard.

# No allowlist-config exemption here, unlike the tool-side guard — see README § Allowlist-config exemption.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/secret-shapes.sh"
# An unset pattern makes grep match every byte, so the guard would block all content while looking like it found a secret in it.
[ -n "${SECRET_PATTERN:-}" ] || { echo "WRITE-SECRET GUARD: could not load scripts/secret-shapes.sh — blocking, because the guard has no shapes to check against." >&2; exit 2; }

INPUT=$(cat)
# Blocks rather than allows: jq failing here yields an empty command, which the check below reads as "nothing to inspect".
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "WRITE-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is free of secret-shaped literals." >&2
  exit 2
fi
[ -z "$CMD" ] && exit 0

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
# normalize_cmd only, never strip_cmd: this is the one guard whose payload IS the heredoc body, so only the writer test below is normalized and the scan at the end still reads the raw command.
# Both spellings are scanned as two lines rather than the normalized one alone, because normalization would narrow a predicate that matches on a quote character.
WRITE_SCAN=$(printf '%s\n%s' "$CMD" "$(normalize_cmd "$CMD")")

IS_WRITE=0
echo "$WRITE_SCAN" | grep -qE '<<[-~]?[[:space:]]*"?'"'"'?[A-Za-z_]' && IS_WRITE=1
echo "$WRITE_SCAN" | grep -qE '\btee\b' && IS_WRITE=1
echo "$WRITE_SCAN" | grep -qE '[^0-9&]>>?[^&]' && IS_WRITE=1
[ "$IS_WRITE" -eq 0 ] && exit 0

if printf '%s' "$CMD" | grep -qE -- "$SECRET_PATTERN"; then
  if fixture_exempt "$CMD"; then
    echo "WRITE-SECRET GUARD: allowed — every matched literal is a sanctioned fixture in fixtures.allow: $SECRET_GUARD_EXEMPTED" >&2
    exit 0
  fi
  echo "WRITE-SECRET GUARD: this command writes to a file and embeds a raw secret-shaped literal (private key / AWS access key / Slack bot token / GitLab PAT). Use a reference (env var, masked-cache path) instead of the literal value — never hardcode it into a script. Writing a secret-scanner allowlist (.gitleaks.toml, .gitleaksignore) is exempt only via the Write/Edit tools, which check the target path; this Bash path cannot verify it." >&2
  exit 2
fi

exit 0
