#!/usr/bin/env bash
# PreToolUse Bash-side counterpart to write-secret-guard.sh. Blocks a command that both writes to a file (redirect/heredoc/tee) and embeds a matching secret shape — narrower than "any command containing the pattern" to keep the same false-positive posture as the prompt guard.

# No allowlist-config exemption here, unlike the tool-side guard — see README § Allowlist-config exemption.
PATTERN='-----BEGIN[ A-Z0-9]*PRIVATE KEY-----|\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16}\b|\bxoxb-[0-9]{10,13}-[0-9]{10,13}|\bglpat-[A-Za-z0-9_-]{20,}'

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
# normalize_cmd only, never strip_cmd: this is the one guard whose payload IS the heredoc body, so masking it would hide the very text being written.
# Both spellings are scanned as two lines rather than the normalized one alone: the raw line is where an escape is part of the secret's own boundary, and normalization would narrow a predicate that matches on a quote character.
WRITE_SCAN=$(printf '%s\n%s' "$CMD" "$(normalize_cmd "$CMD")")

IS_WRITE=0
echo "$WRITE_SCAN" | grep -qE '<<[-~]?[[:space:]]*"?'"'"'?[A-Za-z_]' && IS_WRITE=1
echo "$WRITE_SCAN" | grep -qE '\btee\b' && IS_WRITE=1
echo "$WRITE_SCAN" | grep -qE '[^0-9&]>>?[^&]' && IS_WRITE=1
[ "$IS_WRITE" -eq 0 ] && exit 0

# The same two lines the writer test used: quoting AKIA''XT... out of one shape is exactly how a literal reaches a file unseen, which is the split this guard tells the caller not to perform.
if echo "$WRITE_SCAN" | grep -qE -- "$PATTERN"; then
  echo "WRITE-SECRET GUARD: this command writes to a file and embeds a raw secret-shaped literal (private key / AWS access key / Slack bot token / GitLab PAT). Use a reference (env var, masked-cache path) instead of the literal value — never hardcode it into a script. Writing a secret-scanner allowlist (.gitleaks.toml, .gitleaksignore) is exempt only via the Write/Edit tools, which check the target path; this Bash path cannot verify it." >&2
  exit 2
fi

exit 0
