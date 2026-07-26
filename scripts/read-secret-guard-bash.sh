#!/usr/bin/env bash
# PreToolUse Bash hook, mirrors read-secret-guard.sh's basename gate for cat/head/tail/less/grep readers.

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
CMD=$(strip_cmd "$CMD")

echo "$CMD" | grep -qE '^\s*(cat|head|tail|less|more)\b' || echo "$CMD" | grep -qE '\bgrep\b.*-r' || exit 0

ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

for token in $CMD; do
  BASENAME=$(basename "$token" 2>/dev/null)
  if echo "$BASENAME" | grep -qE '^\.env(\..+)?$' && ! echo "$BASENAME" | grep -qE '^\.env\.(example|sample|template)$'; then
    ask "READ-SECRET GUARD: $BASENAME looks like a live env file — confirm before its contents enter context/transcript."
  fi
  if echo "$BASENAME" | grep -qE '\.(pem|key|p12|pfx)$' \
     || echo "$BASENAME" | grep -qE '^id_(rsa|ed25519|ecdsa|dsa)$' \
     || echo "$BASENAME" | grep -qE '^kubeconfig$' \
     || echo "$token" | grep -qE '\.kube/config$'; then
    ask "READ-SECRET GUARD: $BASENAME looks like a private key or kubeconfig — confirm before its contents enter context/transcript."
  fi
done

exit 0
