#!/usr/bin/env bash
# PreToolUse Read hook. Files with secret-shaped basenames (live .env, private keys, kubeconfig) get an "ask" gate instead of reaching context/transcript silently.

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "READ-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this read is safe." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty path, which the check below reads as "nothing to inspect".
if ! FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null); then
  echo "READ-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this read is safe." >&2
  exit 2
fi

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

BASENAME=$(basename "$FILE_PATH")

ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

# .env / .env.<suffix>, excluding placeholder variants
if echo "$BASENAME" | grep -qE '^\.env(\..+)?$' \
   && ! echo "$BASENAME" | grep -qE '^\.env\.(example|sample|template)$'; then
  ask "READ-SECRET GUARD: $BASENAME looks like a live env file — confirm before its contents enter context/transcript."
fi

# Private keys, PKCS12/PFX bundles, unencrypted SSH keys, kubeconfigs
if echo "$BASENAME" | grep -qE '\.(pem|key|p12|pfx)$' \
   || echo "$BASENAME" | grep -qE '^id_(rsa|ed25519|ecdsa|dsa)$' \
   || echo "$BASENAME" | grep -qE '^kubeconfig$' \
   || echo "$FILE_PATH" | grep -qE '\.kube/config$'; then
  ask "READ-SECRET GUARD: $BASENAME looks like a private key or kubeconfig — confirm before its contents enter context/transcript."
fi

exit 0
