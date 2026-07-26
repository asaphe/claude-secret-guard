#!/usr/bin/env bash
# PreToolUse Read hook. Files with secret-shaped basenames (live .env, private keys, kubeconfig) get an "ask" gate instead of reaching context/transcript silently.

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

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
