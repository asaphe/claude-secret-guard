#!/usr/bin/env bash
# PreToolUse Read hook. Files with secret-shaped basenames (live .env, private keys, kubeconfig) get an "ask" gate instead of reaching context/transcript silently.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
_sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }

# Every verdict below is a grep, and a grep that cannot run matches nothing, which reads as safe - see README § Failing closed.
command -v grep >/dev/null 2>&1 || { echo "READ-SECRET GUARD: grep is not on PATH. Blocking: the guard cannot confirm this read is safe." >&2; exit 2; }

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "READ-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this read is safe." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty value that every check below reads as "nothing to inspect", silently disarming the guard.
if ! FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null); then
  echo "READ-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this read is safe." >&2
  exit 2
fi

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Expanded, not `basename`: with that missing from PATH the name came back empty and nothing below matched; trailing slashes go first, as basename drops them.
BASENAME=${FILE_PATH%"${FILE_PATH##*[!/]}"}; BASENAME=${BASENAME##*/}

ask() {
  # A jq that cannot start would print nothing, which reads as allow, so a fixed ask stands in.
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}' 2>/dev/null \
    || printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"READ-SECRET GUARD: this read may target a secret file, and the reason could not be described. Confirm before its contents enter context/transcript."}}'
  exit 0
}

# .env / .env.<suffix>, excluding placeholder variants
if printf '%s\n' "$BASENAME" | grep -qE '^\.env(\..+)?$' \
   && ! printf '%s\n' "$BASENAME" | grep -qE '^\.env\.(example|sample|template)$'; then
  ask "READ-SECRET GUARD: $BASENAME looks like a live env file — confirm before its contents enter context/transcript."
fi

# Private keys, PKCS12/PFX bundles, unencrypted SSH keys, kubeconfigs
if printf '%s\n' "$BASENAME" | grep -qE '\.(pem|key|p12|pfx)$' \
   || printf '%s\n' "$BASENAME" | grep -qE '^id_(rsa|ed25519|ecdsa|dsa)$' \
   || printf '%s\n' "$BASENAME" | grep -qE '^kubeconfig$' \
   || printf '%s\n' "$FILE_PATH" | grep -qE '\.kube/config$'; then
  ask "READ-SECRET GUARD: $BASENAME looks like a private key or kubeconfig — confirm before its contents enter context/transcript."
fi

exit 0
