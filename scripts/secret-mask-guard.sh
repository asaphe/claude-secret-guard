#!/usr/bin/env bash
# Blocks a raw `op read <uri>` or single-secret `aws secretsmanager get-secret-value --secret-id <id>` call and suggests the masked wrapper instead, so the value never has to reach the tool_result/transcript in the first place — see README § Masked-cache wrappers.

INPUT=$(cat)

# A guard that cannot read its own input has not cleared the command — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "SECRET-MASK GUARD: hook input is empty or not valid JSON, so this command could not be checked for a raw secret read. Refusing it rather than running it unguarded — verify 'jq' is installed and on PATH." >&2
  exit 2
fi

CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')

if [ -z "$CMD" ]; then
  exit 0
fi

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
STRIPPED=$(strip_cmd "$CMD")
if [ -z "$STRIPPED" ]; then
  echo "SECRET-MASK GUARD: the command text could not be normalized, so it could not be checked for a raw secret read. Refusing it rather than running it unguarded — verify 'perl' is installed and on PATH." >&2
  exit 2
fi
CMD="$STRIPPED"

# Already routed through the masked wrapper — nothing to guard.
if echo "$CMD" | grep -qE 'scripts/(op|sm)-cache\.sh'; then
  exit 0
fi

# --- op read <uri> ---
if echo "$CMD" | grep -qE '(^|[^[:alnum:]_-])op[[:space:]]([^|;&]* )?read([[:space:]]|$)' \
   && ! echo "$CMD" | grep -qE '(^|[^[:alnum:]_-])op[[:space:]]([^|;&]* )?item +get([[:space:]]|$)'; then
  URI=$(echo "$CMD" | grep -oE 'op://[^ "'"'"']+' | head -1)
  if [ -n "$URI" ]; then
    echo "SECRET-MASK GUARD: raw 'op read' would put the value in this tool_result/transcript. Use the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask '$URI' — then reference the value downstream via \$(cat <the printed cache path>), never the literal." >&2
  else
    echo "SECRET-MASK GUARD: raw 'op read' would put the value in this tool_result/transcript. Use \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask <uri> instead, then reference the cached file downstream — never the literal value." >&2
  fi
  exit 2
fi

# --- aws secretsmanager batch-get-secret-value (bulk fetch, many values at once) ---
if echo "$CMD" | grep -qE '(^|[^[:alnum:]_-])(aws|rtk aws)[[:space:]]([^|;&]* )?secretsmanager +batch-get-secret-value([[:space:]]|$)'; then
  echo "SECRET-MASK GUARD: raw 'batch-get-secret-value' would put every fetched value in this tool_result/transcript. Use the masked bulk reader instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/aws-batch-secrets.sh --filter <prefix> --values — prints names + byte-lengths only; add --reveal to opt into full values when genuinely needed." >&2
  exit 2
fi

# --- aws secretsmanager get-secret-value --secret-id <id> (single-secret only) ---
if echo "$CMD" | grep -qE '(^|[^[:alnum:]_-])(aws|rtk aws)[[:space:]]([^|;&]* )?secretsmanager +get-secret-value([[:space:]]|$)'; then
  SECRET_ID=$(echo "$CMD" | grep -oE -- '--secret-id[[:space:]]+[^[:space:]]+' | awk '{print $2}' | tr -d '"'"'"'')
  if [ -n "$SECRET_ID" ]; then
    echo "SECRET-MASK GUARD: raw 'get-secret-value' would put the value in this tool_result/transcript. Use the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/sm-cache.sh --mask '$SECRET_ID' — then reference the value downstream via \$(cat <the printed cache path>) or jq against it, never the literal." >&2
  else
    echo "SECRET-MASK GUARD: raw 'get-secret-value' would put the value in this tool_result/transcript. Use \"${CLAUDE_PLUGIN_ROOT}\"/scripts/sm-cache.sh --mask <secret-id> instead, then reference the cached file downstream — never the literal value." >&2
  fi
  exit 2
fi

exit 0
