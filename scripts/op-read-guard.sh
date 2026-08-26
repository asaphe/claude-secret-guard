#!/usr/bin/env bash
# 1Password duplicate-read guard — keys on the parsed secret identity (account, item, fields), never the raw command text, so two fields of one item are distinct reads and a flag reorder is not a new one.

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "OP-READ GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty command, which the check below reads as "nothing to inspect".
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "OP-READ GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
if ! SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null); then
  echo "OP-READ GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi

if [ -z "$CMD" ]; then
  exit 0
fi

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
# Without this a commit message or a heredoc quoting a reference is recorded as a fetch, so the real fetch of it is later refused as a duplicate.
CMD=$(strip_cmd "$CMD")
# Same normalization the mask guard matches on, so `op "item" get` keys the same entry as `op item get` rather than fetching twice.
CMD=$(normalize_cmd "$CMD")

if ! echo "$CMD" | grep -qE '(^|[^[:alnum:]_-])op[[:space:]]([^|;&]* )?read([[:space:]]|$)'; then
  if ! echo "$CMD" | grep -qE '(^|[^[:alnum:]_-])op[[:space:]]([^|;&]* )?item +get([[:space:]]|$)'; then
    exit 0
  fi
fi

# xargs applies shell quoting rules, so a quoted --fields value survives as a single token
TOKENS=$(printf '%s\n' "$CMD" | xargs -n1 2>/dev/null) || exit 0
if [ -z "$TOKENS" ]; then
  exit 0
fi

ACCOUNT=""
ITEM=""
FIELDS=""
SEEN_GET=0
PENDING=""

while IFS= read -r TOK; do
  if [ -n "$PENDING" ]; then
    case "$PENDING" in
      --account) ACCOUNT="$TOK" ;;
      --fields|--field) FIELDS="$FIELDS,$TOK" ;;
    esac
    PENDING=""
    continue
  fi
  case "$TOK" in
    --account=*) ACCOUNT="${TOK#--account=}" ;;
    --fields=*)  FIELDS="$FIELDS,${TOK#--fields=}" ;;
    --field=*)   FIELDS="$FIELDS,${TOK#--field=}" ;;
    --account|--fields|--field|--format|--vault|--session|--config|--encoding|--cache|--otp) PENDING="$TOK" ;;
    get) SEEN_GET=1 ;;
    -*) : ;;
    *) if [ "$SEEN_GET" -eq 1 ] && [ -z "$ITEM" ]; then ITEM="$TOK"; fi ;;
  esac
done <<EOF
$TOKENS
EOF

URI=$(echo "$CMD" | grep -oE 'op://[^ "'"'"']+' | head -1)

if [ -n "$URI" ]; then
  KEY="uri|${ACCOUNT}|${URI}"
  WHAT="$URI"
else
  if [ -z "$ITEM" ]; then
    exit 0
  fi
  NORM=$(printf '%s' "${FIELDS#,}" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sort -u | tr '\n' ',' | sed 's/,$//')
  if [ -z "$NORM" ]; then
    NORM='(whole item)'
  fi
  KEY="item|${ACCOUNT}|${ITEM}|${NORM}"
  WHAT="item ${ITEM} → ${NORM}"
fi

TRACK_FILE="/tmp/claude-op-reads-${SESSION_ID:-shared}"

if [ -f "$TRACK_FILE" ] && grep -qxF "$KEY" "$TRACK_FILE"; then
  echo "Duplicate op read: ${WHAT}. You already read this exact secret earlier in this session — reuse the value you got before, since each read triggers a biometric prompt. A different field of the same item counts as a separate secret and is allowed." >&2
  exit 2
fi

printf '%s\n' "$KEY" >> "$TRACK_FILE"
exit 0
