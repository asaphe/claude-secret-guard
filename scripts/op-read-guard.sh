#!/usr/bin/env bash
# 1Password duplicate-read guard — keys on the parsed secret identity (account, item, fields), never the raw command text, so two fields of one item are distinct reads and a flag reorder is not a new one.

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty')

if [ -z "$CMD" ]; then
  exit 0
fi

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
