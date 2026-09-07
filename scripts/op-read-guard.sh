#!/usr/bin/env bash
# 1Password duplicate-read guard — keys on the parsed secret identity (account, item, fields), never the raw command text, so two fields of one item are distinct reads and a flag reorder is not a new one.

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "OP-READ GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty value that every check below reads as "nothing to inspect", silently disarming the guard.
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

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
# Without this a commit message quoting a reference is recorded as a fetch, so the real fetch of it is later refused as a duplicate.
CMD=$(strip_cmd "$CMD")
# Same normalization the mask guard matches on, so `op "item" get` keys the same entry as `op item get` rather than fetching twice.
CMD=$(normalize_cmd "$CMD")

if ! printf '%s\n' "$CMD" | grep -qE '(^|[^[:alnum:]_-])op[[:space:]]([^|;&]* )?read([[:space:]]|$)'; then
  if ! printf '%s\n' "$CMD" | grep -qE '(^|[^[:alnum:]_-])op[[:space:]]([^|;&]* )?item +get([[:space:]]|$)'; then
    exit 0
  fi
fi

# printf is named rather than xargs' default echo, whose GNU build reads --help/--version/-n as its own flags and rewrites the token stream; quoting rules still apply so a quoted --fields value stays one token, and unparseable input falls through to allow because secret-mask-guard is the security control ahead of this prompt-frequency gate.
# A newline terminates a command exactly as `;` does, but xargs flattens it away — without this the segments merge and a reference printed on one line keys a fetch on another; a trailing backslash is a continuation, so it gets no separator.
SEGMENTED=$(printf '%s\n' "$CMD" | sed 's/\([^\\]\)$/\1 ;/')
TOKENS=$(printf '%s\n' "$SEGMENTED" | xargs -n1 printf '%s\n' 2>/dev/null) || exit 0
if [ -z "$TOKENS" ]; then
  exit 0
fi

ACCOUNT=""
ITEM=""
FIELDS=""
SEEN_GET=0
PENDING=""
SEG_URI=""
SEG_OP=0

while IFS= read -r TOK; do
  # Shell punctuation is not an argument: without this, `op item get --help 2>&1 | head` records "2>&1" as the item name.
  case "$TOK" in
    # Stop once a segment has produced identity, else restart: a reference form never sets ITEM, but a reference is only identity in a segment that actually invoked op — printed elsewhere it is text, and stopping there would key the whole command on a reference nobody fetched.
    '|'|';'|'&'|'&&'|'||')
      if [ -n "$ITEM" ] || { [ -n "$SEG_URI" ] && [ "$SEG_OP" -eq 1 ]; }; then break; fi
      ACCOUNT=""; FIELDS=""; SEEN_GET=0; PENDING=""; SEG_URI=""; SEG_OP=0
      continue ;;
    *'>'*|*'<'*) continue ;;
  esac
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
    # Only flags the CLI declares an argument type for: a boolean listed here swallows the next token, and when that is --account the key loses it.
    --account|--fields|--field|--format|--vault|--session|--config|--encoding) PENDING="$TOK" ;;
    get) SEEN_GET=1 ;;
    op://*) SEG_URI="$TOK" ;;
    -*) : ;;
    # Identity first: a reference or item name that happens to read as the binary is still identity, so the command word is only what is left over.
    *)
      if [ "$SEEN_GET" -eq 1 ] && [ -z "$ITEM" ]; then
        ITEM="$TOK"
      else
        case "$TOK" in op|*/op) SEG_OP=1 ;; esac
      fi ;;
  esac
done <<EOF
$TOKENS
EOF

# Scanning the whole command keys on the first reference that merely appears in it, so fall back to that only when the segment named neither a reference nor an item to key on.
SCAN="$SEG_URI"
[ -n "$SEG_URI" ] || [ -n "$ITEM" ] || SCAN="$CMD"
URI=$(printf '%s\n' "$SCAN" | grep -oE 'op://[^ "'"'"']+' | head -1)

if [ -n "$URI" ]; then
  KEY="uri|${ACCOUNT}|${URI}"
  WHAT="$URI"
else
  if [ -z "$ITEM" ]; then
    exit 0
  fi
  # Sorted and deduplicated so the same fields requested in a different order are one identity, not two.
  NORM=$(printf '%s' "${FIELDS#,}" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sort -u | tr '\n' ',' | sed 's/,$//')
  if [ -z "$NORM" ]; then
    NORM='(whole item)'
  fi
  KEY="item|${ACCOUNT}|${ITEM}|${NORM}"
  WHAT="item ${ITEM} → ${NORM}"
fi

TRACK_FILE="/tmp/claude-op-reads-${SESSION_ID:-shared}"

# Checked before the read too: a planted file would also poison the duplicate verdict below.
if [ -L "$TRACK_FILE" ] || { [ -e "$TRACK_FILE" ] && { [ ! -f "$TRACK_FILE" ] || [ ! -O "$TRACK_FILE" ]; }; }; then
  echo "OP-READ GUARD: $TRACK_FILE is not a regular file owned by this user — refusing to use it. The name is predictable (the session-less fallback is literally 'shared'), so a planted symlink would redirect this append into any file you can write, and a planted regular file would collect the references you fetch. Remove it and retry." >&2
  exit 2
fi

# Whole-line match: a substring match makes a shorter reference collide with a longer one recorded earlier.
if [ -f "$TRACK_FILE" ] && grep -qxF "$KEY" "$TRACK_FILE"; then
  echo "Duplicate op read: ${WHAT}. You already read this exact secret earlier in this session — reuse the value you got before, since each read triggers a biometric prompt. A different field of the same item counts as a separate secret and is allowed." >&2
  exit 2
fi

# The file lists which references were fetched, which maps the credential topology on a shared machine.
(umask 077; : >> "$TRACK_FILE")
# umask applies only at creation, so an already-existing file keeps whatever mode it was made with.
chmod 600 "$TRACK_FILE"
# An interrupted append leaves no trailing newline, and concatenating onto that line makes both it and the new key unmatchable by the whole-line test above.
[ -s "$TRACK_FILE" ] && [ -n "$(tail -c1 "$TRACK_FILE")" ] && printf '\n' >> "$TRACK_FILE"
printf '%s\n' "$KEY" >> "$TRACK_FILE"
exit 0
