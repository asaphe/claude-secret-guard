#!/usr/bin/env bash
# 1Password duplicate-read guard — keys on the parsed secret identity (account, item, fields), never the raw command text, so two fields of one item are distinct reads and a flag reorder is not a new one.

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "OP-READ GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
# Read first, because it decides what a refusal below actually means to the caller.
if ! HOOK_EVENT=$(printf '%s' "$INPUT" | jq -r '.hook_event_name // empty' 2>/dev/null); then
  echo "OP-READ GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Refusing: the guard cannot confirm this command is safe." >&2
  exit 2
fi

# The same refusal means different things on the two events, and claiming a block on the post-run pass tells the caller to retry a read that already happened — spending a second biometric prompt for a value they are already holding.
if [ "$HOOK_EVENT" = "PostToolUse" ]; then
  CONSEQUENCE="The command has already run and is not blocked; this pass only records it, so the read went unrecorded and a later identical read will not be flagged as a duplicate."
else
  CONSEQUENCE="Blocking: the guard cannot confirm this command is safe."
fi

# Blocks rather than allows: jq failing here yields an empty value that every check below reads as "nothing to inspect", silently disarming the guard.
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "OP-READ GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. $CONSEQUENCE" >&2
  exit 2
fi
if ! SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null); then
  echo "OP-READ GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. $CONSEQUENCE" >&2
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

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/session-namespace.sh"
# No fixed "shared" fallback: that name was the same for every user, so on a sticky /tmp the first to create it locked everyone else out through the ownership refusal below, with no way to remove it.
[ -n "$SESSION_ID" ] || SESSION_ID=$(session_namespace)
TRACK_FILE="/tmp/claude-op-reads-${SESSION_ID}"

# Checked before the read too: a planted file would also poison the duplicate verdict below.
if [ -L "$TRACK_FILE" ] || { [ -e "$TRACK_FILE" ] && { [ ! -f "$TRACK_FILE" ] || [ ! -O "$TRACK_FILE" ]; }; }; then
  echo "OP-READ GUARD: $TRACK_FILE is not a regular file owned by this user — refusing to use it. A planted symlink would redirect this append into any file you can write, and a planted regular file would collect the references you fetch. Remove it. $CONSEQUENCE" >&2
  exit 2
fi

# Self-pruning because the Stop hook can only scope a purge when the payload carried a session id: without this, a tracker created outside one persists until reboot and keeps refusing reads against a record nothing will clear.
if [ -f "$TRACK_FILE" ] && [ -n "$(find "$TRACK_FILE" -mmin +720 2>/dev/null)" ]; then
  : >"$TRACK_FILE"
fi

record() {
  # The file lists which references were fetched, which maps the credential topology on a shared machine.
  (umask 077; : >>"$TRACK_FILE")
  # umask applies only at creation, so an already-existing file keeps whatever mode it was made with.
  chmod 600 "$TRACK_FILE"
  # An interrupted append leaves no trailing newline, and concatenating onto that line makes both it and the new key unmatchable by the whole-line test below.
  [ -s "$TRACK_FILE" ] && [ -n "$(tail -c1 "$TRACK_FILE")" ] && printf '\n' >>"$TRACK_FILE"
  printf '%s\n' "$KEY" >>"$TRACK_FILE"
}

# Recording moved off PreToolUse: it ran before the command did, so a fetch the user then denied was still recorded, and the legitimate retry was refused as a duplicate of a read that never happened. PostToolUse only fires once the tool has actually run.
if [ "$HOOK_EVENT" = "PostToolUse" ]; then
  record
  exit 0
fi

# Whole-line match: a substring match makes a shorter reference collide with a longer one recorded earlier.
if [ -f "$TRACK_FILE" ] && grep -qxF "$KEY" "$TRACK_FILE"; then
  echo "Duplicate op read: ${WHAT}. You already read this exact secret earlier in this session — reuse the value you got before, since each read triggers a biometric prompt. A different field of the same item counts as a separate secret and is allowed." >&2
  exit 2
fi

# A payload with no event name predates the PostToolUse wiring, where recording here is the only record that ever happens.
[ -n "$HOOK_EVENT" ] || record
exit 0
