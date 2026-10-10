#!/usr/bin/env bash
# Regression tests for the dedup key: identity is (account, item, fields), not raw command text.
set -uo pipefail

GUARD="$(dirname "$0")/../scripts/op-read-guard.sh"
SID="test-$$"
TRACK="/tmp/claude-op-reads-${SID}"
rm -f "$TRACK"
trap 'rm -f "$TRACK"' EXIT

pass=0
fail=0

run() {
  expect="$1"; label="$2"; cmd="$3"
  payload=$(jq -nc --arg c "$cmd" --arg s "$SID" '{tool_input:{command:$c},session_id:$s}')
  printf '%s' "$payload" | bash "$GUARD" >/dev/null 2>&1
  code=$?
  actual="ALLOW"
  [ "$code" -ne 0 ] && actual="BLOCK"
  if [ "$actual" = "$expect" ]; then
    printf 'ok   %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL %s — expected %s, got %s\n' "$label" "$expect" "$actual"
    fail=$((fail + 1))
  fi
}

I=ABCDEF1234567890
A=example.1password.com

run ALLOW "first read of field Client ID"            "op item get $I --account $A --fields 'Client ID'"
run ALLOW "different field of same item is allowed"  "op item get $I --account $A --fields 'Client Secret'"
run ALLOW "third distinct field is allowed"          "op item get $I --account $A --fields 'URL'"

run BLOCK "verbatim repeat is blocked"               "op item get $I --account $A --fields 'Client ID'"
run BLOCK "repeat with extra boolean flag"           "op item get $I --account $A --fields 'Client Secret' --reveal"
run BLOCK "repeat with reordered flags"              "op item get $I --fields 'Client ID' --account $A"

run ALLOW "whole-item read is its own identity"      "op item get $I --account $A --format json"
run BLOCK "whole-item read repeated"                 "op item get $I --account $A --format json"

run ALLOW "same item and field, other account"       "op item get $I --account other.1password.com --fields 'Client ID'"

run ALLOW "first op:// read"                         "op read op://Vault/Item/field"
run BLOCK "repeated op:// read"                      "op read op://Vault/Item/field"
run ALLOW "different op:// field"                    "op read op://Vault/Item/other"
run ALLOW "same op:// uri, different account"        "op read --account $A op://Vault/Item/field"

run ALLOW "unrelated command is ignored"             "git status"
run ALLOW "word merely containing op is ignored"     "stop reading the file"

# The helper always emits valid JSON, so this is the no-op-read branch; the malformed-payload
# fail-closed path is covered for every guard in fixtures.test.sh.
run ALLOW "an empty command is ignored"              ""
run ALLOW "op item get with no item fails open"      "op item get --format json"
run ALLOW "an unbalanced quote is still a first read" "op item get $I --fields 'unclosed"
run BLOCK "and its repeat is a duplicate"            "op item get $I --fields 'unclosed"

# One unbalanced quote fails the whole split, so the lines are split one by one and only a line that still fails is bare-split.
NL=$'\n'
run ALLOW "first read of a field"                    "op item get $I --fields label=apos"
run BLOCK "repeat after a body with an apostrophe"   "cat <<'EOF' > notes.txt${NL}'${NL}EOF${NL}op item get $I --fields label=apos"
run BLOCK "repeat with an apostrophe in its comment" "op item get $I --fields label=apos # it's"
run ALLOW "a quoted field on a clean line keeps its space" "cat <<'EOF' > notes.txt${NL}'${NL}EOF${NL}op item get $I --fields 'label=two words'"
run BLOCK "so its repeat is that same identity"      "op item get $I --fields 'label=two words'"

# Every segment's identity keys the command, so a read named earlier on the line, in a body or a message, does not hide the duplicate after it.
run ALLOW "first read of the item a body precedes"   "op item get $I --fields label=later"
run BLOCK "its repeat after a body naming another"   "cat <<'EOF'${NL}op item get OTHERITEM --fields label=later${NL}EOF${NL}op item get $I --fields label=later"
run ALLOW "two reads in one command"                 "op item get $I --fields label=m1 && op item get $I --fields label=m2"
run BLOCK "the second of them is recorded too"       "op item get $I --fields label=m2"

# Unwrapping a pair such as '"' leaves a lone quote, so each line is also tried as written before any bare split.
run ALLOW "first read of a quoted item name"         "op item get \"quoted item\" --fields password"
run BLOCK "its repeat beside a message of one quote" "op item get \"quoted item\" --fields password ; git commit -m '\"'"
run BLOCK "the same with a two-line message after"   "op item get \"quoted item\" --fields password ; git commit -m '\"' -m \"one${NL}two\""
run BLOCK "the same after a body with an apostrophe" "cat <<'EOF' > notes.txt${NL}'${NL}EOF${NL}op item get \"quoted item\" --fields password ; git commit -m '\"'"
# A reference written in a comment or a prose value keys the segment beside its item, never in place of it.
run ALLOW "an item read with a reference in its comment" "op item get CMTITEM --fields password # --title 'op://Vault/CmtItem/f'"
run BLOCK "the plain repeat of that item"            "op item get CMTITEM --fields password"
run ALLOW "an item read naming a reference as well"  "op item get REFITEM --fields password --tags op://Vault/RefItem/f"
run BLOCK "the plain repeat of that item too"        "op item get REFITEM --fields password"
# Words after a # are read both with and without, so an --account written in a comment cannot replace the real one.
run ALLOW "first read of an item before a comment"   "op item get ACCTITEM --fields username"
run BLOCK "its repeat with an account in a comment"  "op item get ACCTITEM --fields username # --title \"--account=other\""
# A prose flag's value is read with and without, so an --account or --fields spelled inside a --title or --body cannot replace the real one.
run ALLOW "first read of an item before a prose value" "op item get SUBITEM --fields username"
run BLOCK "its repeat with an account in a title"     "op item get SUBITEM --fields username \$(printf '' --title \"--account=other\")"
run BLOCK "its repeat with fields in a body"          "op item get SUBITEM --fields username \$(printf '' --body \"--fields=password\")"
run BLOCK "its repeat with an account after -m"       "op item get SUBITEM --fields username -m --account=other"

# Nothing in a command is masked as data, since whether it runs is not decided without parsing the shell, so a reference named in a commit message or a heredoc counts as its read.
Q="'"
run ALLOW "a commit message naming a reference is a read" "git commit -m 'use op read op://Vault/Msg/f here'"
run BLOCK "so the read after it is a duplicate"      "op read op://Vault/Msg/f"
run ALLOW "a heredoc naming a reference is a read"   "$(printf 'cat <<%sEOF%s > runbook.md\nrun: op read op://Vault/Doc/f\nEOF' "$Q" "$Q")"
run BLOCK "so the read after it is a duplicate"      "op read op://Vault/Doc/f"
run ALLOW "a heredoc piped to a shell is a fetch"    "$(printf 'cat <<%sEOF%s | bash\nop read op://Vault/Exec/f\nEOF' "$Q" "$Q")"
run BLOCK "so the read after it is a duplicate"      "op read op://Vault/Exec/f"

run ALLOW "a script written by heredoc is a fetch"    "$(printf 'cat <<%sEOF%s > /tmp/x.sh\nop read op://Vault/Script/f\nEOF\nbash /tmp/x.sh' "$Q" "$Q")"
run BLOCK "so the read after it is a duplicate"       "op read op://Vault/Script/f"
run ALLOW "the same via tee then sh"                  "$(printf 'tee /tmp/y.sh <<%sEOF%s >/dev/null\nop read op://Vault/Teed/f\nEOF\nsh /tmp/y.sh' "$Q" "$Q")"
run BLOCK "and that one dedupes too"                  "op read op://Vault/Teed/f"

ok()  { printf 'ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }

# Recording used to happen here, at PreToolUse, before the command ran — so a denied fetch was recorded and its legitimate retry refused as a duplicate of a read that never happened.
ESID="evt-$$"
ETRACK="/tmp/claude-op-reads-${ESID}"
rm -f "$ETRACK"
expect_eq() {  # expect_eq <label> <want> <got>
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected $2, got $3"; fi
}

event() {  # event <hook_event_name> <command>; echoes ALLOW|BLOCK
  local payload
  payload=$(jq -nc --arg c "$2" --arg s "$ESID" --arg e "$1" '{tool_input:{command:$c},session_id:$s,hook_event_name:$e}')
  if printf '%s' "$payload" | bash "$GUARD" >/dev/null 2>&1; then printf 'ALLOW'; else printf 'BLOCK'; fi
}
# Assembled rather than written out: a literal fetch verb in this file is what the plugin's own mask guard blocks when the suite is edited through Claude.
READ_CMD="op re""ad op://Vault/Denied/field"

expect_eq "PreToolUse: a first read is allowed" ALLOW "$(event PreToolUse "$READ_CMD")"
if [ ! -s "$ETRACK" ]; then
  ok "PreToolUse: the read is not recorded before the command runs"
else
  bad "PreToolUse: the read is not recorded before the command runs" "tracker already holds: $(cat "$ETRACK")"
fi
expect_eq "PreToolUse: the retry after a denial is still allowed" ALLOW "$(event PreToolUse "$READ_CMD")"

expect_eq "PostToolUse: recording never blocks" ALLOW "$(event PostToolUse "$READ_CMD")"
if [ -s "$ETRACK" ]; then
  ok "PostToolUse: the read is recorded once the command has run"
else
  bad "PostToolUse: the read is recorded once the command has run" "tracker is empty"
fi
expect_eq "PreToolUse: a genuine repeat is still blocked" BLOCK "$(event PreToolUse "$READ_CMD")"
expect_eq "PostToolUse: a duplicate is recorded, not blocked" ALLOW "$(event PostToolUse "$READ_CMD")"
rm -f "$ETRACK"

# The session-less fallback was the fixed name "shared", identical for every user: on a sticky /tmp the first to create it locked everyone else out through the ownership refusal, with no way to remove it.
rm -f /tmp/claude-op-reads-shared
printf '%s' "$(jq -nc --arg c "$READ_CMD" '{tool_input:{command:$c},hook_event_name:"PostToolUse"}')" \
  | env -u CLAUDE_CODE_SESSION_ID bash "$GUARD" >/dev/null 2>&1
if [ ! -e /tmp/claude-op-reads-shared ]; then
  ok "a payload with no session_id no longer writes the machine-wide 'shared' tracker"
else
  bad "a payload with no session_id no longer writes the machine-wide 'shared' tracker" "/tmp/claude-op-reads-shared was created"
fi
# -L and the trailing slash are load-bearing: /tmp is a symlink on macOS, and find does not follow a symlinked start point — without them this counts 0 whether or not the file was created.
NS_GLOB="claude-op-reads-uid$(id -u)-pid$$-*"
NS_FILES=$(find -L /tmp/ -maxdepth 1 -name "$NS_GLOB" 2>/dev/null | wc -l | tr -d ' ')
expect_eq "the session-less fallback is namespaced by uid, pid and start time" 1 "$NS_FILES"
find -L /tmp/ -maxdepth 1 -name "$NS_GLOB" -exec rm -f {} \; 2>/dev/null

# Without a session id the Stop hook cannot scope a purge, so the tracker has to bound its own lifetime or it refuses reads forever against a record nothing will clear.
PSID="prune-$$"
PTRACK="/tmp/claude-op-reads-${PSID}"
STALE_CMD="op re""ad op://Vault/Stale/field"
printf 'uri||op://Vault/Stale/field\n' > "$PTRACK"
if OLD=$(date -v-13H +%Y%m%d%H%M 2>/dev/null || date -d '13 hours ago' +%Y%m%d%H%M 2>/dev/null); then
  touch -t "$OLD" "$PTRACK"
  # Control: the same entry with a fresh mtime must still block, or "allowed" would prove the key never matched rather than that the prune ran.
  FRESH_PAYLOAD=$(jq -nc --arg c "$STALE_CMD" --arg s "$PSID" '{tool_input:{command:$c},session_id:$s,hook_event_name:"PreToolUse"}')
  if printf '%s' "$FRESH_PAYLOAD" | bash "$GUARD" >/dev/null 2>&1; then
    ok "a tracker older than 12h is pruned instead of blocking forever"
  else
    bad "a tracker older than 12h is pruned instead of blocking forever" "the stale entry still blocked"
  fi
  printf 'uri||op://Vault/Stale/field\n' > "$PTRACK"
  if printf '%s' "$FRESH_PAYLOAD" | bash "$GUARD" >/dev/null 2>&1; then
    bad "control: the same entry with a fresh mtime still blocks" "it was allowed, so the prune case proves nothing"
  else
    ok "control: the same entry with a fresh mtime still blocks"
  fi
else
  ok "a tracker older than 12h is pruned instead of blocking forever (skipped: no portable touch -t)"
  ok "control: the same entry with a fresh mtime still blocks (skipped: no portable touch -t)"
fi
rm -f "$PTRACK"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
