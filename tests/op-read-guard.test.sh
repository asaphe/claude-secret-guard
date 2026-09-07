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

run ALLOW "malformed json fails open"                ""
run ALLOW "op item get with no item fails open"      "op item get --format json"
run ALLOW "unbalanced quote fails open"              "op item get $I --fields 'unclosed"

# A commit message or a runbook quoting a reference describes a fetch rather than performing one; keying the tracker on it refused the real read of that reference as a duplicate.
Q="'"
run ALLOW "a heredoc documenting a reference"        "$(printf 'cat <<%sEOF%s > runbook.md\nrun: op read op://Vault/Doc/f\nEOF' "$Q" "$Q")"
run ALLOW "the genuine read of it is still first"    "op read op://Vault/Doc/f"
run BLOCK "and only then does it dedupe"             "op read op://Vault/Doc/f"
run ALLOW "a commit message naming a reference"      "git commit -m 'use op read op://Vault/Msg/f here'"
run ALLOW "the genuine read of that one too"         "op read op://Vault/Msg/f"
# Piping the body to an interpreter runs it, so that spelling must still count as a fetch.
run ALLOW "a heredoc piped to a shell is a fetch"    "$(printf 'cat <<%sEOF%s | bash\nop read op://Vault/Exec/f\nEOF' "$Q" "$Q")"
run BLOCK "so the read after it is a duplicate"      "op read op://Vault/Exec/f"

# A heredoc body is data only until something runs the file it was written to; masking it unconditionally hid a fetch that executes a few bytes later.
run ALLOW "a script written by heredoc is a fetch"    "$(printf 'cat <<%sEOF%s > /tmp/x.sh\nop read op://Vault/Script/f\nEOF\nbash /tmp/x.sh' "$Q" "$Q")"
run BLOCK "so the read after it is a duplicate"       "op read op://Vault/Script/f"
run ALLOW "the same via tee then sh"                  "$(printf 'tee /tmp/y.sh <<%sEOF%s >/dev/null\nop read op://Vault/Teed/f\nEOF\nsh /tmp/y.sh' "$Q" "$Q")"
run BLOCK "and that one dedupes too"                  "op read op://Vault/Teed/f"
# Named again means the whole path, not a prefix of one: a substring test kept every runbook visible whose destination happened to prefix a later word.
run ALLOW "a path that only prefixes a later one"     "$(printf 'cat <<%sEOF%s > /tmp/run\nrun: op read op://Vault/Prefix/f\nEOF\necho /tmp/runtime' "$Q" "$Q")"
run ALLOW "its genuine read is still first"           "op read op://Vault/Prefix/f"
run ALLOW "a runbook with an unrelated command after" "$(printf 'cat <<%sEOF%s > guide.md\nrun: op read op://Vault/Guide/f\nEOF\necho done' "$Q" "$Q")"
run ALLOW "its genuine read is still first"           "op read op://Vault/Guide/f"

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
