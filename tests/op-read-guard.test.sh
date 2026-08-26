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

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
