#!/usr/bin/env bash
# Regression tests for the tool-side write guard: every payload shape it cannot inspect must block. No secret-shaped literal appears here — known-positives come from scripts/fixture-value.sh at runtime.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0
fail=0

ok()  { printf 'ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }

expect_exit() {  # expect_exit <label> <want> <got>
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected exit $2, got $3"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/secret-guard-write.XXXXXX") || {
  printf 'FATAL: mktemp failed — every case below would run against an empty path and pass vacuously\n'
  exit 1
}
trap 'rm -rf "$WORK"' EXIT

guard() {  # guard <payload-json>
  printf '%s' "$1" | bash "$ROOT/scripts/write-secret-guard.sh" >/dev/null 2>"$WORK/err"
}

KEY=$(bash "$ROOT/scripts/fixture-value.sh" aws-access-key 2>/dev/null)
if [ -z "$KEY" ]; then
  printf 'FATAL: the generator produced no known-positive — every block below would pass vacuously\n'
  exit 1
fi

guard "$(jq -nc --arg s "$KEY" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:$s}]}}')"
expect_exit "MultiEdit: a well-formed edit carrying a key blocks" 2 "$?"

guard "$(jq -nc --arg s "$KEY" '{tool_name:"Write", tool_input:{file_path:"/tmp/probe", content:$s}}')"
expect_exit "Write: content carrying a key blocks" 2 "$?"

guard "$(jq -nc '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:"nothing to see"}]}}')"
expect_exit "MultiEdit: ordinary text is allowed" 0 "$?"

# Malformed edits payloads are uninspectable: `edits[]?` used to swallow each into an empty string the guard read as "nothing to inspect".
guard '{"tool_name":"MultiEdit","tool_input":{"edits":"junk"}}'
expect_exit "MultiEdit: a string where edits[] belongs blocks" 2 "$?"

guard '{"tool_name":"MultiEdit","tool_input":{"edits":null}}'
expect_exit "MultiEdit: a null edits key blocks" 2 "$?"

guard '{"tool_name":"MultiEdit","tool_input":{}}'
expect_exit "MultiEdit: an absent edits key blocks" 2 "$?"

guard '{"tool_name":"MultiEdit","tool_input":{"edits":{"new_string":"x"}}}'
expect_exit "MultiEdit: an object where edits[] belongs blocks" 2 "$?"

guard '{"tool_name":"MultiEdit","tool_input":"oops"}'
expect_exit "MultiEdit: a scalar tool_input blocks" 2 "$?"

# The join("") half of the MultiEdit filter exists for this: neither edit carries the whole key.
HALF_A=${KEY:0:10}
HALF_B=${KEY:10}
guard "$(jq -nc --arg a "$HALF_A" --arg b "$HALF_B" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:$a},{new_string:$b}]}}')"
expect_exit "MultiEdit: a key split across two edits still blocks" 2 "$?"

printf '' | bash "$ROOT/scripts/write-secret-guard.sh" >/dev/null 2>&1
expect_exit "an empty payload blocks" 2 "$?"

guard 'not json at all'
expect_exit "a non-JSON payload blocks" 2 "$?"

guard '[]'
expect_exit "a JSON array payload blocks" 2 "$?"

# These paths were exempt until 0.5.0 dropped the allowlist-config carve-out, so a key in one is now a block like any other file.
for target in .gitleaks.toml .gitleaksignore .secretsignore; do
  guard "$(jq -nc --arg s "$KEY" --arg p "/repo/$target" '{tool_name:"Write", tool_input:{file_path:$p, content:$s}}')"
  expect_exit "Write: a key in $target is no longer exempt" 2 "$?"
done

guard "$(jq -nc --arg s "$KEY" '{tool_name:"Edit", tool_input:{file_path:"/repo/.gitleaks.toml", new_string:$s}}')"
expect_exit "Edit: a key in .gitleaks.toml is no longer exempt" 2 "$?"

guard "$(jq -nc --arg s "$KEY" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:12345}]}}')"
expect_exit "MultiEdit: a numeric new_string carries no shape and is allowed" 0 "$?"

guard "$(jq -nc --arg s "$KEY" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:{v:$s}}]}}')"
expect_exit "MultiEdit: a key nested in an object new_string still blocks" 2 "$?"

guard "$(jq -nc --arg s "$KEY" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:[$s]}]}}')"
expect_exit "MultiEdit: a key inside an array new_string still blocks" 2 "$?"

# Known gap, pinned so a future change to the join() halves shows up here: join("") concatenates in array order, so an intervening edit keeps the fragments apart.
guard "$(jq -nc --arg a "${KEY:0:10}" --arg b "${KEY:10}" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:$a},{new_string:"unrelated"},{new_string:$b}]}}')"
expect_exit "MultiEdit: a key split across NON-adjacent edits is not detected (known gap)" 0 "$?"

guard "$(jq -nc --arg s "$KEY" '{tool_name:"SomethingElse", tool_input:{content:$s}}')"
expect_exit "an unhandled tool name is not this guard's surface" 0 "$?"

# Past fixture_exempt's size cap the span loop is quadratic: 600 KB used not to return at all, and a guard that never returns never delivers its block.
if command -v timeout >/dev/null 2>&1; then
  PAD=$(head -c 300000 /dev/zero | tr '\0' 'x')
  BIG=$(jq -nc --arg s "$KEY" --arg p "$PAD" '{tool_name:"Write", tool_input:{file_path:"/tmp/probe", content:($p + " " + $s + " " + $p)}}')
  printf '%s' "$BIG" | timeout 20 bash "$ROOT/scripts/write-secret-guard.sh" >/dev/null 2>&1
  expect_exit "a 600 KB write carrying a key blocks instead of hanging" 2 "$?"
else
  ok "a 600 KB write carrying a key blocks instead of hanging (skipped: no timeout(1))"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
