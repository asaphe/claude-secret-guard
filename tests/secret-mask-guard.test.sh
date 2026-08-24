#!/usr/bin/env bash
# Regression tests for the mask guard: a command that only *describes* a guarded read is allowed, one that *performs* it is blocked, and an input it cannot parse is refused.
set -uo pipefail

GUARD="$(dirname "$0")/../scripts/secret-mask-guard.sh"

pass=0
fail=0

run() {
  expect="$1"; label="$2"; cmd="$3"
  payload=$(jq -nc --arg c "$cmd" '{tool_input:{command:$c},session_id:"mask-test"}')
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

# run_raw feeds stdin verbatim, for payloads that are not valid hook JSON.
run_raw() {
  expect="$1"; label="$2"; payload="$3"
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

# Assembled rather than written literally so this file does not itself trip the guard it tests.
R='read'
U='op://Vault/Item/field'
# shellcheck disable=SC2016 # literal, unexpanded: the guard must see the substitution syntax
SUB='$('
SM='secretsmanager'

# --- a real read must be blocked, wherever it sits in the command ---
run BLOCK "plain op read"                    "op $R $U"
run BLOCK "op read with intermediate flags"  "op $R --account example.1password.com $U"
run BLOCK "after a semicolon"                "git status; op $R $U"
run BLOCK "after a pipe"                     "printf x | op $R $U"
run BLOCK "after &&"                         "cd /tmp && op $R $U"
run BLOCK "on its own line"                  "cd /tmp
op $R $U"
run BLOCK "behind env prefix"                "env FOO=1 op $R $U"
run BLOCK "behind sudo"                      "sudo op $R $U"
run BLOCK "absolute path to op"              "/usr/local/bin/op $R $U"
run BLOCK "inside command substitution"      "X=${SUB}op $R $U)"
run BLOCK "inside backticks"                 "X=\`op $R $U\`"
run BLOCK "inside eval"                      "eval \"op $R $U\""
run BLOCK "inside bash -c"                   "bash -c \"op $R $U\""
run BLOCK "inside sh -c single-quoted"       "sh -c 'op $R $U'"

run BLOCK "get-secret-value"                 "aws $SM get-secret-value --secret-id my-secret"
run BLOCK "get-secret-value behind rtk"      "rtk aws $SM get-secret-value --secret-id my-secret"
run BLOCK "get-secret-value with flags"      "aws --profile prod $SM get-secret-value --secret-id my-secret"
run BLOCK "batch-get-secret-value"           "aws $SM batch-get-secret-value --secret-id-list a b"
run BLOCK "get-secret-value in substitution" "X=${SUB}aws $SM get-secret-value --secret-id my-secret)"

# --- prose that merely names the pattern must be allowed ---
run ALLOW "--body describing op read"        "gh pr create --title t --body \"Use the wrapper instead of op $R $U\""
run ALLOW "--body describing get-secret"     "gh issue comment 5 --body \"the guard blocks aws $SM get-secret-value calls\""
run ALLOW "-m describing op read"            "git commit -m \"docs: explain why op $R $U is blocked\""
run ALLOW "--title describing op read"       "gh pr create --title \"block op $R calls\" --body \"see docs\""
run ALLOW "--notes describing op read"       "gh release create v1 --notes \"no longer calls op $R here\""
run ALLOW "quoted heredoc of prose"          "cat > doc.md <<'EOF'
never call op $R $U directly
EOF"

# --- prose masking must not hide a read that actually runs ---
run BLOCK "-m whose value substitutes"       "git commit -m \"token ${SUB}op $R $U)\""
run BLOCK "-m whose value uses backticks"    "git commit -m \"token \`op $R $U\`\""
run BLOCK "--body whose value substitutes"   "gh pr create --body \"token ${SUB}op $R $U)\""
run ALLOW "-m single-quoted cannot expand"   "git commit -m 'the literal ${SUB}op $R $U) in prose'"
run BLOCK "bare heredoc that substitutes"    "cat > f.txt <<EOF
value=${SUB}op $R $U)
EOF"

# --- exemptions ---
run ALLOW "op item get is not a mask target" "op item get ABC --account example.1password.com --fields 'Client ID'"
run ALLOW "op-cache wrapper"                 "\"\$CLAUDE_PLUGIN_ROOT\"/scripts/op-cache.sh --mask $U"
run ALLOW "sm-cache wrapper"                 "scripts/sm-cache.sh --mask my-secret"

# --- a word merely ending in "op" is not the op binary ---
run ALLOW "stop read"                        "stop $R the file"
run ALLOW "develop read"                     "develop $R model"
run ALLOW "loop read in a while loop"        "while loop $R line; do :; done"
run ALLOW "unrelated command"                "git status"

# --- unparseable input must be refused, never waved through ---
run BLOCK "unbalanced quote around a read"   "op $R 'unclosed"
run_raw BLOCK "invalid JSON payload"         '{this is not json'
run_raw BLOCK "empty payload"                ''
run_raw ALLOW "valid payload, no command"    '{"tool_input":{},"session_id":"mask-test"}'

# --- a missing interpreter must refuse the command, not silently stop checking it ---
STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT
for bin in perl jq; do
  printf '#!/bin/sh\nexit 127\n' > "$STUB/$bin"
  chmod +x "$STUB/$bin"
done

run_without() {
  missing="$1"; expect="$2"; label="$3"; cmd="$4"
  payload=$(jq -nc --arg c "$cmd" '{tool_input:{command:$c},session_id:"mask-test"}')
  printf '%s' "$payload" | PATH="$STUB-$missing:$PATH" bash "$GUARD" >/dev/null 2>&1
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

for bin in perl jq; do
  mkdir -p "$STUB-$bin"
  cp "$STUB/$bin" "$STUB-$bin/$bin"
done
trap 'rm -rf "$STUB" "$STUB-perl" "$STUB-jq"' EXIT

run_without perl BLOCK "perl unavailable, real read" "op $R $U"
run_without jq   BLOCK "jq unavailable, real read"   "op $R $U"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
