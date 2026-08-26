#!/usr/bin/env bash
# Regression tests for the Bash-side write guard: a command that both writes to a file and embeds a secret shape is blocked, however the literal is spelled.
set -uo pipefail

GUARD="$(dirname "$0")/../scripts/write-secret-guard-bash.sh"

pass=0
fail=0

run() {
  expect="$1"; label="$2"; cmd="$3"
  payload=$(jq -nc --arg c "$cmd" '{tool_name:"Bash",tool_input:{command:$c}}')
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

# Generated rather than committed, so a public checkout never carries a secret-shaped literal of its own.
rand_chars() {
  local charset="$1" count="$2" out=""
  while [ "${#out}" -lt "$count" ]; do
    out="${out}$(head -c 256 /dev/urandom | LC_ALL=C tr -dc "$charset")"
  done
  printf '%s' "${out:0:count}"
}

KEY="AKIA$(rand_chars 'A-Z2-7' 16)"
HEAD4="${KEY:0:4}"
REST="${KEY:4}"

run BLOCK "a plain literal reaching a file"      "echo \"$KEY\" > out.txt"
run BLOCK "a literal appended to a file"         "echo \"$KEY\" >> out.txt"
run BLOCK "a literal piped through tee"          "echo \"$KEY\" | tee out.txt"

# The guard tells the caller not to split a literal across fragments; the scan read only the raw text, so each of these spellings wrote the key to a file unseen.
run BLOCK "split by an empty single-quote pair"  "echo \"$HEAD4''$REST\" > out.txt"
run BLOCK "split by an empty double-quote pair"  "echo \"$HEAD4\"\"$REST\" > out.txt"
run BLOCK "split by a backslash"                 "echo \"$HEAD4\\\\$REST\" > out.txt"

# \b fails when the preceding character is the n of a literal \n, which is how a key lands in k8s stringData or JSON config; the shared pattern counts a two-character escape as a left boundary, and the raw spelling has to survive the scan for it to be visible at all.
run BLOCK "a key behind an escaped newline"      "printf 'x\\n$KEY' > out.txt"
run BLOCK "a key behind an escaped tab"          "printf 'x\\t$KEY' > out.txt"

run ALLOW "an ordinary write"                    "echo hello > out.txt"
run ALLOW "a literal that reaches no file"       "echo \"$KEY\""
run ALLOW "a split literal that reaches no file" "echo \"$HEAD4''$REST\""

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
