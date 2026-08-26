#!/usr/bin/env bash
# Regression tests for the shared shapes, the fixture allowlist and the fail-closed jq handling.
# No secret-shaped literal appears in this file: the listed value is generated at runtime and read
# back from the allowlist, which is the override exercising itself.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0
fail=0

ok()   { printf 'ok   %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf 'FAIL %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }
# Never `A && ok || bad`: that reports a failure whenever ok itself returns non-zero.
check() {  # check <label> <failure-detail> <command...>
  local label="$1" detail="$2"; shift 2
  if "$@"; then ok "$label"; else bad "$label" "$detail"; fi
}

# A fresh copy per case, so a mutated allowlist cannot leak into the next verdict.
plugin_copy() {
  local dst="$WORK/copy-$1"
  rm -rf "$dst"
  mkdir -p "$dst"
  cp -R "$ROOT/scripts" "$dst/scripts"
  cp "$ROOT/fixtures.allow" "$dst/fixtures.allow"
  printf '%s' "$dst"
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/secret-guard-fixtures.XXXXXX") || {
  printf 'FATAL: mktemp failed — every case below would run against an empty path and pass vacuously\n'
  exit 1
}
trap 'rm -rf "$WORK"' EXIT

expect_exit() {  # expect_exit <label> <want> <got>
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected exit $2, got $3"; fi
}

bash_write() {   # bash_write <copy> <command>
  jq -nc --arg c "$2" '{tool_name:"Bash", tool_input:{command:$c}}' \
    | bash "$1/scripts/write-secret-guard-bash.sh" >/dev/null 2>"$WORK/err"
}
tool_write() {   # tool_write <copy> <content>
  jq -nc --arg c "$2" '{tool_name:"Write", tool_input:{file_path:"/tmp/probe", content:$c}}' \
    | bash "$1/scripts/write-secret-guard.sh" >/dev/null 2>"$WORK/err"
}
paste() {        # paste <copy> <prompt>
  jq -nc --arg p "$2" '{prompt:$p}' | bash "$1/scripts/paste-secret-guard.sh" >"$WORK/out" 2>"$WORK/err"
}

# --- the generator emits values the guards actually flag -----------------------
for shape in aws-access-key slack-bot-token gitlab-pat pem-private-key; do
  if VALUE=$(bash "$ROOT/scripts/fixture-value.sh" "$shape" 2>/dev/null) && [ -n "$VALUE" ]; then
    C=$(plugin_copy "gen-$shape")
    tool_write "$C" "$VALUE"
    expect_exit "a generated $shape is a known-positive" 2 "$?"
  else
    bad "a generated $shape is a known-positive" "the generator produced nothing"
  fi
done

bash "$ROOT/scripts/fixture-value.sh" >/dev/null 2>&1
expect_exit "the generator refuses a missing shape name" 64 "$?"
bash "$ROOT/scripts/fixture-value.sh" not-a-shape >/dev/null 2>&1
expect_exit "the generator refuses an unknown shape" 64 "$?"

LISTED=$(bash "$ROOT/scripts/fixture-value.sh" aws-access-key)
FRESH=$(bash "$ROOT/scripts/fixture-value.sh" aws-access-key)
check "the generator does not repeat itself" "two calls returned the same value" [ "$LISTED" != "$FRESH" ]
# Fatal rather than a failed case: with either value empty, every exemption below runs on an empty string and reports ok for a guard that was never given anything to exempt.
if [ -z "$LISTED" ] || [ -z "$FRESH" ]; then
  printf 'FATAL: the generator produced an empty value — the exemption cases below would pass vacuously\n'
  exit 1
fi

# --- the allowlist exempts exactly what it lists, on every content surface ------
C=$(plugin_copy allow)
printf '\n%s\n' "$LISTED" >> "$C/fixtures.allow"

bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
expect_exit "a listed value passes the Bash write guard" 0 "$?"
check "the Bash notice names the exemption" "no notice on stderr" grep -q 'allowed —' "$WORK/err"

tool_write "$C" "$LISTED"
expect_exit "a listed value passes the Write guard" 0 "$?"

paste "$C" "here it is: $LISTED"
PASTE_CODE=$?
# The guard signals a block on stdout and exits 0, so an empty stdout alone cannot tell an exemption from a refusal that never printed one — the exit code and the notice are what separate them.
expect_exit "a listed value passes the paste guard" 0 "$PASTE_CODE"
check "the paste notice names the exemption" "no notice on stderr" grep -q 'allowed —' "$WORK/err"
check "the paste guard emitted no block" "the prompt was blocked" [ ! -s "$WORK/out" ]
# Control: the same guard on the same copy must still block an unlisted value, or the case above proves nothing.
paste "$C" "here it is: $FRESH"
check "an unlisted value blocks the paste guard" "the prompt was allowed" grep -q '"decision"' "$WORK/out"

bash_write "$C" "printf '%s' $FRESH > /tmp/probe"
expect_exit "an unlisted value still blocks" 2 "$?"

bash_write "$C" "printf '%s %s' $LISTED $FRESH > /tmp/probe"
expect_exit "one unlisted match blocks the whole call" 2 "$?"

# --- entries the allowlist must refuse to honour -------------------------------
C=$(plugin_copy pem)
PEM_KEY=$(bash "$ROOT/scripts/fixture-value.sh" pem-private-key 2>/dev/null)
PEM_HEADER=$(printf '%s\n' "$PEM_KEY" | head -1)
if [ -n "$PEM_KEY" ] && [ -n "$PEM_HEADER" ]; then
  printf '\n%s\n%s\n' "$LISTED" "$PEM_HEADER" >> "$C/fixtures.allow"
  bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
  check "a PEM header entry is refused and announced" "no notice" grep -q 'ignoring the PEM header entry' "$WORK/err"
  # The property is that the header buys nothing, which only a real key can show: the notice alone would still print if the entry were honoured.
  tool_write "$C" "$PEM_KEY"
  expect_exit "listing the header does not exempt a real key" 2 "$?"
else
  bad "a PEM header entry is refused and announced" "the generator produced no PEM key"
  bad "listing the header does not exempt a real key" "the generator produced no PEM key"
fi

C=$(plugin_copy partial)
printf '\n%s\n' "${LISTED:0:8}" >> "$C/fixtures.allow"
bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
expect_exit "a prefix entry does not exempt its full value" 2 "$?"
check "the partial entry is announced" "no notice" grep -q 'not a complete value' "$WORK/err"

# --- a fragment is not a complete value, even when a detection alternative matches it ---
C=$(plugin_copy slack-prefix)
SLACK=$(bash "$ROOT/scripts/fixture-value.sh" slack-bot-token)
if [ -n "$SLACK" ]; then
  # The team and bot IDs, which every rotation of the same credential shares; the shapes carry this prefix so a truncated token in source is still flagged, which is what let it pass as "complete".
  TRUNC="${SLACK%-*}"
  printf '\n%s\n' "$TRUNC" >> "$C/fixtures.allow"
  tool_write "$C" "$SLACK"
  expect_exit "a truncated token does not exempt the full one" 2 "$?"
  check "the truncated entry is announced" "no notice" grep -q 'not a complete value' "$WORK/err"
else
  bad "a truncated token does not exempt the full one" "the generator produced no Slack token"
  bad "the truncated entry is announced" "the generator produced no Slack token"
fi

# --- an open-ended shape lets one complete value be the prefix of another ------
C=$(plugin_copy gitlab-prefix)
GL=$(bash "$ROOT/scripts/fixture-value.sh" gitlab-pat)
if [ -n "$GL" ]; then
  LONGER="${GL}EXTRA"
  printf '\n%s\n' "$GL" >> "$C/fixtures.allow"
  tool_write "$C" "$GL"
  expect_exit "the listed value alone is exempt" 0 "$?"
  tool_write "$C" "$LONGER"
  expect_exit "a longer value extending it blocks alone" 2 "$?"
  # Subtracting the listed value by text stripped this prefix out of the neighbour too, leaving the residual check nothing to find.
  tool_write "$C" "$GL
$LONGER"
  expect_exit "and still blocks beside the listed one" 2 "$?"
else
  bad "the listed value alone is exempt" "the generator produced no GitLab PAT"
  bad "a longer value extending it blocks alone" "the generator produced no GitLab PAT"
  bad "and still blocks beside the listed one" "the generator produced no GitLab PAT"
fi

# --- a missing allowlist blocks rather than exempting --------------------------
C=$(plugin_copy missing)
rm -f "$C/fixtures.allow"
bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
expect_exit "a missing allowlist blocks everything" 2 "$?"
check "the missing allowlist is announced" "no notice" grep -q 'missing or unreadable' "$WORK/err"

# --- a two-character escape is a left boundary --------------------------------
C=$(plugin_copy escape)
bash_write "$C" "printf 'a\\n$FRESH' | tee /tmp/probe"
expect_exit "a key behind a \\n escape is still matched" 2 "$?"

# --- an unreadable hook payload blocks on every guard --------------------------
# One variant is not the class: empty stdin and a top-level null both parse, and only the mask guard checked the payload was an object at all.
for g in paste-secret-guard read-secret-guard read-secret-guard-bash \
         write-secret-guard write-secret-guard-bash op-read-guard secret-mask-guard; do
  printf 'not json' | bash "$ROOT/scripts/$g.sh" >/dev/null 2>&1
  expect_exit "$g fails closed on an unparseable payload" 2 "$?"
  printf '' | bash "$ROOT/scripts/$g.sh" >/dev/null 2>&1
  expect_exit "$g fails closed on empty stdin" 2 "$?"
  printf 'null' | bash "$ROOT/scripts/$g.sh" >/dev/null 2>&1
  expect_exit "$g fails closed on a top-level null" 2 "$?"
done

# A .tool_input that is not an object makes the content filters error; an unchecked assignment left the value empty, which every check downstream reads as "nothing here".
for g in read-secret-guard read-secret-guard-bash write-secret-guard write-secret-guard-bash op-read-guard secret-mask-guard; do
  printf '{"tool_name":"Write","tool_input":"oops"}' | bash "$ROOT/scripts/$g.sh" >/dev/null 2>&1
  expect_exit "$g fails closed on a non-object tool_input" 2 "$?"
done

# The MultiEdit filter errors on an edit that is not an object, which used to end only the substitution's subshell and let the write through.
jq -nc --arg k "$FRESH" '{tool_name:"MultiEdit", tool_input:{edits:["junk", {new_string:$k}]}}' \
  | bash "$ROOT/scripts/write-secret-guard.sh" >/dev/null 2>&1
expect_exit "a malformed edits array blocks rather than passing" 2 "$?"
jq -nc --arg k "$FRESH" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:$k}]}}' \
  | bash "$ROOT/scripts/write-secret-guard.sh" >/dev/null 2>&1
expect_exit "control: a well-formed edits array still blocks the key" 2 "$?"
jq -nc '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:"benign"}]}}' \
  | bash "$ROOT/scripts/write-secret-guard.sh" >/dev/null 2>&1
expect_exit "control: a benign multi-edit still passes" 0 "$?"

# --- and one shape definition, not three ---------------------------------------
COPIES=$(grep -lE "^PATTERN=" "$ROOT"/scripts/*.sh 2>/dev/null | wc -l | tr -d ' ')
check "no guard carries its own copy of the pattern" "$COPIES script(s) still define PATTERN" [ "$COPIES" = "0" ]

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
