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

# --- the allowlist exempts exactly what it lists, on every content surface ------
C=$(plugin_copy allow)
printf '\n%s\n' "$LISTED" >> "$C/fixtures.allow"

bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
expect_exit "a listed value passes the Bash write guard" 0 "$?"
check "the Bash notice names the exemption" "no notice on stderr" grep -q 'allowed —' "$WORK/err"

tool_write "$C" "$LISTED"
expect_exit "a listed value passes the Write guard" 0 "$?"

paste "$C" "here it is: $LISTED"
check "a listed value passes the paste guard" "the prompt was blocked" [ ! -s "$WORK/out" ]
# Control: the same guard on the same copy must still block an unlisted value, or the case above proves nothing.
paste "$C" "here it is: $FRESH"
check "an unlisted value blocks the paste guard" "the prompt was allowed" grep -q '"decision"' "$WORK/out"

bash_write "$C" "printf '%s' $FRESH > /tmp/probe"
expect_exit "an unlisted value still blocks" 2 "$?"

bash_write "$C" "printf '%s %s' $LISTED $FRESH > /tmp/probe"
expect_exit "one unlisted match blocks the whole call" 2 "$?"

# --- entries the allowlist must refuse to honour -------------------------------
C=$(plugin_copy pem)
PEM_HEADER=$(bash "$ROOT/scripts/fixture-value.sh" pem-private-key | head -1)
printf '\n%s\n%s\n' "$LISTED" "$PEM_HEADER" >> "$C/fixtures.allow"
bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
check "a PEM header entry is refused and announced" "no notice" grep -q 'ignoring the PEM header entry' "$WORK/err"

C=$(plugin_copy partial)
printf '\n%s\n' "${LISTED:0:8}" >> "$C/fixtures.allow"
bash_write "$C" "printf '%s' $LISTED > /tmp/probe"
expect_exit "a prefix entry does not exempt its full value" 2 "$?"
check "the partial entry is announced" "no notice" grep -q 'not a complete value' "$WORK/err"

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
for g in paste-secret-guard read-secret-guard read-secret-guard-bash \
         write-secret-guard write-secret-guard-bash op-read-guard secret-mask-guard; do
  printf 'not json' | bash "$ROOT/scripts/$g.sh" >/dev/null 2>&1
  expect_exit "$g fails closed on an unparseable payload" 2 "$?"
done

# --- and one shape definition, not three ---------------------------------------
COPIES=$(grep -lE "^PATTERN=" "$ROOT"/scripts/*.sh 2>/dev/null | wc -l | tr -d ' ')
check "no guard carries its own copy of the pattern" "$COPIES script(s) still define PATTERN" [ "$COPIES" = "0" ]

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
