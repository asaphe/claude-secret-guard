#!/usr/bin/env bash
# Regression tests for the masked-cache wrappers: a read that succeeds but returns nothing must fail closed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0
fail=0

ok()  { printf 'ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }

expect_exit() {  # expect_exit <label> <want> <got>
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected exit $2, got $3"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/secret-guard-caches.XXXXXX") || {
  printf 'FATAL: mktemp failed — every case below would run against an empty path and pass vacuously\n'
  exit 1
}
trap 'rm -rf "$WORK"' EXIT

# Not routed through fixture-value.sh: this is deliberately not secret-shaped, so it needs no allowlist entry.
FIXTURE=NOT_A_SECRET_FIXTURE

stub() {  # stub <upstream-binary> <mode>
  mkdir -p "$WORK/bin"
  local body
  # Keyed on binary as well as mode: sm-cache.sh asks for the whole JSON object, so an `aws` stub echoing a bare value would not exercise the field selection this suite is here to pin.
  case "$1:$2" in
    op:good)          body="echo $FIXTURE" ;;
    aws:good)         body="printf '%s' '{\"SecretString\":\"$FIXTURE\"}'" ;;
    aws:binary)       body="printf '%s' '{\"SecretBinary\":\"YmluYXJ5LW9ubHk=\"}'" ;;
    aws:literal-none) body="printf '%s' '{\"SecretString\":\"None\"}'" ;;
    aws:empty-string) body="printf '%s' '{\"SecretString\":\"\"}'" ;;
    *:empty)          body="exit 0" ;;
    *:fail)           body="echo 'upstream refused' >&2; exit 7" ;;
  esac
  printf '#!/usr/bin/env bash\n%s\n' "$body" > "$WORK/bin/$1"
  chmod +x "$WORK/bin/$1"
}

cache_file_for() {  # cache_file_for <session-id>
  find "/tmp/sm-cache-$1" -type f 2>/dev/null | head -1
}

run() {  # run <script> <upstream-binary> <mode> <args...>
  local script="$1" upstream="$2" mode="$3"; shift 3
  stub "$upstream" "$mode"
  PATH="$WORK/bin:$PATH" CLAUDE_CODE_SESSION_ID="cachetest-$$-$RANDOM" \
    bash "$ROOT/scripts/$script" "$@" >/dev/null 2>"$WORK/err"
}

run op-cache.sh op good --mask "op://V/I/f"
expect_exit "op-cache: a real value caches and succeeds" 0 "$?"

run op-cache.sh op empty --mask "op://V/I/f"
expect_exit "op-cache: success-but-empty fails closed" 1 "$?"

run op-cache.sh op fail --mask "op://V/I/f"
expect_exit "op-cache: upstream failure propagates its exit code" 7 "$?"

run sm-cache.sh aws good --mask some-secret-id
expect_exit "sm-cache: a real value caches and succeeds" 0 "$?"

run sm-cache.sh aws empty --mask some-secret-id
expect_exit "sm-cache: success-but-empty fails closed" 1 "$?"

run sm-cache.sh aws fail --mask some-secret-id
expect_exit "sm-cache: upstream failure propagates its exit code" 7 "$?"

# set -e used to abort before the error-surfacing echo, so the captured stderr was discarded.
if grep -q "upstream refused" "$WORK/err"; then
  ok "sm-cache: upstream stderr reaches the caller"
else
  bad "sm-cache: upstream stderr reaches the caller" "stderr was swallowed: $(cat "$WORK/err")"
fi

# `--query SecretString --output text` renders an absent field as the literal "None", which the emptiness check passed — so "None" was cached and reported as a 4-byte secret.
run sm-cache.sh aws binary --mask some-secret-id
expect_exit "sm-cache: a binary-only secret fails closed instead of caching \"None\"" 1 "$?"
if grep -q "SecretBinary" "$WORK/err"; then
  ok "sm-cache: the binary-only case names SecretBinary as the reason"
else
  bad "sm-cache: the binary-only case names SecretBinary as the reason" "stderr was: $(cat "$WORK/err")"
fi

run sm-cache.sh aws empty-string --mask some-secret-id
expect_exit "sm-cache: an explicitly empty SecretString still fails closed" 1 "$?"

# The other half of the same fix: a secret whose value really is the four characters None must survive, or the fix trades one wrong answer for another.
SESSION="cachetest-none-$$-$RANDOM"
stub aws literal-none
PATH="$WORK/bin:$PATH" CLAUDE_CODE_SESSION_ID="$SESSION" \
  bash "$ROOT/scripts/sm-cache.sh" --mask some-secret-id >/dev/null 2>"$WORK/err"
expect_exit "sm-cache: a secret whose value is literally \"None\" still caches" 0 "$?"
CACHED=$(cache_file_for "$SESSION")
if [ -n "$CACHED" ] && [ "$(cat "$CACHED")" = "None" ]; then
  ok "sm-cache: the literal \"None\" value is cached verbatim"
else
  bad "sm-cache: the literal \"None\" value is cached verbatim" "cache held: ${CACHED:+$(cat "$CACHED")}"
fi
rm -rf "/tmp/sm-cache-$SESSION"

run op-cache.sh op empty --mask "op://V/I/f"
if [ -s "$WORK/err" ]; then ok "op-cache: the empty case names itself on stderr"; else bad "op-cache: the empty case names itself on stderr" "no diagnostic emitted"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
