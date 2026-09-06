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

stub() {  # stub <upstream-binary> <good|empty|fail>
  mkdir -p "$WORK/bin"
  {
    printf '#!/usr/bin/env bash\n'
    case "$2" in
      good)  printf 'echo %s\n' "$FIXTURE" ;;
      empty) printf 'exit 0\n' ;;
      fail)  printf 'echo "upstream refused" >&2\nexit 7\n' ;;
    esac
  } > "$WORK/bin/$1"
  chmod +x "$WORK/bin/$1"
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

run op-cache.sh op empty --mask "op://V/I/f"
if [ -s "$WORK/err" ]; then ok "op-cache: the empty case names itself on stderr"; else bad "op-cache: the empty case names itself on stderr" "no diagnostic emitted"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
