#!/usr/bin/env bash
# Regression tests for the cache/tracker namespace: a recycled PID must not resolve to another shell's namespace.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0
fail=0

ok()  { printf 'ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/secret-guard-ns.XXXXXX") || {
  printf 'FATAL: mktemp failed — every case below would run against an empty path and pass vacuously\n'
  exit 1
}
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# ps is stubbed rather than observed: the property under test is that two shells sharing a recycled PID get different namespaces, and that cannot be produced by waiting for the kernel to reissue one.
stub_ps() {  # stub_ps <lstart-output>
  printf '#!/usr/bin/env bash\nprintf %%s %s\n' "'$1'" > "$WORK/bin/ps"
  chmod +x "$WORK/bin/ps"
}

namespace_with() {  # namespace_with <lstart-output> [session-id]
  stub_ps "$1"
  if [ $# -ge 2 ]; then
    PATH="$WORK/bin:$PATH" CLAUDE_CODE_SESSION_ID="$2" \
      bash -c "source '$ROOT/scripts/session-namespace.sh'; session_namespace"
  else
    PATH="$WORK/bin:$PATH" env -u CLAUDE_CODE_SESSION_ID \
      bash -c "source '$ROOT/scripts/session-namespace.sh'; session_namespace"
  fi
}

SID_NS=$(namespace_with 'Mon Sep  7 10:00:00 2026' 'real-session-id')
if [ "$SID_NS" = "real-session-id" ]; then
  ok "a real session id is used verbatim"
else
  bad "a real session id is used verbatim" "got '$SID_NS'"
fi

# Both calls must happen inside ONE process: each bash -c is a new PID, so calling twice from here would compare two different shells and fail for the wrong reason.
stub_ps 'Mon Sep  7 10:00:00 2026'
TWICE=$(PATH="$WORK/bin:$PATH" env -u CLAUDE_CODE_SESSION_ID \
  bash -c "source '$ROOT/scripts/session-namespace.sh'; printf '%s %s' \"\$(session_namespace)\" \"\$(session_namespace)\"")
if [ "${TWICE% *}" = "${TWICE#* }" ]; then
  ok "one shell resolves to a stable namespace across calls"
else
  bad "one shell resolves to a stable namespace across calls" "got '$TWICE'"
fi

# Both resolutions must happen in ONE process so the PID is genuinely held constant — that is the whole scenario: same uid, same recycled PID, different start time. Two separate bash -c calls would differ on the PID alone and pass even with the start time dropped entirely.
stub_ps 'Mon Sep  7 10:00:00 2026'; cp "$WORK/bin/ps" "$WORK/ps-early"
stub_ps 'Mon Sep  7 18:45:31 2026'; cp "$WORK/bin/ps" "$WORK/ps-late"
# shellcheck disable=SC2016  # expanded by the inner shell, which is the point: one process, two ps answers
PAIR=$(PATH="$WORK/bin:$PATH" env -u CLAUDE_CODE_SESSION_ID \
  NS_LIB="$ROOT/scripts/session-namespace.sh" PS_STUB="$WORK/bin/ps" \
  PS_EARLY="$WORK/ps-early" PS_LATE="$WORK/ps-late" \
  bash -c 'source "$NS_LIB"; cp "$PS_EARLY" "$PS_STUB"; FIRST=$(session_namespace); cp "$PS_LATE" "$PS_STUB"; printf "%s %s" "$FIRST" "$(session_namespace)"')
if [ "${PAIR% *}" != "${PAIR#* }" ]; then
  ok "a recycled PID with a different start time is a different namespace"
else
  bad "a recycled PID with a different start time is a different namespace" "both resolved to '${PAIR% *}'"
fi

A=$(namespace_with 'Mon Sep  7 10:00:00 2026')

case "$A" in
  "uid$(id -u)-pid"*) ok "the fallback namespace carries the uid, so two users never share a path" ;;
  *) bad "the fallback namespace carries the uid, so two users never share a path" "got '$A'" ;;
esac

case "$A" in
  *"-pid"*"-"?*) ok "the fallback namespace carries a start-time component" ;;
  *) bad "the fallback namespace carries a start-time component" "got '$A'" ;;
esac

# Without ps this must still produce a usable namespace rather than aborting the wrapper that sourced it.
printf '#!/usr/bin/env bash\nexit 127\n' > "$WORK/bin/ps"
chmod +x "$WORK/bin/ps"
NOPS=$(PATH="$WORK/bin:$PATH" env -u CLAUDE_CODE_SESSION_ID \
  bash -c "source '$ROOT/scripts/session-namespace.sh'; session_namespace" 2>/dev/null)
case "$NOPS" in
  "uid$(id -u)-pid"*) ok "an unavailable ps degrades to uid+pid instead of failing" ;;
  *) bad "an unavailable ps degrades to uid+pid instead of failing" "got '$NOPS'" ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
