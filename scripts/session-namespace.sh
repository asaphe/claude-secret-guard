#!/usr/bin/env bash
# Shared utility: the namespace the per-session caches and the duplicate-read tracker are keyed on — see README § Cache namespacing.

# A bare PID is not a namespace. PIDs recycle, so two unrelated shells can land on one path: the second gets the first's cache, and a stale hit serves a value that has since rotated. The parent's start time separates a recycled PID from the original, and the uid keeps two users on a shared /tmp off each other's paths entirely — which is what made the old fixed "shared" tracker name a lockout on a sticky /tmp.
session_namespace() {
  if [ -n "${CLAUDE_CODE_SESSION_ID:-}" ]; then
    printf '%s' "$CLAUDE_CODE_SESSION_ID"
    return 0
  fi
  local started stamp
  started=$(ps -p "$PPID" -o lstart= 2>/dev/null | tr -d ' \t')
  # Degrades to uid+pid rather than failing: without ps this is exactly the old behaviour plus the uid, and a wrapper that refuses to run because ps is missing is a worse outcome than a narrower namespace.
  stamp=$(printf '%s' "$started" | shasum -a 256 | awk '{print substr($1, 1, 12)}')
  printf 'uid%s-pid%s-%s' "$(id -u)" "$PPID" "$stamp"
}
