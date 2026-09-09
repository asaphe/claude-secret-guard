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
  # Each fallback is gated on the previous producing nothing, not on the binary existing: sha256sum is coreutils and shasum is perl, and one present but failing would otherwise leave the stamp empty and silently drop the start-time component this exists for.
  stamp=$(printf '%s' "$started" | sha256sum 2>/dev/null | awk '{print substr($1, 1, 12)}')
  [ -n "$stamp" ] || stamp=$(printf '%s' "$started" | shasum -a 256 2>/dev/null | awk '{print substr($1, 1, 12)}')
  # Kept whole rather than tailed: the last 12 bytes drop the weekday and all but the month's final letter, so Jan and Jun collide on the same day and time — the collision this stamp exists to prevent.
  [ -n "$stamp" ] || stamp=$(printf '%s' "$started" | tr -cd 'A-Za-z0-9')
  printf 'uid%s-pid%s-%s' "$(id -u)" "$PPID" "$stamp"
}
