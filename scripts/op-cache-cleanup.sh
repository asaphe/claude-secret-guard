#!/usr/bin/env bash
# Stop hook that purges this session's secret caches — pairs with op-cache.sh/sm-cache.sh; without this, cached secrets sit in /tmp until reboot.

INPUT=$(cat)
# Says so rather than exiting quietly: an unreadable payload leaves this session's cached secrets sitting in /tmp.
if ! SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null); then
  echo "OP-CACHE CLEANUP: cannot read the hook payload — jq is missing or the JSON did not parse. This session's cached secrets are still on disk; remove /tmp/op-cache-* and /tmp/sm-cache-* by hand." >&2
  exit 0
fi
if [ -z "$SESSION_ID" ]; then
  echo "OP-CACHE CLEANUP: the payload carried no session_id, so the purge cannot be scoped. Cached secrets under /tmp/op-cache-* and /tmp/sm-cache-* may persist." >&2
fi

if [ -n "$SESSION_ID" ]; then
  rm -rf "/tmp/op-cache-${SESSION_ID}"
  rm -rf "/tmp/sm-cache-${SESSION_ID}"
  # Left behind, this makes the duplicate-read guard refuse every reference again in any session reusing this id.
  rm -f "/tmp/claude-op-reads-${SESSION_ID}"
fi

exit 0
