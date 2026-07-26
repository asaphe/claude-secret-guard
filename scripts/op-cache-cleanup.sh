#!/usr/bin/env bash
# Stop hook that purges this session's secret caches — pairs with op-cache.sh/sm-cache.sh; without this, cached secrets sit in /tmp until reboot.

INPUT=$(cat)
SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty')

if [ -n "$SESSION_ID" ]; then
  rm -rf "/tmp/op-cache-${SESSION_ID}"
  rm -rf "/tmp/sm-cache-${SESSION_ID}"
fi

exit 0
