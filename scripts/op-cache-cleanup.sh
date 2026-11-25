#!/usr/bin/env bash
# Stop hook that purges this session's secret caches — pairs with op-cache.sh/sm-cache.sh; without this, cached secrets sit in /tmp until reboot.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
[ "${LC_ALL:-}" = C ] || unset SG_ASCII_TRAIL; _sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }

INPUT=$(cat)
# Says so rather than exiting quietly: an unreadable payload leaves this session's cached secrets sitting in /tmp.
if ! SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null); then
  echo "OP-CACHE CLEANUP: cannot read the hook payload — jq is missing or the JSON did not parse. This session's cached secrets are still on disk; remove /tmp/op-cache-* and /tmp/sm-cache-* by hand." >&2
  exit 0
fi
if [ -z "$SESSION_ID" ]; then
  echo "OP-CACHE CLEANUP: the payload carried no session_id, so the purge cannot be scoped. Cached secrets under /tmp/op-cache-* and /tmp/sm-cache-* may persist; the duplicate-read tracker prunes itself after 12 hours." >&2
fi

if [ -n "$SESSION_ID" ]; then
  rm -rf "/tmp/op-cache-${SESSION_ID}"
  rm -rf "/tmp/sm-cache-${SESSION_ID}"
  # Left behind, this makes op-read-guard block every reference again in any session reusing this id.
  rm -f "/tmp/claude-op-reads-${SESSION_ID}"
fi

exit 0
