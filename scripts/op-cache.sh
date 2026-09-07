#!/usr/bin/env bash
# Cache a 1Password `op read` value per session to avoid repeated biometric prompts — drop-in replacement for `op read`, masked by default. See README § Masked-cache wrappers for usage.

set -euo pipefail

MASK=1
REFRESH=0
ACCOUNT=""
while :; do
  case "${1:-}" in
    --mask) MASK=1; shift ;;
    --reveal) MASK=0; shift ;;
    --refresh) REFRESH=1; shift ;;
    --account)
      ACCOUNT="${2:-}"
      if [ -z "$ACCOUNT" ]; then
        echo "op-cache.sh: --account requires a value" >&2
        exit 64
      fi
      shift 2
      ;;
    *) break ;;
  esac
done

URI="${1:-}"
if [ -z "$URI" ]; then
  echo "usage: op-cache.sh [--account <account>] [--reveal] [--refresh] op://Vault/Item/field" >&2
  exit 64
fi

if [[ ! "$URI" =~ ^op:// ]]; then
  echo "op-cache.sh: argument must start with op://" >&2
  exit 64
fi

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/session-namespace.sh"
SESSION_ID=$(session_namespace)
CACHE_DIR="/tmp/op-cache-${SESSION_ID}"
# Created private rather than widened afterwards: between mkdir and chmod the directory sat at the process umask, readable by any local user.
(umask 077; mkdir -p "$CACHE_DIR")
chmod 700 "$CACHE_DIR"

KEY=$(printf '%s\n%s' "$ACCOUNT" "$URI" | shasum -a 256 | awk '{print $1}')
CACHE_FILE="${CACHE_DIR}/${KEY}"

emit() {
  if [ "$MASK" -eq 1 ]; then
    local bytes; bytes=$(wc -c < "$CACHE_FILE" | tr -d ' ')
    echo "[MASKED] $URI cached at $CACHE_FILE (${bytes} bytes) — reference via \$(cat $CACHE_FILE), never print the contents"
  else
    cat "$CACHE_FILE"
  fi
}

if [ "$REFRESH" -eq 0 ] && [ -s "$CACHE_FILE" ]; then
  emit
  exit 0
fi

if [ -n "$ACCOUNT" ]; then
  VALUE=$(op read --account "$ACCOUNT" "$URI")
else
  VALUE=$(op read "$URI")
fi
# set -e already exits above on a failed read, with op's own stderr intact; this catches success-but-empty, which used to exit 0 without caching or emitting.
if [ -z "$VALUE" ]; then
  echo "op-cache: empty value returned for $URI" >&2
  exit 1
fi

umask 077
printf '%s' "$VALUE" > "$CACHE_FILE"
emit
