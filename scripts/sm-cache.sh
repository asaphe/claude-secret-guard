#!/usr/bin/env bash
# Cache a single AWS Secrets Manager secret's value per session, mirroring op-cache.sh — drop-in replacement for `aws secretsmanager get-secret-value`, masked by default. See README § Masked-cache wrappers for usage.

set -euo pipefail

MASK=1
REFRESH=0
PROFILE="${AWS_PROFILE:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --mask) MASK=1; shift ;;
    --reveal) MASK=0; shift ;;
    --refresh) REFRESH=1; shift ;;
    --profile) PROFILE="$2"; shift 2 ;;
    *) break ;;
  esac
done

SECRET_ID="${1:-}"
if [ -z "$SECRET_ID" ]; then
  echo "usage: sm-cache.sh [--reveal] [--refresh] [--profile PROFILE] <secret-id>" >&2
  exit 64
fi

SESSION_ID="${CLAUDE_CODE_SESSION_ID:-pid-${PPID}}"
CACHE_DIR="/tmp/sm-cache-${SESSION_ID}"
mkdir -p "$CACHE_DIR"
chmod 700 "$CACHE_DIR"

KEY=$(printf '%s|%s' "$PROFILE" "$SECRET_ID" | shasum -a 256 | awk '{print $1}')
CACHE_FILE="${CACHE_DIR}/${KEY}"

emit() {
  if [ "$MASK" -eq 1 ]; then
    local bytes; bytes=$(wc -c < "$CACHE_FILE" | tr -d ' ')
    echo "[MASKED] ${SECRET_ID}${PROFILE:+ (profile $PROFILE)} cached at $CACHE_FILE (${bytes} bytes) — reference via \$(cat $CACHE_FILE) or jq against it, never print the contents"
  else
    cat "$CACHE_FILE"
  fi
}

if [ "$REFRESH" -eq 0 ] && [ -s "$CACHE_FILE" ]; then
  emit
  exit 0
fi

PROFILE_ARGS=()
[ -n "$PROFILE" ] && PROFILE_ARGS=(--profile "$PROFILE")
VALUE=$(aws secretsmanager get-secret-value "${PROFILE_ARGS[@]}" --secret-id "$SECRET_ID" --query SecretString --output text 2>&1)
RC=$?
if [ "$RC" -ne 0 ] || [ -z "$VALUE" ]; then
  echo "$VALUE" >&2
  exit "$RC"
fi

umask 077
printf '%s' "$VALUE" > "$CACHE_FILE"
emit
