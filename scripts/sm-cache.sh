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
    # Guarded like op-cache.sh's --account: an unguarded "$2" under set -u aborts with a raw "unbound variable" instead of a usable message.
    --profile)
      PROFILE="${2:-}"
      if [ -z "$PROFILE" ]; then
        echo "sm-cache.sh: --profile requires a value" >&2
        exit 64
      fi
      shift 2
      ;;
    *) break ;;
  esac
done

SECRET_ID="${1:-}"
if [ -z "$SECRET_ID" ]; then
  echo "usage: sm-cache.sh [--reveal] [--refresh] [--profile PROFILE] <secret-id>" >&2
  exit 64
fi

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/session-namespace.sh"
SESSION_ID=$(session_namespace)
CACHE_DIR="/tmp/sm-cache-${SESSION_ID}"
# Created private rather than widened afterwards: between mkdir and chmod the directory sat at the process umask, readable by any local user.
(umask 077; mkdir -p "$CACHE_DIR")
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

if ! command -v jq >/dev/null 2>&1; then
  echo "sm-cache.sh: jq is required to tell an absent SecretString from one whose value is the text 'None' — install jq." >&2
  exit 1
fi

PROFILE_ARGS=()
[ -n "$PROFILE" ] && PROFILE_ARGS=(--profile "$PROFILE")
# Streams stay separate like op-cache.sh: merged in, a benign CLI notice on a *successful* call is cached as part of the secret; the ${a[@]+…} form keeps bash 3.2 from aborting on the empty array.
RESPONSE=$(aws secretsmanager get-secret-value ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} --secret-id "$SECRET_ID" --output json) \
  || exit $?

# Not `--query SecretString --output text`: that renders an absent field as the literal "None" (the CLI's text formatter printing Python's None), which passes the emptiness check below and caches "None" as a 4-byte secret. Selecting from the JSON distinguishes an absent field from a secret whose value really is the string "None".
if ! VALUE=$(printf '%s' "$RESPONSE" | jq -er '.SecretString' 2>/dev/null); then
  if printf '%s' "$RESPONSE" | jq -e 'has("SecretBinary")' >/dev/null 2>&1; then
    echo "sm-cache: $SECRET_ID holds only SecretBinary, which this wrapper does not cache — read it with the AWS CLI directly and handle the decoding yourself." >&2
  else
    echo "sm-cache: no SecretString in the response for $SECRET_ID" >&2
  fi
  exit 1
fi
if [ -z "$VALUE" ]; then
  echo "sm-cache: empty value returned for $SECRET_ID" >&2
  exit 1
fi

umask 077
printf '%s' "$VALUE" > "$CACHE_FILE"
emit
