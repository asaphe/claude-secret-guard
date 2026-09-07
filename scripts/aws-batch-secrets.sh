#!/usr/bin/env bash
# Batch secret reader — replaces sequential get-secret-value calls with batch-get-secret-value (20 per API call); --values defaults to a masked summary so a bulk audit doesn't dump plaintext into the transcript. See README § Masked-cache wrappers for usage.

set -euo pipefail

PROFILE="${AWS_PROFILE:-}"
FILTER=""
SHOW_VALUES=false
REVEAL=false
FORMAT="table"
BATCH_SIZE=20

# Guarded like op-cache.sh's --account: an unguarded "$2" under set -u aborts with a raw "unbound variable" instead of a usable message.
require_value() {
  [ -n "$2" ] || { echo "aws-batch-secrets.sh: $1 requires a value" >&2; exit 64; }
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --profile) require_value "$1" "${2:-}"; PROFILE="$2"; shift 2 ;;
    --filter) require_value "$1" "${2:-}"; FILTER="$2"; shift 2 ;;
    --values) SHOW_VALUES=true; shift ;;
    --reveal) REVEAL=true; shift ;;
    --format) require_value "$1" "${2:-}"; FORMAT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: aws-batch-secrets.sh [--profile PROFILE] [--filter PREFIX] [--values] [--reveal] [--format json|table]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

PROFILE_ARGS=()
[ -n "$PROFILE" ] && PROFILE_ARGS=(--profile "$PROFILE")

# No --max-items: it caps the result and hands back a NextToken this script never read, so an account over the cap was silently truncated.
LIST_CMD=(aws secretsmanager list-secrets "${PROFILE_ARGS[@]}")
if [ -n "$FILTER" ]; then
  LIST_CMD+=(--filters "Key=name,Values=$FILTER")
fi

# `|| {…}` rather than `if !`: it suppresses errexit the same way while leaving $? as the CLI's own status, which callers branch on.
SECRETS_JSON=$("${LIST_CMD[@]}" 2>&1) \
  || { RC=$?; printf '%s\n' "$SECRETS_JSON" >&2; exit "$RC"; }
SECRET_ARNS=$(printf '%s\n' "$SECRETS_JSON" | jq -r '.SecretList[].ARN // empty')

if [ -z "$SECRET_ARNS" ]; then
  echo "No secrets found matching filter: $FILTER"
  exit 0
fi

TOTAL=$(printf '%s\n' "$SECRET_ARNS" | wc -l | tr -d ' ')
echo "Found $TOTAL secrets matching '${FILTER:-*}'" >&2

if [ "$SHOW_VALUES" = false ]; then
  printf '%s\n' "$SECRETS_JSON" | jq -r '.SecretList[] | [.Name, .Description // ""] | @tsv'
  exit 0
fi

ALL_RESULTS="[]"
BATCH=()
BATCH_NUM=0

while IFS= read -r arn; do
  BATCH+=("$arn")
  if [ ${#BATCH[@]} -ge $BATCH_SIZE ]; then
    BATCH_NUM=$((BATCH_NUM + 1))
    echo "Fetching batch $BATCH_NUM (${#BATCH[@]} secrets)..." >&2

    # One shell argument per ARN: a single newline-joined string reaches the CLI as one malformed secret id.
    RESULT=$(aws secretsmanager batch-get-secret-value \
      "${PROFILE_ARGS[@]}" \
      --secret-id-list "${BATCH[@]}" \
      2>&1) || true

    # jq exits non-zero on the plain-text AWS error that || true just let through, which under set -e would abandon the remaining batches silently.
    BATCH_RESULTS=$(printf '%s\n' "$RESULT" | jq '.SecretValues // []' 2>/dev/null) || {
      echo "aws-batch-secrets: batch $BATCH_NUM returned no parseable result; raw output withheld because a partially-fetched response carries SecretString values." >&2
      BATCH_RESULTS='[]'
    }
    ALL_RESULTS=$(printf '%s %s\n' "$ALL_RESULTS" "$BATCH_RESULTS" | jq -s 'add')
    BATCH=()
  fi
done <<< "$SECRET_ARNS"

if [ ${#BATCH[@]} -gt 0 ]; then
  BATCH_NUM=$((BATCH_NUM + 1))
  echo "Fetching batch $BATCH_NUM (${#BATCH[@]} secrets)..." >&2

  RESULT=$(aws secretsmanager batch-get-secret-value \
    "${PROFILE_ARGS[@]}" \
    --secret-id-list "${BATCH[@]}" \
    2>&1) || true

  BATCH_RESULTS=$(printf '%s\n' "$RESULT" | jq '.SecretValues // []' 2>/dev/null) || {
    echo "aws-batch-secrets: batch $BATCH_NUM returned no parseable result; raw output withheld because a partially-fetched response carries SecretString values." >&2
    BATCH_RESULTS='[]'
  }
  ALL_RESULTS=$(printf '%s %s\n' "$ALL_RESULTS" "$BATCH_RESULTS" | jq -s 'add')
fi

if [ "$REVEAL" = false ]; then
  echo "Values masked — pass --reveal to print full SecretString contents." >&2
  if [ "$FORMAT" = "json" ]; then
    printf '%s\n' "$ALL_RESULTS" | jq '[.[] | {Name, SecretBytes: ((.SecretString // "") | length)}]'
  else
    printf '%s\n' "$ALL_RESULTS" | jq -r '.[] | [.Name, (((.SecretString // "") | length | tostring) + " bytes")] | @tsv'
  fi
elif [ "$FORMAT" = "json" ]; then
  printf '%s\n' "$ALL_RESULTS" | jq '.'
else
  printf '%s\n' "$ALL_RESULTS" | jq -r '.[] | [.Name, (.SecretString // "(binary)")] | @tsv'
fi

echo "Fetched $TOTAL secrets in $BATCH_NUM batch(es)" >&2
