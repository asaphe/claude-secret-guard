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

# Expanded below as ${a[@]+…}: on bash 3.2 (macOS system bash) an empty array under set -u aborts the script before any AWS call.
PROFILE_ARGS=()
[ -n "$PROFILE" ] && PROFILE_ARGS=(--profile "$PROFILE")

# No --max-items: it caps the result and hands back a NextToken this script never read, so an account over the cap was silently truncated.
LIST_CMD=(aws secretsmanager list-secrets ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"})
if [ -n "$FILTER" ]; then
  LIST_CMD+=(--filters "Key=name,Values=$FILTER")
fi

# Streams stay separate: merged into stdout, a benign CLI notice on a *successful* call becomes part of the JSON and breaks every parse below.
SECRETS_JSON=$("${LIST_CMD[@]}") || exit $?
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
FETCHED=0
FAILED_RC=0

# Assigns globals rather than echoing: run in a command substitution, the counters it maintains would die with the subshell.
fetch_batch() {  # fetch_batch <arn...>
  local rc=0 result batch_results count errors
  BATCH_NUM=$((BATCH_NUM + 1))
  echo "Fetching batch $BATCH_NUM ($# secrets)..." >&2

  # One shell argument per ARN: a single newline-joined string reaches the CLI as one malformed secret id.
  result=$(aws secretsmanager batch-get-secret-value \
    ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} \
    --secret-id-list "$@") || rc=$?

  if [ "$rc" -ne 0 ]; then
    FAILED_RC=$rc
    echo "aws-batch-secrets: batch $BATCH_NUM failed (aws exit $rc); its $# secrets are absent from the output below." >&2
    return 0
  fi

  # A parse failure now means genuinely malformed JSON rather than stderr noise, and it still must not read as an empty batch.
  if ! batch_results=$(printf '%s\n' "$result" | jq '.SecretValues // []' 2>/dev/null); then
    [ "$FAILED_RC" -ne 0 ] || FAILED_RC=1
    echo "aws-batch-secrets: batch $BATCH_NUM returned no parseable result; raw output withheld because a partially-fetched response carries SecretString values." >&2
    return 0
  fi

  # AWS reports per-secret failures inside a successful call, so a 200 does not mean the batch was fully fetched.
  errors=$(printf '%s\n' "$result" | jq -r '.Errors // [] | .[] | [.SecretId, .ErrorCode] | @tsv')
  if [ -n "$errors" ]; then
    [ "$FAILED_RC" -ne 0 ] || FAILED_RC=1
    printf 'aws-batch-secrets: batch %s could not fetch:\n%s\n' "$BATCH_NUM" "$errors" >&2
  fi

  count=$(printf '%s\n' "$batch_results" | jq 'length')
  FETCHED=$((FETCHED + count))
  ALL_RESULTS=$(printf '%s %s\n' "$ALL_RESULTS" "$batch_results" | jq -s 'add')
}

while IFS= read -r arn; do
  BATCH+=("$arn")
  if [ ${#BATCH[@]} -ge $BATCH_SIZE ]; then
    fetch_batch "${BATCH[@]}"
    BATCH=()
  fi
done <<< "$SECRET_ARNS"

if [ ${#BATCH[@]} -gt 0 ]; then
  fetch_batch "${BATCH[@]}"
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

# Reports what the run achieved, not what it listed: the old trailer asserted TOTAL after a swallowed batch and still exited 0.
if [ "$FETCHED" -ne "$TOTAL" ] || [ "$FAILED_RC" -ne 0 ]; then
  echo "Fetched $FETCHED of $TOTAL secrets in $BATCH_NUM batch(es) — INCOMPLETE" >&2
  [ "$FAILED_RC" -eq 0 ] || exit "$FAILED_RC"
  exit 1
fi

echo "Fetched $FETCHED of $TOTAL secrets in $BATCH_NUM batch(es)" >&2
