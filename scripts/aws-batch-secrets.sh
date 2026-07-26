#!/usr/bin/env bash
# Batch secret reader — replaces sequential get-secret-value calls with batch-get-secret-value (20 per API call); --values defaults to a masked summary so a bulk audit doesn't dump plaintext into the transcript. See README § Masked-cache wrappers for usage.

set -euo pipefail

PROFILE="${AWS_PROFILE:-}"
FILTER=""
SHOW_VALUES=false
REVEAL=false
FORMAT="table"
BATCH_SIZE=20

while [[ $# -gt 0 ]]; do
  case $1 in
    --profile) PROFILE="$2"; shift 2 ;;
    --filter) FILTER="$2"; shift 2 ;;
    --values) SHOW_VALUES=true; shift ;;
    --reveal) REVEAL=true; shift ;;
    --format) FORMAT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: aws-batch-secrets.sh [--profile PROFILE] [--filter PREFIX] [--values] [--reveal] [--format json|table]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

PROFILE_ARGS=()
[ -n "$PROFILE" ] && PROFILE_ARGS=(--profile "$PROFILE")

LIST_CMD=(aws secretsmanager list-secrets "${PROFILE_ARGS[@]}" --max-items 500)
if [ -n "$FILTER" ]; then
  LIST_CMD+=(--filters "Key=name,Values=$FILTER")
fi

SECRETS_JSON=$("${LIST_CMD[@]}" 2>&1)
SECRET_ARNS=$(echo "$SECRETS_JSON" | jq -r '.SecretList[].ARN // empty')

if [ -z "$SECRET_ARNS" ]; then
  echo "No secrets found matching filter: $FILTER"
  exit 0
fi

TOTAL=$(echo "$SECRET_ARNS" | wc -l | tr -d ' ')
echo "Found $TOTAL secrets matching '${FILTER:-*}'" >&2

if [ "$SHOW_VALUES" = false ]; then
  echo "$SECRETS_JSON" | jq -r '.SecretList[] | [.Name, .Description // ""] | @tsv'
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

    ARN_LIST=$(printf '%s\n' "${BATCH[@]}" | jq -R . | jq -s .)
    RESULT=$(aws secretsmanager batch-get-secret-value \
      "${PROFILE_ARGS[@]}" \
      --secret-id-list "$(echo "$ARN_LIST" | jq -r '.[]')" \
      2>&1) || true

    BATCH_RESULTS=$(echo "$RESULT" | jq '.SecretValues // []')
    ALL_RESULTS=$(echo "$ALL_RESULTS $BATCH_RESULTS" | jq -s 'add')
    BATCH=()
  fi
done <<< "$SECRET_ARNS"

if [ ${#BATCH[@]} -gt 0 ]; then
  BATCH_NUM=$((BATCH_NUM + 1))
  echo "Fetching batch $BATCH_NUM (${#BATCH[@]} secrets)..." >&2

  ARN_LIST=$(printf '%s\n' "${BATCH[@]}" | jq -R . | jq -s .)
  RESULT=$(aws secretsmanager batch-get-secret-value \
    "${PROFILE_ARGS[@]}" \
    --secret-id-list "$(echo "$ARN_LIST" | jq -r '.[]')" \
    2>&1) || true

  BATCH_RESULTS=$(echo "$RESULT" | jq '.SecretValues // []')
  ALL_RESULTS=$(echo "$ALL_RESULTS $BATCH_RESULTS" | jq -s 'add')
fi

if [ "$REVEAL" = false ]; then
  echo "Values masked — pass --reveal to print full SecretString contents." >&2
  if [ "$FORMAT" = "json" ]; then
    echo "$ALL_RESULTS" | jq '[.[] | {Name, SecretBytes: ((.SecretString // "") | length)}]'
  else
    echo "$ALL_RESULTS" | jq -r '.[] | [.Name, (((.SecretString // "") | length | tostring) + " bytes")] | @tsv'
  fi
elif [ "$FORMAT" = "json" ]; then
  echo "$ALL_RESULTS" | jq '.'
else
  echo "$ALL_RESULTS" | jq -r '.[] | [.Name, (.SecretString // "(binary)")] | @tsv'
fi

echo "Fetched $TOTAL secrets in $BATCH_NUM batch(es)" >&2
