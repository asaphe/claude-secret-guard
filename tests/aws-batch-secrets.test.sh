#!/usr/bin/env bash
# Regression tests for the bulk reader: a batch that did not arrive must never be counted as fetched, and the CLI's stderr must never reach the JSON parser.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0
fail=0

ok()  { printf 'ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL %s — %s\n' "$1" "$2"; fail=$((fail + 1)); }

expect_exit() {  # expect_exit <label> <want> <got>
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected exit $2, got $3"; fi
}

expect_stderr() {  # expect_stderr <label> <pattern>
  if grep -q -- "$2" "$WORK/err"; then ok "$1"; else bad "$1" "stderr lacks '$2': $(tr '\n' '|' < "$WORK/err")"; fi
}

expect_lines() {  # expect_lines <label> <want>
  local got; got=$(wc -l < "$WORK/out" | tr -d ' ')
  if [ "$got" = "$2" ]; then ok "$1"; else bad "$1" "expected $2 stdout lines, got $got"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/secret-guard-batch.XXXXXX") || {
  printf 'FATAL: mktemp failed — every case below would run against an empty path and pass vacuously\n'
  exit 1
}
trap 'rm -rf "$WORK"' EXIT

# Not routed through fixture-value.sh: these stand in for secret *values*, so being secret-shaped would only force an allowlist entry.
stub() {  # stub <listed-count> <batch-mode>
  mkdir -p "$WORK/bin"
  rm -f "$WORK/calls"
  cat > "$WORK/bin/aws" <<STUB
#!/usr/bin/env bash
LISTED=$1
MODE=$2
WORK="$WORK"
STUB
  cat >> "$WORK/bin/aws" <<'STUB'
args="$*"
case "$args" in
  *list-secrets*)
    if [ "$MODE" = "list-fails" ]; then echo "stub: list refused" >&2; exit 253; fi
    jq -nc --argjson n "$LISTED" '{SecretList: [range($n) | {ARN: ("arn:aws:secretsmanager:us-east-1:1:secret:s\(.)"), Name: "s\(.)", Description: "d"}]}'
    ;;
  *batch-get*)
    calls=$(cat "$WORK/calls" 2>/dev/null || echo 0); calls=$((calls + 1)); echo "$calls" > "$WORK/calls"
    n=0; for a in "$@"; do case "$a" in arn:*) n=$((n + 1)) ;; esac; done
    case "$MODE" in
      ok)      jq -nc --argjson n "$n" '{SecretValues: [range($n) | {Name: "s\(.)", SecretString: "value-\(.)"}]}' ;;
      noisy)   echo "urllib3 v2 only supports OpenSSL 1.1.1+" >&2
               jq -nc --argjson n "$n" '{SecretValues: [range($n) | {Name: "s\(.)", SecretString: "value-\(.)"}]}' ;;
      denied)  echo "An error occurred (AccessDeniedException) when calling the operation" >&2; exit 254 ;;
      garbage) echo "not json at all"; exit 0 ;;
      partial) jq -nc --argjson n "$n" '{SecretValues: [range($n - 1) | {Name: "s\(.)", SecretString: "value-\(.)"}], Errors: [{SecretId: "arn:aws:secretsmanager:us-east-1:1:secret:denied-one", ErrorCode: "AccessDeniedException"}]}' ;;
      tail-fails)
        if [ "$calls" -eq 1 ]; then
          jq -nc --argjson n "$n" '{SecretValues: [range($n) | {Name: "s\(.)", SecretString: "value-\(.)"}]}'
        else
          echo "An error occurred (AccessDeniedException) when calling the operation" >&2; exit 254
        fi
        ;;
    esac
    ;;
esac
STUB
  chmod +x "$WORK/bin/aws"
}

run() {  # run <listed-count> <batch-mode> <args...>
  local listed="$1" mode="$2"; shift 2
  stub "$listed" "$mode"
  PATH="$WORK/bin:$PATH" bash "$ROOT/scripts/aws-batch-secrets.sh" "$@" >"$WORK/out" 2>"$WORK/err"
}

run 3 ok --values
expect_exit "a fully fetched run succeeds" 0 "$?"
expect_stderr "a fully fetched run reports 3 of 3" "Fetched 3 of 3 secrets"
expect_lines "a fully fetched run prints one row per secret" 3

run 3 ok --values
expect_stderr "values are masked unless --reveal is passed" "Values masked"
if grep -q "value-0" "$WORK/out"; then bad "the masked default prints byte counts, not values" "a SecretString reached stdout"; else ok "the masked default prints byte counts, not values"; fi

run 3 ok --values --reveal
if grep -q "value-0" "$WORK/out"; then ok "--reveal prints the values"; else bad "--reveal prints the values" "no value on stdout"; fi

# The whole batch used to be discarded here, because 2>&1 merged this notice into the JSON the parse below reads.
run 3 noisy --values
expect_exit "a benign CLI notice on a successful call does not fail the batch" 0 "$?"
expect_stderr "a noisy but successful run still reports 3 of 3" "Fetched 3 of 3 secrets"
expect_lines "a noisy but successful run keeps every row" 3

# The trailer used to assert the listed count and exit 0 after swallowing the failure entirely.
run 3 denied --values
expect_exit "a denied batch propagates the CLI's exit code" 254 "$?"
expect_stderr "a denied batch is reported as incomplete" "Fetched 0 of 3 secrets in 1 batch(es) — INCOMPLETE"
expect_lines "a denied batch prints no rows" 0

run 25 tail-fails --values
expect_exit "a failed tail batch fails the run" 254 "$?"
expect_stderr "a failed tail batch reports what actually arrived" "Fetched 20 of 25 secrets in 2 batch(es) — INCOMPLETE"
expect_lines "a failed tail batch still prints the batch that succeeded" 20

run 3 partial --values
expect_exit "per-secret errors inside a successful call fail the run" 1 "$?"
expect_stderr "per-secret errors are reported as incomplete" "Fetched 2 of 3 secrets"
expect_stderr "per-secret errors name the secret that failed" "denied-one"

run 3 garbage --values
expect_exit "an unparseable batch response fails the run" 1 "$?"
if grep -q "not json at all" "$WORK/err"; then bad "an unparseable response is withheld from stderr" "raw output was echoed"; else ok "an unparseable response is withheld from stderr"; fi

run 3 list-fails --values
expect_exit "a failed list propagates the CLI's exit code" 253 "$?"

run 0 ok --values
expect_exit "an empty list exits clean" 0 "$?"

run 3 ok
expect_exit "the default listing needs no batch call" 0 "$?"
expect_lines "the default listing prints name and description per secret" 3

# Load-bearing on bash 3.2 (macOS system bash), where expanding an empty array under set -u aborts before any AWS call.
unguarded_expansions() {  # unguarded_expansions <path>
  grep -rh 'PROFILE_ARGS\[@\]' "$1" \
    | sed 's/PROFILE_ARGS\[@\]+"[^"]*"//g' \
    | grep -c 'PROFILE_ARGS\[@\]'
}

DOLLAR='$'
printf 'X=(a); echo "%s{PROFILE_ARGS[@]}"\n' "$DOLLAR" > "$WORK/control.sh"
if [ "$(unguarded_expansions "$WORK/control.sh")" -eq 0 ]; then
  bad "the unguarded-expansion probe can see one" "the known-positive control was not detected"
else
  ok "the unguarded-expansion probe can see one"
fi

if [ "$(unguarded_expansions "$ROOT/scripts/")" -eq 0 ]; then
  ok "no script expands PROFILE_ARGS unguarded"
else
  bad "no script expands PROFILE_ARGS unguarded" "$(grep -rn 'PROFILE_ARGS\[@\]' "$ROOT/scripts/" | grep -v 'PROFILE_ARGS\[@\]+')"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
