#!/usr/bin/env bash
# Regression tests for the reader gate: a filename is recognised after shell quoting is removed, and no token is glob-expanded.
set -uo pipefail

# Absolute, because the glob case runs the guard from a different cwd.
GUARD="$(cd "$(dirname "$0")/../scripts" && pwd)/read-secret-guard-bash.sh"
[ -f "$GUARD" ] || { printf 'FATAL: guard not found at %s\n' "$GUARD"; exit 1; }

pass=0
fail=0

decide() {  # decide <command-text> -> ASK | SILENT
  local out
  out=$(printf '%s' "$(jq -nc --arg c "$1" '{tool_input:{command:$c}}')" | bash "$GUARD" 2>/dev/null)
  if printf '%s' "$out" | grep -q '"permissionDecision":[[:space:]]*"ask"'; then
    printf 'ASK'
  else
    printf 'SILENT'
  fi
}

run() {
  local expect="$1" label="$2" cmd="$3" actual
  actual=$(decide "$cmd")
  if [ "$actual" = "$expect" ]; then
    printf 'ok   %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL %s — expected %s, got %s\n' "$label" "$expect" "$actual"
    fail=$((fail + 1))
  fi
}

PEM=secrets.pem
KEY=server.key

# --- the reader is matched anywhere in a segment, not after a fixed wrapper list ---
run ASK "reader behind timeout"               "timeout 5 cat $PEM"
run ASK "reader behind nice"                  "nice cat $PEM"
run ASK "reader behind stdbuf"                "stdbuf -o0 cat $PEM"
run ASK "reader behind ionice"                "ionice -c3 cat $PEM"
run ASK "absolute path to cat"                "/bin/cat $PEM"
run ASK "relative path to head"               "./bin/head $PEM"
run ASK "redirect glued to the reader"        "cat<$PEM"
# The suffix patterns survive the glue; the anchored ones do not, so a glued token has to be split.
run ASK "glued redirect before dotenv"        "cat<.env"
run ASK "glued redirect before an ssh key"    "cat<id_rsa"
run ASK "glued redirect before a kubeconfig"  "cat<kubeconfig"
run ASK "glued redirect under grep"           "grep NEEDLE<$KEY"
run SILENT "glued redirect, ordinary file"    "cat<README.md"

# --- grep is gated whether or not it recurses: -r decides how many files are read, not whether one is a key ---
run ASK "non-recursive -f names a pem"        "grep -f $PEM ."
run ASK "non-recursive grep of a key"         "grep AKIA $KEY"
run ASK "non-recursive grep of dotenv"        "grep TOKEN .env"
run SILENT "non-recursive grep of a log"      "grep needle app.log"

# --- a respelled reader name reaches the gate too, like the mask guard's verbs ---
run ASK "quoted reader name"                  "\"cat\" $PEM"
run ASK "reader split across a quote"         "c\"a\"t $PEM"
run ASK "escaped reader name"                 "\\cat $PEM"

# --- ordinary commands must stay silent ---
run SILENT "path reader over a plain file"    "/bin/cat README.md"

# --- quoted filenames: the reported bypass -------------------------------------
run ASK "unquoted pem"                        "cat $PEM"
run ASK "double-quoted pem"                   "cat \"$PEM\""
run ASK "single-quoted pem"                   "cat '$PEM'"
run ASK "double-quoted dotenv"                'cat ".env"'
run ASK "single-quoted dotenv"                "cat '.env'"
run ASK "quoted absolute ssh key path"        'cat "/home/u/.ssh/id_rsa"'
run ASK "quoted name containing a space"      "cat \"my $PEM\""
run ASK "quoted ed25519 key via head"         'head "id_ed25519"'
run ASK "quoted key via tail"                 "tail '$KEY'"
run ASK "quoted kubeconfig by basename"       'cat "kubeconfig"'
run ASK "quoted kube config by path"          "less \"\$HOME/.kube/config\""
run ASK "quoted p12 via more"                 'more "cert.p12"'
run ASK "quoted pem after end-of-options"     "cat -- \"$PEM\""
run ASK "quoted pem in recursive grep"        "grep -r pattern \"$PEM\""

# `less -m` is a valid no-argument flag, so -m carries a filename here, not prose.
run ASK "less -m does not mask its argument"  "less -m \"$PEM\""

# --- unparseable input must fail toward asking, never toward silence -----------
run ASK "unbalanced quote still asks"         "cat \"$PEM"

# --- prose describing a read must stay silent (the gate's masking) -------------
run SILENT "commit message naming a reader"   'git commit -m "fix grep -r over .env files"'
run SILENT "non-reader first word stays silent" "gh pr create --body \"run cat $PEM\""
# First word is a reader, so the gate fires and only the flag masking keeps these silent.
run SILENT "--body value is masked in the scan"      'cat README.md && gh pr create --body ".env"'
run SILENT "--comment value is masked in the scan"   'cat README.md && gh issue comment 1 --comment ".env"'
run SILENT "--description value is masked in the scan" 'cat README.md && gh repo edit --description ".env"'
run SILENT "--message value is masked in the scan"    'cat README.md && git commit --message ".env"'
run SILENT "heredoc body naming a file"       "$(printf 'cat <<EOF\n%s\nEOF' "$PEM")"

# --- ordinary reads must stay silent -------------------------------------------
run SILENT "plain markdown read"              "cat README.md"
run SILENT "dotenv example is allowlisted"    "cat .env.example"
run SILENT "quoted dotenv example"            'cat ".env.example"'
run SILENT "quoted dotenv template"           'cat ".env.template"'
run SILENT "recursive grep without a match"   "grep -r pattern ."
run SILENT "non-reader command"               "ls -la"
run SILENT "empty command"                    ""

# --- globs are judged by pattern, not expanded against the cwd -----------------
run ASK "bare wildcard could match anything"  "cat *"
run ASK "dotenv prefix wildcard"              "cat .env*"
run ASK "wildcard inside .ssh"                "cat .ssh/*"
run ASK "wildcard with a key suffix"          "cat *.pem"
run SILENT "wildcard that cannot match a secret" "cat *.log"

# --- the reader need not be the first word --------------------------------------
run ASK "reader after a semicolon"            "true; cat $PEM"
run ASK "reader after &&"                     "ls -la && cat $PEM"
run ASK "reader behind sudo"                  "sudo cat $PEM"
run ASK "reader inside bash -c"               "bash -c \"cat $PEM\""
run ASK "reader after a pipe"                 "echo x | head $PEM"
run SILENT "prose separator without a reader" "true; rm -rf build"

# --- shell syntax glued to the filename -----------------------------------------
run ASK "ansi-c quoted dotenv"                "cat \$'.env'"
run ASK "command substitution argument"       "cat \$(echo $PEM)"
run ASK "backtick substitution argument"      "cat \`echo $PEM\`"

# --- end-of-options must not hide a dash-prefixed filename ---------------------
run ASK "dash-prefixed pem after --"          "cat -- -$PEM"
run ASK "dash-prefixed dotenv after --"       "tail -- -.env"

# The verdict must not depend on the cwd, and this arm needs a control that can fail.
GLOBDIR=$(mktemp -d "${TMPDIR:-/tmp}/read-guard-glob.XXXXXX")
trap 'rm -rf "$GLOBDIR"' EXIT
: > "$GLOBDIR/$PEM"
check_from_globdir() {
  local expect="$1" label="$2" cmd="$3" actual
  actual=$(cd "$GLOBDIR" && decide "$cmd")
  if [ "$actual" = "$expect" ]; then
    printf 'ok   %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL %s — expected %s, got %s\n' "$label" "$expect" "$actual"
    fail=$((fail + 1))
  fi
}
check_from_globdir ASK    "positive control from the glob cwd" "cat $PEM"
check_from_globdir SILENT "harmless glob beside a real pem"    "cat *.log"

# --- the authority must carry this guard's exit code, not just its stdout ---
# Only stdout was read, so the reader's own fail-closed branch reached the caller as a plain allow. Stubbed rather than provoked, because every earlier stage refuses the same unreadable payload first and would exit before this one runs.
AUTH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-wiring.XXXXXX") || { printf 'FATAL: mktemp failed\n'; exit 1; }
cp "$(dirname "$GUARD")"/*.sh "$AUTH_DIR/"
printf '#!/bin/sh\necho "READ-SECRET GUARD: stub refusal" >&2\nexit 2\n' > "$AUTH_DIR/read-secret-guard-bash.sh"
chmod +x "$AUTH_DIR/read-secret-guard-bash.sh"
jq -nc '{tool_input:{command:"echo hi"}}' | bash "$AUTH_DIR/bash-secret-authority.sh" >/dev/null 2>&1
AUTH_CODE=$?
if [ "$AUTH_CODE" -eq 2 ]; then
  printf 'ok   the authority propagates the reader refusal\n'; pass=$((pass + 1))
else
  printf 'FAIL the authority propagates the reader refusal — expected exit 2, got %s\n' "$AUTH_CODE"; fail=$((fail + 1))
fi
printf '#!/bin/sh\nexit 0\n' > "$AUTH_DIR/read-secret-guard-bash.sh"
jq -nc '{tool_input:{command:"echo hi"}}' | bash "$AUTH_DIR/bash-secret-authority.sh" >/dev/null 2>&1
AUTH_OK=$?
if [ "$AUTH_OK" -eq 0 ]; then
  printf 'ok   a silent reader still allows\n'; pass=$((pass + 1))
else
  printf 'FAIL a silent reader still allows — expected exit 0, got %s\n' "$AUTH_OK"; fail=$((fail + 1))
fi
rm -rf "$AUTH_DIR"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
