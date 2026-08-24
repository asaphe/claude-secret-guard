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
run SILENT "pr body naming a reader"          "gh pr create --body \"run cat $PEM\""
run SILENT "heredoc body naming a file"       "$(printf 'cat <<EOF\n%s\nEOF' "$PEM")"

# --- ordinary reads must stay silent -------------------------------------------
run SILENT "plain markdown read"              "cat README.md"
run SILENT "dotenv example is allowlisted"    "cat .env.example"
run SILENT "quoted dotenv example"            'cat ".env.example"'
run SILENT "quoted dotenv template"           'cat ".env.template"'
run SILENT "recursive grep without a match"   "grep -r pattern ."
run SILENT "non-reader command"               "ls -la"
run SILENT "empty command"                    ""

# Pre-fix, `for token in $CMD` expanded a bare glob against the cwd and matched the real file.
GLOBDIR=$(mktemp -d "${TMPDIR:-/tmp}/read-guard-glob.XXXXXX")
trap 'rm -rf "$GLOBDIR"' EXIT
: > "$GLOBDIR/$PEM"
glob_actual=$(cd "$GLOBDIR" && decide 'cat *')
if [ "$glob_actual" = "SILENT" ]; then
  printf 'ok   %s\n' "bare glob is not expanded against the cwd"
  pass=$((pass + 1))
else
  printf 'FAIL %s — expected SILENT, got %s\n' "bare glob is not expanded against the cwd" "$glob_actual"
  fail=$((fail + 1))
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
