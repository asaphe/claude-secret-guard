#!/usr/bin/env bash
# Regression tests for the mask guard: a command that only *describes* a guarded read is allowed, one that *performs* it is blocked, and an input it cannot parse is refused.
set -uo pipefail

GUARD="$(dirname "$0")/../scripts/secret-mask-guard.sh"

pass=0
fail=0

run() {
  expect="$1"; label="$2"; cmd="$3"
  payload=$(jq -nc --arg c "$cmd" '{tool_input:{command:$c},session_id:"mask-test"}')
  printf '%s' "$payload" | bash "$GUARD" >/dev/null 2>&1
  code=$?
  actual="ALLOW"
  [ "$code" -ne 0 ] && actual="BLOCK"
  if [ "$actual" = "$expect" ]; then
    printf 'ok   %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL %s — expected %s, got %s\n' "$label" "$expect" "$actual"
    fail=$((fail + 1))
  fi
}

# run_raw feeds stdin verbatim, for payloads that are not valid hook JSON.
run_raw() {
  expect="$1"; label="$2"; payload="$3"
  printf '%s' "$payload" | bash "$GUARD" >/dev/null 2>&1
  code=$?
  actual="ALLOW"
  [ "$code" -ne 0 ] && actual="BLOCK"
  if [ "$actual" = "$expect" ]; then
    printf 'ok   %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL %s — expected %s, got %s\n' "$label" "$expect" "$actual"
    fail=$((fail + 1))
  fi
}

# Assembled rather than written literally so this file does not itself trip the guard it tests.
R='read'
U='op://Vault/Item/field'
# shellcheck disable=SC2016 # literal, unexpanded: the guard must see the substitution syntax
SUB='$('
SM='secretsmanager'
IG='item get'
DG='document get'
TAB=$(printf '\t')

# --- a real read must be blocked, wherever it sits in the command ---
run BLOCK "plain op read"                    "op $R $U"

# --- the wrapper path is not an exemption: a comment naming it used to clear the whole guard ---
run BLOCK "trailing comment names the wrapper" "op $R $U # see scripts/op-cache.sh"
run BLOCK "fetch alongside an item get"      "op $IG X; op $R $U"
run ALLOW "the wrapper actually called"      "\"\$CLAUDE_PLUGIN_ROOT\"/scripts/op-cache.sh --mask $U"

# --- respellings that leave the shell's meaning intact: the predicates normalize before matching ---
run BLOCK "continuation before the read verb" "$(printf 'op \\\n%s %s' "$R" "$U")"
run BLOCK "continuation before the aws verb" "$(printf 'aws %s \\\nget-secret-value --secret-id my-secret' "$SM")"
run BLOCK "double-quoted subcommand"         "op \"$R\" $U"
run BLOCK "single-quoted subcommand"         "op '$R' $U"
run BLOCK "binary split across a quote"      "o\"p\" $R $U"
run BLOCK "backslash inside the binary"      "o\\p $R $U"
run BLOCK "backslash inside the verb"        "op re\\ad $U"
run BLOCK "ansi-c quoted verb"               "op \$'$R' $U"
run BLOCK "tab between the aws words"        "aws $SM${TAB}get-secret-value --secret-id my-secret"
run BLOCK "tab between document and get"     "op document${TAB}get server-key"
# A quote pair holding whitespace is left alone, so searching for the phrase is not performing it.
run ALLOW "grep for the read phrase"         "grep -rn \"op $R\" scripts/"
run ALLOW "echoing the phrase"               "echo \"we block op $R\""

# --- the other 1Password subcommands that print a value ---
run BLOCK "item get --reveal"                "op $IG Netflix --reveal"
run BLOCK "item get --otp"                   "op $IG Netflix --otp"
run BLOCK "document get to stdout"           "op $DG server-key"
run BLOCK "inject to stdout"                 "op inject -i config.tpl"
run BLOCK "inject reading from stdin"        "op inject < config.tpl"
run BLOCK "run with masking disabled"        "op run --no-masking -- env"
run BLOCK "-only is not an output flag"      "op $DG server-key -only"
run BLOCK "out-file pointed at stdout"       "op $DG server-key --out-file /dev/stdout"
run BLOCK "-o precedes the subcommand"       "ssh -o StrictHostKeyChecking=no host \"op $DG server-key\""
run BLOCK "only stderr is redirected"        "op inject -i config.tpl 2>/dev/null"
# Each predicate is flag-conditional and scoped to the fetch's own segment, so the concealing, file-bound and masked forms stay usable.
run ALLOW "item get conceals by default"     "op $IG Netflix --fields label=username"
run ALLOW "document get --out-file"          "op $DG server-key --out-file /tmp/k"
run ALLOW "inject piped to its consumer"     "op inject -i deploy.tpl | kubectl apply -f -"
run ALLOW "inject redirected"                "op inject -i .env.tpl > .env"
run ALLOW "run leaves masking on"            "op run -- ./deploy.sh"
run ALLOW "item get beside a wrapper reveal" "op $IG X --fields label=username && scripts/op-cache.sh --reveal $U"

# --- a destination only counts when it is a file the transcript does not see ---
# strip_cmd replaces a masked body with <<STRIPPED_HEREDOC>>, whose >> is not a redirect.
run BLOCK "heredoc placeholder is not a redirect" "$(printf 'op inject <<EOF\nx\nEOF')"
run BLOCK "quoted heredoc is not a redirect" "$(printf 'op inject <<%sEOF%s\nx\nEOF' "'" "'")"
# >&N duplicates a descriptor rather than naming a file, and stderr reaches the transcript too.
run BLOCK "redirected to stderr"             "op inject -i x >&2"
run BLOCK "redirected to /dev/stdout"        "op inject -i x > /dev/stdout"
run BLOCK "redirected to a duped fd"         "op $DG k > /dev/fd/1"
run ALLOW "control: an ordinary redirect"    "op inject -i x > /tmp/f"
run ALLOW "control: an append redirect"      "op inject -i x >> /tmp/f"
run ALLOW "control: the 1> spelling"         "op inject -i x 1> /tmp/f"

# --- the tail is cut at the FIRST subcommand, not the last ---
# A greedy cut lands inside the filename and hides the very flag it is looking for.
run ALLOW "out-file value contains inject"   "op $DG key --out-file inject.log"
run ALLOW "inject out-file contains inject"  "op inject -i template --out-file inject.tpl"
run BLOCK "control: same shape, no out-file" "op inject -i template.inject"
run BLOCK "op read with intermediate flags"  "op $R --account example.1password.com $U"
run BLOCK "after a semicolon"                "git status; op $R $U"
run BLOCK "after a pipe"                     "printf x | op $R $U"
run BLOCK "after &&"                         "cd /tmp && op $R $U"
run BLOCK "on its own line"                  "cd /tmp
op $R $U"
run BLOCK "behind env prefix"                "env FOO=1 op $R $U"
run BLOCK "behind sudo"                      "sudo op $R $U"
run BLOCK "absolute path to op"              "/usr/local/bin/op $R $U"
run BLOCK "inside command substitution"      "X=${SUB}op $R $U)"
run BLOCK "inside backticks"                 "X=\`op $R $U\`"
run BLOCK "inside eval"                      "eval \"op $R $U\""
run BLOCK "inside bash -c"                   "bash -c \"op $R $U\""
run BLOCK "inside sh -c single-quoted"       "sh -c 'op $R $U'"

run BLOCK "get-secret-value"                 "aws $SM get-secret-value --secret-id my-secret"
run BLOCK "get-secret-value behind rtk"      "rtk aws $SM get-secret-value --secret-id my-secret"
run BLOCK "get-secret-value with flags"      "aws --profile prod $SM get-secret-value --secret-id my-secret"
run BLOCK "batch-get-secret-value"           "aws $SM batch-get-secret-value --secret-id-list a b"
run BLOCK "get-secret-value in substitution" "X=${SUB}aws $SM get-secret-value --secret-id my-secret)"

# --- prose that merely names the pattern must be allowed ---
run ALLOW "--body describing op read"        "gh pr create --title t --body \"Use the wrapper instead of op $R $U\""
run ALLOW "--body describing get-secret"     "gh issue comment 5 --body \"the guard blocks aws $SM get-secret-value calls\""
run ALLOW "-m describing op read"            "git commit -m \"docs: explain why op $R $U is blocked\""
run ALLOW "--title describing op read"       "gh pr create --title \"block op $R calls\" --body \"see docs\""
run ALLOW "--notes describing op read"       "gh release create v1 --notes \"no longer calls op $R here\""
run ALLOW "quoted heredoc of prose"          "cat > doc.md <<'EOF'
never call op $R $U directly
EOF"

# --- prose masking must not hide a read that actually runs ---
run BLOCK "-m whose value substitutes"       "git commit -m \"token ${SUB}op $R $U)\""
run BLOCK "-m whose value uses backticks"    "git commit -m \"token \`op $R $U\`\""
run BLOCK "--body whose value substitutes"   "gh pr create --body \"token ${SUB}op $R $U)\""
run ALLOW "-m single-quoted cannot expand"   "git commit -m 'the literal ${SUB}op $R $U) in prose'"
run BLOCK "bare heredoc that substitutes"    "cat > f.txt <<EOF
value=${SUB}op $R $U)
EOF"

# --- exemptions ---
run ALLOW "op item get is not a mask target" "op item get ABC --account example.1password.com --fields 'Client ID'"
run ALLOW "op-cache wrapper"                 "\"\$CLAUDE_PLUGIN_ROOT\"/scripts/op-cache.sh --mask $U"
run ALLOW "sm-cache wrapper"                 "scripts/sm-cache.sh --mask my-secret"

# --- a word merely ending in "op" is not the op binary ---
run ALLOW "stop read"                        "stop $R the file"
run ALLOW "develop read"                     "develop $R model"
run ALLOW "loop read in a while loop"        "while loop $R line; do :; done"
run ALLOW "unrelated command"                "git status"

# --- unparseable input must be refused, never waved through ---
run BLOCK "unbalanced quote around a read"   "op $R 'unclosed"
run_raw BLOCK "invalid JSON payload"         '{this is not json'
run_raw BLOCK "empty payload"                ''
run_raw ALLOW "valid payload, no command"    '{"tool_input":{},"session_id":"mask-test"}'

# --- a missing interpreter must refuse the command, not silently stop checking it ---
STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT
for bin in perl jq; do
  printf '#!/bin/sh\nexit 127\n' > "$STUB/$bin"
  chmod +x "$STUB/$bin"
done

run_without() {
  missing="$1"; expect="$2"; label="$3"; cmd="$4"
  payload=$(jq -nc --arg c "$cmd" '{tool_input:{command:$c},session_id:"mask-test"}')
  printf '%s' "$payload" | PATH="$STUB-$missing:$PATH" bash "$GUARD" >/dev/null 2>&1
  code=$?
  actual="ALLOW"
  [ "$code" -ne 0 ] && actual="BLOCK"
  if [ "$actual" = "$expect" ]; then
    printf 'ok   %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL %s — expected %s, got %s\n' "$label" "$expect" "$actual"
    fail=$((fail + 1))
  fi
}

for bin in perl jq; do
  mkdir -p "$STUB-$bin"
  cp "$STUB/$bin" "$STUB-$bin/$bin"
done
trap 'rm -rf "$STUB" "$STUB-perl" "$STUB-jq"' EXIT

# --- a quoted argument is an argument, and quotes cannot be paired by a regex ---
# Blanking quoted runs with a sed pattern paired the CLOSING quote of one argument with the OPENING quote of the next, so everything between them — including the flag this check exists to find — was erased.
run BLOCK "reveal between two quoted args"    "op $IG \"My Item\" --reveal --format \"json\""
run BLOCK "otp between two quoted args"       "op $IG \"My Item\" --otp --format \"json\""
run BLOCK "reveal between single-quoted args" "op $IG 'My Item' --reveal --fields 'password'"
run BLOCK "no-masking quoted"                 "op run \"--no-masking\" -- printenv"
# The same pairing bug in the other direction: an ordinary redirect swallowed by the blank.
run ALLOW "quoted item, quoted destination"   "op $DG \"My Doc\" > \"/tmp/out\""
run ALLOW "quoted item, quoted out-file"      "op $DG \"My Doc\" --out-file \"/tmp/out\""
run ALLOW "single-quoted both"                "op $DG 'My Doc' > '/tmp/out'"
run ALLOW "variables for both, quoted"        "op inject -i \"\$TPL\" > \"\$OUT\""
run ALLOW "a # inside a quoted argument"      "op $DG \"a # b\" > /tmp/f"

# --- an alias spelling that does not run is not a destination either ---
# Reading the tail as written let a /dev/stdout inside a comment or a quoted flag value take the block path, refusing a fetch that already named a real file.
run ALLOW "real out-file, alias in a comment"  "op $DG key --out-file /tmp/f # > /dev/stdout"
run ALLOW "real redirect, alias in a comment"  "op $DG key > /tmp/f # /dev/stdout"
run ALLOW "real out-file, quoted -o alias"     "op $DG key --tags '-o /dev/stdout' --out-file /tmp/f"
run ALLOW "real redirect, quoted alias tag"    "op $DG key --tags '/dev/stdout' > /tmp/f"
run BLOCK "control: unquoted bare dash"        "op $DG key --out-file -"
run ALLOW "control: quoted path with a space"  "op $DG key --out-file \"/tmp/my file\""

# --- a quoted stdout alias is still stdout ---
# The permissive test reads a tail with quoted runs blanked, so the restrictive one has to read the tail as written or "/dev/stdout" becomes filler and the broader redirect test calls it a file.
run BLOCK "quoted /dev/stdout"                "op $DG key > \"/dev/stdout\""
run BLOCK "single-quoted /dev/stdout"         "op $DG key > '/dev/stdout'"
run BLOCK "quoted /dev/fd/1"                  "op inject -i t > \"/dev/fd/1\""
run BLOCK "quoted bare dash out-file"         "op $DG key --out-file \"-\""
run BLOCK "control: unquoted /dev/stdout"     "op $DG key > /dev/stdout"

# --- the cut reads the raw segment, so it has to tolerate the quotes normalization removes ---
run ALLOW "quoted subcommand, real redirect"  "op \"document\" get k > /tmp/f"
run ALLOW "quoted subcommand, real out-file"  "op \"inject\" -i t --out-file /tmp/f"
run BLOCK "control: quoted subcommand, none"  "op \"document\" get k"

# --- op's own global flags may carry a quoted value holding whitespace ---
# The value matcher stopped at the first space, so every predicate below went silent — including the raw-read block, which is a fetch reaching the transcript.
run BLOCK "quoted --config with a space"      "op --config \"/Application Support/op\" $R $U"
run BLOCK "quoted --account with a space"     "op --account \"my acct\" $R $U"
run BLOCK "quoted --config then item get"     "op --config \"/a b\" $IG X --reveal"
run BLOCK "quoted --config then document get" "op --config \"/a b\" $DG k"
run BLOCK "short flag carrying a value"       "op -a acct $R $U"
run BLOCK "short flag with a format value"    "op -f json $R $U"

# --- &> and >& reach a file; >&N and >&- do not ---
# These also pin the segment split: & is a separator except when it is part of a redirect operator.
run ALLOW "ampersand redirect to a file"      "op inject -i x &> out.env"
run ALLOW "ampersand append to a file"        "op inject -i x &>> out.env"
run ALLOW "reversed ampersand to a file"      "op inject -i x >& out.env"
run BLOCK "duplicate onto stderr"             "op inject -i x >&2"
run BLOCK "descriptor closed"                 "op inject -i x >&-"
run BLOCK "ampersand redirect to stdout"      "op inject -i x &> /dev/stdout"
run BLOCK "&& still splits the segment"       "op $DG k && scp -o StrictHostKeyChecking=no a b"

# --- a destination only counts when the shell would run it ---
# Text after an unquoted # is a comment and a redirect character inside quotes is an argument; both were honoured, so a trailing comment cleared the check while the value still went to stdout.
run BLOCK "a commented-out redirect"         "op $DG key # > /tmp/k"
run BLOCK "a commented-out pipe"             "op inject -i x # | kubectl apply -f -"
run BLOCK "a commented-out out-file"         "op inject -i x #--out-file /tmp/o"
run BLOCK "a redirect inside a flag value"   "op $DG key --tags '>/tmp/x'"
run BLOCK "an out-file inside a flag value"  "op $DG key --tags '--out-file=/tmp/x'"
run BLOCK "a -o inside a flag value"         "op $DG key --tags '-o=/tmp/x'"
run ALLOW "the same redirect uncommented"    "op $DG key > /tmp/k"
run ALLOW "the same pipe uncommented"        "op inject -i x | kubectl apply -f -"
run ALLOW "a # inside the path is not one"   "op $DG key > /tmp/k#1"

# --- the pipe has to be op's own, not one feeding it ---
# The cut landed on the first literal spelling of the subcommand, so a filename carrying it left cat's pipe in op's tail.
run BLOCK "a pipe into op inject"            "cat inject.tpl | op inject -i -"
run BLOCK "a pipe into a bare op inject"     "cat inject.tpl | op inject"
run ALLOW "control: op's own pipe outward"   "op inject -i inject.tpl | kubectl apply -f -"

# --- op is a command, and its subcommand is a position ---
# The gap between the two was unbounded, so any word after op reached the subcommand test and an ordinary argument spelled like one became a hard block.
run ALLOW "an item named inject"             "op $IG inject"
run ALLOW "a --fields value of inject"       "op $IG X --fields inject"
run ALLOW "a --tags value of inject"         "op $IG X --tags inject"
run ALLOW "a run target named inject"        "op run -- npm run inject"
run ALLOW "grep for inject after a pipe"     "op whoami | grep inject"
run ALLOW "two --grep values, op then read"  "git log --grep \"op\" --grep \"$R\""
run ALLOW "two quoted words in an echo"      "echo \"op\" and \"$R\""
run BLOCK "control: op with a valued flag"   "op --account acme inject -i x"
run BLOCK "control: op with a boolean flag"  "op --debug inject -i x"
run BLOCK "control: behind sudo"             "sudo op inject -i x"
run BLOCK "control: op's own global flag"    "op --account acme $R $U"

run_without perl BLOCK "perl unavailable, real read" "op $R $U"
run_without jq   BLOCK "jq unavailable, real read"   "op $R $U"
# The other half of that trade: strip_cmd degrades to the unmodified command rather than to empty, so an ordinary command must still pass without perl instead of every Bash call becoming a block.
run_without perl ALLOW "perl unavailable, benign command" "ls -la"
run_without perl ALLOW "perl unavailable, git status"     "git status"
run_without perl ALLOW "perl unavailable, an echo"        "echo hi"

# --- a fetch inside a script the command runs ---
# Built at run time, not committed: the body has to be a real fetch, which a committed file would not be allowed to carry.
SGD=$(mktemp -d)
# shellcheck disable=SC2016 # literal, unexpanded: the substitution has to reach the generated script
printf '#!/usr/bin/env bash\nTOKEN=$(op %s %s)\n' "$R" "$U" >"$SGD/fetch.sh"
printf '#!/usr/bin/env bash\naws %s get-secret-value --secret-id prod/app/db\n' "$SM" >"$SGD/sm.sh"
# shellcheck disable=SC2016 # literal, unexpanded: the sibling path has to be resolved by the guard, not here
printf '#!/usr/bin/env bash\nsource "$(dirname "${BASH_SOURCE[0]}")/fetch.sh"\n' >"$SGD/wrapper.sh"
printf '#!/usr/bin/env bash\n# never call op %s directly, use the masked wrapper\necho "use the wrapper" >&2\n' "$R" >"$SGD/prose.sh"
printf '#!/usr/bin/env bash\naws %s describe-secret --secret-id prod/app/db\n' "$SM" >"$SGD/clean.sh"

run BLOCK "bash a script that fetches"        "bash $SGD/fetch.sh"
run BLOCK "an aws fetch inside the script"    "bash $SGD/sm.sh"
run BLOCK "source a script that fetches"      "source $SGD/fetch.sh"
run BLOCK "dot-source a script that fetches"  ". $SGD/fetch.sh"
run BLOCK "the script run by its own path"    "$SGD/fetch.sh"
run BLOCK "a wrapper that sources the fetch"  "bash $SGD/wrapper.sh"
run BLOCK "behind sudo and an assignment"     "FOO=1 sudo bash $SGD/fetch.sh"
run BLOCK "in the command's second segment"   "cd /tmp && bash $SGD/fetch.sh"
run BLOCK "past a flag taking an operand"     "bash -o pipefail $SGD/fetch.sh"
run BLOCK "past a cluster of flags"           "bash -eu $SGD/fetch.sh"
# bash anchors =~ to the string, not the line, so the gate saw only line 1 of a multi-line command.
run BLOCK "multi-line, direct path"           "$(printf 'echo hi\n%s/fetch.sh' "$SGD")"
# A cd inside the command is not followed: paths resolve against the payload cwd, so this is a skip, not a miss.
run ALLOW "multi-line, cd then relative"      "$(printf 'cd %s\n./fetch.sh' "$SGD")"
# The extractor split on whitespace with no quote awareness, so a path spelled with a space was skipped.
mkdir -p "$SGD/my dir" && cp "$SGD/fetch.sh" "$SGD/my dir/fetch.sh"
run BLOCK "quoted path holding a space"       "bash \"$SGD/my dir/fetch.sh\""
# A path holding a shell separator is skipped: the extractor splits segments on ;&|() with no quote
# state, so the candidate is truncated. Pinned as a known skip so the fail-open stays visible.
mkdir -p "$SGD/a&b" && cp "$SGD/fetch.sh" "$SGD/a&b/fetch.sh"
run ALLOW "known skip: & in the path"         "bash \"$SGD/a&b/fetch.sh\""

# --- naming a script is not running it, and a mention inside one is not a fetch ---
run ALLOW "a script that only mentions it"    "bash $SGD/prose.sh"
run ALLOW "a sibling verb that reveals none"  "bash $SGD/clean.sh"
run ALLOW "the path in argument position"     "cat $SGD/fetch.sh"
run ALLOW "grep over the fetching script"     "grep -n export $SGD/fetch.sh"
run ALLOW "-n parses without running it"      "bash -n $SGD/fetch.sh"
run ALLOW "a binary is not a script"          "/bin/ls -la"
run ALLOW "a path that does not resolve"      "bash $SGD/no-such-file.sh"
run ALLOW "a path built from an expansion"    "bash \$SOME_DIR/fetch.sh"

# --- every predicate has to survive the narrowing the body scan applies before re-entry ---
printf '#!/usr/bin/env bash\nop %s X --reveal\n' "$IG" >"$SGD/reveal.sh"
printf '#!/usr/bin/env bash\nop run --no-masking -- ./deploy\n' >"$SGD/nomask.sh"
printf '#!/usr/bin/env bash\nop %s server-key\n' "$DG" >"$SGD/docget.sh"
printf '#!/usr/bin/env bash\naws %s batch-get-secret-value --filters Key=name,Values=prod/\n' "$SM" >"$SGD/batch.sh"
run BLOCK "body: item get --reveal"           "bash $SGD/reveal.sh"
run BLOCK "body: run --no-masking"            "bash $SGD/nomask.sh"
run BLOCK "body: document get to stdout"      "bash $SGD/docget.sh"
run BLOCK "body: batch-get-secret-value"      "bash $SGD/batch.sh"

# --- this plugin's own tree is exempt, and by resolved path rather than by content ---
# The wrappers really do perform the fetch, so a copy of one outside the tree must block: that is what tells the exemption apart from the scan simply not seeing them.
run ALLOW "the wrapper invoked from its tree" "bash $(dirname "$0")/../scripts/op-cache.sh --mask $U"
run ALLOW "the guard's own tests invoked"     "bash $(dirname "$0")/secret-mask-guard.test.sh"
cp "$(dirname "$0")/../scripts/op-cache.sh" "$SGD/copied-wrapper.sh"
run BLOCK "the same wrapper copied outside"   "bash $SGD/copied-wrapper.sh"

# An ordinary script carrying none of the guarded words must clear the scan untouched.
cp "$(dirname "$0")/../scripts/strip-cmd.sh" "$SGD/ordinary.sh"
run ALLOW "an ordinary script, outside"       "bash $SGD/ordinary.sh"
rm -rf "$SGD"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
