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

# --- a quoted word stays one word, so prose naming a key is not a read of it ---
run SILENT "commit message naming a reader"   'git commit -m "fix grep -r over .env files"'
# A flag value is never masked, so a reader and a key both named in one asks, wherever they sit.
run ASK    "reader and key inside a --body"     "gh pr create --body \"run cat $PEM\""
run ASK    "--body naming a key after a reader" 'cat README.md && gh pr create --body ".env"'
run ASK    "--message naming a key after a reader" 'cat README.md && git commit --message ".env"'
run ASK    "heredoc body naming a file"       "$(printf 'cat <<EOF\n%s\nEOF' "$PEM")"

# --- a heredoc body a shell runs is a command, however the shell reaches it ---
NL=$'\n'
run ASK    "eval of a heredoc substitution"      "eval \"\$(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL})\""
run ASK    "eval opened on the line above"       "eval \"\$(${NL}cat <<'EOF'${NL}cat $PEM${NL}EOF${NL})\""
run ASK    "substitution echoed into sh"         "echo \"\$(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL})\" | sh"
run ASK    "source of a heredoc substitution"    "source <(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL})"
run ASK    "dot of a heredoc substitution"       ". <(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL})"
run ASK    "pipe carried past the body"          "cat <<'EOF' |${NL}cat $PEM${NL}EOF${NL}sh"
run ASK    "opener continued by a backslash"     "cat <<'EOF' | \\${NL}sh${NL}cat $PEM${NL}EOF"
run ASK    "subshell piped to sh"                "(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL}) | sh"
run ASK    "first of two heredocs in a group"    "(cat <<'A'${NL}cat $PEM${NL}A${NL}cat <<'B'${NL}true${NL}B${NL}) | sh"
run ASK    "group closed after another command"  "(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL}echo done) | sh"
run ASK    "pipe to a quoted shell"              "cat <<'EOF' | \"sh\"${NL}cat $PEM${NL}EOF"
run ASK    "pipe to a backslashed shell"         "cat <<'EOF' | \\bash${NL}cat $PEM${NL}EOF"
run ASK    "quoted shell reading the heredoc"    "\"bash\" <<'EOF'${NL}cat $PEM${NL}EOF"
run ASK    "pipe to csh"                         "cat <<'EOF' | csh${NL}cat $PEM${NL}EOF"
run ASK    "pipe to tcsh"                        "cat <<'EOF' | tcsh${NL}cat $PEM${NL}EOF"
run ASK    "pipe to fish"                        "cat <<'EOF' | fish${NL}cat $PEM${NL}EOF"
run ASK    "pipe to mksh"                        "cat <<'EOF' | mksh${NL}cat $PEM${NL}EOF"
# A body is never masked, even where nothing visibly runs it: a later command can run it from a variable, a file or a descriptor.
run ASK    "heredoc redirected to a file"        "cat <<'EOF' > f.txt${NL}cat $PEM${NL}EOF"
run ASK    "heredoc piped to grep"               "cat <<'EOF' | grep x${NL}cat $PEM${NL}EOF"
run ASK "group redirected to a file"          "(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL}) > notes.txt"
run ASK "message substitution, then a shell"  "git commit -m \"\$(cat <<'EOF'${NL}cat $PEM${NL}EOF${NL})\" && bash deploy.sh"
run ASK "case arm after a data heredoc"          "cat <<'EOF' > f.txt${NL}cat $PEM${NL}EOF${NL}case x in a) bash y ;; esac"
run ASK "prose closer inside a later body"    "(cat <<'A' > a.md${NL}cat $PEM${NL}A${NL}cat <<'B' > b.md${NL}2) ssh in${NL}B${NL})"

# --- a comment and a heredoc body are pieces of their own, so their quotes cannot pair with the code's ---
Q="'"
TAB=$'\t'
run ASK    "apostrophe in a body, then a glued redirect"  "cat <<'EOF'${NL}can${Q}t${NL}EOF${NL}cat<.env"
run ASK    "apostrophes in a body and a comment"          "cat <<'EOF' > notes.txt${NL}${Q}${NL}EOF${NL}cat .env${NL}# ${Q}"
run ASK    "the same with a tab-stripped body"            "cat <<-'EOF' > notes.txt${NL}${TAB}${Q}${NL}${TAB}EOF${NL}cat .env${NL}# ${Q}"
run ASK    "apostrophe in a comment, then a glued redirect" "# can${Q}t${NL}cat<.env"
run ASK    "apostrophe in a trailing comment"             "cat .env # it${Q}s"
run ASK    "apostrophes in two comments around a read"    "# it${Q}s${NL}cat .env${NL}# that${Q}s it"
# Cut out, never dropped: the text of a comment or a body is still scanned.
run ASK    "a key named in a comment"                     "cat notes.txt # $PEM"
run ASK    "a key named in a comment after a body"        "cat <<'EOF' > notes.txt${NL}x${NL}EOF${NL}cat notes.txt # $PEM"
run SILENT "a real multi-line quote stays one word"       "echo ${Q}${NL}cat .env${NL}# ${Q}"
run SILENT "a # inside a word is not a comment"           "grep -c 'a#b' notes.txt"
# When the whole command will not parse, its bare split stays, so the cut never asks less often than before it existed.
run ASK    "quoted prose beside an apostrophe comment"    "echo \"cat .env\" # it${Q}s"
run ASK    "a quoted key beside an apostrophe comment"    "cat \".env notes\" # it${Q}s"
run ASK    "the same when a body holds the other apostrophe" "cat <<EOF${NL}${Q}${NL}EOF${NL}cat \".env notes\" # ${Q}"
# That split is read first and on its own, so a find later in the command cannot exempt a word it exposed earlier.
run ASK    "a fallback word before a later find"          "echo \"! -name *.pem x\" \"cat\" # it${Q}s${NL}find ."
# Pieces keep their place in the command, so a find after a comment or a body does not reach back into it.
run ASK    "a negated glob in a comment before a find"    "cat README.md # ! -name \"*.pem\"${NL}find ."
run ASK    "a negated glob in a body before a find"       "cat <<'EOF' > notes.txt${NL}! -name *.pem${NL}EOF${NL}find ."
# A find inside a body does not exempt a word after the body, and a body costs no depth.
run ASK    "a find in a body, then a negated glob"        "cat <<'EOF'${NL}find${NL}EOF${NL}ls -- ! -name .env*"
run ASK    "the same after an empty ANSI-C quote"         "cat <<'EOF'${NL}find${NL}EOF${NL}cat\$'' -- ! -name .env*"
run ASK    "a shell -c four bodies deep"                  "bash <<E0${NL}bash <<E1${NL}bash <<E2${NL}bash <<E3${NL}bash -c 'cat .env x'${NL}E3${NL}E2${NL}E1${NL}E0"
# A find opens the exemption only in command position, a comment's end closes it, and the whole-command bare split is read with no exemption at all.
run ASK    "a find named in a comment's flag value"       "cat README.md # --title \"find\"${NL}echo ! -name \".env*\""
run ASK    "a find after a separator inside a comment"    "cat README.md # x ; find${NL}echo ! -name \".env*\""
run ASK    "a body's find read through the bare split"    "cat <<EOF${NL}find${NL}EOF${NL}echo \"! -name .env* notes\" # ${Q}"
run ASK    "a body's piped find through the bare split"   "cat <<EOF${NL}x | find${NL}EOF${NL}echo \"! -name .env* notes\" # ${Q}"
run SILENT "control: a find on its own line still opens it" "cat notes.txt${NL}find . -not -name '*.pem'"
run SILENT "control: a find in process substitution too"  "head -2 <(find . -not -name '*.pem')"
run ASK    "a substitution's end closes the window"       "head -2 <(find .) ! -name .env*"
run ASK    "a find as a flag value opens nothing"         "cat notes.txt --title find ! -name .env*"
# A body line that only starts with the delimiter is not the delimiter, and what follows it is read as well.
run ASK    "a key glued to the delimiter on a body line"  "cat <<EOF${NL}notes${NL}EOF.env${NL}EOF"
# An unparseable piece falls back to a bare split before the redirect split, so a glued redirect still names its file.
run ASK    "unbalanced quote, glued redirect"             "cat<.env ${Q}x"

# --- a quoted word holding a command line is read word by word, not only by how it ends ---
run ASK    "key mid-string in bash -c"           "bash -c \"cat $PEM | head -1\""
run ASK    "key before a separator in sh -c"     "sh -c 'head -1 id_rsa; true'"
run ASK    "key in a nested sh -c"               "bash -c \"sh -c 'cat $KEY notes.txt; true'\""
run ASK    "key glued to a pipe"                 "cat $PEM|head -1"
run ASK    "key glued to a semicolon"            "cat $PEM;true"
run ASK    "glued pipe after a quoted apostrophe" "echo \"it's\"; cat $PEM|head -1"
run ASK    "glued pipe after a quoted quote"     "echo 'say \"hi'; cat $PEM|head -1"
run ASK    "key in a substitution before more"   "echo \"\$(cat $PEM | head -1)\""
run ASK    "key on an earlier line of bash -c"   "bash -c \"cat $PEM${NL}echo done\""
run ASK    "substitution with text after it"     "echo \"\$(tail -c 64 $KEY) done\""
run ASK    "substitution inside an assignment"   "X=\"\$(cat $KEY) done\""
run ASK    "eval of a quoted command line"       "eval \"cat $PEM | head -1\""
run ASK    "shell options before the -c"         "bash -o pipefail -c \"cat $PEM | head -1\""
run SILENT "escaped pipe stays in its word"      'cat README.md; grep x\|.env notes.md'
# Quoted prose with no command punctuation stays one word, so only a key-shaped last word prompts — the documented -m trade-off.
run SILENT "prose -m naming dotenv mid-string"   'cat README.md && git commit -m "rotate the .env loader"'
run SILENT "prose -m naming a key mid-string"    "cat README.md && git commit -m \"move $PEM handling out\""
# Quoted patterns are data even when they carry command punctuation; each of these shapes prompted on real commands while the split was any word holding |, ; or &.
run SILENT "jq -c filter naming .key"            "cat x.json | jq -c '.[] | select(.key) | .value'"
run SILENT "grep alternation of path globs"      "grep -nE '^python/\\*|^\\* ' CODEOWNERS"
run SILENT "markdown code spans in a python body" "grep -c x f.md; python3 - <<'EOF'${NL}s = \"lanes: \`python/**\`, \`*.py\`\"${NL}EOF"

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

# --- a negated find predicate is a pattern that excludes, never a file that is read -------------
run SILENT "not -path exclusion glob"          "find . -name x.md -not -path '*/.git/*' | head -2"
run SILENT "bang -path exclusion glob"         "find . -name x.md ! -path '*/.git/*' | head -2"
run SILENT "not -path excluding dotenv"        "find . ! -path '*/.env*' -type f | head -2"
run SILENT "not -name excluding a key"         "find . -not -name '*.pem' -type f | head -2"
# The exemption is the negated shape only: a POSITIVE predicate can widen what a later -exec reads.
run ASK    "positive -name naming a key"       "find . -name '*.pem' | head -2"
run ASK    "positive -path under .ssh"         "find . -path '*/.ssh/*' | head -2"
# The window is armed by a find TOKEN and closed by the next reader, so a find elsewhere on the line cannot lend its grammar to another command.
run ASK    "not -path without find at all"     "cat -not -path .env"
run ASK    "find in an earlier pipeline"       "find . -type d | head -2; cat -not -path .env"
run ASK    "find only inside a quoted string"  'echo "use find for this"; cat -not -path .env'
run ASK    "find as a variable value"          "X=find; cat -not -path .env"
run ASK    "reader between find and the token" "find . -type d | head -2; grep -r x -not -path $KEY"
# A reader BEFORE find does not close the window: process substitution puts the reader first and find still governs its own arguments.
run SILENT "reader before find on the line"    "head -2 <(find . -not -path '*/.git/*')"
# The second find of a two-command line arrives as F=\$find once the tokenizer strips the substitution punctuation, and still arms the window.
run SILENT "find reached through a substitution" "find . -name x.md -not -path '*/.git/*' | head -2
F=\$(find . -name x.md -not -path '*/.git/*' | head -1)
[ -n \"\$F\" ] && sed -n '1,70p' \"\$F\""
# An exclusion glob does not lend its silence to a real read on the same line.
run ASK    "exclusion glob beside a key read"  "find . -not -path '*/.git/*' | head -2; cat $PEM"
# A second negation makes the predicate positive, so it SELECTS the files it names — the -exec form reads every one.
run ASK    "double-negated -not is positive"   "find . -not -not -path .env | head -2"
run ASK    "double-negated bang is positive"   "find . ! ! -path .env | head -2"
run ASK    "double-negated key pattern"        "find . ! ! -name '*.pem' -exec cat {} +"
# A negated predicate naming a LITERAL path is indistinguishable here from a filename, so only a wildcard operand is exempt.
run ASK    "negated literal dotenv"            "find . -not -path .env | head -2"
run ASK    "negated literal key"               "find . -not -name $PEM | head -2"
# The shapes where a find-token ARGUMENT to a reader lends find's grammar to a secret filename.
run ASK    "find-shaped argument to less"      "less bin/find -not -path .env"
run ASK    "find-shaped argument to cat"       "cat ./find -not -path id_rsa"
run ASK    "find-shaped argument to head"      "head bin/find -not -path $KEY"

# --- an unresolved glob prompt names what the approver is being asked about ----------------------
reason() {  # reason <command-text> -> permissionDecisionReason, or empty
  printf '%s' "$(jq -nc --arg c "$1" '{tool_input:{command:$c}}')" | bash "$GUARD" 2>/dev/null \
    | jq -r '.hookSpecificOutput.permissionDecisionReason // empty'
}
says() {
  local label="$1" cmd="$2" needle="$3" got
  got=$(reason "$cmd")
  case "$got" in
    *"$needle"*) printf 'ok   %s\n' "$label"; pass=$((pass + 1)) ;;
    *) printf 'FAIL %s — reason %q did not contain %q\n' "$label" "$got" "$needle"; fail=$((fail + 1)) ;;
  esac
}

# GLOBDIR is absolute and already holds one pem, so its expansion here is the one the command would get.
: > "$GLOBDIR/id_rsa"
says "absolute glob names its matches"   "cat $GLOBDIR/*"          "it matches 2 file(s)"
says "absolute glob names the filenames" "cat $GLOBDIR/*"          "$PEM"
says "absolute glob matching nothing"    "cat $GLOBDIR/nonesuch/*" "matches nothing under that path right now"
# A relative pattern says why it cannot be expanded rather than implying the guard knows more than it does.
says "relative glob is not expanded"     'cat *'                   "working directory is not the command's"
# Naming a match must never mean reading one: the prompt carries filenames, never contents. A plain sentinel rather than a secret-shaped literal — this asserts that contents do not travel, which no particular shape makes truer.
printf 'CONTENTS-MUST-NOT-TRAVEL\n' > "$GLOBDIR/$KEY"
case "$(reason "cat $GLOBDIR/*")" in
  *CONTENTS-MUST-NOT-TRAVEL*) printf 'FAIL prompt leaked file contents\n'; fail=$((fail + 1)) ;;
  *) printf 'ok   prompt carries names, not contents\n'; pass=$((pass + 1)) ;;
esac

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
