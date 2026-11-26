#!/usr/bin/env bash
# Regression tests for the reader gate: a filename is recognised after shell quoting is removed, and no token is glob-expanded.
set -uo pipefail

# Absolute, because the glob case runs the guard from a different cwd.
GUARD="$(cd "$(dirname "$0")/../scripts" && pwd)/read-secret-guard-bash.sh"
[ -f "$GUARD" ] || { printf 'FATAL: guard not found at %s\n' "$GUARD"; exit 1; }

pass=0
fail=0
WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT
export HOOK_DIAG_ASK_LOG="$WORK/asks.log"

decide() {  # decide <command-text> -> ASK | SILENT, or DIVERGED when the authority's route decides otherwise
  local json out route plain on_route
  json=$(jq -nc --arg c "$1" '{tool_input:{command:$c}}')
  out=$(printf '%s' "$json" | bash "$GUARD" 2>/dev/null)
  # The parse the authority hands over arms the builtin stand-ins and the stem prefilter, so every case here also runs that way.
  route=$(SGA_PREPARSED=1 SGA_INPUT=$json SGA_CMD=$(printf '%s' "$1") bash "$GUARD" </dev/null 2>/dev/null)
  # A here-string, not a pipe: under pipefail, grep -q exiting early on a large output fails the pipeline.
  if grep -q '"permissionDecision":[[:space:]]*"ask"' <<<"$out"; then plain=ASK; else plain=SILENT; fi
  if grep -q '"permissionDecision":[[:space:]]*"ask"' <<<"$route"; then on_route=ASK; else on_route=SILENT; fi
  if [ "$plain" = "$on_route" ]; then printf '%s' "$plain"; else printf 'DIVERGED (%s, %s on the route)' "$plain" "$on_route"; fi
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
for interpreter in python python3 python3.12 node perl ruby; do
  run SILENT "$interpreter heredoc ignores a secret-shaped glob" "cat notes.txt; $interpreter - <<'EOF'${NL}cat *.pem${NL}EOF"
  run ASK "$interpreter heredoc retains a literal key" "cat notes.txt; $interpreter - <<'EOF'${NL}cat secrets.pem${NL}EOF"
  run SILENT "cat piped to $interpreter ignores globs" "cat <<'EOF' | $interpreter${NL}cat .env*${NL}EOF"
  run SILENT "file subsequently run by $interpreter" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}$interpreter A.py"
done
run SILENT "reported: write Python, change directory, isolated run" "cat > \$S/A.py <<'EOF'${NL}paths = list(root.glob('*'))${NL}EOF${NL}cd \$S; python3 -I A.py"
run SILENT "written Python body ignores secret-shaped globs" "cat > \$S/A.py <<'EOF'${NL}cat .env*${NL}EOF${NL}cd \$S; python3 -I A.py"
run SILENT "tee writes a subsequently interpreted file" "tee A.py <<'EOF'${NL}cat *.key${NL}EOF${NL}python3 A.py"
run SILENT "apostrophe fallback retains the interpreter mode" "cat > A.py <<'EOF'${NL}# can't cat *.pem${NL}EOF${NL}python3 A.py"
run SILENT "unquoted interpreter body without substitutions" "cat notes.txt; python3 - <<EOF${NL}cat *.pem${NL}EOF"
run ASK "expanding interpreter body runs shell substitutions" "cat notes.txt; python3 - <<EOF${NL}\$(cat *.pem)${NL}EOF"
run ASK "shell heredoc retains secret-shaped globs" "cat <<'EOF' | bash${NL}cat *.pem${NL}EOF"
run ASK "written shell retains globs despite another interpreter" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}python3 A.py; bash A.py"
run ASK "an unrelated interpreter cannot vouch for a written file" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}python3 B.py"
run ASK "interpreter named as prose is not an execution" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}echo python3 A.py"
run ASK "unknown consumer retains wildcard checks" "cat <<'EOF' | custom-reader${NL}cat *.pem${NL}EOF"
run ASK "an unterminated interpreter heredoc stays strict" "cat notes.txt; python3 - <<'EOF'${NL}cat *.pem"
run ASK "interpreter mode ends before a shell glob" "cat <<'EOF' | python3${NL}cat *.pem${NL}EOF${NL}cat .env*"
run ASK "written interpreter retains literal dotenv" "cat > A.py <<'EOF'${NL}cat .env.prod${NL}EOF${NL}python3 A.py"
run ASK "written interpreter retains literal kubeconfig" "cat > A.py <<'EOF'${NL}cat kubeconfig${NL}EOF${NL}python3 A.py"
run ASK "quoted shell after the interpreter keeps the body strict" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}python3 A.py; \$'bash' A.py"
run ASK "unknown file consumer beside an interpreter" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}custom-reader A.py; python3 A.py"
run ASK "shell on the opener line keeps the body strict" "cat > A.py <<'EOF'; bash A.py${NL}cat *.pem${NL}EOF${NL}python3 A.py"
run SILENT "quoted substitution text remains interpreter data" "cat notes.txt; python3 - <<'EOF'${NL}message = \"\$(cat *.pem)\"${NL}EOF"
MARKERS=$'\004\005'
run ASK "input cannot supply interpreter-mode markers" "cat '${MARKERS}fake' *.pem"
run ASK "a variable command is an unknown file consumer" "cat > A.py <<'EOF'${NL}cat *.pem${NL}EOF${NL}\$python A.py; python3 A.py"
run ASK "shell before an interpreter consumes the body first" "bash <<'EOF' | python3${NL}cat *.pem${NL}EOF"
run ASK "shell between a sink and an interpreter stays strict" "cat <<'EOF' | bash | python3${NL}cat *.pem${NL}EOF"
run ASK "unknown consumer before an interpreter stays strict" "cat <<'EOF' | custom-reader | python3${NL}cat *.pem${NL}EOF"
run ASK "interpreter output sent to a shell stays strict" "cat notes.txt; python3 - <<'EOF' | bash${NL}cat *.pem${NL}EOF"
run ASK "two opener heredocs cannot share a consumer classification" "bash <<'A'; cat <<'B' | python3${NL}cat *.pem${NL}A${NL}print(0)${NL}B"
run SILENT "tee in an interpreter pipeline keeps wildcard data" "cat <<'EOF' | tee A.py | python3${NL}cat *.pem${NL}EOF"
run SILENT "tee owns an interpreter pipeline without a later consumer" "tee A.py <<'EOF' | python3${NL}cat *.pem${NL}EOF"
run ASK "piped body copied by tee is later run by bash" "cat <<'EOF' | tee A.py | python3${NL}cat *.pem${NL}EOF${NL}bash A.py"
run ASK "piped body copied by tee is later sourced" "cat <<'EOF' | tee A.py | python3${NL}cat *.pem${NL}EOF${NL}source A.py"
run ASK "piped body owned by tee is later run by bash" "tee A.py <<'EOF' | python3${NL}cat *.pem${NL}EOF${NL}bash A.py"
run ASK "piped body redirected by cat is later run by bash" "cat > A.py <<'EOF' | python3${NL}cat *.pem${NL}EOF${NL}bash A.py"
run ASK "piped body copied by tee has an unknown later consumer" "cat <<'EOF' | tee A.py | python3${NL}cat *.pem${NL}EOF${NL}custom-reader A.py"
run ASK "piped body retains literal checks" "cat <<'EOF' | tee A.py | python3${NL}cat .env.prod${NL}EOF"
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
# A body fed to a data sink is text, but only when nothing else in the command could run what the sink wrote — see README § Heredoc bodies written as data.
run SILENT "heredoc written to a file by cat"    "cat <<'EOF' > f.txt${NL}cat $PEM${NL}EOF"
run SILENT "reported: prose glob appended by cat" "cat >> \"/tmp/x/notes/verify.md\" <<'EOF'${NL}## Ownership${NL}- src/router/** @example-org/team-a (.github/CODEOWNERS:404 at 4e65f3e3eb; report cited :385 at its head).${NL}- Downstream consumer src/mesh/** @example-org/team-b (CODEOWNERS:459)${NL}EOF"
run SILENT "an apostrophe in a data body"        "cat > notes.md <<'EOF'${NL}can't cat .env${NL}EOF"
run SILENT "mkdir, then a body written by cat"   "mkdir -p out && cat > out/n.md <<'EOF'${NL}cat .env${NL}EOF"
run SILENT "body appended by tee"                "tee -a notes.md >/dev/null <<'EOF'${NL}grep x secrets/*.pem${NL}EOF"
run SILENT "commit message read from stdin"      "git commit -F - <<'EOF'${NL}fix grep over .env files${NL}EOF"
run SILENT "PR body read from stdin"             "gh pr create --title t --body-file - <<'EOF'${NL}run cat $PEM to check${NL}EOF"
# The same sinks stay strict whenever anything could run, pipe or substitute the body, or the consumer is not one of them.
run ASK    "data body, then the file is run"     "cat <<'EOF' > f.txt${NL}cat $PEM${NL}EOF${NL}bash f.txt"
run ASK    "data body, then the file is sourced" "cat > f.sh <<'EOF'${NL}cat $PEM${NL}EOF${NL}. f.sh"
run ASK    "data body, then the file executes"   "cat > f.sh <<'EOF'${NL}cat $PEM${NL}EOF${NL}chmod +x f.sh && ./f.sh"
run ASK    "unquoted delimiter expands the body" "cat > f.txt <<EOF${NL}\$(cat $PEM)${NL}EOF"
run ASK    "a quoted <<' in a filename cannot vouch for an unquoted body" "cat > \"f<<'x\" <<EOF${NL}\$(cat $PEM)${NL}EOF"
run ASK    "one quoted and one unquoted delimiter" "cat > a.txt <<'A'${NL}notes${NL}A${NL}cat > b.txt <<B${NL}\$(cat $PEM)${NL}B"
run ASK    "a backslash-escaped delimiter stays strict (a backslash in the command text)" "cat > f.txt <<\\EOF${NL}see secrets/*.pem${NL}EOF"
run SILENT "a partly quoted delimiter is data"   "cat > f.txt <<E\"O\"F${NL}see secrets/*.pem${NL}EOF"
run ASK    "a shell after a semicolon on the opener" "cat > f.sh <<'EOF'; bash f.sh${NL}cat $PEM${NL}EOF"
run ASK    "a brace group, then the file is run" "{ cat > f.sh <<'EOF'${NL}cat $PEM${NL}EOF${NL}} ; bash f.sh"
run ASK    "a body held in a variable, then eval" "read -r -d '' X <<'EOF'${NL}cat $PEM${NL}EOF${NL}eval \"\$X\""
run ASK    "a body on a descriptor, then read"   "exec 3<<'EOF'${NL}cat $PEM${NL}EOF${NL}cat <&3"
run ASK    "git config before commit"            "git -c core.x=1 commit -F - <<'EOF'${NL}cat $PEM${NL}EOF"
run ASK    "data body to a descriptor"           "cat <<'EOF' >&3${NL}cat $PEM${NL}EOF"
run ASK    "data body to a process substitution" "cat <<'EOF' > >(bash)${NL}cat $PEM${NL}EOF"
run ASK    "cat with no redirect"                "cat <<'EOF'${NL}cat $PEM${NL}EOF"
run ASK    "a cat named by a relative path"      "./cat > f.txt <<'EOF'${NL}cat $PEM${NL}EOF"
run ASK    "an assignment before the sink"       "X=1 cat > f.txt <<'EOF'${NL}cat $PEM${NL}EOF"
run ASK    "git commit reading a file, not stdin" "git commit -F msg.txt <<'EOF'${NL}cat $PEM${NL}EOF${NL}bash msg.txt"
run ASK    "gh api is not a body sink"           "gh api -F body=@- <<'EOF'${NL}cat $PEM${NL}EOF"
run ASK    "shell reading a quoted-delimiter body" "bash <<'EOF'${NL}cat secrets/*.pem${NL}EOF"
run ASK    "python shelling out to a reader"     "python3 - <<'EOF'${NL}import os; os.system(\"cat k.pem\")${NL}EOF"
run ASK    "cat body piped to bash"              "cat <<'EOF' | bash${NL}cat k.pem${NL}EOF"
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
run ASK    "the word after a substitution is an argument" "cat notes.txt \$(echo) find ! -name .env*"
run ASK    "the same after a backtick substitution"       "cat notes.txt \`echo\` find ! -name .env*"
run ASK    "a find as a flag value opens nothing"         "cat notes.txt --title find ! -name .env*"
run ASK    "a single-quoted \$(find is text, not a command" "bash -c 'cat \${@: -1}' --body '\$(find' ! -name '.env*'"
run SILENT "control: an unquoted substitution still opens it" "cat notes.txt; x=\$(find . -not -name '*.pem')"
# With perl missing, the bash fallback's bare split is read with no exemption, as the perl path's bare split is.
NOPERL=$(mktemp -d)
printf '#!/bin/sh\nexit 127\n' >"$NOPERL/perl"; chmod +x "$NOPERL/perl"
decide_noperl() {
  local out
  out=$(printf '%s' "$(jq -nc --arg c "$1" '{tool_input:{command:$c}}')" | PATH="$NOPERL:$PATH" bash "$GUARD" 2>/dev/null)
  if grep -q '"permissionDecision":[[:space:]]*"ask"' <<<"$out"; then printf 'ASK'; else printf 'SILENT'; fi
}
for c in "cat notes.txt && git commit -m \"x | find\" && echo ! -name .env*" "cat notes.txt && echo ! -name .env*" "cat ~/.ssh/id_rsa|base64" "cat *.pem|head" "cat *.pem;echo" "cat *.pem&&echo" "X=\`cat .env\`" "cat \\.env" "cat \$'.env'"; do
  actual=$(decide_noperl "$c")
  if [ "$actual" = ASK ]; then printf 'ok   no perl: %s\n' "$c"; pass=$((pass + 1)); else printf 'FAIL no perl: %s — expected ASK, got %s\n' "$c" "$actual"; fail=$((fail + 1)); fi
done
rm -rf "$NOPERL"
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
run SILENT "JMESPath projection ending in Key"   "grep -c 'Contents[].Key' out.json"
run SILENT "jq filter selecting .key"            "grep -c 'to_entries[]|select(.key)' out.json"
run SILENT "regex alternation of env files"      "grep -n '.env.web|env.production' Makefile"
run ASK "bracket glob before a key suffix"       "cat key[12].pem"
run ASK "dotted name ending in .key"             "cat s.key"
run SILENT "dotenv example is allowlisted"    "cat .env.example"
run SILENT "quoted dotenv example"            'cat ".env.example"'
run SILENT "quoted dotenv template"           'cat ".env.template"'
run SILENT "recursive grep without a match"   "grep -r pattern ."
run SILENT "non-reader command"               "ls -la"
run SILENT "empty command"                    ""

# --- globs are judged by pattern, not expanded against the cwd -----------------
run SILENT "bare wildcard has no secret stem" "cat *"
run SILENT "bare question mark has no secret stem" "cat ?"
run SILENT "git pathspec excludes tests" "git grep foo -- ':!**/tests/**'"
run SILENT "virtualenv pathspec has no secret stem" "git grep foo -- '**/.venv/**'"
run SILENT "scratch listing" "ls *"
run SILENT "listing after a reader" "cat README.md; ls *"
run ASK "absolute Downloads pem glob" 'cat ~/Downloads/*.pem'
run ASK "literal production dotenv" "cat .env.prod"
run ASK "dotenv prefix wildcard"              "cat .env*"
run ASK "wildcard inside .ssh"                "cat .ssh/*"
run ASK "wildcard with a key suffix"          "cat *.pem"
run ASK "secret glob is case-insensitive" "cat *.PEM"
run ASK "secret glob after a tab separator" $'cat\t*.pem'
run ASK "question mark retains an SSH stem" "cat id_?"
run SILENT "wildcard that cannot match a secret" "cat *.log"
for pattern in '*.key' '*.p12' '*.pfx' '.env.*' 'id_*' '*kubeconfig*' '.kube/config*' '.ssh/known*'; do
  run ASK "derived secret stem: $pattern" "cat $pattern"
done

# --- a stem asks only as a whole name segment of a path, never inside a pattern or expression ---
run SILENT "jsonpath env list read by grep"        "grep -o '{range .spec.containers[0].env[*]}{.name}{end}' notes.txt"
run SILENT "regex escaping a dotted env name"      "grep -n 'role/\\\$\\{\\{ *env\\.ENVIRONMENT *\\}\\}' ci.yaml"
run SILENT "regex alternation naming id_token"     "grep -nE 'oidc_id_token|id_token.*refresh' auth.py"
run SILENT "id_ inside an identifier"              "grep -n 'DEPLOYMENT_ID_LENGTH *=' ids.py"
run SILENT "dict unpacking of os.environ"          "grep -n '{**os.environ, x}' run.py"
run SILENT "env in a longer word"                  "cat *.environment"
run SILENT "key in a longer extension"             "cat *.keys"
run SILENT "template field ending in key"          "grep -n '[\${each.key}-*]' main.tf"
run SILENT "JMESPath filter naming a Key"          "grep -n 'Contents[?ends_with(Key, x)].Key' q.txt"
run SILENT "URL query after an env name"           "grep -n 'contents/<svc>.env?ref=<sha>' notes.txt"
run SILENT "assignment of a status code"           "id_rc=\$?; cat app.log"
run ASK "key glob under a quoted spaced path"     'cat "/My Drive/keys/*.pem"'
run ASK "env glob as an --include value"          "grep -r TOKEN --include=*.env ."
run ASK "env glob in a directory"                 "grep -r TOKEN env/*.env"
run ASK "wildcard directory before a key name"    "cat backups/*/id_rsa"
run ASK "key glob with a backup suffix"           "cat *.key.bak"
run ASK "key-type name after a separator"        "cat backup-id_rsa*"
run ASK "brace list of key globs"                "cat {*.pem,*.key}"
run ASK "brace list naming an env glob"          "grep -l SECRET {*.env,*.yaml}"
run ASK "brace list of ssh key names"            "cat ~/backup/{id_*,known_hosts}"
run ASK "brace backup suffix on a key glob"      "cat *.pem{,.bak}"
run ASK "brace list as an --include value"       "grep -r KEY --include={*.env,*.pem} ."
run ASK "editor backup of a key glob"            "cat *.key~"
run ASK "pipe in a directory before a key glob"  'cat "a|b"/*.pem'
run SILENT "brace list with no secret name"        "cat {*.log,*.txt}"
# bash skips a } with no comma before it, so this expands to `a}` and `.env`, which no list match here reproduces.
run ASK "brace list past an unpaired close brace" "cat {a},.env}"
run SILENT "unpaired close brace, no secret name"  "cat {a},b.txt}"
run ASK "brace list around a nested pair"         "cat {x.key,b{c}}"
run SILENT "unpaired braces in a query expression" "jq -r '{a},.key}[]' f.json"
run ASK "literal brace list of env files"       "cat .env{,.local}"
run ASK "literal brace list of key names"       "cat id_{rsa,ed25519}"
run ASK "literal brace list of key extensions"  "cat server.{pem,crt}"
run ASK "letter range reaching a key extension" "cat *.pe{l..n}"
run ASK "quoted newline inside a brace list"     $'cat {"\n",*.pem}'
run ASK "range this gate cannot expand"         "cat {a..zz}.pem"
run ASK "brace word past the cap naming a key"  "cat {a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}*.pem"
run SILENT "brace word past the cap naming none"   "cat {a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}*.txt"
run SILENT "JSON body past the cap"                 "grep -c x f.txt; echo '{\"a\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65]}'"
run SILENT "large numeric range"                    "cat notes.txt; printf 'x%.0s' {1..300}"
run ASK "bracket class after an env stem"       "cat .env[.]*"
run ASK "negated bracket class after an env stem" "cat .env[!x]*"
run ASK "stem split across an over-cap list"    "cat .{e,a1..a70}nv"
run ASK "ssh dir split across an over-cap list" "cat ~/.s{s,a1..a70}h/config"
run SILENT "over-cap word naming no stem"          "cat x1{1..90}"
run SILENT "numbered parts past the cap"           "cat part{1..100}.log"
run SILENT "dated files past the cap"              "head -n1 data_{2019..2024}_{01..12}.csv"
run SILENT "source tree past the cap"              "grep -l TODO src/{a,b,c,d,e,f,g,h}/{1,2,3,4,5,6,7,8,9}.py"
run ASK "deep absolute glob still asks"         "cat /*/*/*/*/*/*/.env*"
run SILENT "numeric range with no secret name"     "cat {1..5}.log"
run ASK "zero-padded range before a secret file" "cat logs/2024-{08..12}.log .env"
run ASK "zero-padded range reaching a key extension" "cat x.p{08..12}"
run SILENT "zero-padded range with no secret name" "cat logs/2024-{08..12}.log"
run ASK "range past int64 before a secret file"  "cat {0..18446744073709551615} .env"
run SILENT "regex interval quantifier"             "grep -nE 'x{1,3}' f.txt"
run ASK "key-type name after an underscore"      "cat old_id_ed25519*"
run SILENT "id_ token name after a separator"      "cat okta_id_token*"
run ASK "assignment of a secret glob"             "F=~/.ssh/id_*; cat \$F"
run ASK "braced home before .ssh"                 "cat \${HOME}/.ssh/*"
run ASK "kubeconfig with a prefix"                "cat prod-kubeconfig*"
run ASK "env glob after a separator prefix"       "cat app.env.*"

# --- a kubectl output template is evaluated against API objects, not opened as a local file ---
# Each case pipes into grep, since a reader anywhere in the command is what arms the scan.
# The templates end in .env*, which still asks outside kubectl, so each SILENT case exercises the exemption itself.
run SILENT "kubectl jsonpath over container env names" "kubectl --context c -n ns get deploy a b -o jsonpath='{range .items[*]}{.metadata.name}{\": \"}{range .spec.template.spec.containers[*].env[*]}{.name}{\" \"}{end}{\"\\n\"}{end}' 2>&1 | tr ' ' '\\n' | grep -i relay"
run SILENT "kubectl -o=jsonpath form"                  "kubectl get pods -o=jsonpath='{.items[*].metadata.name}.env*' | grep -i relay"
run SILENT "kubectl glued -ojsonpath form"             "kubectl get pods -ojsonpath='{.items[*].metadata.name}.env*' | grep -i relay"
run SILENT "kubectl --output=custom-columns form"      "kubectl get pods --output=custom-columns='N:.metadata.name,F:*.env*' | grep -i relay"
run SILENT "kubectl after a path and an assignment"    "KUBECONFIG=k /usr/local/bin/kubectl get pods -o jsonpath='{.items[*].metadata.name}.env*' | grep -i relay"
run ASK    "control: the same template read by cat"    "cat jsonpath='{.items[*].metadata.name}.env*' | grep -i relay"
run ASK    "kubectl jsonpath-file still opens a file"  "kubectl get pods -o jsonpath-file=.env* | grep -i relay"
run ASK    "kubectl cp of a dotenv wildcard"           "kubectl cp ns/pod:/app/.env* ./x && grep -r x ./x"
run ASK    "the next command is read on its own"       "kubectl get pods -o jsonpath='{.items[*].metadata.name}.env*' && cat .env*"
run ASK    "a program named by a variable is unknown"  "\$K get pods -o jsonpath='{.items[*].metadata.name}.env*' | grep -i relay"
run ASK    "a template value outside kubectl"          "grep -o jsonpath='{.items[*].metadata.name}.env*' notes.txt"
run ASK    "a substitution closes the kubectl context" "grep -r x \$(kubectl config current-context) -o 'jsonpath=.env*'"
run ASK    "a pipe hands the next words to grep"       "kubectl get pods | grep -o jsonpath='{.items[*].metadata.name}.env*' -r ."
# The no-perl bare split cannot tell a command from text, so it grants no exemption.
NOPERL=$(mktemp -d)
printf '#!/bin/sh\nexit 127\n' >"$NOPERL/perl"; chmod +x "$NOPERL/perl"
actual=$(decide_noperl "kubectl get pods -o jsonpath='{.items[*].metadata.name}.env*' | grep -i relay")
if [ "$actual" = ASK ]; then printf 'ok   no perl: a kubectl template still asks\n'; pass=$((pass + 1)); else printf 'FAIL no perl: a kubectl template still asks — got %s\n' "$actual"; fail=$((fail + 1)); fi
rm -rf "$NOPERL"

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
GLOBDIR="$WORK/glob"
mkdir "$GLOBDIR"
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
check_from_globdir SILENT "scratch listing beside a real pem" "ls *"
check_from_globdir SILENT "broad glob beside a real pem" "cat *"

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
says "absolute glob names its matches"   "cat $GLOBDIR/*.pem"          "it matches 1 file(s)"
says "absolute glob names the filenames" "cat $GLOBDIR/*.pem"          "$PEM"
says "absolute glob matching nothing"    "cat $GLOBDIR/nonesuch/*.pem" "matches nothing under that path right now"
# A relative pattern says why it cannot be expanded rather than implying the guard knows more than it does.
says "relative glob is not expanded"     'cat *.pem'                   "working directory is not the command's"
# Every prompt names the word, where it sits, and what approving lets happen.
BT='`'
says "names the flagged word"            "cat .env"                                    "flagged ${BT}.env${BT} in the command line"
says "names a body and its consumer"     "cat <<'EOF' | grep x${NL}cat $PEM${NL}EOF"   "flagged ${BT}$PEM${BT} in the heredoc body fed to ${BT}cat${BT}"
says "names where a piped body goes"     "cat <<'EOF' | bash${NL}cat $PEM${NL}EOF"   "the heredoc body fed to ${BT}cat${BT}, piped on to ${BT}bash${BT}"
says "names a shell -c operand"          "bash -c 'cat $KEY; true'"                    "in the command line passed to a shell ${BT}-c${BT}"
says "names a comment"                   "cat notes.txt # $PEM"                        'in a shell comment'
says "names a substitution"              "echo \"\$(cat $PEM) done\""                  'in a command substitution'
says "says what approving lets happen"   "cat .env"                                    'Approving runs the command as written: if it does read the file, its contents enter the context/transcript'
# Naming a match must never mean reading one: the prompt carries filenames, never contents. A plain sentinel rather than a secret-shaped literal — this asserts that contents do not travel, which no particular shape makes truer.
printf 'CONTENTS-MUST-NOT-TRAVEL\n' > "$GLOBDIR/$KEY"
case "$(reason "cat $GLOBDIR/*.key")" in
  *CONTENTS-MUST-NOT-TRAVEL*) printf 'FAIL prompt leaked file contents\n'; fail=$((fail + 1)) ;;
  *) printf 'ok   prompt carries names, not contents\n'; pass=$((pass + 1)) ;;
esac

: >"$HOOK_DIAG_ASK_LOG"
LOG_CMD="cat .env.prod${NL}# ts=forged${NL}---${NL}hook=forged"
jq -nc --arg c "$LOG_CMD" '{session_id:"probe-123!",tool_input:{command:$c}}' | bash "$GUARD" >"$WORK/out"
EXPECTED_LOG=$(printf '%s\n' '---' 'hook=read-secret-guard-bash' 'session=probe-123' 'decision=ask:literal' 'cmd=cat .env.prod # ts=forged --- hook=forged')
if [ "$(sed '2d' "$HOOK_DIAG_ASK_LOG")" = "$EXPECTED_LOG" ] \
  && sed -n '2p' "$HOOK_DIAG_ASK_LOG" | grep -qE '^ts=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then
  printf 'ok   ask logging has six ordered, newline-free fields\n'; pass=$((pass + 1))
else
  printf 'FAIL malformed ask decision log\n'; fail=$((fail + 1))
fi
run ASK "wildcard ask is logged separately" "cat *.pem"
if tail -2 "$HOOK_DIAG_ASK_LOG" | head -1 | grep -qx 'decision=ask:wildcard'; then
  printf 'ok   wildcard decision class is recorded\n'; pass=$((pass + 1))
else
  printf 'FAIL wildcard ask log lost its decision class\n'; fail=$((fail + 1))
fi
if HOOK_DIAG_ASK_LOG="$WORK" decide 'cat *.pem' | grep -qx ASK; then
  printf 'ok   ask logging does not alter verdicts\n'; pass=$((pass + 1))
else
  printf 'FAIL ask log changed the permission verdict\n'; fail=$((fail + 1))
fi
printf 'not json' | bash "$GUARD" >"$WORK/out" 2>"$WORK/err"
if [ "$?" -eq 2 ] && grep -q 'cannot read the hook payload' "$WORK/err"; then
  printf 'ok   unparsable input fails closed\n'; pass=$((pass + 1))
else
  printf 'FAIL unparsable input did not fail closed\n'; fail=$((fail + 1))
fi

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

# A scan that would overrun the hook timeout asks.
actual=$(SECRET_GUARD_SCAN_DEADLINE=0 decide "cat notes.txt")
if [ "$actual" = ASK ]; then printf 'ok   an exhausted deadline asks\n'; pass=$((pass + 1)); else printf 'FAIL an exhausted deadline asks — got %s\n' "$actual"; fail=$((fail + 1)); fi
many=$(printf '{a,b}{a,b}*.txt %.0s' $(seq 1 300))
burn=$(printf 'x%s{1..60} ' 1 2 3 4 5 6 7 8 9)
run ASK "split stem after the budget is spent"   "cat $burn .e{n,:}v"
wide=$(printf 'a,%.0s' $(seq 1 50000))
run ASK "one list of 50000 alternatives"         "cat {${wide}a} .env"
many65=$(printf ',a%s' $(seq 1 65))
run ASK "colon split stem past the cap"         "cat .{e,:}nv{${many65}}"
run ASK "space split key past the cap"          "cat x.p{e,\" \"}m{${many65}}"
longglob=$(printf 'a%.0s' $(seq 1 100000))
run ASK "secret read after a 100 KB glob"       "cat *${longglob} .env"
run ASK "secret name inside a 5 KB brace word"  "cat {.env,x:${longglob:0:5000}}"
run ASK "brace words past the per-command budget" "cat $many server.{pem,crt}"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
