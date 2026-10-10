#!/usr/bin/env bash
# Control suite for the fixture override — every verdict below is known in advance, see README § Sanctioned fixtures.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(dirname "$SCRIPT_DIR")"
# Absolute, so a stub jq shadowing PATH can still delegate to the real one.
REAL_JQ="$(command -v jq)"

PASS=0
FAIL=0
WORK=$(mktemp -d)
# A unique session_id is mandatory: without one the tracker is keyed on $CLAUDE_CODE_SESSION_ID (the live session's, under Claude Code) or the calling process, which the trap never removes.
SESSION_ID="secret-guard-suite-$$"
ERR="$WORK/stderr"
OUT="$WORK/stdout"
trap 'rm -rf "$WORK" "/tmp/claude-op-reads-$SESSION_ID"*' EXIT

ok()  { PASS=$((PASS + 1)); }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$1"; }

assert_exit() {
  if [ "$3" -eq "$2" ]; then ok; else bad "$1 — expected exit $2, got $3"; fi
}

assert_err_has() {
  if grep -qF -- "$2" "$ERR"; then ok; else bad "$1 — stderr lacked '$2', got: $(head -c 160 "$ERR")"; fi
}

assert_err_lacks() {
  if grep -qF -- "$2" "$ERR"; then bad "$1 — stderr unexpectedly contained '$2'"; else ok; fi
}

# GNU stat reads -f as --file-system: it prints a filesystem block to stdout and exits 1, so trying the BSD form first leaves that block glued to the fallback's answer and no mode can ever match.
file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

# A fresh copy per case, so a mutated allowlist cannot leak into the next verdict.
plugin_copy() {
  local dst="$WORK/copy-$1"
  rm -rf "$dst"
  mkdir -p "$dst"
  cp -R "$PLUGIN_ROOT/scripts" "$dst/scripts"
  cp "$PLUGIN_ROOT/fixtures.allow" "$dst/fixtures.allow"
  # The shipped list carries no entries, so each copy lists the sanctioned operand itself.
  printf '%s\n' "$LISTED" >>"$dst/fixtures.allow"
  printf '%s' "$dst"
}

write_guard() {
  jq -n --arg c "$2" '{tool_name:"Write", tool_input:{file_path:"/tmp/fixture-probe", content:$c}}' \
    | "$1/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
}

bash_guard() {
  jq -n --arg c "$2" '{tool_name:"Bash", tool_input:{command:$c}}' \
    | "$1/scripts/write-secret-guard-bash.sh" >"$OUT" 2>"$ERR"
}

paste_guard() {
  jq -n --arg p "$2" '{prompt:$p}' | "$1/scripts/paste-secret-guard.sh" >"$OUT" 2>"$ERR"
}

# The chained entry point hooks.json actually registers; the direct calls above bypass it.
authority_guard() {
  jq -n --arg c "$2" --arg s "$SESSION_ID" '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
    | "$1/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
}

# Both operands are generated at runtime, so neither is typed into this file; plugin_copy lists LISTED in every copy.
LISTED=$("$PLUGIN_ROOT/scripts/fixture-value.sh" aws-access-key)
FRESH=$("$PLUGIN_ROOT/scripts/fixture-value.sh" aws-access-key)

# With either operand empty, every case that expects an allow reports ok for a guard that was handed nothing to inspect.
if [ -z "$LISTED" ] || [ -z "$FRESH" ]; then
  echo "the generator produced no value — every allow case below would pass vacuously." >&2
  exit 1
fi
if [ "$LISTED" = "$FRESH" ] || grep -qxF -- "$FRESH" "$PLUGIN_ROOT/fixtures.allow"; then
  echo "the generated value collided with an allowlist entry — rerun." >&2
  exit 1
fi

echo "=== Write/Edit surface ==="

COPY=$(plugin_copy base)

# Control: without this, every "blocked" verdict below is also what a broken harness produces.
write_guard "$COPY" "nothing secret-shaped here"
assert_exit "benign content passes" 0 $?
assert_err_lacks "benign content is silent" "WRITE-SECRET GUARD"

write_guard "$COPY" "let key = \"$LISTED\";"
assert_exit "verdict 1: a listed value is allowed" 0 $?
assert_err_has "verdict 1 emits the notice" "allowed —"
assert_err_has "verdict 1 names what it exempted" "$LISTED"

write_guard "$COPY" "let key = \"$FRESH\";"
assert_exit "verdict 2a: an unlisted value blocks" 2 $?
assert_err_has "verdict 2a explains the block" "would write a raw secret-shaped literal"

write_guard "$COPY" "let a = \"$LISTED\"; let b = \"$FRESH\";"
assert_exit "verdict 2b: one unlisted value blocks the whole call" 2 $?
assert_err_lacks "verdict 2b does not claim an exemption" "allowed —"

# Regression: the write surface has no generator bail-out, so naming the generator must not exempt an unlisted value alongside it.
write_guard "$COPY" "run scripts/fixture-value.sh aws-access-key; let stale = \"$FRESH\";"
assert_exit "naming the generator does not exempt written content" 2 $?
assert_err_has "the generator mention still reports a block" "would write a raw secret-shaped literal"

# \b fails when the preceding character is the n of a literal \n, which is how a key lands in k8s stringData or JSON config.
COPY=$(plugin_copy escaped)
for esc in 'n' 't' 'r'; do
  write_guard "$COPY" "data: \"tok\\${esc}${FRESH}\""
  assert_exit "a key behind an escaped \\$esc still blocks" 2 $?
done

# MultiEdit joined only with a newline, so a key split across two adjacent edits reassembled in the file but never in what the guard saw.
COPY=$(plugin_copy multiedit)
jq -n --arg a "${FRESH:0:10}" --arg b "${FRESH:10}" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:$a},{new_string:$b}]}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a key split across two adjacent edits blocks" 2 $?
jq -n '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:"nothing"},{new_string:"benign"}]}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a benign multi-edit still passes" 0 $?

jq -n --arg a "$FRESH" '{tool_name:"NotebookEdit", tool_input:{new_source:$a}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a key in a notebook cell blocks" 2 $?

COPY=$(plugin_copy substring)
printf 'seen once: %s in a log line\n' "$FRESH" >>"$COPY/fixtures.allow"
write_guard "$COPY" "let key = \"$FRESH\";"
assert_exit "an entry that merely contains the value does not exempt it" 2 $?

# Behavioural only — it does not isolate the -oE/-qE divergence that motivated the residual rewrite, because the widened Slack shape is greedy enough to swallow the next token's prefix.
COPY=$(plugin_copy adjacent)
SLACK_A=$("$PLUGIN_ROOT/scripts/fixture-value.sh" slack-bot-token)
SLACK_B=$("$PLUGIN_ROOT/scripts/fixture-value.sh" slack-bot-token)
printf '%s\n' "$SLACK_A" >>"$COPY/fixtures.allow"
write_guard "$COPY" "$SLACK_A"
assert_exit "the listed token alone is exempt" 0 $?
write_guard "$COPY" "${SLACK_A}${SLACK_B}"
assert_exit "an unlisted secret adjacent to a listed one still blocks" 2 $?

# A prefix entry would subtract what every rotation of the same credential shares.
COPY=$(plugin_copy rotation)
printf '%s\n' "$SLACK_A" >>"$COPY/fixtures.allow"
write_guard "$COPY" "${SLACK_A%-*}-${SLACK_B##*-}"
assert_exit "a rotation sharing the listed token's prefix still blocks" 2 $?

COPY=$(plugin_copy prefix-entry)
printf '%s\n' "${SLACK_A%-*}" >>"$COPY/fixtures.allow"
write_guard "$COPY" "$SLACK_A"
assert_exit "a prefix-only allowlist entry exempts nothing" 2 $?
assert_err_has "the prefix entry is announced as ignored" "not a complete value"

# An open-ended shape lets one COMPLETE value be the prefix of another: subtracting the listed one by value stripped that prefix out of the unlisted neighbour, leaving the residual check nothing to find.
COPY=$(plugin_copy prefix-of-longer)
LONGER="${SLACK_A}EXTRA"
printf '%s\n' "$SLACK_A" >>"$COPY/fixtures.allow"
write_guard "$COPY" "$LONGER"
assert_exit "a longer value extending the listed one blocks alone" 2 $?
write_guard "$COPY" "fixture: $SLACK_A
real: $LONGER"
assert_exit "a longer value extending the listed one still blocks beside it" 2 $?
assert_err_lacks "the longer value is not reported as exempt" "allowed —"

# An unreadable payload must block: jq failing here used to yield an empty field and exit 0, disarming the guard on every call.
COPY=$(plugin_copy nojq)
printf '#!/bin/sh\nexit 127\n' >"$COPY/jq"; chmod +x "$COPY/jq"

# Answers only .tool_name, so the four content extractions are what blocks — a stub failing every call blocks at the tool-name guard above them and isolates nothing.
CONTENT_COPY=$(plugin_copy nojq-content)
printf '#!/bin/sh\ncase "$*" in *.tool_name*) exec %s "$@" ;; esac\nexit 127\n' "$REAL_JQ" >"$CONTENT_COPY/jq"
chmod +x "$CONTENT_COPY/jq"
for t in Write Edit MultiEdit NotebookEdit; do
  jq -n --arg t "$t" --arg c "x" '{tool_name:$t, tool_input:{content:$c, new_string:$c, new_source:$c, edits:[{new_string:$c}]}}' \
    | PATH="$CONTENT_COPY:$PATH" "$CONTENT_COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
  assert_exit "$t blocks when jq cannot read its content" 2 $?
  # The tool-name guard's message alone carries this tail, so its absence pins the block to the content extraction.
  assert_err_lacks "$t blocks at the content extraction, not the tool-name guard" "Install jq"
done

# Real jq on well-formed JSON: the MultiEdit filter errors on a non-object edit, which used to end only the substitution's subshell and let the write through.
FILTER_COPY=$(plugin_copy jq-filter-error)
jq -n --arg s "$FRESH" '{tool_name:"MultiEdit", tool_input:{edits:[$s]}}' \
  | "$FILTER_COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a filter error on a well-formed payload blocks rather than allows" 2 $?
assert_err_has "the filter error explains the block" "cannot read the hook payload"

for guard in write-secret-guard.sh write-secret-guard-bash.sh paste-secret-guard.sh; do
  jq -n --arg c "let key = \"$FRESH\";" '{tool_name:"Write", tool_input:{content:$c, command:$c}, prompt:$c}' \
    | PATH="$COPY:$PATH" "$COPY/scripts/$guard" >"$OUT" 2>"$ERR"
  assert_exit "$guard blocks when jq cannot run" 2 $?
  assert_err_has "$guard says why it blocked" "cannot read the hook payload"
done

COPY=$(plugin_copy base)
jq -n --arg c "let key = \"$LISTED\";" '{tool_name:"Edit", tool_input:{file_path:"/tmp/p", new_string:$c}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "Edit reaches the same verdict as Write" 0 $?

jq -n --arg c "let key = \"$FRESH\";" '{tool_name:"Edit", tool_input:{file_path:"/tmp/p", new_string:$c}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "Edit blocks an unlisted value, so the new_string is really read" 2 $?

jq -n --arg c "let key = \"$FRESH\";" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:$c}]}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "MultiEdit reaches the same verdict as Write" 2 $?

# Every edit must be scanned, not just the first.
jq -n --arg c "let key = \"$FRESH\";" '{tool_name:"MultiEdit", tool_input:{edits:[{new_string:"harmless"},{new_string:$c}]}}' \
  | "$COPY/scripts/write-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "MultiEdit scans past the first edit" 2 $?

echo "=== Fail-closed edges ==="

COPY=$(plugin_copy missing)
rm -f "$COPY/fixtures.allow"
write_guard "$COPY" "let key = \"$LISTED\";"
assert_exit "verdict 3a: a missing allowlist blocks" 2 $?
assert_err_has "verdict 3a names the unreadable allowlist" "missing or unreadable"

# Both edges block, so only the contract distinguishes fail-closed from an empty list that happens to block.
(
  # shellcheck source=/dev/null
  source "$COPY/scripts/secret-shapes.sh"
  # shellcheck disable=SC2034  # read by fixture_allowlist from the file sourced above
  SECRET_GUARD_ALLOWLIST="$WORK/definitely-absent"
  fixture_allowlist >/dev/null 2>"$ERR"
)
assert_exit "verdict 3a: fixture_allowlist reports unreadable rather than returning an empty list" 1 $?
assert_err_has "verdict 3a: it says why, rather than yielding a silently empty list" "missing or unreadable"

if [ "$(id -u)" -ne 0 ]; then
  COPY=$(plugin_copy unreadable)
  chmod 000 "$COPY/fixtures.allow"
  write_guard "$COPY" "let key = \"$LISTED\";"
  assert_exit "verdict 3b: an unreadable allowlist blocks" 2 $?
  chmod 644 "$COPY/fixtures.allow"
else
  echo "skipped: verdict 3b needs a non-root user to make a file unreadable"
fi

COPY=$(plugin_copy emptylist)
grep -E '^[[:space:]]*#' "$PLUGIN_ROOT/fixtures.allow" >"$COPY/fixtures.allow"
write_guard "$COPY" "let key = \"$LISTED\";"
assert_exit "a comments-only allowlist exempts nothing" 2 $?

# --- an exemption must cover a WHOLE value, and only the values listed -------------
# The allowlist used to be applied by deleting each entry and re-testing the remainder. Two real
# secrets got through that way, so these three fix the arithmetic rather than the entries.
echo "=== Exemption arithmetic ==="

COPY=$(plugin_copy arith)
# An entry may legitimately end in a shape character; deleting it then spliced that character onto
# whatever followed, and the next secret lost the left boundary the pattern requires.
GL=$("$PLUGIN_ROOT/scripts/fixture-value.sh" gitlab-pat)
DONOR="${GL%?}-"
printf '\n%s\n' "$DONOR" >>"$COPY/fixtures.allow"
bash_guard "$COPY" "printf '%s' Z$DONOR$FRESH > /tmp/fixture-probe"
assert_exit "a listed entry cannot donate a boundary to the secret beside it" 2 $?

# An open-ended shape means a listed value can sit INSIDE a longer, independently valid one.
COPY=$(plugin_copy contain)
GL2=$("$PLUGIN_ROOT/scripts/fixture-value.sh" gitlab-pat)
printf '\n%s\n' "$GL2" >>"$COPY/fixtures.allow"
bash_guard "$COPY" "printf '%s' ${GL2}ZZZZZZ > /tmp/fixture-probe"
assert_exit "a listed value contained in a longer one exempts neither" 2 $?
bash_guard "$COPY" "printf '%s' $GL2 > /tmp/fixture-probe"
assert_exit "control: the listed value itself still passes" 0 $?

# Adjacency is the case subtraction was originally chosen for, so enumeration has to keep it working.
# Both entries are the same open-ended shape on purpose: with no separator between them, the enumerator
# greedily merges the pair into ONE span, which is the arrangement a per-span lookup gets wrong.
COPY=$(plugin_copy adjacent)
A=$("$PLUGIN_ROOT/scripts/fixture-value.sh" gitlab-pat)
B=$("$PLUGIN_ROOT/scripts/fixture-value.sh" gitlab-pat)
printf '\n%s\n%s\n' "$A" "$B" >>"$COPY/fixtures.allow"
assert_exit "control: both fixtures reached the allowlist" 2 "$(grep -c '^glpat' "$COPY/fixtures.allow")"
bash_guard "$COPY" "printf '%s %s' $A $B > /tmp/fixture-probe"
assert_exit "two listed values separated by a space pass" 0 $?
bash_guard "$COPY" "printf '%s' $A$B > /tmp/fixture-probe"
assert_exit "two listed values with nothing between them pass" 0 $?
bash_guard "$COPY" "printf '%s %s' $A $FRESH > /tmp/fixture-probe"
assert_exit "control: one unlisted value among them blocks" 2 $?

# A span with no valid left boundary is not something the guards would have blocked on by itself, so
# finding one beside a listed fixture must not turn the exemption into a refusal.
bash_guard "$COPY" "printf '%s' $A > /tmp/fixture-probe; echo X$B >> /tmp/fixture-probe"
assert_exit "a glued, boundary-less occurrence does not refuse the exemption" 0 $?
bash_guard "$COPY" "printf '%s' ${A}ZZZZZZ > /tmp/fixture-probe"
assert_exit "control: a listed value inside a longer one still blocks" 2 $?

# --- an empty or non-object payload is not "nothing to inspect" --------------------
echo "=== Payload shape ==="

COPY=$(plugin_copy payload)
for guard in paste-secret-guard read-secret-guard read-secret-guard-bash \
             write-secret-guard write-secret-guard-bash op-read-guard secret-mask-guard; do
  printf '' | "$COPY/scripts/$guard.sh" >"$OUT" 2>"$ERR"
  assert_exit "$guard blocks an empty payload" 2 $?
  printf 'null' | "$COPY/scripts/$guard.sh" >"$OUT" 2>"$ERR"
  assert_exit "$guard blocks a bare null payload" 2 $?
done
# The Stop hook is the deliberate exception: exiting non-zero there is worse than a skipped purge,
# so it warns and names what it could not remove.
printf '' | "$COPY/scripts/op-cache-cleanup.sh" >"$OUT" 2>"$ERR"
assert_exit "the Stop hook does not block on an empty payload" 0 $?
assert_err_has "the Stop hook says the caches were left behind" "may persist"

echo "=== PEM cannot be allowlisted ==="

# The header family widened with the shapes; a form the ignore-rule missed could be listed and would blind the guard to every key of that family.
DASH=$(printf '%0.s-' 1 2 3 4 5)
for hdr in "BEGIN PGP PRIVATE KEY BLOCK" "BEGIN OPENSSH PRIVATE KEY" "BEGIN RSA PRIVATE KEY"; do
  COPY=$(plugin_copy "hdr-${hdr// /-}")
  printf '%s\n' "${DASH}${hdr}${DASH}" >>"$COPY/fixtures.allow"
  write_guard "$COPY" "${DASH}${hdr}${DASH}"
  assert_exit "a listed '$hdr' header exempts nothing" 2 $?
  assert_err_has "'$hdr' is announced as ignored" "ignoring the private-key header entry"
done
COPY=$(plugin_copy hdr-putty)
printf 'PuTTY-User-Key-File-2\n' >>"$COPY/fixtures.allow"
write_guard "$COPY" "PuTTY-User-Key-File-2"
assert_exit "a listed PuTTY key header exempts nothing" 2 $?

# Harvested from a generated key so no header literal is typed into this file either.
PEM=$("$PLUGIN_ROOT/scripts/fixture-value.sh" pem-private-key)
PEM_HEADER=$(printf '%s\n' "$PEM" | head -1)

COPY=$(plugin_copy pem)
printf '%s\n' "$PEM_HEADER" >>"$COPY/fixtures.allow"
write_guard "$COPY" "$PEM"
assert_exit "a PEM header entry does not exempt a private key" 2 $?
assert_err_has "the ignored PEM entry is announced" "ignoring the private-key header entry"

echo "=== Bash surface ==="

COPY=$(plugin_copy bash)

bash_guard "$COPY" "printf '%s' $LISTED > /tmp/fixture-probe"
assert_exit "a listed value is allowed in a write command" 0 $?
assert_err_has "the Bash notice is emitted" "allowed —"

bash_guard "$COPY" "printf '%s' $FRESH > /tmp/fixture-probe"
assert_exit "an unlisted value blocks a write command" 2 $?

bash_guard "$COPY" "printf '%s' $FRESH | tee /tmp/fixture-probe"
assert_exit "a tee write is gated" 2 $?

# The writer test reads both the raw and the normalized command, so a respelled writer still counts as one.
bash_guard "$COPY" "printf '%s' $FRESH | t\"e\"e /tmp/fixture-probe"
assert_exit "a tee split across a quote is gated" 2 $?

bash_guard "$COPY" "$(printf 'git commit \\\n  -m "key %s"' "$FRESH")"
assert_exit "a continuation before -m is gated" 2 $?

bash_guard "$COPY" "$(printf 'curl https://example.invalid/%s -\\\no /tmp/fixture-probe' "$FRESH")"
assert_exit "a continuation inside curl -o is gated" 2 $?

# The payload scan is deliberately NOT normalized: a two-character escape is part of the secret's own left boundary.
bash_guard "$COPY" "printf 'a\\n$FRESH' | tee /tmp/fixture-probe"
assert_exit "a key behind an escape is still gated" 2 $?

# Normalization must not narrow a predicate that requires the quote it removes.
bash_guard "$COPY" "python3 -c \"open('/tmp/fixture-probe','w').write('$FRESH')\""
assert_exit "an inline python writer survives normalization" 2 $?

bash_guard "$COPY" "cat <<EOF
$FRESH
EOF"
assert_exit "a heredoc write is gated" 2 $?

# A backslash quotes the delimiter exactly like '' or "", and the quote-only predicate skipped it.
for delim in "<<'EOF'" '<<"EOF"' '<<\EOF' '<<-\EOF'; do
  bash_guard "$COPY" "cat $delim
$FRESH
EOF"
  assert_exit "a heredoc delimited with $delim is gated" 2 $?
done

# Negative control: the widened delimiter must not turn every heredoc into a block.
bash_guard "$COPY" 'cat <<\EOF
no secret here
EOF'
assert_exit "a heredoc without a secret still passes" 0 $?

# The delimiter's first character stays [A-Za-z_]: adding digits would match the << of an arithmetic left-shift.
bash_guard "$COPY" "x=\$((1 << 2)); echo $FRESH"
assert_exit "an arithmetic left-shift is not read as a heredoc write" 0 $?

bash_guard "$COPY" "echo $FRESH | wc -c"
assert_exit "a non-write command is out of scope, unchanged by the override" 0 $?

# A here-string only feeds stdin; the heredoc pattern matched its third < and called it a write.
bash_guard "$COPY" "wc -c <<<$FRESH"
assert_exit "a here-string is not a file write" 0 $?

# Writers that spell no redirect were entirely out of scope, so the guard never looked at them.
bash_guard "$COPY" "sed -i '' 's/x/$FRESH/' f.txt"
assert_exit "sed -i is gated" 2 $?
bash_guard "$COPY" "curl -o out -d $FRESH https://example.invalid"
assert_exit "curl -o is gated" 2 $?
bash_guard "$COPY" "python3 -c \"open('f','w').write('$FRESH')\""
assert_exit "an inline python writer is gated" 2 $?

# Each writer needs its writing form: a bare name matched `npm install`, and a w/a anywhere in the args matched a read-only open().
bash_guard "$COPY" "npm install pkg --token=$FRESH"
assert_exit "npm install is not a file write" 0 $?
bash_guard "$COPY" "pnpm install -D x --token=$FRESH"
assert_exit "a -D package install is not a file write" 0 $?
bash_guard "$COPY" "install src dst && echo $FRESH"
assert_exit "a bare install(1) is a file write" 2 $?
bash_guard "$COPY" "curl -LO https://example.invalid/$FRESH"
assert_exit "a clustered curl -LO is a file write" 2 $?
bash_guard "$COPY" "curl -s https://example.invalid -d $FRESH"
assert_exit "a curl with no output flag is not a file write" 0 $?

# A commit message persists to disk in git history; a secret store is where a secret is supposed to go.
bash_guard "$COPY" "git commit -m 'key is $FRESH'"
assert_exit "a secret in a commit message is a write" 2 $?
bash_guard "$COPY" "git commit -m 'fix(secret-guard): narrow the write predicate'"
assert_exit "an ordinary commit message is not a write" 0 $?
for form in "git commit --message='k $FRESH'" "git -c user.name=x commit -m 'k $FRESH'" "git tag --message='$FRESH' v1"; do
  bash_guard "$COPY" "$form"
  assert_exit "a long/prefixed git message form is a write" 2 $?
done
bash_guard "$COPY" "git commit --amend --no-edit"
assert_exit "git commit --amend is not a message write" 0 $?

# The value can be glued to the flag, and a process substitution is not a file write.
bash_guard "$COPY" "git commit -m'key $FRESH'"
assert_exit "a glued -m'msg' is a write" 2 $?
bash_guard "$COPY" "git commit -m\"key $FRESH\""
assert_exit "a glued -m\"msg\" is a write" 2 $?
bash_guard "$COPY" "git commit -m'ordinary message'"
assert_exit "a glued ordinary message is not a write" 0 $?
for w in "tee >(cat) <<<$FRESH" "echo $FRESH >& /tmp/fixture-probe" "echo $FRESH >&/tmp/fixture-probe"; do
  bash_guard "$COPY" "$w"
  assert_exit "a write-side redirect is gated: ${w:0:24}" 2 $?
done
# Input process substitution carries no > at all, so it was never in scope; fd duplication targets a digit or -.
for n in "diff <(echo $FRESH) <(echo b)" "echo $FRESH 2>&-"; do
  bash_guard "$COPY" "$n"
  assert_exit "not a file write: ${n:0:24}" 0 $?
done

# Flag clustering is the recurring shape here: a writer flag is not always first in its group, and a program is not always first in its command.
for w in "sed -ni 's/x/$FRESH/p' f" "perl -pi -e 's/x/$FRESH/' f" "sed --in-place 's/x/$FRESH/' f" "sudo install -m 600 a b && echo $FRESH" "/usr/bin/install -m 600 a b && echo $FRESH"; do
  bash_guard "$COPY" "$w"
  assert_exit "clustered/prefixed writer is gated: ${w%% *}" 2 $?
done
for n in "sed -n '1,5p' f # $FRESH" "perl -e 'print 1' # $FRESH" "yarn install # $FRESH" "npm install -D pkg --token=$FRESH"; do
  bash_guard "$COPY" "$n"
  assert_exit "non-writer stays out of scope: ${n%% *}" 0 $?
done

# CONTRIBUTING tells the reader not to split a literal across variables; the scan read only the raw text, so quoting the shape apart wrote the key to a file unseen.
SPLIT_A="${FRESH:0:4}"
SPLIT_B="${FRESH:4}"
for w in "echo \"$SPLIT_A''$SPLIT_B\" > f" "echo \"$SPLIT_A\"\"$SPLIT_B\" > f" "echo \"$SPLIT_A\\\\$SPLIT_B\" > f"; do
  bash_guard "$COPY" "$w"
  assert_exit "a literal split by quoting still blocks: ${w:0:18}" 2 $?
done
# The raw spelling has to survive alongside the normalized one: normalization deletes the backslash that forms this boundary.
bash_guard "$COPY" "printf 'x\\n$FRESH' > f"
assert_exit "an escaped-newline boundary still blocks" 2 $?
# Detection and exemption must read the same text, or a listed fixture clears a split key beside it.
LISTED_AWS=$(grep -m1 '^AKIA' "$COPY/fixtures.allow")
bash_guard "$COPY" "echo $LISTED_AWS \"$SPLIT_A''$SPLIT_B\" > f"
assert_exit "a listed fixture does not clear a split key beside it" 2 $?
bash_guard "$COPY" "echo $LISTED_AWS > f"
assert_exit "the listed fixture alone is still exempt" 0 $?

# A tool the guards shell out to is the same fail-open as a missing jq: an empty result reads as "nothing to inspect".
COPY=$(plugin_copy noperl)
printf '#!/bin/sh\nexit 127\n' >"$COPY/perl"; chmod +x "$COPY/perl"
jq -n --arg s "$SESSION_ID-noperl" '{session_id:$s, tool_name:"Bash", tool_input:{command:"cat /home/u/.env"}}' \
  | PATH="$COPY:$PATH" "$COPY/scripts/read-secret-guard-bash.sh" >"$OUT" 2>"$ERR"
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a missing perl silently disarmed the read guard"; fi
for store in "gh secret set FOO --body $FRESH" "aws ssm put-parameter --name /x --value $FRESH" "kubectl create secret generic s --from-literal=k=$FRESH"; do
  bash_guard "$COPY" "$store"
  assert_exit "a sanctioned secret store is not blocked: ${store%% *}" 0 $?
done
bash_guard "$COPY" "python3 -c \"print(open('data.json').read())\" # $FRESH"
assert_exit "a read-only open() is not a file write" 0 $?

# Regression: an fd prefix is part of the redirect operator. These all reach a file and were silently out of scope.
for redir in '1>' '2>' '&>' '2>>' '10>' '>|'; do
  bash_guard "$COPY" "echo $FRESH $redir /tmp/fixture-probe"
  assert_exit "a $redir redirect is gated" 2 $?
done

# Controls for the loop above: fd duplication writes no file, so widening the operator must not swallow it.
for dup in '2>&1' '>&2'; do
  bash_guard "$COPY" "echo $FRESH $dup"
  assert_exit "$dup is fd duplication, not a file write" 0 $?
done

# Regression: naming the generator used to exempt the whole command, so a trailing comment turned a real write into a pass.
bash_guard "$COPY" "printf '%s' $FRESH > /tmp/b  # see scripts/fixture-value.sh"
assert_exit "naming the generator does not exempt a command" 2 $?

# The other half of that removal: piping the generator was never blocked to begin with, because its output is not in the command text.
bash_guard "$COPY" "scripts/fixture-value.sh aws-access-key > /tmp/a"
assert_exit "piping the generator into a file still passes" 0 $?

echo "=== Bash authority chain ==="

COPY=$(plugin_copy authority)

authority_guard "$COPY" "ls -la > /tmp/fixture-probe"
assert_exit "the chain passes a benign write" 0 $?

authority_guard "$COPY" "printf '%s' $LISTED > /tmp/fixture-probe"
assert_exit "the chain allows a listed value" 0 $?
assert_err_has "the chain forwards the notice to stderr" "allowed —"

authority_guard "$COPY" "printf '%s' $FRESH > /tmp/fixture-probe"
assert_exit "the chain blocks an unlisted value" 2 $?
assert_err_has "the chain forwards the block reason" "WRITE-SECRET GUARD"

echo "=== Prompt-paste surface ==="

COPY=$(plugin_copy paste)

paste_guard "$COPY" "check this fixture: $LISTED"
assert_exit "a listed value does not discard the prompt" 0 $?
if [ -s "$OUT" ]; then bad "a listed value still emitted a block decision"; else ok; fi
assert_err_has "the paste notice is emitted" "allowed —"

paste_guard "$COPY" "check this: $FRESH"
assert_exit "the paste guard still exits 0 when blocking" 0 $?
if [ "$(jq -r '.decision // empty' <"$OUT")" = "block" ]; then ok; else bad "an unlisted value did not block the prompt"; fi

echo "=== Ask surfaces and the rest of the chain ==="

COPY=$(plugin_copy ask)

jq -n '{tool_name:"Read", tool_input:{file_path:"/etc/ssl/private/server.key"}}' \
  | "$COPY/scripts/read-secret-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "the Read guard never blocks" 0 $?
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a private-key basename did not produce an ask"; fi

jq -n '{tool_name:"Read", tool_input:{file_path:"/repo/.env.example"}}' \
  | "$COPY/scripts/read-secret-guard.sh" >"$OUT" 2>"$ERR"
if [ -s "$OUT" ]; then bad ".env.example must stay readable without an ask"; else ok; fi

authority_guard "$COPY" "cat /home/u/.env"
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "the chain did not surface the read-guard ask"; fi

# Regression: IFS-splitting a quoted path with a space used to leave a trailing quote on the basename, so the guard passed silently.
authority_guard "$COPY" "cat \"/my projects/.env\""
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a quoted .env path containing a space did not produce an ask"; fi

authority_guard "$COPY" "cat '/my dir/server.pem'"
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a quoted private-key path containing a space did not produce an ask"; fi

# Controls for the two above: unquoting must not start flagging things nobody is reading.
authority_guard "$COPY" "cat \"/my projects/readme.txt\""
if [ -s "$OUT" ]; then bad "a quoted benign path must not produce an ask"; else ok; fi

# A secret-named search pattern now asks: over-asking is the deliberate trade for never going silent on a read.
authority_guard "$COPY" "grep -r \"id_rsa\" ."
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a secret-named grep pattern must produce an ask"; fi

# --include names the files grep opens, so it is a path filter and asking is correct: `grep -r --include='*.pem' X .` prints .pem contents.
authority_guard "$COPY" "grep -r --include=\"*.pem\" needle ."
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a flag value naming .pem files must produce an ask"; fi

# The counterpart is scanned on the same terms, since a clustered or glued spelling of it defeated every attempt to recognise one.
authority_guard "$COPY" "grep -r --regexp=\"id_rsa\" ."
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a regexp flag value naming a secret must produce an ask"; fi

# Restricting the strip to path-like tokens left a quoted bare filename unmatched, so a plain reader passed silently.
for q in '.env' 'id_rsa' 'kubeconfig'; do
  authority_guard "$COPY" "cat \"$q\""
  if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a quoted bare $q did not produce an ask"; fi
done

authority_guard "$COPY" "grep -r needle /etc/ssl/private/server.key"
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a real key path under grep must still produce an ask"; fi

# A reader prefixed by sudo/command/VAR= and a recursive grep spelled -R or -nr were all outside the gate.
for cmd in "sudo cat /etc/ssl/private/server.key" "command cat /home/u/.env" "VAR=1 cat /home/u/.env" "grep -nr needle /etc/ssl/private/server.key" "grep -R needle /etc/ssl/private/server.key"; do
  authority_guard "$COPY" "$cmd"
  if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "no ask for: $cmd"; fi
done
authority_guard "$COPY" "echo cat"
if [ -s "$OUT" ]; then bad "a bare word 'cat' must not produce an ask"; else ok; fi

# Every guard must fail closed on an unreadable payload — the first pass fixed only the three the review named.
COPY=$(plugin_copy nojq-all)
printf '#!/bin/sh\nexit 127\n' >"$COPY/jq"; chmod +x "$COPY/jq"
for guard in secret-mask-guard.sh read-secret-guard.sh read-secret-guard-bash.sh op-read-guard.sh; do
  jq -n '{tool_name:"Read", tool_input:{file_path:"/a/.env", command:"cat /a/.env"}}' \
    | PATH="$COPY:$PATH" "$COPY/scripts/$guard" >"$OUT" 2>"$ERR"
  assert_exit "$guard blocks when jq cannot run" 2 $?
  assert_err_has "$guard says why it blocked" "cannot read the hook payload"
done

COPY=$(plugin_copy base)
# A flag value is never masked, so a commit message naming a fetch is held to the fetch's rule.
authority_guard "$COPY" "git commit -m 'switch to op read op://Vault/Item/field'"
assert_exit "a commit message naming a fetch blocks like the fetch" 2 $?

# A heredoc body is never masked, so under every delimiter spelling the Bash write guard recognises, a fetch named in one is recorded and the same fetch after it is a duplicate.
for hd in "<<'PROSE'" '<<"PROSE"' '<<PROSE' '<<\PROSE' '<<-\PROSE' '<< PROSE' '<<- PROSE' '<< \PROSE'; do
  HD_SESSION="$SESSION_ID-hd-$(printf '%s' "$hd" | tr -dc 'A-Za-z')-$RANDOM"
  HD_CMD="cat $hd
switch to op read op://Vault/Item/field
PROSE"
  for _ in 1 2; do
    jq -n --arg s "$HD_SESSION" --arg c "$HD_CMD" \
      '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
      | "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
    HD_CODE=$?
  done
  assert_exit "a heredoc body naming a fetch is recorded, delimiter $hd" 2 "$HD_CODE"
  rm -f "/tmp/claude-op-reads-$HD_SESSION"
done

# Each other guard sees the body too; the mask guard is the one that fails on the first call rather than the second.
jq -n --arg c "cat <<\\PROSE
switch to op read op://Vault/Item/field
PROSE" '{tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/secret-mask-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "the mask guard sees a backslash heredoc body" 2 $?

# The third caller asks rather than blocks, so a path named inside a heredoc raises its prompt.
jq -n --arg s "$SESSION_ID-hdread" --arg c "cat <<\\PROSE
then edit /home/u/.env by hand
PROSE" '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/read-secret-guard-bash.sh" >"$OUT" 2>"$ERR"
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a heredoc body naming .env did not raise the read ask"; fi

# Negative control: the same path outside a heredoc must still raise it, or the assertion above would pass on a guard that never asks.
jq -n --arg s "$SESSION_ID-hdread2" --arg c "cat /home/u/.env" \
  '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/read-secret-guard-bash.sh" >"$OUT" 2>"$ERR"
if [ "$(jq -r '.hookSpecificOutput.permissionDecision // empty' <"$OUT")" = "ask" ]; then ok; else bad "a real .env read stopped asking"; fi

# Control: a fetch outside any heredoc blocks the same way.
authority_guard "$COPY" "op read op://Vault/Item/still-real"
assert_exit "a bare fetch outside any heredoc still blocks" 2 $?

# A here-string never hides the lines after it up to a later WORD.
jq -n --arg c "wc -c <<< \"WORD\"
op read op://Vault/Item/real
WORD" '{tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/secret-mask-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a fetch after a here-string is not masked away" 2 $?

# Called directly, not through the chain: secret-mask-guard blocks a raw fetch first, so this guard would never reach its append.
PERM_SESSION="$SESSION_ID-perms"
jq -n --arg s "$PERM_SESSION" --arg c "op read op://Vault/Item/perms-probe" \
  '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
PERM_FILE="/tmp/claude-op-reads-$PERM_SESSION"
# The tracking file maps which references were fetched, so it must not be world-readable.
if [ "$(file_mode "$PERM_FILE")" = "600" ]; then ok; else bad "the op-read tracking file is not mode 600"; fi
rm -f "$PERM_FILE"

# The check above only ever saw a fresh file, and umask applies at creation only — a pre-existing one kept whatever mode it was made with.
PRE_SESSION="$SESSION_ID-preexisting"
PRE_FILE="/tmp/claude-op-reads-$PRE_SESSION"
: > "$PRE_FILE"; chmod 644 "$PRE_FILE"
jq -n --arg s "$PRE_SESSION" --arg c "op read op://Vault/Item/pre-probe" \
  '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a pre-existing tracking file is still usable" 0 $?
if [ "$(file_mode "$PRE_FILE")" = "600" ]; then ok; else bad "a pre-existing tracking file keeps its permissive mode"; fi
if grep -qF 'op://Vault/Item/pre-probe' "$PRE_FILE"; then ok; else bad "the reference was not recorded in a pre-existing tracking file"; fi
rm -f "$PRE_FILE"

# Appending follows a symlink, so a planted link redirects the write into any file this user can write.
LINK_SESSION="$SESSION_ID-symlink"
LINK_FILE="/tmp/claude-op-reads-$LINK_SESSION"
VICTIM="$WORK/symlink-victim"
: > "$VICTIM"
ln -s "$VICTIM" "$LINK_FILE"
jq -n --arg s "$LINK_SESSION" --arg c "op read op://Vault/Item/link-probe" \
  '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a symlinked tracking path blocks instead of following the link" 2 $?
if [ -s "$VICTIM" ]; then bad "the append reached the symlink target"; else ok; fi
assert_err_has "the symlink block says why" "not a regular file owned by this user"
rm -f "$LINK_FILE"

# A directory is the other non-regular path: the guard must refuse it rather than error out mid-append.
DIR_SESSION="$SESSION_ID-dir"
DIR_FILE="/tmp/claude-op-reads-$DIR_SESSION"
mkdir -p "$DIR_FILE"
jq -n --arg s "$DIR_SESSION" --arg c "op read op://Vault/Item/dir-probe" \
  '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' \
  | "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a directory at the tracking path blocks" 2 $?
rmdir "$DIR_FILE"

# Naming the masked wrapper used to exempt the whole command, so a trailing comment let a raw fetch through.
authority_guard "$COPY" "op read op://Vault/Item/field  # use scripts/op-cache.sh instead"
assert_exit "naming the wrapper does not exempt a raw fetch" 2 $?
authority_guard "$COPY" "scripts/op-cache.sh --mask op://Vault/Item/field"
assert_exit "a real wrapper call still passes" 0 $?

# One command can carry both forms; the raw read still needs blocking.
authority_guard "$COPY" "op read op://Vault/Item/field && op item get Item"
assert_exit "a raw op read alongside an item get still blocks" 2 $?

echo "=== Generator emits real known-positives ==="

COPY=$(plugin_copy generator)
for shape in aws-access-key slack-bot-token gitlab-pat pem-private-key; do
  value=$("$PLUGIN_ROOT/scripts/fixture-value.sh" "$shape")
  write_guard "$COPY" "$value"
  assert_exit "a generated $shape is flagged by the guard" 2 $?
done

echo "=== Wrapper option arguments ==="

# Under set -u an unguarded "$2" aborts with a raw "unbound variable" and exit 1 instead of a usable message.
for opt in --profile --filter --format; do
  "$PLUGIN_ROOT/scripts/aws-batch-secrets.sh" "$opt" >"$OUT" 2>"$ERR"
  assert_exit "aws-batch-secrets.sh $opt with no value exits 64" 64 $?
  assert_err_has "aws-batch-secrets.sh $opt names the option" "$opt requires a value"
done

# Negative control: the parser still accepts a well-formed call, so the guard above rejects a missing value rather than every call.
"$PLUGIN_ROOT/scripts/aws-batch-secrets.sh" --help >"$OUT" 2>"$ERR"
assert_exit "aws-batch-secrets.sh --help still parses" 0 $?

"$PLUGIN_ROOT/scripts/sm-cache.sh" --profile >"$OUT" 2>"$ERR"
assert_exit "sm-cache.sh --profile with no value exits 64" 64 $?
assert_err_has "sm-cache.sh --profile names the option" "--profile requires a value"

# Negative control: a well-formed --profile parses and the run stops at the missing secret-id, not at the option.
"$PLUGIN_ROOT/scripts/sm-cache.sh" --profile some-profile >"$OUT" 2>"$ERR"
assert_exit "sm-cache.sh accepts a well-formed --profile" 64 $?
assert_err_has "sm-cache.sh stops at the missing secret-id" "usage: sm-cache.sh"

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ]
