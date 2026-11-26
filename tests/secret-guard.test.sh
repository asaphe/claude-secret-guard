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
# The read guard logs every ask; without this the suite appends to the live decision log.
export HOOK_DIAG_ASK_LOG="$WORK/asks.log"
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

# The authority's one-jq parse takes only the plain-string shape; anything else must reach each stage's own parse, message included.
printf '' | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "the authority blocks an empty payload" 2 $?
assert_err_has "the authority's empty-payload block is the first stage's own" "SECRET-MASK GUARD: cannot read the hook payload — it is empty"
printf '%s' '{"tool_input":"x","session_id":"s"}' | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "the authority blocks a payload whose tool_input is not an object" 2 $?
assert_err_has "that block comes from the stage's own field parse" "SECRET-MASK GUARD: cannot read the hook payload — jq is missing or the JSON did not parse"
for shape in '{"tool_input":{"command":["cat","/a/.env"]}}' '{"tool_input":{"command":"cat /a/.env"},"session_id":{"a":1}}'; do
  printf '%s' "$shape" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"; got=$?
  printf '%s' "$shape" | "$COPY/scripts/read-secret-guard-bash.sh" >"$WORK/stage.out" 2>/dev/null; want=$?
  assert_exit "the authority exits as the stage does on $shape" "$want" "$got"
  if cmp -s "$OUT" "$WORK/stage.out"; then ok; else bad "the authority's output on $shape differs from the stage's own"; fi
done
# A stage's own $(jq -r …) trims trailing newlines, and the ask log records the command it saw.
NL_SHAPE='{"tool_input":{"command":"cat /a/.env\n\n"},"session_id":"s"}'
printf '%s' "$NL_SHAPE" | HOOK_DIAG_ASK_LOG="$WORK/nl-auth.log" "$COPY/scripts/bash-secret-authority.sh" >/dev/null 2>&1
printf '%s' "$NL_SHAPE" | HOOK_DIAG_ASK_LOG="$WORK/nl-stage.log" "$COPY/scripts/read-secret-guard-bash.sh" >/dev/null 2>&1
if [ -s "$WORK/nl-stage.log" ] && [ "$(grep '^cmd=' "$WORK/nl-auth.log")" = "$(grep '^cmd=' "$WORK/nl-stage.log")" ]; then ok
else bad "the authority hands the stages a command with trailing newlines their own parse would have trimmed"; fi

# A stage's own $(jq -r …) gets a real NUL for \u0000 and bash drops it, so each of these always read as the bare command.
for nul in 'op rea\u0000d op://v/i/f' 'aws secretsmanager get-secret-val\u0000ue --secret-id x' 'op item get x --rev\u0000eal'; do
  printf '{"tool_input":{"command":"%s"},"session_id":"%s"}' "$nul" "$SESSION_ID" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "a \\u0000 inside '$nul' still blocks" 2 $?
  assert_err_has "the \\u0000 block for '$nul' is the mask guard's own" "SECRET-MASK GUARD: "
done
printf '{"tool_input":{"command":"c\\u0000at /a/.env"},"session_id":"%s"}' "$SESSION_ID" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a \\u0000 inside a reader name still exits 0" 0 $?
if grep -qF '"ask"' "$OUT"; then ok; else bad "a \\u0000 inside a reader name no longer asks"; fi
mkdir -p "$WORK/nulcwd"
printf 'op read op://v/i/f\n' >"$WORK/nulcwd/fetch.sh"
printf '{"tool_input":{"command":"bash ./fetch.sh"},"session_id":"%s","cwd":"%s\\u0000cwd"}' "$SESSION_ID" "$WORK/nul" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a \\u0000 inside cwd still resolves the invoked script" 2 $?
assert_err_has "the cwd block names the script it scanned" "fetch.sh performs a raw secret read"

# Each stage parses every JSON value on stdin and acts on all of them, so a second value can never hide the first.
printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"} {"tool_input":{"command":"ls"},"session_id":"%s"}' "$SESSION_ID" "$SESSION_ID" \
  | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a second JSON value does not hide a raw op read in the first" 2 $?
printf '{"tool_input":{"command":"ls"},"session_id":"%s"} {"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" "$SESSION_ID" \
  | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a first JSON value does not hide a raw op read in the second" 2 $?
printf '{"tool_input":{"command":"ls"},"session_id":"%s"} 5' "$SESSION_ID" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a non-object second value is refused as before" 2 $?
assert_err_has "that refusal is the first stage's own" "SECRET-MASK GUARD: cannot read the hook payload — it is empty, not a JSON object"

# $(cat) drops every NUL byte, so stdin reads as the bytes around them.
printf '\0{"tool_input":{"command":"ls"},"session_id":"%s"}' "$SESSION_ID" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a NUL byte before the payload is dropped, not read as its end" 0 $?
printf '{"tool_input":{"command":"ls"},"session_id":"%s"}\0junk' "$SESSION_ID" | "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "bytes after a NUL are still part of the payload" 2 $?
# The PostToolUse guard's own $(cat) printed bash's null-byte warning wherever the running bash prints one.
NUL_WARN=$(bash -c 'x=$(printf "a\0b")' 2>&1 | grep -c 'ignored null byte')
printf '{"tool_input":{"command":"ls"},"session_id":"%s","hook_event_name":"PostToolUse"}\0' "$SESSION_ID" | "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a NUL byte on the PostToolUse guard's stdin is dropped" 0 $?
if [ "$(grep -c 'ignored null byte' "$ERR")" = "$NUL_WARN" ]; then ok; else bad "the PostToolUse guard's null-byte warning count differs from this bash's own ($NUL_WARN)"; fi

# Run as its own pipeline, the duplicate-read stage without a session id was named after a parent that is new on every call.
F5_ITEM="f5probe$$"
for n in 1 2; do
  printf '{"tool_input":{"command":"op item get %s --fields password"}}' "$F5_ITEM" | env -u CLAUDE_CODE_SESSION_ID "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "call $n of an item get without a session id is not a duplicate" 0 $?
done
grep -lF "$F5_ITEM" /tmp/claude-op-reads-uid"$(id -u)"-pid* 2>/dev/null | while IFS= read -r f; do rm -f "$f"; done

# A parse the environment claims happened, when nothing parsed this payload, would hand every stage an empty command.
printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" \
  | SGA_PREPARSED=1 SG_NC_PRIMED=1 SG_NC_IN='op read op://v/i/f' SG_NC_OUT=ls "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "an inherited parse flag does not disarm the authority" 2 $?
printf '' | SGA_PREPARSED=1 "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "an inherited parse flag does not disarm the PostToolUse guard" 2 $?
# Without a session id each stage runs as its own bash, which inherits whatever the authority did not clear.
printf '{"tool_input":{"command":"op read op://v/i/f"}}' | env -u CLAUDE_CODE_SESSION_ID SGA_PREPARSED=1 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "an inherited parse flag does not disarm the stages run as their own bash" 2 $?

# Inherited shell options act on every line that changed, so under errexit the stages' own parse must still decide.
printf '{"tool_input":{"command":"cat /a/.env"}}' | env -u CLAUDE_CODE_SESSION_ID SHELLOPTS=errexit "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "under errexit a reader still exits 0" 0 $?
if grep -qF '"ask"' "$OUT"; then ok; else bad "under errexit a reader no longer asks"; fi
printf '{"tool_input":{"command":"op item get %s --fields password"},"hook_event_name":"PostToolUse"}' "$F5_ITEM" \
  | env -u CLAUDE_CODE_SESSION_ID SHELLOPTS=errexit "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "under errexit the PostToolUse guard still records a read" 0 $?
grep -lF "$F5_ITEM" /tmp/claude-op-reads-uid"$(id -u)"-pid* 2>/dev/null | while IFS= read -r f; do rm -f "$f"; done
# Stripping trailing newlines one at a time copies the text each time; this many outran the 30 s hook timeout, which lets the command run unchecked.
MANY_NL=$(printf 'op read op://v/i/f'; printf '\n%.0s' {1..60000}; printf x); MANY_NL=${MANY_NL%x}
jq -n --arg c "$MANY_NL" --arg s "$SESSION_ID" '{session_id:$s, tool_input:{command:$c}}' >"$WORK/many-nl.json"
SECONDS=0
"$COPY/scripts/bash-secret-authority.sh" <"$WORK/many-nl.json" >"$OUT" 2>"$ERR"
assert_exit "a raw op read followed by 60,000 newlines blocks" 2 $?
if [ "$SECONDS" -le 10 ]; then ok; else bad "a command followed by 60,000 newlines took ${SECONDS}s"; fi
{ cat "$WORK/many-nl.json"; printf '\n%.0s' {1..40000}; } >"$WORK/many-nl-stdin.json"
SECONDS=0
"$COPY/scripts/bash-secret-authority.sh" <"$WORK/many-nl-stdin.json" >"$OUT" 2>"$ERR"
assert_exit "a payload followed by 40,000 newlines on stdin blocks the same command" 2 $?
if [ "$SECONDS" -le 10 ]; then ok; else bad "a payload followed by 40,000 newlines on stdin took ${SECONDS}s"; fi

# A cwd starting with a dash reaches dirname, whose complaint about it has always been part of the output.
mkdir -p "$WORK/dashcwd/-sgd"
printf 'echo hi\n' >"$WORK/dashcwd/-sgd/s.sh"
(cd "$WORK/dashcwd" && printf '{"tool_input":{"command":"bash ./s.sh"},"session_id":"%s","cwd":"-sgd"}' "$SESSION_ID" | "$COPY/scripts/bash-secret-authority.sh") >"$OUT" 2>"$ERR"
assert_exit "a dash-leading cwd with a benign script passes" 0 $?
# Matched against this dirname's own complaint: GNU, BSD and uutils word it differently.
DASH_ERR=$(dirname -sgd/s.sh 2>&1 >/dev/null | head -n 1)
if [ -n "$DASH_ERR" ]; then
  assert_err_has "a dash-leading script path still goes through dirname" "$DASH_ERR"
else
  echo "skipped: this dirname accepts a dash-leading path without an error, so stderr cannot show it ran"
fi

# Bash 3.2 itself: posix mode cannot parse the mask guard's `< <(…)`, and a Shift-JIS backslash can be a character's second byte.
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'echo "${BASH_VERSINFO[0]}"')" -lt 5 ]; then
  mkdir -p "$WORK/bash32"; ln -sf /bin/bash "$WORK/bash32/bash"
  printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" \
    | PATH="$WORK/bash32:$PATH" POSIXLY_CORRECT=1 /bin/bash "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "in posix mode a raw op read still blocks" 2 $?
  assert_err_has "in posix mode the block is the mask guard's own" "SECRET-MASK GUARD: raw 'op read'"
  printf '{"tool_input":{"command":"ls"},"session_id":"%s"}' "$SESSION_ID" \
    | PATH="$WORK/bash32:$PATH" POSIXLY_CORRECT=1 /bin/bash "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "in posix mode a stage bash cannot parse still blocks" 2 $?
  # Not grep -q: under pipefail its early exit fails the pipeline and reads as a missing locale.
  if locale -a 2>/dev/null | grep -x 'ja_JP.SJIS' >/dev/null; then
    jq -n --arg c "$(printf 'echo pad\\x %s\n\304\201\\\nop read op://v/i/f' "$(printf 'y%.0s' {1..600})")" --arg s "$SESSION_ID" \
      '{session_id:$s, tool_input:{command:$c}}' >"$WORK/sjis.json"
    PATH="$WORK/bash32:$PATH" LC_ALL=ja_JP.SJIS /bin/bash "$COPY/scripts/bash-secret-authority.sh" <"$WORK/sjis.json" >"$OUT" 2>"$ERR"
    assert_exit "in Shift-JIS a backslash that ends a character does not join the next line" 2 $?
  else
    echo "skipped: the Shift-JIS case needs the ja_JP.SJIS locale"
  fi
else
  echo "skipped: the posix-mode and Shift-JIS cases need a /bin/bash before 5"
fi

# Every stage was its own bash, so each read BASH_ENV: the authority once and the four stages once each.
printf 'printf x >>"%s"\n' "$WORK/bashenv.log" >"$WORK/bashenv.sh"
printf '{"tool_input":{"command":"ls"},"session_id":"%s"}' "$SESSION_ID" | BASH_ENV="$WORK/bashenv.sh" "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a plain command passes with BASH_ENV set" 0 $?
if [ "$(cat "$WORK/bashenv.log")" = "xxxxx" ]; then ok; else bad "BASH_ENV was read $(wc -c <"$WORK/bashenv.log" | tr -d ' ') times, not once by the authority and once per stage"; fi
# A missing stage file was bash's own 127, and a missing payload helper must not cost the stages their payload.
STAGE_GONE=$(plugin_copy stage-gone)
rm "$STAGE_GONE/scripts/write-secret-guard-bash.sh"
printf '{"tool_input":{"command":"ls"},"session_id":"%s"}' "$SESSION_ID" | "$STAGE_GONE/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a missing stage file exits as bash does" 127 $?
HELPER_GONE=$(plugin_copy helper-gone)
rm "$HELPER_GONE/scripts/hook-payload.sh"
printf '{"tool_input":{"command":"ls"},"session_id":"%s"}' "$SESSION_ID" | "$HELPER_GONE/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "without hook-payload.sh a plain command still passes" 0 $?
printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" | "$HELPER_GONE/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "without hook-payload.sh a raw op read still blocks" 2 $?
# In posix mode a . that cannot open its file exits the shell before any stage runs.
printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" | POSIXLY_CORRECT=1 "$HELPER_GONE/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "in posix mode without hook-payload.sh a raw op read still blocks" 2 $?
printf '{"tool_input":{"command":"op read op://v/i/f"},"hook_event_name":"PostToolUse","session_id":"%s"}' "$SESSION_ID" | POSIXLY_CORRECT=1 "$HELPER_GONE/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "in posix mode without hook-payload.sh the PostToolUse guard still exits 0" 0 $?
# A sourced stage runs one function level deeper, inside sg_stage.
printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" | FUNCNEST=1 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "under FUNCNEST=1 a raw op read still blocks" 2 $?
printf '{"tool_input":{"command":"cat /a/.env"},"session_id":"%s"}' "$SESSION_ID" | FUNCNEST=2 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "under FUNCNEST=2 a reader still exits 0" 0 $?
if grep -qF '"ask"' "$OUT"; then ok; else bad "under FUNCNEST=2 a reader no longer asks"; fi
# Under FUNCNEST=1 the reader's own nesting stops its scan partway, which must ask, as its check for a stopped inspection always did.
printf '{"tool_input":{"command":"cat /a/.env"},"session_id":"%s"}' "$SESSION_ID" | FUNCNEST=1 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "under FUNCNEST=1 a reader still exits 0" 0 $?
if grep -qF '"ask"' "$OUT"; then ok; else bad "under FUNCNEST=1 a reader no longer asks"; fi
# Bash reads a FUNCNEST with blanks or a plus sign as the number, so the level a stage adds is given back for those too.
for fn in ' 1' '1 ' '+1'; do
  printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" | FUNCNEST=$fn "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "under FUNCNEST='$fn' a raw op read still blocks" 2 $?
  assert_err_has "under FUNCNEST='$fn' the block is the op read check's own" "raw 'op read'"
done
printf '{"tool_input":{"command":"cat /a/.env"},"session_id":"%s"}' "$SESSION_ID" | FUNCNEST=00 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
if grep -qF '"ask"' "$OUT"; then ok; else bad "under FUNCNEST=00 a reader no longer asks"; fi
assert_err_lacks "FUNCNEST=00 stays no limit, as bash reads it" "nesting level"
# A shell error partway through a stage ends it, and every route must then refuse: an exit 1 reaches Claude Code as an allow.
for stage in secret-mask-guard_1 secret-mask-guard_2 write-secret-guard-bash op-read-guard read-secret-guard-bash; do
  BROKEN=$(plugin_copy "abort-$stage")
  fn=sg_${stage//-/_}; file=${stage%_[12]}.sh
  perl -0pi -e "s/^(${fn}\\(\\) \\{[^\\n]*\\n)/\$1: \\\$((1\\/0))\\n/m" "$BROKEN/scripts/$file"
  # shellcheck disable=SC2016  # the injected line, matched as text
  if grep -q '^: \$((1/0))$' "$BROKEN/scripts/$file"; then ok; else bad "the abort was not injected into $stage"; fi
  for route in one-jq own-bash direct; do
    payload=$(jq -nc --arg s "$SESSION_ID" '{session_id:$s, hook_event_name:"PreToolUse", tool_name:"Bash", tool_input:{command:"cat notes.txt"}}')
    case $route in
      one-jq) printf '%s' "$payload" | "$BROKEN/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR" ;;
      own-bash) printf '%s' "$payload" | BASH_ENV=/dev/null "$BROKEN/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR" ;;
      direct) printf '%s' "$payload" | bash "$BROKEN/scripts/$file" >"$OUT" 2>"$ERR" ;;
    esac
    rc=$?
    if [ "$stage" = read-secret-guard-bash ]; then
      if [ "$rc" -eq 0 ] && grep -qF '"ask"' "$OUT"; then ok; else bad "an aborted reader did not ask on the $route route (exit $rc)"; fi
    else
      assert_exit "an aborted $stage blocks on the $route route" 2 "$rc"
      assert_err_has "an aborted $stage says it stopped partway on the $route route" "stopped partway"
    fi
  done
done
# The read builtin honors an inherited TMOUT, which $(cat) never did.
{ printf '{"tool_input":{"command":'; sleep 2; printf '"ls"},"session_id":"%s"}' "$SESSION_ID"; } | TMOUT=1 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_exit "a payload paused longer than an inherited TMOUT is still read whole" 0 $?
# Under nocasematch the memo would hand a script body equal to the command up to case the command's normalization.
mkdir -p "$WORK/nocase/sub"
printf 'SH SUB/S.SH # op read\n' >"$WORK/nocase/sub/s.sh"
(cd "$WORK/nocase" && printf '{"tool_input":{"command":"sh sub/s.sh # OP READ"},"session_id":"%s","cwd":"%s"}' "$SESSION_ID" "$WORK/nocase" | env BASHOPTS=nocasematch "$COPY/scripts/bash-secret-authority.sh") >"$OUT" 2>"$ERR"
assert_exit "under nocasematch a script that runs op read still blocks" 2 $?
# Under an invalid locale every restore of LC_ALL warns from the script's own line, which 0.6.15 never did here; bash 3.2 never warns, so a control restore must warn first.
mkdir -p "$WORK/locale-ctl/scripts"
printf 'f() { local LC_ALL=C; :; }\nf\n' >"$WORK/locale-ctl/scripts/restore.sh"
if LC_ALL=xx_YY.UTF-8 bash "$WORK/locale-ctl/scripts/restore.sh" 2>&1 | grep -E 'scripts/[^ ]*\.sh: line [0-9]+: warning: setlocale' >/dev/null; then
  for cmd in 'ls -la /tmp' 'op read op://v/i/f'; do
    printf '{"tool_input":{"command":"%s"},"session_id":"%s"}' "$cmd" "$SESSION_ID" | LC_ALL=xx_YY.UTF-8 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
    if grep -qE 'scripts/[^ ]*\.sh: line [0-9]+: warning: setlocale' "$ERR"; then bad "under an invalid LC_ALL a stage restored the locale on '$cmd': $(grep -m1 -E 'scripts/[^ ]*\.sh: line [0-9]+: warning: setlocale' "$ERR")"; else ok; fi
  done
  # Under lastpipe a pipeline's last command runs in the shell, which restores a LC_ALL=C on it; env, as BASHOPTS is readonly here and a prefix assignment fails.
  for cmd in 'echo a\necho b' 'ls -la /tmp' 'cat /a/.env'; do
    printf '{"tool_input":{"command":"%s"},"session_id":"%s"}' "$cmd" "$SESSION_ID" | env BASHOPTS=lastpipe LC_ALL=xx_YY.UTF-8 "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
    if grep -qE 'scripts/[^ ]*\.sh: line [0-9]+: warning: setlocale' "$ERR"; then bad "under lastpipe and an invalid LC_ALL a stage restored the locale on '$cmd': $(grep -m1 -E 'scripts/[^ ]*\.sh: line [0-9]+: warning: setlocale' "$ERR")"; else ok; fi
  done
else
  echo "skipped: the invalid-locale cases need a bash on PATH that warns when it restores an invalid locale (bash 5)"
fi
# With LC_ALL and LANG empty a forked stage's locale restore crashes bash 5, too rarely to catch by running; safe: C in a subshell or exported in $(…), a named-locale restore.
locale_unsafe() {
  # The preamble's locale line sets C once and never restores it, so only that exact line is admitted.
  SG_PREAMBLE_LOCALE=$(sed -n 6p "$PLUGIN_ROOT/scripts/bash-secret-authority.sh") awk 'BEGIN { pre = ENVIRON["SG_PREAMBLE_LOCALE"] }
    /^[[:space:]]*#/ || $0 == pre { prev = $0; next }
    {
      l = $0
      gsub(/\([[:space:]]*(export )?LC_ALL=C;/, "(", l)
      gsub(/\|\|/, "OR", l)
      if (l ~ /(^|[^A-Za-z_])(local|declare|typeset|unset|read|printf[[:space:]]+-v)[[:space:]][^;&|]*(LC_[A-Z]+|LANG)([^A-Za-z_]|$)/ ||
          (l ~ /(^|[^A-Za-z_])(LC_[A-Z]+|LANG)\+?=/ && prev !~ /\[ -n "\$\{LC_ALL:-\}\$\{LANG:-\}" \]/)) print FILENAME ":" FNR
      prev = $0
    }' "$@"
}
# shellcheck disable=SC2016  # a sample script for the lint, never expanded
printf '%s\n' '  x || LC_ALL=C tr a b <f' '  local LC_ALL=C' '  unset LC_ALL' '  local x LC_ALL' '  printf a | LC_ALL=C read v' \
  '  printf a | LC_ALL=C some_function' '  ( LC_ALL=C; y ); LANG=C z' '  printf -v LC_ALL %s C' '  read -r LANG <f' '  y=$(printf a | LC_ALL=C tr a b)' '  ( LC_ALL=C; [[ a =~ b ]] )' \
  '  (export LC_ALL=C; tr -d x) <f' '  case ${LC_ALL:-C} in C) ;; esac' "$(sed -n 6p "$PLUGIN_ROOT/scripts/bash-secret-authority.sh")" '_sg_mb=x; LC_ALL=C' >"$WORK/locale-unsafe.sh"
flagged=$(locale_unsafe "$WORK/locale-unsafe.sh" | sed 's/.*://' | tr '\n' ' ')
if [ "$flagged" = "1 2 3 4 5 6 7 8 9 10 15 " ]; then ok; else bad "control: the locale lint flags lines '$flagged' of the sample, not exactly its unsafe lines 1-10 and 15"; fi
unsafe=$(locale_unsafe "$PLUGIN_ROOT"/scripts/*.sh)
if [ -z "$unsafe" ]; then ok; else bad "a locale assignment a forked stage would restore: $unsafe"; fi
# With no locale the brace file's tr runs by exec, a fork fewer on bash 3.2; only a missing tr shows it, in an error that names exec.
mkdir -p "$WORK/notr"
for tool in bash jq mktemp grep sed cat rm head awk perl dirname wc; do ln -s "$(command -v "$tool")" "$WORK/notr/$tool"; done
printf '{"tool_input":{"command":"cat /a/{x,b}"},"session_id":"%s"}' "$SESSION_ID" | env -u LC_ALL -u LANG PATH="$WORK/notr" "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
assert_err_has "with no locale and no tr, the brace file's tr was run by exec" "exec: tr: not found"
# macOS EUC decoders take a quote as a character's second byte, so an eval of jq's quoting emptied every stage's command and ran a cwd's $(…).
EUC_CHAR=$'\xe6\x97\xa5'
if locale -a 2>/dev/null | grep -x 'ja_JP.eucJP' >/dev/null; then
  EUC_RUN=(env LC_ALL=ja_JP.eucJP CLAUDE_CODE_SESSION_ID="$SESSION_ID-euc")
  jq -n --arg c "op read op://v/i/f # $EUC_CHAR" '{tool_input:{command:$c}}' | "${EUC_RUN[@]}" "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "under eucJP a raw op read ending in a CJK character still blocks" 2 $?
  jq -n --arg c "cat /a/.env # $EUC_CHAR" '{tool_input:{command:$c}}' | "${EUC_RUN[@]}" "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "under eucJP a reader ending in a CJK character exits 0" 0 $?
  if grep -qF '"ask"' "$OUT"; then ok; else bad "under eucJP a reader ending in a CJK character no longer asks"; fi
  # A cwd alone breaks it, and sed in 0.6.15 rejects a command ending in a lone EUC lead byte, so these keep the command ASCII.
  jq -n --arg w "/tmp/d$EUC_CHAR" '{tool_input:{command:"op read op://v/i/f"}, cwd:$w}' | "${EUC_RUN[@]}" "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "under eucJP a raw op read from a cwd ending in a CJK character still blocks" 2 $?
  EUC_ITEM="eucprobe$$"
  jq -n --arg c "op item get $EUC_ITEM --fields password" --arg w "/tmp/d$EUC_CHAR" '{tool_input:{command:$c}, hook_event_name:"PostToolUse", cwd:$w}' \
    | "${EUC_RUN[@]}" "$COPY/scripts/op-read-guard.sh" >"$OUT" 2>"$ERR"
  assert_exit "under eucJP the PostToolUse guard exits 0" 0 $?
  if grep -lF "$EUC_ITEM" "/tmp/claude-op-reads-$SESSION_ID-euc"* >/dev/null 2>&1; then ok; else bad "under eucJP the PostToolUse guard did not record an item get from a cwd ending in a CJK character"; fi
  mkdir -p "$WORK/euc"
  for hook in bash-secret-authority.sh:PreToolUse op-read-guard.sh:PostToolUse; do
    rm -f "$WORK/euc/ran"
    jq -n --arg c "ls $EUC_CHAR" --arg w "$WORK/euc/\$(touch $WORK/euc/ran)$EUC_CHAR" --arg e "${hook#*:}" '{tool_input:{command:$c}, hook_event_name:$e, cwd:$w}' \
      | "${EUC_RUN[@]}" "$COPY/scripts/${hook%%:*}" >"$OUT" 2>"$ERR"
    if [ -e "$WORK/euc/ran" ]; then bad "under eucJP ${hook%%:*} ran text from the payload's cwd"; else ok; fi
  done
else
  echo "skipped: the EUC cases need the ja_JP.eucJP locale"
fi
# The one-jq parse is for UTF-8 and one-character-per-byte locales; Big5 counts — as three yet joins high bytes, like glibc's EUC-TW, which takes a quote as a later byte.
cat >"$WORK/parse.sh" <<'EOF'
. "$1"; SGA_INPUT='{"tool_input":{"command":"ls"},"session_id":"s"}'; sg_parse_payload 2>/dev/null; echo $?
EOF
for spec in C:0 en_US.UTF-8:0 en_US.ISO8859-1:0 zh_TW.Big5:1 ja_JP.eucJP:1 ja_JP.SJIS:1; do
  if locale -a 2>/dev/null | grep -x "${spec%:*}" >/dev/null; then
    got=$(env -u LANG -u LC_CTYPE LC_ALL="${spec%:*}" "$BASH" "$WORK/parse.sh" "$PLUGIN_ROOT/scripts/hook-payload.sh")
    if [ "$got" = "${spec##*:}" ]; then ok; else bad "under ${spec%:*} the one-jq parse returned '$got', not ${spec##*:}"; fi
  else
    echo "skipped: the parse-route case under ${spec%:*} needs a locale by that name"
  fi
done
# With LC_ALL and LANG empty the brace file's tr must still read bytes, or a Shift-JIS lead byte at a word's end stops it with an error.
if locale -a 2>/dev/null | grep -x 'ja_JP.SJIS' >/dev/null; then
  jq -n --arg c $'cat \xc4\x81{a,b}\xc4\x81' --arg s "$SESSION_ID" '{session_id:$s, tool_input:{command:$c}}' \
    | env -u LC_ALL -u LANG LC_CTYPE=ja_JP.SJIS "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  assert_exit "under LC_CTYPE=ja_JP.SJIS a brace word ending in a lead byte passes" 0 $?
  assert_err_lacks "under LC_CTYPE=ja_JP.SJIS the brace file's tr reads bytes" "Illegal byte sequence"
else
  echo "skipped: the Shift-JIS brace-file case needs the ja_JP.SJIS locale"
fi

echo "=== Inherited options and locales ==="
COPY=$(plugin_copy inherited)
DASH=$'\xe2\x80\x94'
run_hook() {  # run_hook <script> <payload> [env argument...]
  local script=$1 payload=$2
  shift 2
  printf '%s' "$payload" | env "$@" "$COPY/scripts/$script" >"$OUT" 2>"$ERR"
}
bash_payload() { jq -nc --arg c "$1" --arg s "$SESSION_ID" '{session_id:$s, hook_event_name:"PreToolUse", tool_input:{command:$c}}'; }
asked() { if [ "$2" -eq 0 ] && grep -qF '"ask"' "$OUT"; then ok; else bad "$1 — expected an ask, got exit $2: $(head -c 160 "$ERR")"; fi; }
quiet() { if [ "$2" -eq 0 ] && [ ! -s "$OUT" ]; then ok; else bad "$1 — expected a silent pass, got exit $2: $(head -c 160 "$OUT")"; fi; }
# Every hook the plugin wires, one known verdict each; <prefix> puts a non-ASCII character before the guarded text.
check_hooks() {  # check_hooks <label> <prefix> [env argument...]
  local label=$1 pre=$2 cmd
  shift 2
  run_hook bash-secret-authority.sh "$(bash_payload "${pre}op read op://v/i/f")" "$@"
  assert_exit "$label: a raw op read blocks" 2 $?
  for cmd in 'cat /a/.env' 'cat ~/.ssh/id_rsa' 'cat /a/{1..100}.env'; do
    run_hook bash-secret-authority.sh "$(bash_payload "$pre$cmd")" "$@"
    asked "$label: '$cmd' asks" $?
  done
  run_hook bash-secret-authority.sh "$(bash_payload "${pre}echo $FRESH > /tmp/fixture-probe")" "$@"
  assert_exit "$label: writing a key from Bash blocks" 2 $?
  run_hook bash-secret-authority.sh "$(bash_payload "ls -la /tmp")" "$@"
  quiet "$label: a plain command passes" $?
  run_hook read-secret-guard.sh "$(jq -nc --arg p "/a/$DASH/.kube/config" '{tool_name:"Read", tool_input:{file_path:$p}}')" "$@"
  asked "$label: the Read hook asks for a kubeconfig" $?
  run_hook write-secret-guard.sh "$(jq -nc --arg c "$pre$FRESH" '{tool_name:"Write", tool_input:{file_path:"/tmp/fixture-probe", content:$c}}')" "$@"
  assert_exit "$label: the Write hook blocks a key" 2 $?
  run_hook paste-secret-guard.sh "$(jq -nc --arg c "$pre$FRESH" '{prompt:$c}')" "$@"
  if grep -qF '"block"' "$OUT"; then ok; else bad "$label: the prompt hook no longer blocks a pasted key"; fi
  mkdir -p "/tmp/op-cache-$SESSION_ID-inherited"
  run_hook op-cache-cleanup.sh "$(jq -nc --arg s "$SESSION_ID-inherited" '{session_id:$s}')" "$@"
  if [ -e "/tmp/op-cache-$SESSION_ID-inherited" ]; then rm -rf "/tmp/op-cache-$SESSION_ID-inherited"; bad "$label: the Stop hook left the session's cache behind"; else ok; fi
}
check_hooks "control" ""
check_hooks "control, UTF-8 with a non-ASCII character" "echo $DASH; " LC_ALL=en_US.UTF-8
# keyword moved every `local x=…` into the environment and noclobber kept the reader's token file empty; env, as SHELLOPTS is readonly here.
for opt in keyword noclobber; do
  check_hooks "under SHELLOPTS=$opt" "" SHELLOPTS=$opt
done
# A legacy decoder leaves UTF-8 undecoded, and grep then matches nothing on the line, so every guard passed it; each hook now matches in C there.
for loc in ja_JP.SJIS zh_CN.GBK zh_TW.Big5 zh_CN.GB18030 ja_JP.eucJP ko_KR.eucKR; do
  if locale -a 2>/dev/null | grep -x "$loc" >/dev/null; then
    check_hooks "under LC_ALL=$loc" "echo $DASH; " LC_ALL=$loc
  else
    echo "skipped: the $loc cases need a locale by that name"
  fi
done
if locale -a 2>/dev/null | grep -x 'ja_JP.SJIS' >/dev/null; then
  check_hooks "under LC_CTYPE=ja_JP.SJIS alone" "echo $DASH; " -u LC_ALL -u LANG LC_CTYPE=ja_JP.SJIS
  # The shell itself joins a \ after a non-ASCII byte to that character, so `—\ .env` names .env there and one word with a space in UTF-8.
  run_hook bash-secret-authority.sh "$(bash_payload "cat $DASH\\ .env")" LC_ALL=ja_JP.SJIS
  asked "under Shift-JIS a backslash after a non-ASCII character asks" $?
  if grep -qF 'under this locale the shell can read' "$OUT"; then ok; else bad "under Shift-JIS the backslash ask lost its reason: $(head -c 160 "$OUT")"; fi
  run_hook bash-secret-authority.sh "$(bash_payload "cat $DASH| tr a b")" LC_ALL=ja_JP.SJIS
  asked "under Shift-JIS a pipe after a non-ASCII character asks" $?
else
  echo "skipped: the LC_CTYPE and joined-byte cases need the ja_JP.SJIS locale"
fi
run_hook bash-secret-authority.sh "$(bash_payload "cat $DASH\\ .env")" LC_ALL=en_US.UTF-8
quiet "control: in UTF-8 a backslash after a non-ASCII character is an escape" $?
# The oracle is the shell itself: wherever bash splits `<char>\ .env` into two words, the reader must ask.
printf "printf '[%%s]' %s\\\\ .env\n" $'\xe6\x97\xa5' >"$WORK/joined.sh"
for loc in ja_JP.SJIS zh_CN.GBK zh_TW.Big5 zh_CN.GB18030 ja_JP.eucJP ko_KR.eucKR en_US.UTF-8; do
  locale -a 2>/dev/null | grep -x "$loc" >/dev/null || continue
  split=$(LC_ALL=$loc bash "$WORK/joined.sh" 2>/dev/null | grep -c '\]\[')
  run_hook bash-secret-authority.sh "$(bash_payload "cat "$'\xe6\x97\xa5'"\\ .env")" LC_ALL=$loc
  rc=$?
  # Asking where the shell keeps the escape only costs a prompt, so outside UTF-8 a pass is not required.
  if [ "$split" -eq 1 ]; then asked "under $loc, where bash splits a backslash off a character, the reader asks" $rc
  elif [ "$loc" = en_US.UTF-8 ]; then quiet "control: under $loc bash keeps the escape and the reader passes" $rc; fi
done
# Wherever bash joins the quote after 日 and runs what the guard reads as quoted text, that command must not pass silently.
printf '%s\n' "printf '[%s]' "$'\xe6\x97\xa5'"'; echo R\"\"AN; #'" >"$WORK/joined-quote.sh"
# Built outside $(…): bash 3.2 misparses a $'…' beside braces inside a double-quoted substitution.
JOINED_QUOTE=$(bash_payload "echo "$'\xe6\x97\xa5'"'; cat .env; #'")
JOINED_BRACE=$(bash_payload "cat {.env,a$DASH}x}")
for loc in ja_JP.SJIS zh_CN.GBK zh_TW.Big5 zh_CN.GB18030 ja_JP.eucJP ko_KR.eucKR en_US.UTF-8; do
  locale -a 2>/dev/null | grep -x "$loc" >/dev/null || continue
  ran=$(LC_ALL=$loc bash "$WORK/joined-quote.sh" 2>/dev/null | grep -c RAN)
  run_hook bash-secret-authority.sh "$JOINED_QUOTE" LC_ALL=$loc
  rc=$?
  if [ "$ran" -eq 1 ]; then asked "under $loc, where bash joins the quote and runs the rest, the command asks" $rc
  elif [ "$loc" = en_US.UTF-8 ]; then quiet "control: under $loc the quote opens and the rest is text" $rc; fi
done
if locale -a 2>/dev/null | grep -x 'ja_JP.SJIS' >/dev/null; then
  run_hook bash-secret-authority.sh "$JOINED_BRACE" LC_ALL=ja_JP.SJIS
  asked "under Shift-JIS a close brace joined to a character asks" $?
fi
if locale -a 2>/dev/null | grep -x 'ja_JP.eucJP' >/dev/null; then
  # The reader's own `…` once took its closing quote under EUC, so every reader command asked that the inspection stopped partway.
  run_hook bash-secret-authority.sh "$(bash_payload 'cat notes.txt')" LC_ALL=ja_JP.eucJP
  quiet "under eucJP a plain read passes" $?
  run_hook bash-secret-authority.sh "$(bash_payload "cat /a/$(printf 'x%.0s' {1..210})/.env")" LC_ALL=ja_JP.eucJP
  asked "under eucJP a long secret path asks" $?
  if grep -qF 'flagged' "$OUT"; then ok; else bad "under eucJP a long secret path asked for the wrong reason: $(head -c 160 "$OUT")"; fi
else
  echo "skipped: the EUC controls need the ja_JP.eucJP locale"
fi
# A PATH without one tool: grep's absence read as "no match" everywhere, basename's emptied the Read hook's file name, and tr's the brace fallback's word.
without() {  # without <tool>: prints a PATH directory holding every tool the hooks run except <tool>
  local dir="$WORK/without-$1" t
  mkdir -p "$dir"
  for t in bash env jq mktemp grep sed cat rm head tail awk perl dirname basename wc tr date mkdir chmod find sort cut uniq xargs; do
    [ "$t" = "$1" ] || ln -sf "$(command -v "$t")" "$dir/$t"
  done
  printf '%s' "$dir"
}
NO_GREP=$(without grep)
for hook in bash-secret-authority.sh:"$(bash_payload 'ls -la /tmp')" read-secret-guard.sh:'{"tool_name":"Read","tool_input":{"file_path":"/a/notes.txt"}}' \
            write-secret-guard.sh:'{"tool_name":"Write","tool_input":{"file_path":"/tmp/x","content":"hello"}}' paste-secret-guard.sh:'{"prompt":"hello"}'; do
  printf '%s' "${hook#*:}" | PATH="$NO_GREP" "$NO_GREP/bash" "$COPY/scripts/${hook%%:*}" >"$OUT" 2>"$ERR"
  assert_exit "without grep ${hook%%:*} blocks" 2 $?
  assert_err_has "without grep ${hook%%:*} names grep" "grep is not on PATH"
done
NO_BASENAME=$(without basename)
for path in /a/.env /a/.env/ /a/id_rsa; do
  jq -nc --arg p "$path" '{tool_name:"Read", tool_input:{file_path:$p}}' | PATH="$NO_BASENAME" "$NO_BASENAME/bash" "$COPY/scripts/read-secret-guard.sh" >"$OUT" 2>"$ERR"
  asked "without basename the Read hook asks for $path" $?
done
NO_TR=$(without tr)
for cmd in 'cat /a/{1..100}.env' 'cat /a/{.env,b}'; do
  bash_payload "$cmd" | PATH="$NO_TR" "$NO_TR/bash" "$COPY/scripts/bash-secret-authority.sh" >"$OUT" 2>"$ERR"
  asked "without tr '$cmd' asks" $?
done
# Every hook and Bash stage opens with the same preamble, before any line bash would parse under the inherited state.
PREAMBLE=$(sed -n '3,6p' "$PLUGIN_ROOT/scripts/bash-secret-authority.sh")
case $PREAMBLE in *'set +o keyword +o noclobber'*'export LC_ALL SG_ASCII_TRAIL'*) ok ;; *) bad "control: the authority's preamble is not where this check reads it" ;; esac
for script in $(jq -r '.. | .command? // empty' "$PLUGIN_ROOT/hooks/hooks.json" | sed 's#.*/scripts/##') \
              $(sed -n 's/.*sg_stage \([a-z-]*\.sh\).*/\1/p' "$PLUGIN_ROOT/scripts/bash-secret-authority.sh"); do
  checked=$((${checked:-0} + 1))
  if [ "$(sed -n '3,6p' "$PLUGIN_ROOT/scripts/$script")" = "$PREAMBLE" ]; then ok; else bad "$script does not open with the shared preamble"; fi
  if sed -n '1,2p' "$PLUGIN_ROOT/scripts/$script" | grep -qv '^#'; then bad "$script runs a line before its preamble"; else ok; fi
done
# Six wired hooks and four stages, op-read-guard.sh in both lists.
if [ "${checked:-0}" -eq 10 ]; then ok; else bad "control: the preamble check read ${checked:-0} scripts, not the 6 hooks and 4 stages"; fi

echo "=== Normalization memo and gates ==="
# shellcheck source-path=SCRIPTDIR/../scripts
. "$PLUGIN_ROOT/scripts/strip-cmd.sh"
for text in $'op "read" x\n\n' 'o\p read' "\$'op' read" ''; do
  fresh=$(normalize_cmd "$text"; printf x)
  normalize_cmd_prime "$text"
  primed=$(normalize_cmd "$text"; printf x)
  if [ "$fresh" = "$primed" ]; then ok; else bad "a primed normalization of $(printf %q "$text") differs from a fresh one"; fi
  other=$(normalize_cmd "$text \"y\""; printf x)
  if [ "$other" = "$(SG_NC_PRIMED='' normalize_cmd "$text \"y\""; printf x)" ]; then ok; else bad "priming $(printf %q "$text") changed another text's normalization"; fi
done
unset SG_NC_PRIMED
# On the authority's route the quote unwrap runs by builtin; it must yield the sed's bytes, run no sed within its budget, and hand anything past it to the sed.
mkdir -p "$WORK/sed-log"
printf '#!/bin/sh\n: >>"%s/sed-ran"\nexec "%s" "$@"\n' "$WORK" "$(command -v sed)" >"$WORK/sed-log/sed"; chmod +x "$WORK/sed-log/sed"
UNQ_IN=('a"b"c' '$"x"' "\$'y'" '"a b"c"' '""' "''" $'a\n""' '$$"a"' '"a"b"' "'it''s'" $'x "y\tz" w' $'"a\nb"' "o\"p\" \$'read' x")
UNQ_OVER=("$(printf '"q"%.0s' {1..70})" "$(printf 'y%.0s' {1..2100})\"z\"" $'\xc3\xa9"x"')
unq_check() {  # unq_check <expect sed: 0|1> <text>
  rm -f "$WORK/sed-ran"
  local want got
  want=$(normalize_cmd "$2"; printf x)
  got=$(SGA_PREPARSED=1 PATH="$WORK/sed-log:$PATH" normalize_cmd "$2"; printf x)
  if [ "$got" = "$want" ]; then ok; else bad "the builtin unwrap of $(printf %q "${2:0:60}") differs from the sed's"; fi
  if [ -e "$WORK/sed-ran" ]; then ran=1; else ran=0; fi
  if [ "$ran" = "$1" ]; then ok; else bad "on the route sed ran=$ran for $(printf %q "${2:0:60}"), expected $1"; fi
}
for text in "${UNQ_IN[@]}"; do unq_check 0 "$text"; done
for text in "${UNQ_OVER[@]}"; do unq_check 1 "$text"; done
# Every respelling normalize_cmd undoes must still open the gate, or a predicate behind it goes blind to that spelling.
GATE_OPEN=('op' 'o"p"' "o'p'" 'o\p' $'o\\\np' "o\$'p'" 'o$"p"' $'\xc3\xa9op' $'\xffop' $'op\xff' $'\x83op')
GATE_SHUT=('o p' 'oxp' 'ls -la /tmp' $'\xc3\xa9xp' $'\xff oxp')
for text in "${GATE_OPEN[@]}"; do
  case "$(normalize_cmd "$text")" in *op*) ;; *) bad "control: $(printf %q "$text") does not normalize to op" ;; esac
done
GATE_WANT=$(printf '1%.0s' "${GATE_OPEN[@]}"; printf '0%.0s' "${GATE_SHUT[@]}")
cat >"$WORK/gate.sh" <<'EOF'
. "$1"; shift; norm_may_re G op
c=$'\x83op'; [[ $c =~ $G ]] && printf 1 || printf 0
for t in "$@"; do norm_may_hold "$t" "$G" && printf 1 || printf 0; done
EOF
# A bare =~ passes every case in C, so they are pinned where it fails; the first digit is 1 where =~ matches \x83op in place: C (bash 3.2's fallback for a missing locale) or glibc.
for loc in none en_US.UTF-8 C.UTF-8 ja_JP.SJIS; do
  if [ "$loc" = none ]; then run=(env -u LC_ALL -u LANG -u LC_CTYPE); else run=(env -u LANG -u LC_CTYPE "LC_ALL=$loc"); fi
  got=$("${run[@]}" "$BASH" "$WORK/gate.sh" "$PLUGIN_ROOT/scripts/strip-cmd.sh" "${GATE_OPEN[@]}" "${GATE_SHUT[@]}" 2>/dev/null)
  case $loc:$got in
    none:?* | *:0*) if [ "${got#?}" = "$GATE_WANT" ]; then ok; else bad "under $loc the gate answers ${got#?} for $(printf '%q ' "${GATE_OPEN[@]}" "${GATE_SHUT[@]}"), not the C locale's $GATE_WANT"; fi ;;
    *:1*) printf 'skipped: the gate cases under %s need =~ to fail on \\x83op, and here it matches (the locale is missing, or this libc matches it)\n' "$loc" ;;
    *) bad "the gate check under $loc printed nothing" ;;
  esac
done
# Before bash 5 a long text holding a backslash goes through perl and tr; failing stubs force the builtin route, and the two must yield the same bytes.
mkdir -p "$WORK/perl-shim" "$WORK/perl-tr-stub"
printf '#!/bin/sh\n: >>"%s/perl-ran"\nexec "%s" "$@"\n' "$WORK" "$(command -v perl)" >"$WORK/perl-shim/perl"
printf '#!/bin/sh\nexit 1\n' >"$WORK/perl-tr-stub/perl"
cp "$WORK/perl-tr-stub/perl" "$WORK/perl-tr-stub/tr"
chmod +x "$WORK/perl-shim/perl" "$WORK/perl-tr-stub/perl" "$WORK/perl-tr-stub/tr"
LONG_CONT=$(printf 'x "y" \\\n%.0s' {1..150}; printf x); LONG_CONT=${LONG_CONT%x}
LONG_BS=$(printf '\\%.0s' {1..600}; printf '\n\\\n\n'; printf x); LONG_BS=${LONG_BS%x}
LONG_MB=$(printf '\303\251\\\n\303\\\n\251 $"a" %.0s' {1..80}; printf '\n\134'; printf x); LONG_MB=${LONG_MB%x}
for text in "$LONG_CONT" "$LONG_BS" "$LONG_MB"; do
  routed=$(PATH="$WORK/perl-shim:$PATH" normalize_cmd "$text"; printf x)
  builtin=$(PATH="$WORK/perl-tr-stub:$PATH" normalize_cmd "$text"; printf x)
  if [ "$routed" = "$builtin" ]; then ok; else bad "the perl/tr route normalizes a ${#text}-character text differently from the builtin one"; fi
done
if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
  if [ -e "$WORK/perl-ran" ]; then ok; else bad "control: perl never ran, so the comparison above checked the builtin route against itself"; fi
elif [ -e "$WORK/perl-ran" ]; then bad "bash $BASH_VERSION took the perl route, which only bash before 5 needs"; else ok; fi
# Bash 3.2 spent over a minute stripping these 800 continuations, past the hook's 30 s timeout, and a hook killed at its timeout lets the command run unchecked.
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'echo "${BASH_VERSINFO[0]}"')" -lt 5 ]; then
  jq -n --arg c "$(printf 'echo "line %s" \\\n' {1..800})" --arg s "$SESSION_ID" '{session_id:$s, tool_input:{command:$c}}' >"$WORK/cont.json"
  SECONDS=0
  /bin/bash "$COPY/scripts/bash-secret-authority.sh" <"$WORK/cont.json" >"$OUT" 2>"$ERR"
  assert_exit "800 continuations under /bin/bash pass" 0 $?
  if [ "$SECONDS" -le 10 ]; then ok; else bad "800 continuations took ${SECONDS}s under /bin/bash $(/bin/bash -c 'echo "$BASH_VERSION"')"; fi
  # macOS's codeset-only LC_CTYPE=UTF-8 names no language and must take the same route.
  rm -f "$WORK/perl-ran"
  # shellcheck disable=SC2016  # expanded by the inner bash
  env -u LC_ALL -u LANG LC_CTYPE=UTF-8 PATH="$WORK/perl-shim:$PATH" /bin/bash -c '. "$1"; normalize_cmd "$2" >/dev/null' _ "$PLUGIN_ROOT/scripts/strip-cmd.sh" "$LONG_CONT"
  if [ -e "$WORK/perl-ran" ]; then ok; else bad "under LC_CTYPE=UTF-8 bash 3.2 skipped the perl route"; fi
else
  echo "skipped: the 800-continuation timing needs a /bin/bash before 5"
fi

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

echo "=== Builtin stand-ins match each stage's own route ==="

# BASH_ENV sends every stage through its own bash, parse, sed, grep and perl, so each case must come out byte for byte as on the one-jq route.
mkdir -p "$WORK/tool-log"
for tool in grep sed perl tr; do
  printf '#!/bin/sh\nprintf "%%s\\n" %s >>"%s/tool-log/ran"\nexec "%s" "$@"\n' "$tool" "$WORK" "$(command -v "$tool")" >"$WORK/tool-log/$tool"
  chmod +x "$WORK/tool-log/$tool"
done
route_pair() {  # route_pair <command>: sets ROUTE_TOOLS to the tools the one-jq route ran
  jq -n --arg c "$1" --arg s "$SESSION_ID" '{session_id:$s, tool_name:"Bash", tool_input:{command:$c}}' >"$WORK/route.json"
  rm -f "$WORK/tool-log/ran"
  PATH="$WORK/tool-log:$PATH" "$COPY/scripts/bash-secret-authority.sh" <"$WORK/route.json" >"$WORK/route1.out" 2>"$WORK/route1.err"; r1=$?
  ROUTE_TOOLS=$(sort -u "$WORK/tool-log/ran" 2>/dev/null | tr '\n' ' ')
  BASH_ENV=/dev/null "$COPY/scripts/bash-secret-authority.sh" <"$WORK/route.json" >"$WORK/route2.out" 2>"$WORK/route2.err"; r2=$?
  if [ "$r1" = "$r2" ] && cmp -s "$WORK/route1.out" "$WORK/route2.out" && cmp -s "$WORK/route1.err" "$WORK/route2.err"; then ok
  else bad "the one-jq route and the stages' own route differ on $(printf %q "$1"): exit $r1 vs $r2"; fi
}
# shellcheck disable=SC2016  # command text handed to the guard, never expanded here
ROUTE_CASES=('ls -la' 'git status' 'cat notes.txt | head -5' 'cat .env' 'cat .e"n"v' "cat .e'n'v" 'cat .e\nv' 'head ~/.s"s"h/config' 'tail -f ~/.kube/config'
  'cat ID_RSA' 'cat x.PEM' 'cat *.pem' 'cat .e?v' 'cat {.e,x}nv' 'cat .{d..f}nv' 'cat {a},.env}' 'cat .e{n,m}v' "awk '{print \$1}' notes.txt | head"
  "jq '{a:.b}' f.json | head" 'grep -rn token . 2>/dev/null' 'cat $(echo .env)' 'cat `echo k.pem`' 'cat .env;' 'cat k.pem|head' 'cat<.env' 'cat .e.n.v'
  $'cat <<\'EOF\' > f\nsee .env\nEOF' $'cat > f <<EOF\n$(cat .env)\nEOF' "printf '%s' $FRESH > /tmp/fixture-probe" "printf '%s' $LISTED > /tmp/fixture-probe"
  "echo $FRESH 2>&1" "echo $FRESH > f" $'echo a\necho b > f' "git commit -m \"$FRESH\"" "git tag -m \"x $FRESH\" v1" 'op read op://v/i/f' 'o"p" read op://v/i/f'
  'op item get x --reveal' $'cat \xc3\xa9 .env' "x\"y z\"w \$'q' cat .e\$'n'v" 'sed -i s/a/b/ f' 'curl -o f https://x' 'dd if=a of=b' $'echo a\nopen("f", "w")')
for c in "${ROUTE_CASES[@]}"; do route_pair "$c"; done
# Controls: without them the comparisons above could have run the same tools on both routes.
route_pair 'cat notes.txt | head -5'
if [ -z "$ROUTE_TOOLS" ]; then ok; else bad "a reader naming nothing secret still ran: $ROUTE_TOOLS"; fi
route_pair 'cat .e"n"v'
case " $ROUTE_TOOLS " in *" perl "*) ok ;; *) bad "a reader naming a quoted .env skipped the tokenizer: $ROUTE_TOOLS" ;; esac
route_pair "printf '%s' $FRESH > /tmp/fixture-probe"
case " $ROUTE_TOOLS " in *" grep "*) ok ;; *) bad "a write of a secret shape skipped its grep: $ROUTE_TOOLS" ;; esac
# Sourced by anything but the authority's loader, a stage file still runs, as it did before it held a function.
printf '{"tool_input":{"command":"op read op://v/i/f"},"session_id":"%s"}' "$SESSION_ID" | bash -c ". \"\$1\"" _ "$COPY/scripts/secret-mask-guard.sh" >"$OUT" 2>"$ERR"
assert_exit "a mask guard sourced by another script still blocks a raw op read" 2 $?

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
for guard in secret-mask-guard.sh read-secret-guard.sh read-secret-guard-bash.sh op-read-guard.sh bash-secret-authority.sh; do
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
