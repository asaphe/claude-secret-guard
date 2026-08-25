#!/usr/bin/env bash
# PreToolUse Bash hook, mirrors read-secret-guard.sh's basename gate for cat/head/tail/less/grep readers.

INPUT=$(cat)
# Blocks rather than allows: jq failing here yields an empty command, which every check below reads as "nothing to inspect".
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "READ-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
[ -z "$CMD" ] && exit 0

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
GATE_CMD=$(strip_cmd "$CMD")
SCAN_CMD=$(strip_cmd "$CMD" long-flags-only)

# Normalized like the mask guard's verbs, or a quoted reader name (`"cat" secrets.pem`) splits into its own segment with no trailing space and matches nothing.
GATE_CMD=$(normalize_cmd "$GATE_CMD")

# A reader is a reader wherever it sits, so separators and wrappers must not anchor it away.
SEP=$';&|()`"\''
# Matched anywhere inside a segment rather than after a fixed wrapper list, which went silent on any prefix the list omitted (timeout, nice, stdbuf, ionice, doas). A leading / admits the same reader named by path, and grep carries no recursive-flag condition: -r decides how many files are read, never whether the one named is a key.
printf '%s' "$GATE_CMD" | tr "$SEP" '\n' | grep -qE '(^|[[:space:]]|/)(cat|head|tail|less|more|grep)([[:space:]<]|$)' \
  || exit 0

ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

# Shell-aware split: a quoted filename must lose its quotes before the basename patterns see it, and no token may be glob-expanded against the cwd.
tokenize() {
  printf '%s' "$1" | perl -0777 -e '
    no warnings;
    use Text::ParseWords qw(shellwords);
    my $cmd = do { local $/; <STDIN> };
    my @w = shellwords($cmd);
    # $'…' and substitution syntax survive tokenizing as punctuation glued to the filename.
    @w = map { my $t = $_; $t =~ s/^\$//; $t =~ s/[()`]//g; $t } @w;
    # A redirect glues its target to the reader, and the basename patterns are anchored: cat<.env is one token that matches nothing.
    @w = grep { length } map { split /[<>]+/, $_ } @w;
    # Unbalanced quotes yield nothing; fall back to a bare split so the guard still asks rather than going silent.
    @w = map { my $t = $_; $t =~ s/["\x27]//g; $t } ($cmd =~ /\S+/g) unless @w;
    print join("\0", @w), "\0" if @w;
  '
}

while IFS= read -r -d '' token; do
  BASENAME=$(basename -- "$token" 2>/dev/null)
  # A glob is not expanded here, so judge the pattern by what it could match rather than by the cwd.
  if printf '%s' "$token" | grep -qE '[*?]' && { printf '%s' "$BASENAME" | grep -qE '^\.env|^[*?]+$' || printf '%s' "$token" | grep -qE '(^|/)\.ssh/'; }; then
    ask "READ-SECRET GUARD: $token is an unresolved glob that could match a secret file — confirm before its contents enter context/transcript."
  fi
  if printf '%s' "$BASENAME" | grep -qE '^-*\.env(\..+)?$' && ! printf '%s' "$BASENAME" | grep -qE '^-*\.env\.(example|sample|template)$'; then
    ask "READ-SECRET GUARD: $BASENAME looks like a live env file — confirm before its contents enter context/transcript."
  fi
  if printf '%s' "$BASENAME" | grep -qE '\.(pem|key|p12|pfx)$' \
     || printf '%s' "$BASENAME" | grep -qE '^-*id_(rsa|ed25519|ecdsa|dsa)$' \
     || printf '%s' "$BASENAME" | grep -qE '^-*kubeconfig$' \
     || printf '%s' "$token" | grep -qE '\.kube/config$'; then
    ask "READ-SECRET GUARD: $BASENAME looks like a private key or kubeconfig — confirm before its contents enter context/transcript."
  fi
done < <(tokenize "$SCAN_CMD")

exit 0
