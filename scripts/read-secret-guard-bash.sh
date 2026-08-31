#!/usr/bin/env bash
# PreToolUse Bash hook, mirrors read-secret-guard.sh's basename gate for cat/head/tail/less/grep readers.

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "READ-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
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

# What the prompt can honestly say about a pattern that is never expanded for the verdict — an absolute glob has no cwd dependence, so naming its matches is reproducible where naming a relative one's would not be; see README § What an unresolved glob prompt says.
describe_glob() {
  local p="$1" hits n
  # shellcheck disable=SC2088  # the literal ~ is what tokenize hands over; expanding it is the point
  case "$p" in "~/"*) p="${HOME}/${p#\~/}" ;; esac
  case "$p" in
    /*) ;;
    *) printf "not expanded here, since this hook's working directory is not the command's"; return ;;
  esac
  # Names only, never contents: the contents are the thing this prompt exists to withhold.
  hits=$(compgen -G "$p" 2>/dev/null)
  [ -n "$hits" ] || { printf 'it matches nothing under that path right now, but expands when the command runs'; return; }
  n=$(printf '%s\n' "$hits" | grep -c .)
  printf 'it matches %s file(s): %s' "$n" "$(printf '%s\n' "$hits" | head -6 | sed 's@.*/@@' | tr '\n' ' ' | sed 's/ $//')"
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

# The exemption below is armed by a `find` TOKEN and disarmed by the next reader token, so it is live only inside the window where find's own grammar governs — see README § Why a negated find predicate is exempt.
RE_FIND_TOK='^([A-Za-z_][A-Za-z0-9_]*=)?\$?(.*/)?find$'
RE_READER_TOK='^(.*/)?(cat|head|tail|less|more|grep)$'
FIND_ACTIVE=""
PREV=""
PREV2=""
PREV3=""

while IFS= read -r -d '' token; do
  # A SINGLY negated find predicate whose operand is a WILDCARD can only SHRINK the set of files touched, so it is never a read target; a second negation makes it positive again and a literal operand is indistinguishable from a filename — see README § Why a negated find predicate is exempt.
  if [ -n "$FIND_ACTIVE" ] \
     && [[ $PREV =~ ^-(i?path|i?name|i?wholename|i?regex)$ ]] \
     && { [ "$PREV2" = "-not" ] || [ "$PREV2" = "!" ]; } \
     && [ "$PREV3" != "-not" ] && [ "$PREV3" != "!" ] \
     && [[ $token == *[*?]* ]]; then
    PREV3=$PREV2; PREV2=$PREV; PREV=$token
    continue
  fi
  if [[ $token =~ $RE_FIND_TOK ]]; then
    FIND_ACTIVE=1
  elif [[ $token =~ $RE_READER_TOK ]]; then
    FIND_ACTIVE=""
  fi
  PREV3=$PREV2; PREV2=$PREV; PREV=$token
  BASENAME=$(basename -- "$token" 2>/dev/null)
  # A glob is not expanded here, so judge the pattern by what it could match rather than by the cwd.
  if printf '%s' "$token" | grep -qE '[*?]' && { printf '%s' "$BASENAME" | grep -qE '^\.env|^[*?]+$' || printf '%s' "$token" | grep -qE '(^|/)\.ssh/'; }; then
    ask "READ-SECRET GUARD: $token is an unresolved glob that could match a secret file — $(describe_glob "$token"). Confirm before its contents enter context/transcript."
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
