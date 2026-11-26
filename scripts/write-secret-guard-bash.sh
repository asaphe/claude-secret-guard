#!/usr/bin/env bash
# PreToolUse Bash-side counterpart to write-secret-guard.sh. Blocks a command that both writes to a file (redirect/heredoc/tee) and embeds a matching secret shape — narrower than "any command containing the pattern" to keep the same false-positive posture as the prompt guard.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
[ "${LC_ALL:-}" = C ] || unset SG_ASCII_TRAIL; _sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }
sg_write_secret_guard_bash() {  # One function, so the authority loads this file in its own process and no forked stage opens a script - see README § Process launches per call.
SGA_DIR=${BASH_SOURCE[0]%/*}; [ "$SGA_DIR" != "${BASH_SOURCE[0]}" ] || SGA_DIR=.
# shellcheck source-path=SCRIPTDIR
{ [ "${BASH_SOURCE[0]}" != "$0" ] && [[ ${SGA_HAVE-} == *" secret-shapes.sh "* ]]; } || source "$SGA_DIR/secret-shapes.sh"
# shellcheck source-path=SCRIPTDIR
{ [ "${BASH_SOURCE[0]}" != "$0" ] && [[ ${SGA_HAVE-} == *" strip-cmd.sh "* ]]; } || source "$SGA_DIR/strip-cmd.sh"
# An unset pattern makes grep match every byte, so the guard would block all content while looking like it found a secret in it.
[ -n "${SECRET_PATTERN:-}" ] || { echo "WRITE-SECRET GUARD: could not load scripts/secret-shapes.sh — blocking, because the guard has no shapes to check against." >&2; exit 2; }

if [ -n "${SGA_PREPARSED:-}" ]; then
  INPUT=$SGA_INPUT; CMD=$SGA_CMD
else
INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "WRITE-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is free of secret-shaped literals." >&2
  exit 2
fi
# Blocks rather than allows: an unparseable payload cannot be shown to be safe, and jq failing here would otherwise exit 0 on every call and disarm the guard silently.
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "WRITE-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is free of secret-shaped literals. Install jq, or disable the secret-guard plugin deliberately." >&2
  exit 2
fi
fi
[ -z "$CMD" ] && exit 0

# Both spellings are scanned as two lines rather than the normalized one alone: the raw line is where an escape is part of the secret's own boundary, and normalization widens most of these predicates but narrows the two that require a quote character, open('f','w') and git commit -m"…".
WRITE_SCAN=$(printf '%s\n%s' "$CMD" "$(normalize_cmd "$CMD")")

# A backslash quotes the delimiter exactly like '' or "", so <<\EOF is a heredoc the earlier quote-only form skipped.
W_HEREDOC='(^|[^<])<<[-~]?[[:space:]]*(\\|"|'"'"')?[A-Za-z_]'
W_TEE='\btee\b'
# Writers that never spell a redirect. Each needs its writing form, not just its name: a bare `install` matches `npm install`, which writes no file the guard cares about.
W_TOOL='\b(dd|truncate)\b|\b(sed|perl|ruby)\b[^|;&]*([[:space:]]-[A-Za-z]*i|--in-place)|(^|[;&|])[[:space:]]*(sudo[[:space:]]+)?([A-Za-z0-9_.-]*/)*install[[:space:]]|\b(curl|wget)\b[^|;&]*([[:space:]]-[A-Za-z]*[oO]|--output)'
# The mode argument, not any w/a in the path: open('data.json') is a read.
W_OPEN="\bopen\([^)]*,[^)]*['\"][wax]"
# A commit or tag message persists to disk in git history, so it is a write like any file.
W_GIT='\bgit\b[^|;&]*[[:space:]](commit|tag)\b[^|;&]*([[:space:]]-[A-Za-z]*[mF]([[:space:]]|=|"|'"'"')|--message|--file)'
# An fd prefix is part of the operator; >& reaches a file unless its target is a digit or -, which is duplication; >( is a write-side substitution.
W_REDIR='[0-9&]?>>?[[:space:]]*([^&>[:space:]]|&[[:space:]]*[^0-9>&[:space:]-])'
# Zero only when grep -E <ere> matches no line of <text>: on the authority's route, over ASCII, the ERE without \b and with a line start allowed after any newline only widens - see README § Process launches per call.
sg_grep_misses() {  # sg_grep_misses <text> <ere>
  [ -n "${SGA_PREPARSED:-}" ] && ! shopt -q nocasematch && [[ $1 != *[![:ascii:]]* ]] || return 1
  local _gm_re=${2//'[^'/} _gm_esc=${2//\\\\/}
  # An anchor this cannot widen, a \\b it would split, or an escape bash's engine reads unlike grep (\s, \w, \<, a back-reference) leaves the answer to grep.
  [[ $_gm_re != *'$'* && ${_gm_re//'(^|'/} != *'^'* && $2 != *'\\b'* && ${_gm_esc//'\b'/} != *\\[[:alnum:]\<\>\`\']* ]] || return 1
  _gm_re=${2//\\b/}
  _gm_re=${_gm_re//'(^|'/"(^|"$'\n'"|"}
  [[ $1 =~ $_gm_re ]]
  [ $? -eq 1 ]
}
# One grep for every kind of write: a line matching any alternative is a write, exactly as when each had its own grep.
sg_grep_misses "$WRITE_SCAN" "$W_HEREDOC|$W_TEE|$W_TOOL|$W_OPEN|$W_GIT|$W_REDIR" && exit 0
printf '%s\n' "$WRITE_SCAN" | grep -qE "$W_HEREDOC|$W_TEE|$W_TOOL|$W_OPEN|$W_GIT|$W_REDIR" || exit 0

# No generator bail-out on any surface: the generator's output never appears in the command text, so piping it was never blocked and the exemption only ever served text that merely named the path.
# The same two lines the writer test used: quoting AKIA''XT… out of one shape is exactly how a literal reaches a file unseen, and exempting on the raw text alone would clear a split key that sat beside a listed fixture.
sg_grep_misses "$WRITE_SCAN" "$SECRET_PATTERN" && exit 0
if printf '%s\n' "$WRITE_SCAN" | grep -qE -- "$SECRET_PATTERN"; then
  if fixture_exempt "$WRITE_SCAN"; then
    echo "WRITE-SECRET GUARD: allowed — every matched literal is a sanctioned fixture in fixtures.allow: $SECRET_GUARD_EXEMPTED" >&2
    exit 0
  fi
  echo "WRITE-SECRET GUARD: this command writes to a file and embeds a raw secret-shaped literal (private key / AWS access key / Slack bot token / GitLab PAT). Use a reference (env var, masked-cache path) instead of the literal value — never hardcode it into a script. If it is a test fixture, add its exact value to the plugin's fixtures.allow, or pipe scripts/fixture-value.sh — do not assemble it from fragments to get past this guard." >&2
  exit 2
fi

exit 0
}
# Run, or sourced by anything but the authority's loader, the stage runs one function level down, so an inherited FUNCNEST, read as bash reads it, gets that level back.
if [ -z "${SGA_LOADING:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then _sg_n=${FUNCNEST:-}; _sg_n=${_sg_n#"${_sg_n%%[![:space:]]*}"}; _sg_n=${_sg_n%"${_sg_n##*[![:blank:]]}"}; _sg_n=${_sg_n#+}; case $_sg_n in '' | *[!0-9]* | ???????????????????*) ;; *) [ $((10#$_sg_n)) -eq 0 ] || FUNCNEST=$((10#$_sg_n + 1)) ;; esac; sg_write_secret_guard_bash ${1+"$@"}; fi
# Reached only when a shell error or FUNCNEST aborted the stage partway, since every path through it exits; before it was a function, such an abort skipped one command, not the rest.
if [ -z "${SGA_LOADING:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then echo "WRITE-SECRET GUARD: this check stopped partway, so it could not confirm this command is free of secret-shaped literals. Blocking." >&2; exit 2; fi
