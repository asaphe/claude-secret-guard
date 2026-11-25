#!/usr/bin/env bash
# Shared utility: normalize_cmd() rewrites respellings that change a command's bytes without changing what the shell runs. Nothing in a command is masked as data — not a heredoc body, not a flag value — because telling data from an executed region takes a shell parser; see README § Failing closed.

# A quote pair holding whitespace is left alone: it is the only thing telling a search for the guarded phrase apart from a command performing it — see README § Respellings the predicates normalize.
normalize_cmd() {
  # A pure function, and every stage of one call normalizes the same command: bash-secret-authority.sh primes this once — see README § Process launches per call.
  if [ -n "${SG_NC_PRIMED:-}" ] && [[ $1 == "$SG_NC_IN" ]]; then printf '%s' "$SG_NC_OUT"; return 0; fi
  local _nc _sg_ext=""
  # Before bash 5, deleting a backslash by pattern costs time in length × backslashes (11 s for 4 KB on 3.2), so a long text there goes through perl and tr, which yield the same bytes.
  [ "${BASH_VERSINFO[0]}" -ge 5 ] || [ "${#1}" -le 512 ] || [[ $1 != *\\* ]] || _sg_ext=1
  # Only where a backslash byte is always a backslash: in SJIS, GBK or Big5 it can be a character's second byte, which bash keeps and perl and tr would delete.
  case ${LC_ALL:-${LC_CTYPE:-${LANG:-C}}} in C | POSIX | *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) ;; *) _sg_ext="" ;; esac
  if [ -n "$_sg_ext" ] && _nc=$(printf '%s' "$1" | perl -0777 -pe 's/\\\n//g' 2>/dev/null && printf x); then _nc=${_nc%x}; else _nc=${1//\\$'\n'/}; fi
  # The $ goes with the quote: $'read' and $"read" are quoting forms whose argv is the bare word.
  _nc=$(printf '%s' "$_nc" | sed -E 's/\$?"([^"[:space:]]*)"/\1/g; s/\$?'"'"'([^'"'"'[:space:]]*)'"'"'/\1/g' 2>/dev/null) || { printf '%s' "$1"; return 0; }
  if [ -n "$_sg_ext" ] && [[ $_nc == *\\* ]] && _sg_ext=$(export LC_ALL=C; printf '%s' "$_nc" | tr -d '\134' 2>/dev/null && printf x); then _nc=${_sg_ext%x}; else _nc=${_nc//\\/}; fi
  if [ -n "$_nc" ]; then printf '%s' "$_nc"; else printf '%s' "$1"; fi
}

# The x keeps the trailing newlines a command substitution would strip, so a primed result is byte-identical to a fresh one.
normalize_cmd_prime() {
  SG_NC_OUT=$(normalize_cmd "$1"; printf x)
  SG_NC_OUT=${SG_NC_OUT%x}
  SG_NC_IN=$1
  SG_NC_PRIMED=1
}

# Normalization only deletes \, newline, $, " and ', so a word it can yield is spelled in the raw text with nothing but those between its letters.
SG_NORM_GAP=$'["\'$\\\\\n]*'
# Sets <var> to an ERE that matches raw text whose normalization could contain any of the words.
norm_may_re() {  # norm_may_re <var> <word>...
  local _var=$1 _re="" _w _i
  shift
  for _w in "$@"; do
    [ -z "$_re" ] || _re+="|"
    for ((_i = 0; _i < ${#_w}; _i++)); do
      [ "$_i" -eq 0 ] || _re+=$SG_NORM_GAP
      _re+=${_w:_i:1}
    done
  done
  printf -v "$_var" '%s' "$_re"
}

# One character in UTF-8 and three where a character is a byte; neither in SJIS, GBK or Big5, where a character's second byte can be an ASCII one.
SG_DASH=$'\xe2\x80\x94'
SG_ONE_OR_THREE='^(.|...)$'

# A necessary condition: false only when no normalization of <text> can contain the words. C's answer, because in a UTF-8 locale =~ fails on any invalid byte, the one wrong answer a gate must never give.
norm_may_hold() {  # norm_may_hold <text> <ere from norm_may_re>
  # A wrong open only costs the checks behind the gate, so a match in place stands; ASCII text misses alike in every locale.
  [[ $1 =~ $2 ]] && return 0
  [[ $1 == *[![:ascii:]]* ]] || return 1
  # Where no ASCII byte can sit inside another character, a miss over text that decodes is C's miss too, with no subprocess; see README § Process launches per call.
  [[ $SG_DASH =~ $SG_ONE_OR_THREE && $1 =~ ^.*$ ]] && return 1
  # Restoring the locale crashed bash 5 in a forked stage and warned when invalid, so C stays in a subshell.
  ( LC_ALL=C; [[ $1 =~ $2 ]] )
}
