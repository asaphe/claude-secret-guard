#!/usr/bin/env bash
# Shared utility: normalize_cmd() rewrites respellings that change a command's bytes without changing what the shell runs. Nothing in a command is masked as data — not a heredoc body, not a flag value — because telling data from an executed region takes a shell parser; see README § Failing closed.

# A quote pair holding whitespace is left alone: it is the only thing telling a search for the guarded phrase apart from a command performing it — see README § Respellings the predicates normalize.
normalize_cmd() {
  local _nc
  _nc=${1//\\$'\n'/}
  # The $ goes with the quote: $'read' and $"read" are quoting forms whose argv is the bare word.
  _nc=$(printf '%s' "$_nc" | sed -E 's/\$?"([^"[:space:]]*)"/\1/g; s/\$?'"'"'([^'"'"'[:space:]]*)'"'"'/\1/g' 2>/dev/null) || { printf '%s' "$1"; return 0; }
  _nc=${_nc//\\/}
  if [ -n "$_nc" ]; then printf '%s' "$_nc"; else printf '%s' "$1"; fi
}

