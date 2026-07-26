#!/usr/bin/env bash
# Shared utility: strip_cmd() masks heredoc bodies and -m/--message content so downstream pattern-matching ignores commit-message text — see README § strip-cmd.sh.

strip_cmd() {
  printf '%s' "$1" | perl -0777 -pe '
    s/<<-?["\x27]?([A-Za-z_][A-Za-z0-9_]*)["\x27]?\s*\n.*?\n[ \t]*\1\b/<<STRIPPED_HEREDOC>>/gs;
    s/(-m|--message)([ =]+)"((?:\\.|[^"\\])*)"/\1\2"STRIPPED_MSG"/g;
    s/(-m|--message)([ =]+)\x27[^\x27]*\x27/\1\2\x27STRIPPED_MSG\x27/g;
  '
}
