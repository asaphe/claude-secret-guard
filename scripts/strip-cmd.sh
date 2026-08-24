#!/usr/bin/env bash
# Shared utility: strip_cmd() masks the parts of a command that are data rather than an executed command — heredoc bodies and prose-carrying flag values — so downstream pattern-matching does not fire on a command that merely describes a guarded pattern. A region that can still execute is never masked — see README § Failing closed.

strip_cmd() {
  # $2 = "long-flags-only" keeps -m unmasked: for a reader command its value is a filename, not prose — see README § Flag masking and filenames.
  printf '%s' "$1" | STRIP_CMD_MODE="${2-}" perl -0777 -pe '
    my $EXEC = qr/\$\(|`/;
    my $LONG = qr/--message|--description|--comment|--title|--notes|--body/;
    my $FLAG = ($ENV{STRIP_CMD_MODE} // "") eq "long-flags-only" ? $LONG : qr/$LONG|-m/;
    s{<<-?(["\x27])([A-Za-z_][A-Za-z0-9_]*)\1\s*\n.*?\n[ \t]*\2\b}{<<STRIPPED_HEREDOC>>}gs;
    s{<<-?([A-Za-z_][A-Za-z0-9_]*)\s*\n(.*?)\n[ \t]*\1\b}{
      my ($body, $all) = ($2, $&);
      $body =~ $EXEC ? $all : "<<STRIPPED_HEREDOC>>";
    }gse;
    s{(?<![-\w])($FLAG)([ =]+)"((?:\\.|[^"\\])*)"}{
      my ($flag, $sep, $val) = ($1, $2, $3);
      $val =~ $EXEC ? "$flag$sep\"$val\"" : "$flag$sep\"STRIPPED_MSG\"";
    }ge;
    s{(?<![-\w])($FLAG)([ =]+)\x27[^\x27]*\x27}{$1$2\x27STRIPPED_MSG\x27}g;
  '
}
