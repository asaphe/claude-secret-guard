#!/usr/bin/env bash
# Shared utility: normalize_cmd() rewrites respellings that change a command's bytes without changing what the shell runs, and strip_cmd() masks the parts of a command that are data rather than an executed command — heredoc bodies and prose-carrying flag values — so downstream pattern-matching does not fire on a command that merely describes a guarded pattern. A region that can still execute is never masked — see README § Failing closed.

# A quote pair holding whitespace is left alone: it is the only thing telling a search for the guarded phrase apart from a command performing it — see README § Respellings the predicates normalize.
normalize_cmd() {
  local _nc
  _nc=${1//\\$'\n'/}
  # The $ goes with the quote: $'read' and $"read" are quoting forms whose argv is the bare word.
  _nc=$(printf '%s' "$_nc" | sed -E 's/\$?"([^"[:space:]]*)"/\1/g; s/\$?'"'"'([^'"'"'[:space:]]*)'"'"'/\1/g' 2>/dev/null) || { printf '%s' "$1"; return 0; }
  _nc=${_nc//\\/}
  if [ -n "$_nc" ]; then printf '%s' "$_nc"; else printf '%s' "$1"; fi
}

strip_cmd() {
  # $2 = "long-flags-only" keeps -m unmasked for reader commands (README § Flag masking and filenames); output degrades to the unmodified command, never to empty, since a missing perl would otherwise hit every caller's "nothing to inspect" early exit.
  local _sc_out
  _sc_out=$(printf '%s' "$1" | STRIP_CMD_MODE="${2-}" perl -0777 -e '
    my $cmd = do { local $/; <STDIN> };
    my $EXEC = qr/\$\(|`/;
    my $LONG = qr/--message|--description|--comment|--title|--notes|--body/;
    my $mode = $ENV{STRIP_CMD_MODE} // "";
    # The cluster spelling masks git commit -am like -m, but never a cluster holding c: -c is the flag every shell runs its operand with, so bash -cm would mask an executed command.
    my $FLAG = $mode eq "long-flags-only" ? $LONG : qr/$LONG|-(?![A-Za-z]*c)[A-Za-z]*m/;
    # A heredoc piped into an interpreter is executed by it, whatever the delimiter quoting did in the parent shell; the path-qualified spelling runs the same interpreter.
    # The quotes are optional because the builtins execute `source "/dev/stdin"` exactly as they execute the bare spelling.
    my $INTERP = qr{(?:^|[\s;&|(])(?:(?:[^\s;&|()<>]*/)?(?:(?:ba|z|k|da)?sh|python[\d.]*|perl|ruby|node|ssh|awk|xargs|env)(?:\s|$)|(?:source|\.)[ \t]+["\x27]?/dev/(?:stdin|fd/\d+))};

    # Offsets inside a quoted region: a flag there is text, not a flag, and masking from it swallows whatever follows the closing quote.
    my @q;
    my $mapq = sub {
      @q = ();
      my $st = 0;
      for (my $i = 0; $i < length($cmd); $i++) {
        my $c = substr($cmd, $i, 1);
        if ($st == 0) { $q[$i] = 0; $st = 1 if $c eq "\x27"; $st = 2 if $c eq q{"}; }
        elsif ($st == 1) { $q[$i] = 1; $st = 0 if $c eq "\x27"; }
        else {
          $q[$i] = 1;
          if ($c eq chr(92)) { $i++; $q[$i] = 1 if $i < length($cmd); }
          elsif ($c eq q{"}) { $st = 0; }
        }
      }
    };

    # Only the segment that actually owns the heredoc decides it: `python x.py && cat <<EOF` feeds cat, while a separator inside quotes is no segment break at all.
    my $owner = sub {
      my ($p) = @_;
      my ($st, $cut) = (0, 0);
      for (my $i = 0; $i < length($p); $i++) {
        my $c = substr($p, $i, 1);
        if ($st == 0) {
          if ($c eq "\x27") { $st = 1 }
          elsif ($c eq q{"}) { $st = 2 }
          elsif ($c =~ /[;&|]/) { $cut = $i + 1 }
        } elsif ($st == 1) { $st = 0 if $c eq "\x27" }
        else { if ($c eq chr(92)) { $i++ } elsif ($c eq q{"}) { $st = 0 } }
      }
      return substr($p, $cut);
    };
    my $heredoc = sub {
      my ($pre, $tail, $body, $all, $quoted, $post) = @_;
      return $all if $owner->($pre) =~ $INTERP;
      # The rest of that line consumes the body too: `<<EOF | python3` feeds it to an interpreter exactly as a preceding command would.
      return $all if $tail =~ $INTERP;
      # A body written to a file is data only until something runs that file. If the destination is named again later in the same command, the masked region executes a few bytes on and must stay visible.
      for my $tok ("$pre $tail" =~ m{([^\s"\x27;&|<>()]*[/.][^\s"\x27;&|<>()]*)}g) {
        next if length($tok) < 3;
        return $all if index($post, $tok) >= 0;
      }
      return $all if !$quoted && $body =~ $EXEC;
      return "$pre<<STRIPPED_HEREDOC>>$tail";
    };
    # The operator does not have to end its line: `cat <<EOF > file` and `cat <<EOF | tee file` are the ordinary spellings, and requiring whitespace to the newline left both bodies unmasked.
    $cmd =~ s{([^\n]*?)(?<!<)<<-?[ \t]*(["\x27])([A-Za-z_][A-Za-z0-9_]*)\2([^\n]*)\n(.*?)\n[ \t]*\3\b}{ $heredoc->($1, $4, $5, $&, 1, substr($cmd, $+[0])) }gse;
    $cmd =~ s{([^\n]*?)(?<!<)<<-?[ \t]*\\([A-Za-z_][A-Za-z0-9_]*)([^\n]*)\n(.*?)\n[ \t]*\2\b}{ $heredoc->($1, $3, $4, $&, 1, substr($cmd, $+[0])) }gse;
    $cmd =~ s{([^\n]*?)(?<!<)<<-?[ \t]*([A-Za-z_][A-Za-z0-9_]*)([^\n]*)\n(.*?)\n[ \t]*\2\b}{ $heredoc->($1, $3, $4, $&, 0, substr($cmd, $+[0])) }gse;

    $mapq->();
    $cmd =~ s{(?<![-\w])($FLAG)([ =]*)"((?:\\.|[^"\\])*)"}{
      # $& is captured up front: the $EXEC test below is itself a match and would otherwise overwrite it.
      my ($flag, $sep, $val, $at, $all) = ($1, $2, $3, $-[0], $&);
      ($q[$at] || $val =~ $EXEC) ? $all : "$flag$sep\"STRIPPED_MSG\"";
    }ge;
    $mapq->();
    $cmd =~ s{(?<![-\w])($FLAG)([ =]*)\x27([^\x27]*)\x27}{
      # No $EXEC test here, unlike the double-quoted rule: single quotes suppress expansion, so a substitution inside them is literal text.
      my ($at, $all) = ($-[0], $&);
      $q[$at] ? $all : "$1$2\x27STRIPPED_MSG\x27";
    }ge;
    print $cmd;
  ' 2>/dev/null) || { printf '%s' "$1"; return 0; }
  if [ -n "$_sc_out" ]; then printf '%s' "$_sc_out"; else printf '%s' "$1"; fi
}
