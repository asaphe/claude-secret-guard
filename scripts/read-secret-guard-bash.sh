#!/usr/bin/env bash
# PreToolUse Bash hook, mirrors read-secret-guard.sh's basename gate for cat/head/tail/less/grep readers.

# First, and in ASCII: an option or locale inherited from the environment changes how every line below runs - see README § Inherited options and locales.
set +o keyword +o noclobber
[ "${LC_ALL:-}" = C ] || unset SG_ASCII_TRAIL; _sg_mb=$'\xe2\x80\x94'; [ ${#_sg_mb} -eq 1 ] || { printf -v _sg_mb '\\x%x' {128..255}; printf -v _sg_mb '%b' "$_sg_mb"; [ ${#_sg_mb} -eq 128 ]; } || { _sg_mb=$'\xe4\x5c'; [ ${#_sg_mb} -ne 1 ] || SG_ASCII_TRAIL=1; LC_ALL=C; export LC_ALL SG_ASCII_TRAIL; }
sg_read_secret_guard_bash() {  # One function, so the authority loads this file in its own process and no forked stage opens a script - see README § Process launches per call.
if [ -n "${SGA_PREPARSED:-}" ]; then
  INPUT=$SGA_INPUT; CMD=$SGA_CMD
else
INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty value, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "READ-SECRET GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty value that every check below reads as "nothing to inspect", silently disarming the guard.
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "READ-SECRET GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
fi
[ -z "$CMD" ] && exit 0

SGA_DIR=${BASH_SOURCE[0]%/*}; [ "$SGA_DIR" != "${BASH_SOURCE[0]}" ] || SGA_DIR=.
# shellcheck source-path=SCRIPTDIR
{ [ "${BASH_SOURCE[0]}" != "$0" ] && [[ ${SGA_HAVE-} == *" strip-cmd.sh "* ]]; } || source "$SGA_DIR/strip-cmd.sh"

ask() {
  local log session flat
  log=${HOOK_DIAG_ASK_LOG:-${HOME}/.claude/local/hook-ask-decisions.log}
  session=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' | tr -dc 'A-Za-z0-9-')
  # shellcheck disable=SC2030,SC2031  # tr, not ${CMD//$'\n'/ } (~50 s on bash 3.2 for 37 KB); C by export, as lastpipe restores a LC_ALL=C prefix here
  flat=$(export LC_ALL=C; printf '%s' "$CMD" | tr '\r\n' '  ')
  # Diagnostics must never replace the permission decision when the log is unwritable.
  { mkdir -p "$(dirname "$log")" && (
    umask 077
    printf '%s\n' '---' "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)" 'hook=read-secret-guard-bash' \
      "session=$session" "decision=${2:-ask:literal}" "cmd=$flat" >>"$log"
  ); } 2>/dev/null || :
  # A jq that cannot start would print nothing, which reads as allow, so a fixed ask stands in.
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}' 2>/dev/null \
    || printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"READ-SECRET GUARD: this command may read a secret file, and the reason was too large to describe. Confirm before its contents enter context/transcript."}}'
  exit 0
}

# Where the decoder joins an ASCII byte, a quote, separator or space included, to the character before it, the shell parses such a command unlike any C scan here.
if [ -n "${SG_ASCII_TRAIL:-}" ]; then
  case $CMD in
    *[$'\200'-$'\377']*) ask "READ-SECRET GUARD: under this locale the shell can read an ASCII character right after a non-ASCII one, even a quote, a ; or a space, as part of that character, so it may split and run this command differently than this guard reads it, and a secret it reads could go unflagged. Confirm before running it." "ask:inspection" ;;
  esac
fi

# Matched anywhere inside a segment rather than after a fixed wrapper list, which would go silent on any prefix the list omits (timeout, nice, stdbuf, ionice, doas); a separator bounds a reader name exactly as a line end does.
SEP=$';&|()`"\''
# The gate below needs a reader's name, so a command that cannot spell one is cleared before any grep.
norm_may_re SG_MAY_READER cat head tail less more grep
norm_may_hold "$CMD" "$SG_MAY_READER" || exit 0
# Normalized like the mask guard's predicates, or a quoted reader name (`"cat" secrets.pem`) splits into its own segment with no trailing space and matches nothing.
GATE_CMD=$(normalize_cmd "$CMD")
# A leading slash admits the same reader named by path, and grep carries no recursive-flag condition: -r decides how many files are read, never whether the one named is a key — see README § Why grep is gated unconditionally.
SG_READER_RE="(^|[[:space:]/$SEP])(cat|head|tail|less|more|grep)([[:space:]<$SEP]|\$)"
# A newline is whitespace on both sides of a reader name, so over ASCII bash's whole-text match is grep's line match; elsewhere grep decides as before.
if [ -n "${SGA_PREPARSED:-}" ] && ! shopt -q nocasematch && [[ $GATE_CMD != *[![:ascii:]]* ]]; then [[ $GATE_CMD =~ $SG_READER_RE ]] || exit 0
else printf '%s' "$GATE_CMD" | grep -qE "$SG_READER_RE" || exit 0; fi
# Input bytes must not impersonate the tokenizer metadata that narrows scanning.
case "$CMD" in
  *[$'\001\002\003\004\005']*) ask "READ-SECRET GUARD: command contains reserved tokenizer control bytes and cannot be inspected safely." "ask:inspection" ;;
esac

# What the prompt can honestly say about a pattern that is never expanded for the verdict — an absolute glob has no cwd dependence, so naming its matches is reproducible where naming a relative one's would not be; see README § What an unresolved glob prompt says.
describe_glob() {
  local p="$1" hits n wild
  # shellcheck disable=SC2088  # the literal ~ is what tokenize hands over; expanding it is the point
  case "$p" in "~/"*) p="${HOME}/${p#\~/}" ;; esac
  case "$p" in
    /*) ;;
    *) printf "not expanded here, since this hook's working directory is not the command's"; return ;;
  esac
  wild=$(printf '%s\n' "${p//\//$'\n'}" | grep -c '[*?[]')
  # A deep absolute glob walks the filesystem with no bound, and the ask is only written after the listing returns.
  [ "$wild" -le 2 ] || { printf "not listed here, since a glob this broad is too slow to expand within the hook's time budget"; return; }
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
    # A comment and a heredoc body are cut out as pieces of their own, never dropped, and kept in text order: a quote inside one otherwise pairs with one in the code around it, and the find exemption reads tokens in sequence — see README § Reader-gate words and filenames.
    my $pieces = sub {
      my ($s) = @_;
      my $code = "";
      my (@out, @pend, @extra);
      my ($st, $n) = (0, length $s);
      for (my $i = 0; $i < $n; $i++) {
        my $c = substr($s, $i, 1);
        if ($st != 1 && $c eq chr(92)) { $code .= substr($s, $i++, 2); next }
        if ($st == 0) {
          if ($c eq "#" && ($i == 0 || substr($s, $i - 1, 1) =~ /[\s;&|()<>]/)) {
            my $e = index($s, "\n", $i);
            $e = $n if $e < 0;
            push @out, ["code", $code], ["com", substr($s, $i, $e - $i)];
            $code = "";
            $i = $e - 1;
            next;
          }
          if (substr($s, $i, 3) eq "<<<") { $code .= "<<<"; $i += 2; next }
          pos($s) = $i;
          if (substr($s, $i, 2) eq "<<" && $s =~ /\G<<(-?)[ \t]*((?:[^\s;&|<>()\\\x27"]|\\.|\x27[^\x27]*\x27|"[^"]*")+)/gc) {
            my ($m, $strip, $d) = (substr($s, $i, pos($s) - $i), $1, $2);
            # Any quote or backslash in the delimiter word itself stops the shell expanding the body; this word, not text elsewhere, is what decides it.
            my $q = $d =~ /["\x27\\]/ ? 1 : 0;
            $d =~ s/\\(.)/$1/g;
            $d =~ s/["\x27]//g;
            # The command word the body is fed to, named in the prompt only; the verdict never trusts it — see the data-sink check below.
            my ($who) = $code =~ /([^;&|()\n`]*)\z/;
            ($who) = $who =~ /^\s*(\S+)/;
            $who = "" unless defined $who;
            $who =~ s/["\x27\\]//g;
            push @pend, [$d, $strip, $who, $q];
            $code .= $m;
            $i += length($m) - 1;
            next;
          }
          if ($c eq "\n" && @pend) {
            # A pipe on the opener line is where the body really goes, so the prompt names that consumer too.
            if ($code =~ /<<[^\n]*\|\s*["\x27\\]*([^\s"\x27\\;&|()]+)[^\n]*\z/) { my $to = $1; $_->[2] .= "`, piped on to `$to" for grep { length $_->[2] } @pend }
            my $opener = $code;
            push @out, ["code", $code . $c];
            $code = "";
            my $p = $i + 1;
            for my $h (@pend) {
              my ($d, $strip, $who, $q, $body, $closed) = (@$h, "", 0);
              while ($p < $n) {
                my $e = index($s, "\n", $p);
                $e = $n - 1 if $e < 0;
                my $line = substr($s, $p, $e - $p + 1);
                $body .= $line;
                $p = $e + 1;
                $line =~ s/\n\z//;
                $line =~ s/^\t+// if $strip;
                if ($line eq $d) { $closed = 1; last }
                push @extra, substr($line, length $d) if length($d) && length($line) > length($d) && substr($line, 0, length $d) eq $d;
              }
              push @out, ["bod", $body, $who, $q, $opener, substr($s, $p), $closed], map { ["com", $_] } @extra;
              @extra = ();
            }
            @pend = ();
            $i = $p - 1;
            next;
          }
          $st = 1 if $c eq "\x27";
          $st = 2 if $c eq q{"};
        } elsif ($st == 1) { $st = 0 if $c eq "\x27" }
        else { $st = 0 if $c eq q{"} }
        $code .= $c;
      }
      push @out, ["code", $code];
      return grep { length $_->[1] } @out;
    };
    my $fell = 0;
    my $split = sub {
      my ($s) = @_;
      # An unquoted |, ; or & is an operator, not part of a word: cat k.pem|head names k.pem.
      my ($out, $st) = ("", 0);
      for (my $i = 0; $i < length($s); $i++) {
        my $c = substr($s, $i, 1);
        if ($st != 1 && $c eq chr(92)) { $out .= substr($s, $i++, 2); next }
        if ($st == 0) {
          if ($c =~ /[|;&]/) { $out .= " $c "; next }
          # Only an unquoted opener starts a command: a single-quoted $(find is literal text, and a double-quoted substitution is followed below and marked there.
          $out .= " \x01 " if $c eq "`" || ($c eq "(" && ($i == 0 || substr($s, $i - 1, 1) !~ /[\$<>]/)) || ($c =~ /[\$<>]/ && substr($s, $i + 1, 1) eq "(");
          if ($c eq "\n") { $out .= " ; "; next }
          $st = 1 if $c eq "\x27";
          $st = 2 if $c eq q{"};
        } elsif ($st == 1) { $st = 0 if $c eq "\x27" }
        else { $st = 0 if $c eq q{"} }
        $out .= $c;
      }
      my @w = shellwords($out);
      # Unbalanced quotes yield nothing; fall back to a bare split of this piece so the guard still asks rather than going silent.
      unless (@w) { @w = map { my $t = $_; $t =~ s/["\x27]//g; $t } ($out =~ /\S+/g); $fell = 1 if @w }
      return @w;
    };
    my $INTERPRETER = qr{(?:^|/)(?:python(?:[0-9]+(?:\.[0-9]+)*)?|node|perl|ruby)$};
    my $literal_body = sub {
      my ($p) = @_;
      return 0 unless $p->[0] eq "bod" && $p->[6];
      # Shell substitutions in an expanding body execute before its interpreter sees the text.
      return 0 if !$p->[3] && $p->[1] =~ /\$\(|`/;
      my ($reader) = split /`, piped on to `/, $p->[2];
      return 0 unless $reader =~ /$INTERPRETER/ || $reader =~ m{^(?:(?:/usr)?/bin/)?(?:cat|tee)$};
      my @opener = $split->($p->[4]);
      return 0 unless 1 == grep { /^<</ } @opener;
      my (@pipeline, @part, @segments);
      my $piped = 0;
      my $interpreted_pipeline = sub {
        my ($body, $interpreted) = (0, 0);
        for my $part (@pipeline) {
          $body = 1 if grep { /^<</ } @$part;
          next unless $body;
          return 0 unless @$part;
          if ($part->[0] =~ /$INTERPRETER/) { $interpreted = 1 }
          elsif ($part->[0] !~ m{^(?:(?:/usr)?/bin/)?(?:cat|tee)$}) { return 0 }
        }
        return $body && $interpreted;
      };
      for my $word (@opener, ";") {
        if ($word =~ /^(?:[;&|]+|\x01)$/) {
          if (@part) { push @pipeline, [@part]; push @segments, [@part] }
          @part = ();
          unless ($word eq "|") {
            $piped = 1 if $interpreted_pipeline->();
            @pipeline = ();
          }
        } else { push @part, $word }
      }
      return 0 unless $piped || $p->[2] =~ m{^(?:(?:/usr)?/bin/)?(?:cat|tee)$};
      my @dest;
      for my $segment (@segments) {
        my @a = @$segment;
        for (my $i = 0; $i < @a; $i++) {
          push @dest, $1 if $a[$i] =~ /^>>?([^>].*)$/;
          push @dest, $a[$i + 1] if $a[$i] =~ /^>>?$/ && defined $a[$i + 1];
        }
        if ($a[0] =~ m{^(?:(?:/usr)?/bin/)?tee$}) {
          for (my $i = 1; $i < @a; $i++) {
            if ($a[$i] =~ /^(?:<<-?|>>?)$/) { $i++; next }
            next if $a[$i] =~ /^[<>-]/;
            push @dest, $a[$i];
          }
        }
      }
      return 0 unless $piped || @dest;
      my $later = $p->[4] . "\n" . join "", map { $_->[0] eq "code" ? $_->[1] : "" } $pieces->($p->[5]);
      return 0 if $later =~ /[()`{}\\]/;
      $later =~ s/\$(?=["\x27])//g;
      my @later = $split->($later);
      return 0 if grep { m{(?:^|/)(?:(?:ba|z|k|da|a|c|tc|mk|fi)?sh|eval|source)$} || $_ eq "." || m{^\./} } @later;
      my @segment;
      my ($matched, $unsafe) = (0, 0);
      my $executes = sub {
        return unless @segment;
        return if $segment[0] =~ m{^(?:(?:/usr)?/bin/)?tee$};
        return if $segment[0] =~ m{^(?:(?:/usr)?/bin/)?(?:cat|tee)$} && grep { /^<</ } @segment;
        for my $dest (@dest) {
          my ($base) = $dest =~ m{([^/]+)$};
          if (grep { my $arg = $_; $arg =~ s/^\d*[<>]+//; $arg eq $dest || $arg eq $base } @segment[1 .. $#segment]) {
            if ($segment[0] =~ /$INTERPRETER/) { $matched = 1 }
            else { $unsafe = 1 }
          }
        }
      };
      for my $word (@later, ";") {
        if ($word =~ /^(?:[;&|]+|\x01)$/) {
          $executes->();
          @segment = ();
        } else { push @segment, $word }
      }
      return ($piped || $matched) && !$unsafe;
    };
    # A body is text, not a command, only when the whole command is data sinks fed by heredocs plus mkdir: nothing in it can pipe, substitute, group, run or source what a sink wrote, so the routes a later command takes to run a body are absent — see README § Heredoc bodies written as data.
    my $data = 0;
    {
      my @top = $pieces->($cmd);
      my $bods = grep { $_->[0] eq "bod" } @top;
      last unless $bods;
      my $code = join "", map { $_->[0] eq "code" ? $_->[1] : "" } @top;
      last if $code =~ /[`\\(){}|]/;
      # An unquoted delimiter expands the body, so a $(...) in it runs before the sink ever sees the text.
      last if grep { $_->[0] eq "bod" && !$_->[3] } @top;
      $code =~ s/&&/\n/g;
      last if $code =~ /&/;
      my ($ok, $ops) = (1, 0);
      for my $line (split /[\n;]/, $code) {
        next unless $line =~ /\S/;
        my @a = shellwords($line);
        unless (@a) { $ok = 0; last }
        if ($a[0] eq "mkdir") { $ok = 0 if grep { /^[<>]/ } @a; last unless $ok; next }
        my @h = grep { /^<</ } @a;
        unless (@h == 1 && $h[0] =~ /^<<-?(?:\w[\w.-]*)?$/) { $ok = 0; last }
        my @r;
        for (my $j = 1; $j < @a; $j++) {
          if ($a[$j] =~ /^<<-?$/) { $j++; next }
          next if $a[$j] =~ /^<</;
          push @r, $a[$j] =~ /^(>>?)([^>].*)$/ ? ($1, $2) : $a[$j];
        }
        my $dest = sub { defined $_[0] && length $_[0] && $_[0] !~ /^[&<>|]/ };
        my $stdin = sub { my ($flag, @args) = @_; my $s = " " . join(" ", @args) . " "; $s =~ / (?:$flag) - / || $s =~ / --(?:body-)?file=- / };
        my $good = 0;
        if ($a[0] =~ m{^(?:(?:/usr)?/bin/)?cat$}) {
          $good = @r == 2 && $r[0] =~ /^>>?$/ && $dest->($r[1]);
        } elsif ($a[0] =~ m{^(?:(?:/usr)?/bin/)?tee$}) {
          splice(@r, -2) if @r >= 2 && $r[-2] =~ /^>>?$/ && $dest->($r[-1]);
          $good = !grep { /^-/ ? !/^(?:-a|--append)$/ : !$dest->($_) } @r;
        } elsif ($a[0] eq "git") {
          my $k = 0;
          $k += 2 while defined $r[$k] && $r[$k] eq "-C";
          $good = defined $r[$k] && $r[$k] eq "commit" && !grep({ /^[<>]/ } @r) && $stdin->("-F|--file", @r[$k + 1 .. $#r]);
        } elsif ($a[0] eq "gh") {
          $good = @r >= 2 && $r[0] =~ /^(?:pr|issue)$/ && $r[1] =~ /^(?:create|comment|edit|review)$/ && !grep({ /^[<>]/ } @r) && $stdin->("-F|--body-file", @r[2 .. $#r]);
        }
        unless ($good) { $ok = 0; last }
        $ops++;
      }
      $data = 1 if $ok && $ops == $bods;
    }
    # Text the shell runs as a command line is split the way the shell splits it, and other quoted text, such as a grep or jq pattern, stays one word — see README § Reader-gate words and filenames.
    my $tok;
    $tok = sub {
      my ($s, $depth, $ctx, $literal) = @_;
      my (@w, @own, @run);
      for my $p ($pieces->($s)) {
        my ($kind, $text, $who) = @$p;
        # A \x04 word names where the words after it sit, for the prompt only; it never reaches the patterns or the find window.
        my $where = $kind eq "bod" ? (length $who ? "the heredoc body fed to `$who`" : "a heredoc body") : $kind eq "com" ? "a shell comment" : $ctx;
        my $only = $literal || $literal_body->($p);
        if ($kind eq "bod" && $data) { push @w, "\x01"; push @own, 0; next }
        # A heredoc body is tokenized like any command line, since a shell may be what reads it, at the same depth because each body is shorter than its parent; its own -c, eval and $(...) were followed in that call, and the marker after it keeps a find inside it from exempting anything later.
        my @pw = $kind eq "bod" ? ($tok->($text, $depth, $where, $only), "\x01") : $kind eq "com" ? ($split->($text), "\x01") : $split->($text);
        push @w, "\x04" . ($only ? "\x05" : "") . $where, @pw;
        push @own, 0, ($kind ne "bod") x @pw;
      }
      return @w if $depth > 3;
      # The operand of a shell -c or of eval and the body of a $(...) substitution are command lines too: bash -c "cat k.pem | head". The shell must own the -c, or a jq -c filter would be split; backticks are left whole because Markdown code spans in a python heredoc use the same character.
      my $SHELL = qr{(?:^|/)(?:ba|z|k|da|a|c|tc|mk|fi)?sh$};
      for my $i (grep { $own[$_] } 0 .. $#w) {
        push @run, "\x01", $tok->($w[$i], $depth + 1, $w[$i - 1] =~ /eval$/ ? "the command line run by `eval`" : "the command line passed to a shell `-c`", $literal)
          if $i && (($w[$i - 1] =~ /^-[A-Za-z]*c[A-Za-z]*$/ && grep { $_ =~ $SHELL } @w[($i > 5 ? $i - 5 : 0) .. $i - 2]) || $w[$i - 1] =~ m{(?:^|/)eval$});
        push @run, "\x01", $tok->($1, $depth + 1, "a command substitution `\$(...)`", $literal) while $w[$i] =~ /\$\(((?:[^()]++|\((?1)\))*)\)/g;
      }
      return (@w, @run);
    };
    my @w = $tok->($cmd, 0, "the command line");
    # An unbalanced quote used to expose every word through a bare split of the whole command, and with heredoc bodies masked that quote could sit anywhere, so the split stays, first and unaltered, whenever the whole or any piece will not parse. A body passed as data is left out of it, as it is out of the pieces.
    my $scan = $data ? join("", map { $_->[0] eq "bod" ? "\n" : $_->[1] } $pieces->($cmd)) : $cmd;
    my @whole = shellwords($scan);
    my @bare;
    unless (@whole && !$fell) {
      push @bare, "\x02";
      for my $p ($pieces->($cmd)) {
        next if $data && $p->[0] eq "bod";
        push @bare, "\x04" . ($literal_body->($p) ? "\x05" : "") . "the command read word by word (it did not parse cleanly, so text is checked too)",
          (map { my $t = $_; $t =~ s/["\x27]//g; $t } ($p->[1] =~ /\S+/g));
      }
      push @bare, "\x01";
    }
    # Punctuation survives tokenizing glued to the filename — $'"'"'…'"'"', substitution syntax, and a trailing ; or & each defeat the end-anchored suffix patterns.
    @w = map { my $t = $_; /^\x04/ ? $t : do { my @end = $t =~ /[)`][;&]*$/ ? ("\x03") : (); $t =~ s/^\$//; $t =~ s/[()`]//g; $t =~ s/[;&]+$// unless $t =~ /^[;&|]+$/; $t =~ s/\$+$//; ($t, @end) } } @w;
    # A redirect glues its target to the reader, and the basename patterns are anchored: cat<.env is one token that matches nothing.
    @w = grep { length } map { /^\x04/ ? $_ : split /[<>]+/, $_ } @w;
    @w = (@bare, @w);
    print join("\0", @w), "\0" if @w;
  '
}

# Fails closed like the jq check above: with nowhere to tokenize into, no argument was ever inspected.
TOKENS_FILE=$(mktemp) || ask "READ-SECRET GUARD: could not create the temporary file this gate tokenizes into, so the arguments of this read were never inspected — confirm before its contents enter context/transcript."
FLAT_FILE=""
trap 'rm -f "$TOKENS_FILE" ${FLAT_FILE:+"$FLAT_FILE"}' EXIT
# A hook the harness kills at its timeout lets the command run unchecked, so a scan that would overrun asks instead.
SCAN_DEADLINE=20
# Tests lower it to exercise the overrun path; it can never be raised past the default.
[[ ${SECRET_GUARD_SCAN_DEADLINE:-} =~ ^[0-9]+$ ]] && [ "$SECRET_GUARD_SCAN_DEADLINE" -lt "$SCAN_DEADLINE" ] && SCAN_DEADLINE=$SECRET_GUARD_SCAN_DEADLINE
SG_GAP='[^[:alnum:]]*'
SG_STEM_RE="\\.${SG_GAP}[eE]${SG_GAP}[nN]${SG_GAP}[vV]|\\.${SG_GAP}[pP]${SG_GAP}[eE]${SG_GAP}[mM]|\\.${SG_GAP}[kK]${SG_GAP}[eE]${SG_GAP}[yY]|\\.${SG_GAP}[pP]${SG_GAP}1${SG_GAP}2|\\.${SG_GAP}[pP]${SG_GAP}[fF]${SG_GAP}[xX]|\\.${SG_GAP}[sS]${SG_GAP}[sS]${SG_GAP}[hH]|[iI]${SG_GAP}[dD]${SG_GAP}_|[kK]${SG_GAP}[uU]${SG_GAP}[bB]${SG_GAP}[eE]${SG_GAP}[cC]${SG_GAP}[oO]${SG_GAP}[nN]${SG_GAP}[fF]${SG_GAP}[iI]${SG_GAP}[gG]"
SG_DOTS_RE='\.[^[:alnum:]]*\.'
# Every word judged below is the command's own text with only non-alphanumeric characters dropped, so where no brace can expand (no comma, no two dots), ASCII text that cannot spell a stem that way has none to flag - see README § Process launches per call.
if [ -n "${SGA_PREPARSED:-}" ] && [ "$SECONDS" -lt "$SCAN_DEADLINE" ] && [[ $CMD != *[![:ascii:]]* ]] && { [[ $CMD != *'{'* ]] || [[ $CMD != *,* && ! $CMD =~ $SG_DOTS_RE ]]; } && ! [[ $CMD =~ $SG_STEM_RE ]]; then exit 0; fi
tokenize "$CMD" >"$TOKENS_FILE" 2>/dev/null
# A missing perl empties this, which would make every read silent — fall back to a bare split so the gate still asks.
if [ ! -s "$TOKENS_FILE" ]; then
  # Led by the no-exemption marker, as the perl path's bare split is, since a bare split cannot tell a command from text; the trailing newline keeps `read -d ''` from discarding the last token at EOF.
  { printf '\002\n'; printf '%s' "$CMD" | tr -d '"'"'"'\\$' | tr -s ' \t\n<>|;&()`' '\n'; printf '\n'; } | tr '\n' '\0' >"$TOKENS_FILE"
fi
# Every word with its braces and commas removed, read in step with the words: one tr here, where a tr per over-budget word cost ~15 ms and a large JSON heredoc has thousands.
case $CMD in
  # Only a word holding a brace reads it, and no word holds a byte the command does not.
  *'{'*)
    FLAT_FILE=$(mktemp) || FLAT_FILE=""
    # Without LC_ALL and LANG, restoring the locale after tr crashes bash 5 in a forked stage, so there tr gets C from a subshell that execs it and so never restores it.
    # shellcheck disable=SC2030,SC2031  # the subshell's LC_ALL is meant for tr alone
    if [ -n "${LC_ALL:-}${LANG:-}" ]; then
      [ -z "$FLAT_FILE" ] || LC_ALL=C tr -d '{},' <"$TOKENS_FILE" >"$FLAT_FILE" || : >"$FLAT_FILE"
    else
      [ -z "$FLAT_FILE" ] || (export LC_ALL=C; exec tr -d '{},') <"$TOKENS_FILE" >"$FLAT_FILE" || : >"$FLAT_FILE"
    fi
    ;;
esac

# Matched with bash's own regex engine rather than a grep per test: this loop runs before every Bash call, and the forks it used to spend cost more than the scan it performs.
shopt -s nocasematch
RE_GLOB='[*?]'
# A stem or path added below goes into SG_STEM_RE too, or the authority's route clears a read of it before the scan.
ENV_STEM='\.env'
KEY_STEM='\.(pem|key|p12|pfx)'
SSH_STEM='id_'
KUBE_STEM='kubeconfig'
RE_ENV="^-*${ENV_STEM}(\..+)?$"
RE_ENV_SAMPLE='^-*\.env\.(example|sample|template)$'
RE_KEY_NAME="${KEY_STEM}$|^-*${SSH_STEM}(rsa|ed25519|ecdsa|dsa)$|^-*${KUBE_STEM}$"
RE_KEY_PATH='\.kube/config$|(^|/)\.ssh(/|$)'
# A stem counts only as a whole name segment of the last path component, never inside another word — see README § Which wildcards are asked about.
RE_GLOB_SECRET="${ENV_STEM}([*?._~-]|\[[^]0-9*]|\$)|${KEY_STEM}([*?._~-]|\[[^]0-9*]|\$)|(^|[*?])${SSH_STEM}|[._-]${SSH_STEM}(rsa|ed25519|ecdsa|dsa)|(^|[*?._-])${KUBE_STEM}"
# Up to 16 punctuation or space characters, the gap a brace split leaves between a stem's letters; letters are excluded, or dotted jq paths match.
RE_GAP=$'[^[:alnum:]/\n]{0,16}'
# A stem's letters in order, so a name split across brace alternatives (`.{e,x}nv`) still counts once the braces are removed.
RE_STEM_FRAG="\\.e${RE_GAP}n${RE_GAP}v|\\.p${RE_GAP}e${RE_GAP}m|\\.k${RE_GAP}e${RE_GAP}y|\\.p${RE_GAP}1${RE_GAP}2|\\.p${RE_GAP}f${RE_GAP}x|i${RE_GAP}d${RE_GAP}_${RE_GAP}(r${RE_GAP}s${RE_GAP}a|e${RE_GAP}d|e${RE_GAP}c|d${RE_GAP}s${RE_GAP}a)|k${RE_GAP}u${RE_GAP}b${RE_GAP}e${RE_GAP}c${RE_GAP}o${RE_GAP}n${RE_GAP}f|\\.s${RE_GAP}s${RE_GAP}h"
# Any stem anywhere in the word: the pre-segment rule, kept for a brace word too large to expand.
RE_STEM_ANY="${ENV_STEM}|${KEY_STEM}|${SSH_STEM}|${KUBE_STEM}"
# A regex alternation or escape is a pattern for a matcher, not a path a shell expands.
RE_NOT_PATH='[|\\]'
# Shapes a JMESPath or jq expression takes and a filename practically never does: an empty or filter bracket, a pipe, an unopened ].
RE_QUERY_EXPR='\[\]|\[\?|\||^[^[]*\]'

# The exemption below is armed by a `find` TOKEN and disarmed by the next reader token, so it covers only the window in which find's own grammar governs — see README § Why a negated find predicate is exempt.
RE_FIND_TOK='^([A-Za-z_][A-Za-z0-9_]*=)?\$?(.*/)?find$'
RE_READER_TOK='^(.*/)?(cat|head|tail|less|more|grep)$'
RE_CMD_START='^([;|&]+|sudo|doas|env|exec|time|nohup|nice|command|xargs)$'
RE_SEP_TOK='^[;|&]+$'
RE_ASSIGN_TOK='^[A-Za-z_][A-Za-z0-9_]*='
# kubectl applies these templates to API objects and never opens a local file; jsonpath-file and the other -file variants do, so they stay scanned.
RE_KUBE_TEMPLATE='^(jsonpath|jsonpath-as-json|custom-columns|go-template|template)='
RE_KUBE_TEMPLATE_FLAG='^(-o=?|--output=)(jsonpath|jsonpath-as-json|custom-columns|go-template|template)='
PROG=""
FIND_ACTIVE=""
NO_EXEMPT=""
PREV=""
PREV2=""
PREV3=""
# Where the flagged word sits, for the prompt only; the no-perl fallback carries no markers, so it keeps this default.
WHERE="the command"
LITERAL_ONLY=""

# Expansion is bounded per command, not per word, or many small brace words add up to the same overrun.
BRACE_BUDGET=512
# ASCII A through z, the order bash walks a letter range in, punctuation between the cases included.
RANGE_CHARS='ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz'
# What tr deletes from an over-budget word, for when tr cannot run; quadratic on bash 3.2, so never the first choice.
SG_BRACE_CHARS='[{},]'

# Each comma list or range in braces becomes its alternatives, as the shell expands it, so `{*.pem,*.key}` is judged as `*.pem` and `*.key`; anything it cannot expand within budget fails closed.
expand_braces() {  # expand_braces <word>; fills BRACE_ALTS
  local pending=("$1") i=0 t pre post rest a b n
  [ ${#1} -le 4096 ] || return 1
  local re_list='^(.*)\{([^{}]*,[^{}]*)\}(.*)$' re_range='^(.*)\{([A-Za-z]|-?[0-9]+)\.\.([A-Za-z]|-?[0-9]+)\}(.*)$'
  BRACE_ALTS=()
  while [ "$i" -lt ${#pending[@]} ]; do
    t=${pending[$i]}; i=$((i + 1))
    [ "$SECONDS" -lt "$SCAN_DEADLINE" ] && [ "$BRACE_BUDGET" -gt 0 ] || return 1
    if [[ $t =~ $re_list ]]; then
      pre=${BASH_REMATCH[1]}; post=${BASH_REMATCH[3]}; rest="${BASH_REMATCH[2]},"
      n=${rest//[^,]/}
      [ ${#n} -le "$BRACE_BUDGET" ] || return 1
      while [[ $rest == *,* ]]; do pending+=("${pre}${rest%%,*}${post}"); rest=${rest#*,}; BRACE_BUDGET=$((BRACE_BUDGET - 1)); done
    elif [[ $t =~ $re_range ]]; then
      pre=${BASH_REMATCH[1]}; a=${BASH_REMATCH[2]}; b=${BASH_REMATCH[3]}; post=${BASH_REMATCH[4]}
      if [[ $a == [A-Za-z] && $b == [A-Za-z] ]]; then a=${RANGE_CHARS%%"$a"*}; a=${#a}; b=${RANGE_CHARS%%"$b"*}; b=${#b}; n=chr
      elif [[ $a =~ ^-?[0-9]{1,6}$ && $b =~ ^-?[0-9]{1,6}$ ]]; then
        # Read as base 10: a leading zero means octal to bash and `08` aborts the scan; six digits keep the width check below from overflowing.
        a=$(( ${a%%[0-9]*}10#${a#-} )); b=$(( ${b%%[0-9]*}10#${b#-} )); n=int
      else return 1; fi
      [ $(( a > b ? a - b : b - a )) -lt 64 ] || return 1
      while :; do
        if [ "$n" = chr ]; then pending+=("${pre}${RANGE_CHARS:a:1}${post}"); else pending+=("${pre}${a}${post}"); fi
        BRACE_BUDGET=$((BRACE_BUDGET - 1))
        [ "$a" -eq "$b" ] && break
        if [ "$a" -lt "$b" ]; then a=$((a + 1)); else a=$((a - 1)); fi
      done
    else
      # Unpaired braces bash still expands (`{a},.env}` gives `a}` and `.env`) go to the stem check below, unless the word has a query or regex shape, as on the literal path.
      [[ $t == *\{*,*\}* ]] && [[ ! $t =~ $RE_QUERY_EXPR && ! $t =~ $RE_NOT_PATH ]] && return 1
      BRACE_ALTS+=("$t")
    fi
    [ $(( ${#pending[@]} - i + ${#BRACE_ALTS[@]} )) -le 64 ] || return 1
  done
}

# One wording for every hit, so the approver always learns which word, where it sits, and what approving lets happen — see README § What a reader-gate prompt says.
ask_read() {  # ask_read <word> <what it looks like>
  local w=$1
  [ ${#w} -le 200 ] || w="${w:0:200}"$'\xe2\x80\xa6'  # the word appears twice in an argv string Linux caps at 128 KB; an escape, as no code byte may be non-ASCII
  ask "READ-SECRET GUARD: flagged \`$w\` in $WHERE — $2. The guard cannot tell whether this command reads that file or only mentions the name as text. Approving runs the command as written: if it does read the file, its contents enter the context/transcript. Approve only if \`$w\` is not a file this command reads." "${3:-ask:literal}"
}

# An expansion error aborts this loop and falls through to exit 0, so only a loop that reached the last token may allow.
SCAN_EOF=""
while IFS= read -r -d '' token || { SCAN_EOF=1; false; }; do
  # -u, not <&4: a redirection per token saves and restores fd 0 each time, up to a fifth of the scan's CPU on a large heredoc.
  if IFS= read -r -u 4 -d '' FLAT_TOKEN; then FLAT_READ=1; else FLAT_READ=""; fi
  [ "$SECONDS" -lt "$SCAN_DEADLINE" ] || ask "READ-SECRET GUARD: this command is too long to inspect within the hook's time budget, so its arguments were not all checked — confirm before any secret file it reads enters context/transcript." "ask:deadline"
  # \001 starts a command; \002 opens the whole-command bare split, read with no exemption so that text 0.6.5 masked cannot widen it there; \003 closes a substitution, whose next word is an argument, not a command; \004 names where the words after it sit.
  case "$token" in
    $'\001') FIND_ACTIVE=""; PREV=""; PREV2=""; PREV3=""; NO_EXEMPT=""; PROG=""; continue ;;
    $'\002') NO_EXEMPT=1; WHERE="the command read word by word (it did not parse cleanly, so text is checked too)"; continue ;;
    $'\003') FIND_ACTIVE=""; PREV=$'\003'; PREV2=""; PREV3=""; PROG="?"; continue ;;
    $'\004'*) WHERE=${token#?}; LITERAL_ONLY=""; case "$WHERE" in $'\005'*) LITERAL_ONLY=1; WHERE=${WHERE#?} ;; esac; continue ;;
  esac
  # A SINGLY negated find predicate whose operand is a WILDCARD can only SHRINK the set of files touched, so it is never a read target; a second negation makes it positive again and a literal operand is indistinguishable from a filename — see README § Why a negated find predicate is exempt.
  if [ -n "$FIND_ACTIVE" ] && [ -z "$NO_EXEMPT" ] \
     && [[ $PREV =~ ^-(i?path|i?name|i?wholename|i?regex)$ ]] \
     && { [ "$PREV2" = "-not" ] || [ "$PREV2" = "!" ]; } \
     && [ "$PREV3" != "-not" ] && [ "$PREV3" != "!" ] \
     && [[ $token == *[*?]* ]]; then
    PREV3=$PREV2; PREV2=$PREV; PREV=$token
    continue
  fi
  # Armed only by a find in command position, so prose that merely names find — a comment, a flag value, a body read as data — cannot open the exemption for a later word.
  if [[ $token =~ $RE_FIND_TOK ]] && [[ -z $PREV || $PREV =~ $RE_CMD_START ]]; then
    FIND_ACTIVE=1
  elif [[ $token =~ $RE_READER_TOK ]]; then
    FIND_ACTIVE=""
  fi
  PREV3=$PREV2; PREV2=$PREV; PREV=$token
  # The first word after a separator that is neither a wrapper nor an assignment names the program; after a substitution it stays unknown.
  if [[ $token =~ $RE_SEP_TOK ]]; then
    PROG=""
  elif [ -z "$PROG" ] && [[ ! $token =~ $RE_CMD_START ]] && [[ ! $token =~ $RE_ASSIGN_TOK ]]; then
    PROG=${token##*/}
  fi
  # see README § Why a kubectl output template is exempt
  if [ -z "$NO_EXEMPT" ] && [ "$PROG" = kubectl ] \
     && { { [[ $PREV2 =~ ^(-o|--output)$ ]] && [[ $token =~ $RE_KUBE_TEMPLATE ]]; } || [[ $token =~ $RE_KUBE_TEMPLATE_FLAG ]]; }; then
    continue
  fi
  # Every token is scanned, grep's pattern operand included: modelling grep's flag grammar to spare that one token cost four fail-opens — see README § Why the pattern operand is scanned.
  case "$token" in
    --*=*) token=${token#*=}; FLAT_TOKEN=${FLAT_TOKEN#*=} ;;
  esac
  BRACE_ALTS=("$token")
  if [[ $token == *\{*\}* ]] && [[ $token == *,* || $token == *..* ]]; then
    # shellcheck disable=SC2031  # past the budget a word asks if a stem, or its start, remains once braces and commas go; tr keeps that linear on 3.2
    if ! expand_braces "$token"; then
      FLAT=$FLAT_TOKEN; [ -n "$FLAT_READ" ] || FLAT=$(export LC_ALL=C; printf '%s' "$token" | tr -d '{},') || FLAT=${token//$SG_BRACE_CHARS/}
      if [[ $FLAT =~ $RE_STEM_ANY ]] || [[ $FLAT =~ $RE_STEM_FRAG ]] || [[ $FLAT =~ $RE_KEY_PATH ]]; then
        ask_read "$token" "a brace list or range this gate could not expand within its budget, holding what looks like a secret file name" "ask:wildcard"
      fi
      BRACE_ALTS=("$token")
    fi
  fi
  for alt in "${BRACE_ALTS[@]}"; do
    # A word this long gets one linear match; the trims below run in quadratic time on bash 3.2 and can outlast the hook timeout.
    if [ ${#alt} -gt 4096 ]; then
      [[ $alt =~ $RE_STEM_ANY ]] || [[ $alt =~ $RE_KEY_PATH ]] && ask_read "$token" "a word too long to judge by its last path component, holding what looks like a secret file name" "ask:wildcard"
      continue
    fi
    # Trailing slashes come off first, so a directory argument still yields the name basename would have given it.
    BASENAME=${alt%"${alt##*[!/]}"}
    BASENAME=${BASENAME##*/}
    # A glob is not expanded here, so judge the pattern by what it could match rather than by the hook's cwd, which is not necessarily the command's.
    if [[ $alt =~ $RE_GLOB ]]; then
      [ -n "$LITERAL_ONLY" ] && continue
      STEM=${alt//\*/}; STEM=${STEM//\?/}
      # Only the text after the last = names a file: an assignment, a URL query or a flag value.
      GLOB_BASE=${alt##*=}; GLOB_BASE=${GLOB_BASE%"${GLOB_BASE##*[!/]}"}; GLOB_BASE=${GLOB_BASE##*/}
      if [[ $STEM =~ $RE_KEY_PATH ]] || { [[ ! $GLOB_BASE =~ $RE_NOT_PATH ]] && [[ ! $GLOB_BASE =~ $RE_QUERY_EXPR ]] \
           && [[ $GLOB_BASE =~ $RE_GLOB_SECRET ]]; }; then
        ask_read "$token" "an unresolved wildcard that could match a secret file; $(describe_glob "$token")" "ask:wildcard"
      fi
      continue
    fi
    # see README § Which literal names are asked about
    [[ $BASENAME =~ $RE_QUERY_EXPR ]] && [[ ! $alt =~ $RE_KEY_PATH ]] && continue
    if [[ $BASENAME =~ $RE_ENV ]] && [[ ! $BASENAME =~ $RE_ENV_SAMPLE ]]; then
      ask_read "$token" "it looks like a live env file, which usually holds secrets"
    fi
    # Case-insensitive throughout: the matchers name files, and the filesystem this runs on is usually case-insensitive too.
    if [[ $BASENAME =~ $RE_KEY_NAME ]] || [[ $alt =~ $RE_KEY_PATH ]]; then
      ask_read "$token" "it looks like a private key or kubeconfig"
    fi
  done
done <"$TOKENS_FILE" 4<"${FLAT_FILE:-/dev/null}"
[ -n "$SCAN_EOF" ] || ask "READ-SECRET GUARD: this command stopped the inspection partway, so its arguments were not all checked — confirm before any secret file it reads enters context/transcript." "ask:aborted"

exit 0
}
# Run, or sourced by anything but the authority's loader, the stage runs one function level down, so an inherited FUNCNEST gets that level back.
if [ -z "${SGA_LOADING:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then case ${FUNCNEST:-} in '' | 0 | *[!0-9]*) ;; *) FUNCNEST=$((10#$FUNCNEST + 1)) ;; esac; sg_read_secret_guard_bash ${1+"$@"}; fi
