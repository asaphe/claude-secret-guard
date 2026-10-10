#!/usr/bin/env bash
# PreToolUse Bash hook, mirrors read-secret-guard.sh's basename gate for cat/head/tail/less/grep readers.

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
[ -z "$CMD" ] && exit 0

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"

# Matched anywhere inside a segment rather than after a fixed wrapper list, which would go silent on any prefix the list omits (timeout, nice, stdbuf, ionice, doas).
SEP=$';&|()`"\''
# Normalized like the mask guard's predicates, or a quoted reader name (`"cat" secrets.pem`) splits into its own segment with no trailing space and matches nothing.
GATE_CMD=$(normalize_cmd "$CMD")
# A leading slash admits the same reader named by path, and grep carries no recursive-flag condition: -r decides how many files are read, never whether the one named is a key — see README § Why grep is gated unconditionally.
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
    # A comment and a heredoc body are cut out as pieces of their own, never dropped, and kept in text order: a quote inside one otherwise pairs with one in the code around it, and the find exemption reads tokens in sequence — see README § Reader-gate words and filenames.
    my $pieces = sub {
      my ($s) = @_;
      my $code = "";
      my (@out, @pend);
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
            $d =~ s/\\(.)/$1/g;
            $d =~ s/["\x27]//g;
            push @pend, [$d, $strip];
            $code .= $m;
            $i += length($m) - 1;
            next;
          }
          if ($c eq "\n" && @pend) {
            push @out, ["code", $code . $c];
            $code = "";
            my $p = $i + 1;
            for my $h (@pend) {
              my ($d, $strip, $body) = (@$h, "");
              while ($p < $n) {
                my $e = index($s, "\n", $p);
                $e = $n - 1 if $e < 0;
                my $line = substr($s, $p, $e - $p + 1);
                $body .= $line;
                $p = $e + 1;
                $line =~ s/\n\z//;
                $line =~ s/^\t+// if $strip;
                last if $line eq $d;
              }
              push @out, ["bod", $body];
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
    # Text the shell runs as a command line is split the way the shell splits it, and other quoted text, such as a grep or jq pattern, stays one word — see README § Reader-gate words and filenames.
    my $tok;
    $tok = sub {
      my ($s, $depth) = @_;
      my (@w, @own, @run);
      for my $p ($pieces->($s)) {
        my ($kind, $text) = @$p;
        # A heredoc body is tokenized like any command line, since a shell may be what reads it, at the same depth because each body is shorter than its parent; its own -c, eval and $(...) were followed in that call, and the marker after it keeps a find inside it from exempting anything later.
        my @pw = $kind eq "bod" ? ($tok->($text, $depth), "\x01body-end") : $split->($text);
        push @w, @pw;
        push @own, ($kind ne "bod") x @pw;
      }
      return @w if $depth > 3;
      # The operand of a shell -c or of eval and the body of a $(...) substitution are command lines too: bash -c "cat k.pem | head". The shell must own the -c, or a jq -c filter would be split; backticks are left whole because Markdown code spans in a python heredoc use the same character.
      my $SHELL = qr{(?:^|/)(?:ba|z|k|da|a|c|tc|mk|fi)?sh$};
      for my $i (grep { $own[$_] } 0 .. $#w) {
        push @run, $tok->($w[$i], $depth + 1)
          if $i && (($w[$i - 1] =~ /^-[A-Za-z]*c[A-Za-z]*$/ && grep { $_ =~ $SHELL } @w[($i > 5 ? $i - 5 : 0) .. $i - 2]) || $w[$i - 1] =~ m{(?:^|/)eval$});
        push @run, $tok->($1, $depth + 1) while $w[$i] =~ /\$\(((?:[^()]++|\((?1)\))*)\)/g;
      }
      return (@w, @run);
    };
    my @w = $tok->($cmd, 0);
    # An unbalanced quote used to expose every word through a bare split of the whole command, and with heredoc bodies masked that quote could sit anywhere, so the split stays, first and unaltered, whenever the whole or any piece will not parse.
    my @whole = shellwords($cmd);
    my @bare = (@whole && !$fell) ? () : map { my $t = $_; $t =~ s/["\x27]//g; $t } ($cmd =~ /\S+/g);
    # Punctuation survives tokenizing glued to the filename — $'"'"'…'"'"', substitution syntax, and a trailing ; or & each defeat the end-anchored suffix patterns.
    @w = map { my $t = $_; $t =~ s/^\$//; $t =~ s/[()`]//g; $t =~ s/[;&]+$//; $t =~ s/\$+$//; $t } @w;
    # A redirect glues its target to the reader, and the basename patterns are anchored: cat<.env is one token that matches nothing.
    @w = grep { length } map { split /[<>]+/, $_ } @w;
    @w = (@bare, @w);
    print join("\0", @w), "\0" if @w;
  '
}

# Fails closed like the jq check above: with nowhere to tokenize into, no argument was ever inspected.
TOKENS_FILE=$(mktemp) || ask "READ-SECRET GUARD: could not create the temporary file this gate tokenizes into, so the arguments of this read were never inspected — confirm before its contents enter context/transcript."
trap 'rm -f "$TOKENS_FILE"' EXIT
tokenize "$CMD" >"$TOKENS_FILE" 2>/dev/null
# A missing perl empties this, which would make every read silent — fall back to a bare split so the gate still asks.
if [ ! -s "$TOKENS_FILE" ]; then
  # The trailing newline is load-bearing: without it the final token has no NUL and `read -d ''` discards it at EOF.
  { printf '%s' "$CMD" | tr -d '"'"'"'' | tr -s ' \t\n<>' '\n'; printf '\n'; } | tr '\n' '\0' >"$TOKENS_FILE"
fi

# Matched with bash's own regex engine rather than a grep per test: this loop runs before every Bash call, and the forks it used to spend cost more than the scan it performs.
shopt -s nocasematch
RE_GLOB='[*?]'
RE_GLOB_SECRET='^\.env|^[*?]+$'
RE_SSH_GLOB='(^|/)\.ssh/'
RE_ENV='^-*\.env(\..+)?$'
RE_ENV_SAMPLE='^-*\.env\.(example|sample|template)$'
RE_KEY_NAME='\.(pem|key|p12|pfx)$|^-*id_(rsa|ed25519|ecdsa|dsa)$|^-*kubeconfig$'
RE_KEY_PATH='\.kube/config$|(^|/)\.ssh(/|$)'

# The exemption below is armed by a `find` TOKEN and disarmed by the next reader token, so it covers only the window in which find's own grammar governs — see README § Why a negated find predicate is exempt.
RE_FIND_TOK='^([A-Za-z_][A-Za-z0-9_]*=)?\$?(.*/)?find$'
RE_READER_TOK='^(.*/)?(cat|head|tail|less|more|grep)$'
FIND_ACTIVE=""
PREV=""
PREV2=""
PREV3=""

while IFS= read -r -d '' token; do
  if [ "$token" = $'\001body-end' ]; then
    FIND_ACTIVE=""; PREV=""; PREV2=""; PREV3=""
    continue
  fi
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
  # Every token is scanned, grep's pattern operand included: modelling grep's flag grammar to spare that one token cost four fail-opens — see README § Why the pattern operand is scanned.
  case "$token" in
    --*=*) token=${token#*=} ;;
  esac
  # Trailing slashes come off first, so a directory argument still yields the name basename would have given it.
  BASENAME=${token%"${token##*[!/]}"}
  BASENAME=${BASENAME##*/}
  # A glob is not expanded here, so judge the pattern by what it could match rather than by the hook's cwd, which is not necessarily the command's.
  if [[ $token =~ $RE_GLOB ]] && { [[ $BASENAME =~ $RE_GLOB_SECRET ]] || [[ $token =~ $RE_SSH_GLOB ]]; }; then
    ask "READ-SECRET GUARD: $token is an unresolved glob that could match a secret file — $(describe_glob "$token"). Confirm before its contents enter context/transcript."
  fi
  if [[ $BASENAME =~ $RE_ENV ]] && [[ ! $BASENAME =~ $RE_ENV_SAMPLE ]]; then
    ask "READ-SECRET GUARD: $BASENAME looks like a live env file — confirm before its contents enter context/transcript."
  fi
  # Case-insensitive throughout: the matchers name files, and the filesystem this runs on is usually case-insensitive too.
  if [[ $BASENAME =~ $RE_KEY_NAME ]] || [[ $token =~ $RE_KEY_PATH ]]; then
    ask "READ-SECRET GUARD: $BASENAME looks like a private key or kubeconfig — confirm before its contents enter context/transcript."
  fi
done <"$TOKENS_FILE"

exit 0
