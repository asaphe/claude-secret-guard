#!/usr/bin/env bash
# Blocks a raw `op read <uri>` or single-secret `aws secretsmanager get-secret-value --secret-id <id>` call and suggests the masked wrapper instead, so the value never has to reach the tool_result/transcript in the first place — see README § Masked-cache wrappers.

INPUT=$(cat)
# An empty or non-object payload parses without error and yields an empty command, which every check below reads as "nothing to inspect" — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "SECRET-MASK GUARD: cannot read the hook payload — it is empty, not a JSON object, or jq is missing. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi
# Blocks rather than allows: jq failing here yields an empty value that every check below reads as "nothing to inspect", silently disarming the guard.
if ! CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null); then
  echo "SECRET-MASK GUARD: cannot read the hook payload — jq is missing or the JSON did not parse. Blocking: the guard cannot confirm this command is safe." >&2
  exit 2
fi

if [ -z "$CMD" ]; then
  exit 0
fi

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
STRIPPED=$(strip_cmd "$CMD")
# Unreachable while strip_cmd degrades to its input rather than to empty, and kept as the backstop for if that ever stops holding: an empty scan matches no predicate and would read as "nothing to inspect".
if [ -z "$STRIPPED" ]; then
  echo "SECRET-MASK GUARD: the command text came back empty from normalization, so it could not be checked for a raw secret read. Refusing it rather than running it unguarded." >&2
  exit 2
fi
CMD="$STRIPPED"

# Matched on normalized text: a continuation, an escape or a quote inside the phrase changes the bytes without changing what the shell runs.
SCAN=$(normalize_cmd "$CMD")

# Anchored to the subcommand position rather than to "anywhere after op": only op's own global flags and their values may precede it, or a word that happens to be spelled like a subcommand reads as one. The flag names are a closed set, so `git log --grep op --grep read` is not an op invocation.
# A value may be a quoted run holding whitespace — `--config "/Application Support/op"` is an ordinary spelling, and a matcher that stopped at the first space silenced every predicate below.
OP_PRE='(^|[^[:alnum:]_-])op["'"'"']?([[:space:]]+(--(account|config|session|format|encoding|cache|debug|no-color|iso-timestamps)([[:space:]=]+("[^"]*"|'"'"'[^'"'"']*'"'"'|[^-[:space:]][^[:space:]]*))?|-[A-Za-z]+([[:space:]]+("[^"]*"|'"'"'[^'"'"']*'"'"'|[^-[:space:]][^[:space:]]*))?))*[[:space:]]+'

# No wrapper-path early exit: a legitimate wrapper call does not match the fetch patterns below anyway, so all it could exempt was text that merely named the path — a trailing `# see scripts/op-cache.sh` used to clear the whole guard.
# --- op read <uri> ---
# Not conditioned on the absence of `op item get` (one command can carry both), and word-anchored so `stop read` and `loop read` are not an op invocation.
if printf '%s\n' "$SCAN" | grep -qE "${OP_PRE}read([[:space:]]|\$)"; then
  URI=$(printf '%s\n' "$CMD" | grep -oE 'op://[^ "'"'"']+' | head -1)
  if [ -n "$URI" ]; then
    echo "SECRET-MASK GUARD: raw 'op read' would put the value in this tool_result/transcript. Use the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask '$URI' — then reference the value downstream via \$(cat <the printed cache path>), never the literal." >&2
  else
    echo "SECRET-MASK GUARD: raw 'op read' would put the value in this tool_result/transcript. Use \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask <uri> instead, then reference the cached file downstream — never the literal value." >&2
  fi
  exit 2
fi

# --- the other 1Password subcommands that print a value ---
# &> and >& are redirect operators, not command separators, so they are hidden from the split and restored inside the segment.
# Restored through a variable, never as a literal: bash 5.2 made a bare & in a replacement expand to the matched text, so the literal spelling silently produces different output on either side of that release.
SG_AMPGT='&>'
SG_SQ="'"
SG_GTAMP='>&'
SEG_SRC=${CMD//&>/$'\001'}
SEG_SRC=${SEG_SRC//>&/$'\002'}
# Decided per segment: the flag that makes each of these dangerous has to belong to the same command, or `op item get X && op-cache.sh --reveal <uri>` reads as a revealing item-get.
# Split on the raw text and normalized per segment, so the two views stay paired and the flag checks below read a segment nothing has rewritten.
while IFS= read -r SEG_RAW; do
  SEG_RAW=${SEG_RAW//$'\001'/"$SG_AMPGT"}
  SEG_RAW=${SEG_RAW//$'\002'/"$SG_GTAMP"}
  SEG=$(normalize_cmd "$SEG_RAW")
  if printf '%s\n' "$SEG" | grep -qE "${OP_PRE}item[[:space:]]+get([[:space:]]|\$)" \
     && printf '%s\n' "$SEG" | grep -qE '(^|[[:space:]])--(reveal|otp)([[:space:]=]|$)'; then
    echo "SECRET-MASK GUARD: 'op item get' with --reveal or --otp prints the concealed value into this tool_result/transcript. Fetch the one field you need as a secret reference through the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask 'op://<vault>/<item>/<field>' — or drop the flag and the field stays concealed." >&2
    exit 2
  fi

  if printf '%s\n' "$SEG" | grep -qE "${OP_PRE}run([[:space:]]|\$)" \
     && printf '%s\n' "$SEG" | grep -qE '(^|[[:space:]])--no-masking([[:space:]=]|$)'; then
    echo "SECRET-MASK GUARD: 'op run --no-masking' turns off the masking op applies to the subprocess's stdout and stderr, so anything the command echoes lands in this tool_result/transcript. Drop the flag." >&2
    exit 2
  fi

  printf '%s\n' "$SEG" | grep -qE "${OP_PRE}(document[[:space:]]+get|inject)([[:space:]]|\$)" || continue
  # Only what follows the subcommand can be its own output flag; an -o earlier on the line belongs to another command, as in `ssh -o X host "op document get k"`.
  # Cut where the anchored pattern matched, not at the first literal spelling: `cat inject.tpl | op inject -i -` cut inside the filename, and the tail then held cat's pipe rather than op's own.
  # Read from the raw segment with quote state tracked: normalization deletes the quotes that tell a redirect operator apart from an argument merely spelled like one, and a regex cannot pair quotes — blanking them with one ate the --reveal flag two checks above.
  # Only the characters that could FORM an operator are neutralized inside a quoted run, so `> "/dev/stdout"` still names stdout while `--tags "-o /x"` names nothing; a run that is exactly a dash is the stdout operand and survives.
  SEG_ONE=$(printf '%s' "$SEG_RAW" | tr -s '[:space:]' ' ')
  SEG_QSUB="[\"$SG_SQ]?"
  SEG_PAT="${OP_PRE}${SEG_QSUB}(document${SEG_QSUB}[[:space:]]+${SEG_QSUB}get|inject)${SEG_QSUB}"
  SEG_TAIL=$(printf '%s' "$SEG_ONE" | awk -v pat="$SEG_PAT" -v sq="'" '
    {
      if (!match($0, pat)) exit
      tail = substr($0, RSTART + RLENGTH)
      out = ""; q = ""; buf = ""
      for (i = 1; i <= length(tail); i++) {
        c = substr(tail, i, 1)
        if (q == "") {
          if (c == "\"" || c == sq) { q = c; buf = ""; continue }
          if (c == "#" && (i == 1 || substr(tail, i - 1, 1) == " ")) break
          out = out c
        } else if (c == q) {
          q = ""
          if (buf != "-") gsub(/[-<>&|#]/, "x", buf)
          out = out " " buf " "
          buf = ""
        } else buf = buf c
      }
      if (q != "") { gsub(/[-<>&|#]/, "x", buf); out = out " " buf }
      print out
    }')
  # strip_cmd's own placeholder carries a >> that is not a redirect.
  SEG_TAIL=${SEG_TAIL//<<STRIPPED_HEREDOC>>/}
  # Named before any destination is honoured: stdout under another name is not somewhere else for the value to go.
  if printf '%s' "$SEG_TAIL" | grep -qE '(--out-file|-o|&?>>?|>&)[[:space:]=]*["'"'"']?(/dev/(stdout|fd/[0-9]+)|-)["'"'"']?([[:space:]]|$)'; then
    :
  # A pipe or a redirect that names a file sends the value somewhere the transcript does not see. `2>` does not, and `>&N`/`>&-` duplicate or close a descriptor rather than naming a file — but `&>f`, `&>>f` and `>&f` do reach one.
  elif printf '%s' "$SEG_TAIL" | grep -qE '(^|[[:space:]])(--out-file([[:space:]=]|$)|-o([[:space:]=/]|$))' \
    || printf '%s' "$SEG_TAIL" | grep -qE '\|' \
    || printf '%s' "$SEG_TAIL" | grep -qE '(^|[[:space:]])(&?>>?|1>>?)[[:space:]]*[^&[:space:]]' \
    || printf '%s' "$SEG_TAIL" | grep -qE '(^|[[:space:]])>&[[:space:]]*[^0-9&[:space:]-]'; then
    continue
  fi
  echo "SECRET-MASK GUARD: 'op document get' and 'op inject' print the resolved secret to stdout, which is this tool_result/transcript. Give it somewhere else to go — --out-file <path> (op creates that file 0600), a redirect, or a pipe into whatever consumes it." >&2
  exit 2
done < <(printf '%s\n' "$SEG_SRC" | tr ';&' '\n')

# --- aws secretsmanager batch-get-secret-value (bulk fetch, many values at once) ---
if printf '%s\n' "$SCAN" | grep -qE '(^|[^[:alnum:]_-])(aws|rtk aws)[[:space:]]([^|;&]* )?secretsmanager[[:space:]]+batch-get-secret-value([[:space:]]|$)'; then
  echo "SECRET-MASK GUARD: raw 'batch-get-secret-value' would put every fetched value in this tool_result/transcript. Use the masked bulk reader instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/aws-batch-secrets.sh --filter <prefix> --values — prints names + byte-lengths only; add --reveal to opt into full values when genuinely needed." >&2
  exit 2
fi

# --- aws secretsmanager get-secret-value --secret-id <id> (single-secret only) ---
if printf '%s\n' "$SCAN" | grep -qE '(^|[^[:alnum:]_-])(aws|rtk aws)[[:space:]]([^|;&]* )?secretsmanager[[:space:]]+get-secret-value([[:space:]]|$)'; then
  SECRET_ID=$(printf '%s\n' "$CMD" | grep -oE -- '--secret-id[[:space:]=]+[^[:space:]]+' | sed -E 's/^--secret-id[[:space:]=]+//' | tr -d '"'"'"'')
  if [ -n "$SECRET_ID" ]; then
    echo "SECRET-MASK GUARD: raw 'get-secret-value' would put the value in this tool_result/transcript. Use the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/sm-cache.sh --mask '$SECRET_ID' — then reference the value downstream via \$(cat <the printed cache path>) or jq against it, never the literal." >&2
  else
    echo "SECRET-MASK GUARD: raw 'get-secret-value' would put the value in this tool_result/transcript. Use \"${CLAUDE_PLUGIN_ROOT}\"/scripts/sm-cache.sh --mask <secret-id> instead, then reference the cached file downstream — never the literal value." >&2
  fi
  exit 2
fi

# --- a fetch inside a script this command runs: every predicate above reads the command line only, so `bash deploy.sh` or `source env.sh` hides an ordinary fetch one file away — see README § Fetches inside an invoked script.

# Names the script each segment runs, from command position only: a path merely passed as an argument is data, and scanning those is the false-positive class the predicates above already refuse.
sg_invoked_scripts() {
  printf '%s\n' "$1" | awk '
    function base(p,   a, n) { n = split(p, a, "/"); return a[n] }
    # Whitespace inside a quoted run is not a word break, and a path spelled with one was silently skipped.
    function protect(s,   out, i, c, q) {
      out = ""; q = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (q == "") { if (c == "\"" || c == "'"'"'") q = c }
        else if (c == q) q = ""
        else if (c == " " || c == "\t") c = SOH
        out = out c
      }
      return out
    }
    BEGIN { SOH = sprintf("%c", 1) }
    {
      s = protect($0)
      gsub(/&&|\|\|/, ";", s)
      n = split(s, seg, /[;&|()\n]/)
      for (i = 1; i <= n; i++) {
        c = seg[i]
        # None of these change which word is the command being run, and neither does a flag on one, but an operand-taking flag has to take its operand with it or the operand reads as the command.
        while (match(c, /^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*|sudo|env|exec|time|nohup)([[:space:]]+|$)/)) {
          p = substr(c, RSTART, RLENGTH); gsub(/[[:space:]]/, "", p)
          c = substr(c, RSTART + RLENGTH)
          while (match(c, /^[[:space:]]*(--[A-Za-z0-9-]+=[^[:space:]]*|-[-A-Za-z0-9]+)([[:space:]]+|$)/)) {
            f = substr(c, RSTART, RLENGTH); gsub(/[[:space:]]/, "", f)
            c = substr(c, RSTART + RLENGTH)
            if (f ~ /=/) continue
            need = 0
            if (f ~ /^--/) {
              if ((p == "sudo" && f ~ /^--(user|group|prompt|host|role|type|chdir|close-from|chroot|command-timeout|login-class|other-user)$/) ||
                  (p == "env"  && f ~ /^--(unset|chdir|split-string)$/) ||
                  (p == "time" && f ~ /^--(format|output)$/)) need = 1
            } else {
              # getopt: the first operand-taking letter takes the rest of the token when there is one, so -uroot carries its own operand and the next word is still the command.
              body = substr(f, 2)
              for (ci = 1; ci <= length(body); ci++) {
                ch = substr(body, ci, 1)
                if ((p == "sudo" && index("ughprtcCUDRT", ch)) || (p == "env" && index("uCS", ch)) ||
                    (p == "time" && index("fo", ch)) || (p == "exec" && index("a", ch))) {
                  if (ci == length(body)) need = 1
                  break
                }
              }
            }
            if (need)
              sub(/^[[:space:]]*[^[:space:]]+([[:space:]]+|$)/, "", c)
          }
        }
        nf = split(c, w, /[[:space:]]+/)
        k = 0
        for (j = 1; j <= nf; j++) if (w[j] != "") { k = j; break }
        if (k == 0) continue
        b = base(w[k])
        if (b ~ /^(ba|z|k|da)?sh$/ || w[k] == "source" || w[k] == ".") {
          skip = 0
          for (j = k + 1; j <= nf; j++) {
            if (w[j] == "") continue
            if (skip) { skip = 0; continue }
            if (w[j] ~ /^--/) {
              # Only these two long forms take a separate operand; every other one is a switch, and an =-joined operand carries its own.
              if (w[j] ~ /^--(rcfile|init-file)$/) skip = 1
              continue
            }
            if (w[j] ~ /^-/) {
              # getopt over the cluster, not an exact-token test: -n parses the file without running any of it, while o and c take an operand — the rest of the token when there is one, else the next word, so -euo takes pipefail and the script is the word after it.
              obody = substr(w[j], 2); noexec = 0
              for (oi = 1; oi <= length(obody); oi++) {
                och = substr(obody, oi, 1)
                if (och == "n") { noexec = 1; break }
                if (och == "o" || och == "c") { if (oi == length(obody)) skip = 1; break }
              }
              if (noexec) break
              continue
            }
            gsub(SOH, " ", w[j]); print w[j]; break
          }
        } else if (w[k] ~ /^(\.\.?\/|\/|~\/)/) { gsub(SOH, " ", w[k]); print w[k] }
      }
    }' 2>/dev/null | sort -u
}

# Only the spellings a shell resolves without running anything: a path assembled from an expansion this cannot see stays unresolved, and an unresolved path is skipped rather than guessed at.
sg_resolve() {
  local _p="$1" _base="$2"
  _p=${_p//\"/}
  _p=${_p//\'/}
  # shellcheck disable=SC2016 # literal: these match the text "$HOME" as a script spells it, not its value
  # Prefix forms, never a pattern replacement: bash 5.2 expands a bare & in the replacement to the matched text, and quoting it to stop that is taken literally by 3.2, so the same line resolves differently on each.
  case "$_p" in
    \~/*) _p="$HOME/${_p#\~/}" ;;
    '${HOME}'/*) _p="$HOME/${_p#'${HOME}'/}" ;;
    '$HOME'/*) _p="$HOME/${_p#'$HOME'/}" ;;
    SG_BASEDIR/*) _p="$_base/${_p#SG_BASEDIR/}" ;;
    SG_BASEDIR) _p="$_base" ;;
  esac
  case "$_p" in
    /*) printf '%s' "$_p" ;;
    *) printf '%s/%s' "$_base" "$_p" ;;
  esac
}

# A full-line comment is prose about a command, not a command — the same distinction the predicates above already draw for a command that only describes a guarded read.
sg_script_body() {
  [ -f "$1" ] || return 1
  [ -r "$1" ] || return 1
  [ "$(wc -c <"$1" 2>/dev/null || echo 0)" -le 262144 ] || return 1
  # -I yields nothing for a binary rather than reading it as text, and a binary is not a script.
  grep -Iv '^[[:space:]]*#' "$1" 2>/dev/null
}

SG_DEPTH=${SG_BODY_DEPTH:-0}
# Command position, in bash and without a subprocess: this runs on every Bash call, and a command that starts no script has to cost nothing to clear.
SG_PFX='([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*|sudo|env|exec|time|nohup|-[^[:space:]]*([[:space:]]+[^-[:space:]][^[:space:]]*)?)[[:space:]]+'
SG_INV='(^|[[:space:];&|(])([^[:space:];&|()]*/)?((ba|z|k|da)?sh|source)[[:space:]]|(^|[[:space:];&|(])\.[[:space:]]|(^|[;&|(]|&&|\|\|)[[:space:]]*('"$SG_PFX"')*(\.{1,2}/|/|~/)'
# Newlines become separators for the gate test only: bash anchors =~ to the string rather than the line, so a direct-path run on line 2 matched nothing, and a literal newline cannot go in the pattern because grep -E reads one as a pattern separator and the bracket it sits in would split across two.
SG_GATE=${CMD//$'\n'/;}
# The invoked script, then what that script sources: deeper needs a case where a sourced file's own sourced file carries the fetch, and each level costs a scan of every candidate.
if [ "$SG_DEPTH" -lt 2 ] && [[ $SG_GATE =~ $SG_INV ]]; then
  SG_BASE=${SG_BODY_BASE:-$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null)}
  [ -n "$SG_BASE" ] || SG_BASE=$PWD
  SG_TEXT=$CMD
  # Collapsed to one token first: the whitespace inside the substitution would otherwise split the sibling path it builds into two words.
  if [[ $CMD == *dirname* || $CMD == *BASH_SOURCE* ]]; then
    SG_TEXT=$(printf '%s' "$CMD" | sed -E 's/\$\((cd[[:space:]]+)?dirname[^)]*\)/SG_BASEDIR/g; s/\$\{(BASH_SOURCE(\[0\])?|0)%\/\*\}/SG_BASEDIR/g' 2>/dev/null) || SG_TEXT=$CMD
  fi
  # This plugin's own tree is exempt by resolved path: the masked wrappers perform the fetch on purpose and mask what they print, and the tests carry guarded command text as data. A path comparison, so a comment naming one of these files cannot claim the exemption the way a text match would.
  SG_OWN=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd -P)

  # Guarded on the root resolving: without it the exemption below cannot fire and the scan would block this plugin's own wrappers, so losing the scan is the better of the two failures.
  while [ -n "$SG_OWN" ] && IFS= read -r SG_TOK; do
    [ -n "$SG_TOK" ] || continue
    SG_FILE=$(sg_resolve "$SG_TOK" "$SG_BASE")
    [ -f "$SG_FILE" ] || continue
    [ -r "$SG_FILE" ] || continue
    SG_DIR=$(cd "$(dirname "$SG_FILE")" 2>/dev/null && pwd -P) || continue
    case "$SG_DIR" in "$SG_OWN" | "$SG_OWN"/*) continue ;; esac
    SG_BODY=$(sg_script_body "$SG_FILE") || continue
    [ -n "$SG_BODY" ] || continue
    # Kept: lines naming a guarded tool, and lines that invoke another script — without the second class the level below is never reached. One normalization for the whole file, because re-entering the guard on every line of a script costs a subprocess per line of it.
    SG_BODY=$(normalize_cmd "$SG_BODY" | grep -E "(^|[^[:alnum:]_-])(op|secretsmanager)([^[:alnum:]_-]|\$)|$SG_INV")
    [ -n "$SG_BODY" ] || continue
    if ! SG_PAYLOAD=$(jq -nc --arg c "$SG_BODY" '{tool_input:{command:$c}}' 2>/dev/null); then
      echo "SECRET-MASK GUARD: $SG_FILE names a guarded tool but its contents could not be handed to the checker — jq failed. Blocking: the guard cannot confirm this script is free of a raw secret read." >&2
      exit 2
    fi
    # Re-entered rather than re-implemented: a second copy of the predicates is what lets a widening reach the command line and not the file, the same argument that put the shape pattern in one place.
    SG_WHY=$(printf '%s' "$SG_PAYLOAD" | SG_BODY_DEPTH=$((SG_DEPTH + 1)) SG_BODY_BASE="$SG_DIR" bash "${BASH_SOURCE[0]}" 2>&1 >/dev/null)
    SG_RC=$?
    if [ "$SG_RC" -ne 0 ]; then
      echo "SECRET-MASK GUARD: $SG_FILE performs a raw secret read, so running it would put the value in this tool_result/transcript. The calling command cannot mask that — change the fetch inside that file. What matched there: ${SG_WHY#SECRET-MASK GUARD: }" >&2
      exit 2
    fi
  done < <(sg_invoked_scripts "$SG_TEXT")
fi

exit 0
