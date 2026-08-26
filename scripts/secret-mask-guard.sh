#!/usr/bin/env bash
# Blocks a raw `op read <uri>` or single-secret `aws secretsmanager get-secret-value --secret-id <id>` call and suggests the masked wrapper instead, so the value never has to reach the tool_result/transcript in the first place — see README § Masked-cache wrappers.

INPUT=$(cat)

# A guard that cannot read its own input has not cleared the command — see README § Failing closed.
if [ -z "$INPUT" ] || ! printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1; then
  echo "SECRET-MASK GUARD: hook input is empty or not valid JSON, so this command could not be checked for a raw secret read. Refusing it rather than running it unguarded — verify 'jq' is installed and on PATH." >&2
  exit 2
fi

CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')

if [ -z "$CMD" ]; then
  exit 0
fi

# shellcheck source=scripts/strip-cmd.sh
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

# Anchored to the subcommand position rather than to "anywhere after op": only op's own global flags and their values may precede it, or a word that happens to be spelled like a subcommand reads as one. The flag names are a closed set, so an unrelated command carrying both words in flag values is not an op invocation.
# A value may be a quoted run holding whitespace — `--config "/Application Support/op"` is an ordinary spelling, and a matcher that stopped at the first space silenced every predicate below.
OP_PRE='(^|[^[:alnum:]_-])op["'"'"']?([[:space:]]+(--(account|config|session|format|encoding|cache|debug|no-color|iso-timestamps)([[:space:]=]+("[^"]*"|'"'"'[^'"'"']*'"'"'|[^-[:space:]][^[:space:]]*))?|-[A-Za-z]+([[:space:]]+("[^"]*"|'"'"'[^'"'"']*'"'"'|[^-[:space:]][^[:space:]]*))?))*[[:space:]]+'

# No wrapper-path early exit: a legitimate wrapper call does not match the fetch patterns below anyway, so all it could exempt was text that merely named the path — a trailing `# see scripts/op-cache.sh` used to clear the whole guard.
# --- op read <uri> ---
# Not conditioned on the absence of `op item get`: one command can carry both, and the raw read still needs blocking.
if echo "$SCAN" | grep -qE "${OP_PRE}read([[:space:]]|\$)"; then
  URI=$(echo "$CMD" | grep -oE 'op://[^ "'"'"']+' | head -1)
  if [ -n "$URI" ]; then
    echo "SECRET-MASK GUARD: raw 'op read' would put the value in this tool_result/transcript. Use the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask '$URI' — then reference the value downstream via \$(cat <the printed cache path>), never the literal." >&2
  else
    echo "SECRET-MASK GUARD: raw 'op read' would put the value in this tool_result/transcript. Use \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask <uri> instead, then reference the cached file downstream — never the literal value." >&2
  fi
  exit 2
fi

# --- aws secretsmanager batch-get-secret-value (bulk fetch, many values at once) ---
if echo "$SCAN" | grep -qE '(^|[^[:alnum:]_-])(aws|rtk aws)[[:space:]]([^|;&]* )?secretsmanager[[:space:]]+batch-get-secret-value([[:space:]]|$)'; then
  echo "SECRET-MASK GUARD: raw 'batch-get-secret-value' would put every fetched value in this tool_result/transcript. Use the masked bulk reader instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/aws-batch-secrets.sh --filter <prefix> --values — prints names + byte-lengths only; add --reveal to opt into full values when genuinely needed." >&2
  exit 2
fi

# --- aws secretsmanager get-secret-value --secret-id <id> (single-secret only) ---
# --- the other 1Password subcommands that print a value ---
# Decided per segment: the flag that makes each of these dangerous has to belong to the same command, or `op item get X && op-cache.sh --reveal <uri>` reads as a revealing item-get.
# &> and >& are redirect operators, not command separators, so they are hidden from the split and restored inside the segment.
# Restored through a variable, never as a literal: bash 5.2 made a bare & in a replacement expand to the matched text, so the literal spelling silently produces different output on either side of that release.
SG_AMPGT='&>'
SG_SQ="'"
SG_GTAMP='>&'
SEG_SRC=${CMD//&>/$'\001'}
SEG_SRC=${SEG_SRC//>&/$'\002'}
# Split on the raw text and normalized per segment, so the two views stay paired and the flag checks below read a segment nothing has rewritten.
while IFS= read -r SEG_RAW; do
  SEG_RAW=${SEG_RAW//$'\001'/"$SG_AMPGT"}
  SEG_RAW=${SEG_RAW//$'\002'/"$SG_GTAMP"}
  SEG=$(normalize_cmd "$SEG_RAW")
  if echo "$SEG" | grep -qE "${OP_PRE}item[[:space:]]+get([[:space:]]|\$)" \
     && echo "$SEG" | grep -qE '(^|[[:space:]])--(reveal|otp)([[:space:]=]|$)'; then
    echo "SECRET-MASK GUARD: 'op item get' with --reveal or --otp prints the concealed value into this tool_result/transcript. Fetch the one field you need as a secret reference through the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/op-cache.sh --mask 'op://<vault>/<item>/<field>' — or drop the flag and the field stays concealed." >&2
    exit 2
  fi

  if echo "$SEG" | grep -qE "${OP_PRE}run([[:space:]]|\$)" \
     && echo "$SEG" | grep -qE '(^|[[:space:]])--no-masking([[:space:]=]|$)'; then
    echo "SECRET-MASK GUARD: 'op run --no-masking' turns off the masking op applies to the subprocess's stdout and stderr, so anything the command echoes lands in this tool_result/transcript. Drop the flag." >&2
    exit 2
  fi

  echo "$SEG" | grep -qE "${OP_PRE}(document[[:space:]]+get|inject)([[:space:]]|\$)" || continue
  # Only what follows the subcommand can be its own output flag; an -o earlier on the line belongs to another command, as in `ssh -o X host "op document get k"`.
  # Cut where the anchored pattern matched, not at the first literal spelling: `cat inject.tpl | op inject -i -` cut inside the filename, and the tail then held cat's pipe rather than op's own.
  # Read from the raw segment with quote state tracked: normalization deletes the quotes that tell a redirect operator apart from an argument merely spelled like one, and a regex cannot pair quotes — blanking them with one ate the --reveal flag two checks above.
  SEG_ONE=$(printf '%s' "$SEG_RAW" | tr -s '[:space:]' ' ')
  SEG_QSUB="[\"$SG_SQ]?"
  SEG_PAT="${OP_PRE}${SEG_QSUB}(document${SEG_QSUB}[[:space:]]+${SEG_QSUB}get|inject)${SEG_QSUB}"
  # The alias check below must read the tail as written: blanking a quoted run turns "/dev/stdout" into filler, and the broader destination test then reads it as a real file.
  SEG_TAIL_RAW=$(printf '%s' "$SEG_ONE" | awk -v pat="$SEG_PAT" '{ if (match($0, pat)) print substr($0, RSTART + RLENGTH) }')
  SEG_TAIL=$(printf '%s' "$SEG_ONE" | awk -v pat="$SEG_PAT" -v sq="'" '
    {
      if (!match($0, pat)) exit
      tail = substr($0, RSTART + RLENGTH)
      out = ""; q = ""
      for (i = 1; i <= length(tail); i++) {
        c = substr(tail, i, 1)
        if (q == "") {
          if (c == "\"" || c == sq) { q = c; out = out " "; continue }
          if (c == "#" && (i == 1 || substr(tail, i - 1, 1) == " ")) break
          out = out c
        } else {
          if (c == q) { q = ""; out = out " "; continue }
          out = out "x"
        }
      }
      print out
    }')
  # strip_cmd's own placeholder carries a >> that is not a redirect.
  SEG_TAIL=${SEG_TAIL//<<STRIPPED_HEREDOC>>/}
  SEG_TAIL_RAW=${SEG_TAIL_RAW//<<STRIPPED_HEREDOC>>/}
  # Named before any destination is honoured: stdout under another name is not somewhere else for the value to go.
  if echo "$SEG_TAIL_RAW" | grep -qE '(--out-file|-o|&?>>?|>&)[[:space:]=]*["'"'"']?(/dev/(stdout|fd/[0-9]+)|-)["'"'"']?([[:space:]]|$)'; then
    :
  # A pipe or a redirect that names a file sends the value somewhere the transcript does not see. `2>` does not, and `>&N`/`>&-` duplicate or close a descriptor rather than naming a file — but `&>f`, `&>>f` and `>&f` do reach one.
  elif echo "$SEG_TAIL" | grep -qE '(^|[[:space:]])(--out-file([[:space:]=]|$)|-o([[:space:]=/]|$))' \
    || echo "$SEG_TAIL" | grep -qE '\|' \
    || echo "$SEG_TAIL" | grep -qE '(^|[[:space:]])(&?>>?|1>>?)[[:space:]]*[^&[:space:]]' \
    || echo "$SEG_TAIL" | grep -qE '(^|[[:space:]])>&[[:space:]]*[^0-9&[:space:]-]'; then
    continue
  fi
  echo "SECRET-MASK GUARD: 'op document get' and 'op inject' print the resolved secret to stdout, which is this tool_result/transcript. Give it somewhere else to go — --out-file <path> (op creates that file 0600), a redirect, or a pipe into whatever consumes it." >&2
  exit 2
done < <(printf '%s\n' "$SEG_SRC" | tr ';&' '\n')

# --- aws secretsmanager get-secret-value --secret-id <id> (single-secret only) ---
if echo "$SCAN" | grep -qE '(^|[^[:alnum:]_-])(aws|rtk aws)[[:space:]]([^|;&]* )?secretsmanager[[:space:]]+get-secret-value([[:space:]]|$)'; then
  SECRET_ID=$(echo "$CMD" | grep -oE -- '--secret-id[[:space:]]+[^[:space:]]+' | awk '{print $2}' | tr -d '"'"'"'')
  if [ -n "$SECRET_ID" ]; then
    echo "SECRET-MASK GUARD: raw 'get-secret-value' would put the value in this tool_result/transcript. Use the masked wrapper instead: \"${CLAUDE_PLUGIN_ROOT}\"/scripts/sm-cache.sh --mask '$SECRET_ID' — then reference the value downstream via \$(cat <the printed cache path>) or jq against it, never the literal." >&2
  else
    echo "SECRET-MASK GUARD: raw 'get-secret-value' would put the value in this tool_result/transcript. Use \"${CLAUDE_PLUGIN_ROOT}\"/scripts/sm-cache.sh --mask <secret-id> instead, then reference the cached file downstream — never the literal value." >&2
  fi
  exit 2
fi

exit 0
