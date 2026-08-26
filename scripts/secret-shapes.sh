#!/usr/bin/env bash
# Shared utility: the secret shapes every content guard matches on, plus the fixture allowlist that subtracts named values from them — see README § Sanctioned fixtures.

# Boundary-free, because an allowlist entry is validated against these with -x, where the value is the whole line.
SECRET_GUARD_PEM_HEADER='-----BEGIN[ A-Z0-9]*PRIVATE KEY-----'

# One definition, three consumers: a widened copy cannot drift into a single guard.
SECRET_SHAPES_BOUNDED='(A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16}\b|xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}|xoxb-[0-9]{10,13}-[0-9]{10,13}|glpat-[A-Za-z0-9_-]{20,}'

# What the guards detect. The bare Slack prefix stays here so a truncated token in source is still flagged.
SECRET_SHAPES="$SECRET_GUARD_PEM_HEADER|$SECRET_SHAPES_BOUNDED"

# What an allowlist entry may be, which is not the same corpus: the bare prefix is a *fragment* of a token, and accepting one as complete subtracts the team and bot IDs every rotation of that credential shares.
SECRET_SHAPES_COMPLETE="$SECRET_GUARD_PEM_HEADER|(A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16}\b|xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}|glpat-[A-Za-z0-9_-]{20,}"

# A two-character escape counts as a left boundary (\b fails before a key written as "…\nAKIA…"), while PEM stays a top-level alternative — where the three duplicated copies had it — because a header carries its own leading dashes and needs no boundary.
SECRET_PATTERN="((^|[^0-9A-Za-z]|\\\\[nrtv])($SECRET_SHAPES_BOUNDED)|$SECRET_GUARD_PEM_HEADER)"

# Resolved from this file rather than the plugin root so a guard always reads the allowlist shipped beside it.
SECRET_GUARD_ALLOWLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/fixtures.allow"

# Allowlist entries with comments and blanks dropped; non-zero if the file cannot be read.
fixture_allowlist() {
  # Distinct from an empty list, which blocks for its own reason — this edge must stay observable.
  if [ ! -r "$SECRET_GUARD_ALLOWLIST" ]; then
    echo "SECRET GUARD: $SECRET_GUARD_ALLOWLIST is missing or unreadable — nothing is exempt until it is restored." >&2
    return 1
  fi
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '' | '#'*) continue ;; esac
    # A header is byte-identical in a live key, so honouring one would blind the whole PEM family.
    if printf '%s' "$line" | grep -qE -- "$SECRET_GUARD_PEM_HEADER"; then
      echo "SECRET GUARD: ignoring the PEM header entry in $SECRET_GUARD_ALLOWLIST — a header is identical in a real private key, so it can never be a fixture. Generate PEM fixtures with scripts/fixture-value.sh pem-private-key." >&2
      continue
    fi
    # Validated against the complete-values corpus, so a fragment that happens to match a detection alternative is still refused.
    if ! printf '%s' "$line" | grep -qxE -- "$SECRET_SHAPES_COMPLETE"; then
      echo "SECRET GUARD: ignoring the entry '$line' in $SECRET_GUARD_ALLOWLIST — it is not a complete value of any guarded shape. List the exact literal, not a fragment or prefix." >&2
      continue
    fi
    printf '%s\n' "$line"
  done <"$SECRET_GUARD_ALLOWLIST"
}

# Whether a span is exactly a run of listed entries, longest tried first so one entry that is a prefix of another cannot strand the rest.
fixture_span_listed() {
  local span="$1" ordered="$2" entry progress=1
  while [ -n "$span" ] && [ "$progress" -eq 1 ]; do
    progress=0
    while IFS= read -r entry; do
      [ -n "$entry" ] || continue
      case "$span" in
        "$entry"*) span=${span#"$entry"}; progress=1; break ;;
      esac
    done <<EOF
$ordered
EOF
  done
  [ -z "$span" ]
}

# Zero when every guarded value in $1 is accounted for by the allowlist — see README § Sanctioned fixtures.
fixture_exempt() {
  local text="$1" allow ordered matched span residual rest before exempted=""

  allow=$(fixture_allowlist) || return 1

  printf '%s' "$text" | grep -qE -- "$SECRET_PATTERN" || return 1

  # Enumerated whole rather than subtracted: deleting an entry that ends in a shape character spliced the neighbour's left boundary away, and a listed value CONTAINED in a longer real one took the whole thing with it. Enumeration is safe on this corpus only because the shapes carry no leading boundary of their own — that is what made -oE skip a match on GNU grep before.
  matched=$(printf '%s' "$text" | grep -oE -- "$SECRET_SHAPES") || return 1
  [ -n "$matched" ] || return 1
  ordered=$(printf '%s\n' "$allow" | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2-)

  # A span that does not decompose is left in the residual rather than refused outright: an open-ended shape merges adjacent values into one span, and a span with no valid left boundary is not something the callers would have blocked on anyway.
  residual=""
  rest="$text"
  while IFS= read -r span; do
    [ -n "$span" ] || continue
    # Consumed one occurrence at a time, left to right as grep enumerated them: a listed value can also be the prefix of a longer unlisted one, and replacing it by value everywhere subtracted it from that neighbour too.
    case "$rest" in *"$span"*) ;; *) continue ;; esac
    before=${rest%%"$span"*}
    rest=${rest#*"$span"}
    if fixture_span_listed "$span" "$ordered"; then
      exempted="${exempted:+$exempted, }$span"
      # A newline rather than a deletion, so the remainder keeps the boundaries it had.
      residual="$residual$before"$'\n'
    else
      residual="$residual$before$span"
    fi
  done <<EOF
$matched
EOF
  residual="$residual$rest"

  [ -n "$exempted" ] || return 1
  printf '%s' "$residual" | grep -qE -- "$SECRET_PATTERN" && return 1
  # shellcheck disable=SC2034  # read by the sourcing guard to name what it exempted
  SECRET_GUARD_EXEMPTED="$exempted"
  return 0
}
