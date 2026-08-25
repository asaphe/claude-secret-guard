#!/usr/bin/env bash
# Shared utility: the secret shapes every content guard matches on, plus the fixture allowlist that subtracts named values from them — see README § Sanctioned fixtures.

# One definition, three consumers: a widened copy cannot drift into a single guard.
# Boundary-free, because an allowlist entry is validated against this with -x, where the value is the whole line.
# The Slack alternation lists the full token before its prefix so a listed value cannot be a prefix every rotation shares; keeping the prefix form second means this matches exactly the set the three duplicated copies matched before.
SECRET_SHAPES='-----BEGIN[ A-Z0-9]*PRIVATE KEY-----|(A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16}\b|xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}|xoxb-[0-9]{10,13}-[0-9]{10,13}|glpat-[A-Za-z0-9_-]{20,}'

# A two-character escape counts as a left boundary: \b fails before a key written as "…\nAKIA…" because the preceding character is the n.
SECRET_PATTERN="(^|[^0-9A-Za-z]|\\\\[nrtv])($SECRET_SHAPES)"

# Resolved from this file rather than the plugin root so a guard always reads the allowlist shipped beside it.
SECRET_GUARD_ALLOWLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/fixtures.allow"

SECRET_GUARD_PEM_HEADER='-----BEGIN[ A-Z0-9]*PRIVATE KEY-----'

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
    # A partial entry would subtract a prefix that every rotation of the same credential shares, so an entry must be a whole value on its own.
    if ! printf '%s' "$line" | grep -qxE -- "$SECRET_SHAPES"; then
      echo "SECRET GUARD: ignoring the entry '$line' in $SECRET_GUARD_ALLOWLIST — it is not a complete value of any guarded shape. List the exact literal, not a fragment or prefix." >&2
      continue
    fi
    printf '%s\n' "$line"
  done <"$SECRET_GUARD_ALLOWLIST"
}

# Zero only when EVERY match in $1 is an exact allowlist entry — see README § Sanctioned fixtures.
fixture_exempt() {
  local text="$1" allow entry residual exempted=""

  allow=$(fixture_allowlist) || return 1

  printf '%s' "$text" | grep -qE -- "$SECRET_PATTERN" || return 1

  # Listed values are subtracted and the remainder re-tested, rather than enumerated with -oE: GNU grep skips a match whose leading boundary the previous match consumed, so enumeration silently misses the second of two adjacent secrets.
  residual="$text"
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    case "$residual" in *"$entry"*) exempted="${exempted:+$exempted, }$entry" ;; esac
    residual=${residual//"$entry"/}
  done <<EOF
$allow
EOF

  [ -n "$exempted" ] || return 1
  printf '%s' "$residual" | grep -qE -- "$SECRET_PATTERN" && return 1
  # shellcheck disable=SC2034  # read by the sourcing guard to name what it exempted
  SECRET_GUARD_EXEMPTED="$exempted"
  return 0
}
