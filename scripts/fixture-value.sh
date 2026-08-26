#!/usr/bin/env bash
# Emits one freshly generated value of a named secret shape, so a known-positive fixture never has to be typed or hidden from the guards — see README § Sanctioned fixtures.

set -euo pipefail

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/secret-shapes.sh"

usage() {
  echo "usage: fixture-value.sh <aws-access-key|slack-bot-token|gitlab-pat|pem-private-key>" >&2
  echo "Takes a shape name and nothing else — there is no argument that accepts a value, which is what makes this incapable of emitting a real secret." >&2
  exit 64
}

[ $# -eq 1 ] || usage

# head bounds the read, so tr never takes a SIGPIPE that pipefail would turn into an exit.
rand_chars() {
  local charset="$1" count="$2" out=""
  while [ "${#out}" -lt "$count" ]; do
    out="${out}$(head -c 256 /dev/urandom | LC_ALL=C tr -dc "$charset")"
  done
  printf '%s' "${out:0:count}"
}

SHAPE="$1"
case "$SHAPE" in
  aws-access-key)   VALUE="AKIA$(rand_chars 'A-Z2-7' 16)" ;;
  slack-bot-token)  VALUE="xoxb-$(rand_chars '0-9' 11)-$(rand_chars '0-9' 12)-$(rand_chars 'A-Za-z0-9' 24)" ;;
  gitlab-pat)       VALUE="glpat-$(rand_chars 'A-Za-z0-9' 20)" ;;
  pem-private-key)
    command -v openssl >/dev/null 2>&1 || {
      echo "fixture-value.sh: pem-private-key needs the openssl CLI, which is not on PATH." >&2
      exit 69
    }
    VALUE=$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null)
    ;;
  *) usage ;;
esac

# A value the guards would not flag is useless as a known-positive, so the generator proves its own output before emitting it.
if ! printf '%s' "$VALUE" | grep -qE -- "$SECRET_PATTERN"; then
  echo "fixture-value.sh: the generated '$SHAPE' value does not match the guard pattern — refusing to emit it." >&2
  exit 70
fi

printf '%s\n' "$VALUE"
