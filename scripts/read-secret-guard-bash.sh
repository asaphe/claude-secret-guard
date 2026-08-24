#!/usr/bin/env bash
# PreToolUse Bash hook, mirrors read-secret-guard.sh's basename gate for cat/head/tail/less/grep readers.

INPUT=$(cat)
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
[ -z "$CMD" ] && exit 0

# shellcheck source=scripts/strip-cmd.sh
source "$(dirname "${BASH_SOURCE[0]}")/strip-cmd.sh"
GATE_CMD=$(strip_cmd "$CMD")
SCAN_CMD=$(strip_cmd "$CMD" long-flags-only)

printf '%s' "$GATE_CMD" | grep -qE '^\s*(cat|head|tail|less|more)\b' || printf '%s' "$GATE_CMD" | grep -qE '\bgrep\b.*-r' || exit 0

ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

# Shell-aware split: a quoted filename must lose its quotes before the basename patterns see it, and no token may be glob-expanded against the cwd.
tokenize() {
  printf '%s' "$1" | perl -0777 -e '
    no warnings;
    use Text::ParseWords qw(shellwords);
    my $cmd = do { local $/; <STDIN> };
    my @w = shellwords($cmd);
    # Unbalanced quotes yield nothing; fall back to a bare split so the guard still asks rather than going silent.
    @w = map { my $t = $_; $t =~ s/["\x27]//g; $t } ($cmd =~ /\S+/g) unless @w;
    print join("\0", @w), "\0" if @w;
  '
}

while IFS= read -r -d '' token; do
  BASENAME=$(basename "$token" 2>/dev/null)
  if printf '%s' "$BASENAME" | grep -qE '^\.env(\..+)?$' && ! printf '%s' "$BASENAME" | grep -qE '^\.env\.(example|sample|template)$'; then
    ask "READ-SECRET GUARD: $BASENAME looks like a live env file — confirm before its contents enter context/transcript."
  fi
  if printf '%s' "$BASENAME" | grep -qE '\.(pem|key|p12|pfx)$' \
     || printf '%s' "$BASENAME" | grep -qE '^id_(rsa|ed25519|ecdsa|dsa)$' \
     || printf '%s' "$BASENAME" | grep -qE '^kubeconfig$' \
     || printf '%s' "$token" | grep -qE '\.kube/config$'; then
    ask "READ-SECRET GUARD: $BASENAME looks like a private key or kubeconfig — confirm before its contents enter context/transcript."
  fi
done < <(tokenize "$SCAN_CMD")

exit 0
