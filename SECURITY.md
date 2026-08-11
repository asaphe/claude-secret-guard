# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
**[Report a vulnerability](https://github.com/asaphe/claude-secret-guard/security/advisories/new)**

Please do not open a public issue for a security report.

This is a solo-maintained project. Expect an acknowledgement within a week and a
fix or an explicit decision not to fix within a month. There is no paid support
and no SLA.

## Supported versions

Pre-1.0. Only the current `main` is supported.

## What counts as a vulnerability here

These hooks are a guard, not a boundary. They block a short list of
high-confidence secret shapes on the paths Claude actually uses, and the list is
deliberately short to keep false positives near zero — a guard that cries wolf
gets disabled, which is worse than no guard. Judge a report against that. In
scope:

- A bypass of a guard that is supposed to fire: a write path the tool-side hook
  never sees, a command shape the Bash-side hook treats as a non-write, or an
  encoding that evades a pattern the guard claims to cover.
- A guard that leaks the value it is blocking — into stderr, a log file, or the
  transcript. The error messages are written to name the *shape*, never the
  match.
- Anything in the masked-cache wrappers that writes a fetched secret to disk
  unmasked, leaves it readable by another user, or lets it survive past the
  cleanup.

Out of scope:

- A secret shape the patterns deliberately do not cover. The pattern list is
  short by design; see the README.
- The allowlist-config exemption. Its trade-off is stated in the README, and the
  Bash-side guard deliberately does not carry it.
- Findings that require an attacker who already holds write access to your hook
  scripts or your Claude settings.
