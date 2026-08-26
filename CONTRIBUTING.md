# Contributing to claude-secret-guard

Thanks for considering a contribution.

## Developer Certificate of Origin (DCO)

Contributions require a sign-off, not a signed CLA. Add `-s` to your commits:

```sh
git commit -s -m "fix: ..."
```

This adds a `Signed-off-by` trailer certifying you have the right to submit
the change under this project's license (Apache-2.0). See
[developercertificate.org](https://developercertificate.org/) for the exact
text you're certifying.

## Before opening a PR

```sh
shellcheck -x scripts/*.sh tests/*.sh
for f in scripts/*.sh tests/*.sh; do bash -n "$f"; done
for t in tests/*.test.sh; do bash "$t"; done
jq empty .claude-plugin/plugin.json .claude-plugin/marketplace.json hooks/hooks.json
for t in tests/*.test.sh; do bash "$t"; done
```

## Adding or changing a pattern

The secret-shape pattern (PEM headers, AWS access keys, Slack bot tokens,
GitLab PATs) lives once, in `scripts/secret-shapes.sh`, and is sourced by
`paste-secret-guard.sh`, `write-secret-guard.sh` and
`write-secret-guard-bash.sh`. It used to be duplicated verbatim across the
three, on the reasoning that all of them must stay calibrated to the same
near-zero-false-positive bar — which is exactly the argument for one
definition, since a copy is what lets a widening reach one guard and not the
others.

That bar is unchanged: every one of these guards is on a live, blocking path
where a false positive breaks the task. Justify the false-positive risk of any
addition explicitly in the PR description, and remember the pattern now has a
second consumer — `fixtures.allow` validates each entry against it with `-x`,
so a shape that matches only part of a real value cannot have that value
allowlisted.

Do not add broader/noisier patterns (JWTs, generic-keyword-context
heuristics, etc.) here — that's what
[redacto](https://github.com/asaphe/redacto) is for, on the log-sweep side
where false positives are free.

## Test fixtures

A known-positive control for a secret scanner **is** a secret-shaped literal.
Do not split one across variables to get it past the guards — that trains a
bypass habit and leaves no record. Generate one with
`scripts/fixture-value.sh <shape>`, or, if a test needs one *specific* value,
add it to `fixtures.allow` in the same PR. See README § Sanctioned fixtures.

## Reporting a security issue

If you find a secret shape this plugin fails to catch, or a case where a
guard can be bypassed, please open an issue.
