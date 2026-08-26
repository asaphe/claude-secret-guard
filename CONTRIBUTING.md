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
```

## Adding or changing a pattern

The secret-shape pattern (PEM headers, AWS access keys, Slack bot tokens,
GitLab PATs) is intentionally duplicated verbatim across
`paste-secret-guard.sh`, `write-secret-guard.sh`, `write-secret-guard-bash.sh`,
and referenced by name in `secret-mask-guard.sh` — this is deliberate, not an
oversight: every one of these guards is on a live, blocking path where a
false positive breaks the task, so all four must stay calibrated to the
same near-zero-false-positive bar. If you change the pattern in one, change
it in all of them, and justify the false-positive risk of any addition
explicitly in the PR description.

Do not add broader/noisier patterns (JWTs, generic-keyword-context
heuristics, etc.) here — that's what
[redacto](https://github.com/asaphe/redacto) is for, on the log-sweep side
where false positives are free.

## Reporting a security issue

If you find a secret shape this plugin fails to catch, or a case where a
guard can be bypassed, please open an issue.
