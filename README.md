# claude-secret-guard

A Claude Code plugin that prevents secrets from landing in Claude's
context, prompt history, or the files it writes — narrow, near-zero-false-positive
pattern blocks, not a comprehensive scanner.

## Why this exists

Claude Code sessions routinely touch real secrets — fetching them from a
secret manager, reading a `.env` file, pasting a token into a prompt to
debug something. Every one of those is a path a secret can take into a
transcript, a prompt-history file, or a file Claude writes. This plugin
closes the highest-value slice of that surface:

1. **Prompt paste** (`UserPromptSubmit`) — blocks a prompt before it's ever
   written to history if it contains an obvious raw secret shape.
2. **Writing a secret into a file** (`PreToolUse` on `Write`/`Edit`/`MultiEdit`,
   plus the Bash equivalent for heredoc/redirect/`tee`) — the same shape
   check, applied to content Claude is about to persist to disk. This is
   the highest-value guard here: a secret hardcoded into a script is worse
   than one that only ever touched a local log, since the script can get
   committed and shared.
3. **Reading an existing secret file** (`PreToolUse` on `Read`, plus the
   Bash equivalent for `cat`/`head`/`tail`/`grep -r`) — an "ask" gate (not a
   hard block) on filenames that look like live secrets: `.env`, private
   keys, kubeconfigs.
4. **Fetching a secret from a manager and printing it raw** (`PreToolUse`
   on `Bash`) — blocks `op read` and `aws secretsmanager get-secret-value`/
   `batch-get-secret-value` when called directly, and points at the masked
   wrapper scripts instead (see below).

**This is deliberately not comprehensive.** The pattern set (PEM headers,
AWS access keys, Slack bot tokens, GitLab PATs) is the same narrow,
near-zero-false-positive list everywhere in this plugin, on purpose — a
false positive on `Write`/`Edit` breaks the task outright, unlike a
post-hoc log scanner where a false positive is free. If you want broad,
after-the-fact detection across your logs (JWTs, more token shapes,
structural PEM handling, validity-gated rewrites), pair this with
[redacto](https://github.com/asaphe/redacto) — a different tool for a
different risk tolerance: this plugin trades recall for safety on a live,
blocking path; redacto trades the other way on an already-ended transcript.

## Install

```sh
claude plugin marketplace add asaphe/claude-secret-guard
claude plugin install secret-guard@claude-secret-guard
```

No external dependencies beyond what you're already using: `jq` (hook
JSON parsing), `perl` (command-text normalization, ships with macOS and
most Linux distributions), and `op`/`aws` CLI only if you use the
masked-cache wrappers.

## Failing closed

`secret-mask-guard.sh` is the one stage here that exists to stop a
plaintext secret reaching the transcript, so it refuses anything it
cannot actually inspect: an empty or non-JSON hook payload, or command
text it cannot normalize because `jq` or `perl` is unavailable. In each
case it blocks with a message naming the missing tool, rather than
letting the command run unchecked. The other stages are UX guards
(duplicate-read suppression, confirm-before-read prompts) and correctly
fail open — a broken dependency there costs a prompt, not a secret.

That distinction is why the mask guard decides what to match on
*normalized* text. `strip-cmd.sh` masks the parts of a command that are
data rather than an executed command — heredoc bodies and the values of
prose-carrying flags like `--body` and `-m` — so writing a PR body or a
commit message *about* `op read` is not treated as performing one. A
region that can still execute is never masked: a flag value or bare
heredoc body containing `$(…)` or backticks stays visible to the
predicate, because that text does run.

## Flag masking and filenames

Masking a flag value is right for the mask guard, where the value is
prose. It is wrong for the reader gate in
`read-secret-guard-bash.sh`, where a short flag's value can be the very
filename that gate exists to notice: `less -m` is a valid no-argument
flag, so `less -m "secrets.pem"` is an ordinary read whose argument
masking would hide. `-b` is left out of the masked set entirely for the
same reason (`cat -b`).

So the reader gate strips twice. It decides *whether the command is a
read* from fully-masked text, which keeps a commit message mentioning
`grep -r` from tripping it, and then scans for *filenames* in text where
short flags are left intact. Long prose flags (`--body`, `--message`,
`--title`, `--notes`, `--description`, `--comment`) are masked in both,
since no reader command accepts them.

That gate also tokenizes with shell quoting rules rather than bare word
splitting. Splitting on whitespace left quote characters attached, so
`cat "secrets.pem"` never matched the basename patterns that
`cat secrets.pem` did, and it also let a glob expand against the working
directory. Input it cannot parse — an unbalanced quote — falls back to a
bare split with quotes removed, so the gate still asks rather than going
silent.

## Why one Bash authority script, not several parallel hooks

`hooks/hooks.json` registers a single script (`bash-secret-authority.sh`)
for the `Bash` matcher, which internally chains `secret-mask-guard.sh` →
`write-secret-guard-bash.sh` → `op-read-guard.sh` → `read-secret-guard-bash.sh`
in a fixed order and exits on the first block. This isn't just tidiness:
Claude Code runs multiple hooks registered on the same matcher without
documented ordering guarantees, and a hook that rewrites the command
(`updatedInput`) can silently override another hook's block for the same
call if they're registered as independent parallel hooks. Chaining
block-before-rewrite inside one script sidesteps that ambiguity entirely.
If you add your own Bash hook alongside this plugin, keep that in mind —
especially if yours rewrites `tool_input.command`.

## Masked-cache wrappers

`scripts/op-cache.sh` and `scripts/sm-cache.sh` are drop-in replacements
for `op read` and `aws secretsmanager get-secret-value` that cache the
value once per session under `/tmp/{op,sm}-cache-<session-id>/` (mode 600)
and print a masked confirmation + the cache file path instead of the value
itself — reference the value downstream via `$(cat <printed-path>)`. Pass
`--reveal` to opt into printing the real value when you genuinely need to
(e.g. checking its format), and `--refresh` to force a re-fetch if the
secret rotated mid-session. `scripts/aws-batch-secrets.sh` is the same
idea for `batch-get-secret-value` (defaults to a masked name+byte-length
summary; `--values --reveal` opts into full values).

`scripts/op-cache-cleanup.sh` is a `Stop` hook that purges both cache
directories when the session ends, so values don't sit in `/tmp`
indefinitely.

AWS profile: all three wrapper scripts read `AWS_PROFILE` if set, or fall
back to whatever your `aws` CLI's own default credential resolution does —
pass `--profile` explicitly to override either.

## Allowlist-config exemption

`write-secret-guard.sh` exits 0 without scanning when the write targets a
secret-scanner allowlist: `.gitleaks.toml`, `gitleaks.toml`, `.gitleaksignore`,
or `.secretsignore`. Those files exist to enumerate the values a scanner should
ignore, so a synthetic fixture literal is their legitimate content — and without
the exemption the guard blocks the one edit that makes another scanner stop
firing on test fixtures. Matching is on the exact basename, so a lookalike
(`my.gitleaks.toml.bak`, `gitleaks.toml.tmpl`) is still scanned.

`write-secret-guard-bash.sh` deliberately does **not** carry the exemption. The
tool-side guard reads a structured `file_path` and knows exactly what is being
written; the Bash-side guard sees only a command string, where the real target
has to be inferred and can be inferred wrongly — `tee .gitleaks.toml other.env`
writes both, and a redirect can be hidden behind a variable or a later pipe
stage. An exemption there would fail open, so writing an allowlist config via a
heredoc stays blocked; use Write/Edit for it. Its error message says so.

The trade-off accepted: a real credential committed inside a file with one of
those four basenames is not caught by this guard. Such a file is already an
allowlist, so a scanner would ignore the value regardless.

## What this plugin does not do

- No log sweeping — see [redacto](https://github.com/asaphe/redacto) for
  that; the two are designed to be used together.
- No generic-keyword-context detection (`generic-api-key`-style heuristics)
  — too high a false-positive rate for a hard-blocking path.
- No coverage for exotic exfiltration paths (e.g. a secret smuggled through
  a base64-encoded blob) — this guards the direct, common cases, not an
  adversarial one.

## License

Apache-2.0.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — sign off your commits
(`git commit -s`), no CLA required.
