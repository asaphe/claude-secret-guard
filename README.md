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
   Bash equivalent for `cat`/`head`/`tail`/`less`/`more`/`grep`) — an "ask"
   gate (not a hard block) on filenames that look like live secrets: `.env`,
   private keys, kubeconfigs.
4. **Fetching a secret from a manager and printing it raw** (`PreToolUse`
   on `Bash`) — blocks `op read`, `op item get --reveal`/`--otp`,
   `op document get` and `op inject` with nowhere but stdout to send the
   value, `op run --no-masking`, and `aws secretsmanager get-secret-value`/
   `batch-get-secret-value` when called directly, and points at the masked
   wrapper scripts instead (see below).

**This is deliberately not comprehensive.** The pattern set (PEM and PuTTY
private-key headers, AWS access keys, Slack bot/user/app tokens, the GitLab
token families) is the same narrow,
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
text it cannot read because `jq` is unavailable. It blocks with a message
naming the missing tool, rather than letting the command run unchecked.

**Every stage does the same for `jq` specifically.** An unreadable hook
payload blocks the call rather than being read as "nothing to inspect" —
`jq -r '… // empty'` returns an empty string when `jq` is missing or the
JSON does not parse, and every check downstream treats empty as "nothing
here", which silently disarms the guard. That is deliberate and it is not
free: with `jq` absent, every guarded call is refused.

`perl` is the exception, on purpose. `strip-cmd.sh` degrades to the
*unmodified* command when `perl` cannot run, so the predicates still see the
raw text and a real fetch is still blocked. Returning empty instead would hit
the same "nothing to inspect" exit; blocking every call would make an absent
interpreter a hard outage. Neither trade is necessary.

That distinction is why the mask guard decides what to match on
*normalized* text. `strip-cmd.sh` masks the parts of a command that are
data rather than an executed command — heredoc bodies and the values of
prose-carrying flags like `--body` and `-m` — so writing a PR body or a
commit message *about* `op read` is not treated as performing one. A
region that can still execute is never masked: a flag value or bare
heredoc body containing `$(…)` or backticks stays visible to the
predicate, because that text does run. So does a body fed to an
interpreter, wherever the interpreter sits on that line — before the
operator (`python3 <<'EOF'`) or after it (`cat <<'EOF' | python3`). An
ordinary destination on the same line (`cat <<'EOF' > file`,
`| tee file`) leaves the body masked and is preserved as written.

### Respellings the predicates normalize

A predicate matches the verb as written, one line at a time, so a rewrite that
changes the bytes without changing what the shell runs used to walk straight
past it. All of these were ordinary fetches that reached the transcript
unblocked: a backslash-newline continuation inside the matched phrase (`op \`
then `read op://…`), a quoted subcommand (`op "read" op://…`), a binary name
split across a quote (`o"p" read op://…`), a backslash inside either word
(`o\p read`, `op re\ad`), the `$'…'` and `$"…"` quoting forms, and a tab where
the two-word verbs spelled their separator as a literal space.

`normalize_cmd()` in `scripts/strip-cmd.sh` undoes exactly that — it joins
continuations, deletes backslashes, and unwraps a quote pair — and the guards
match on its output. **A quote pair holding whitespace is deliberately left
alone**, because that is the only thing separating a command that *performs*
the fetch from one that *searches for the phrase*: without the exception,
`grep -rn "op read" .` becomes a hard block with no approval path.

Order matters twice. `strip_cmd()` masks prose first, so the placeholder left
behind is a bare word and unwrapping quotes cannot re-expose a commit message.
And normalization is not the universal widening it looks like: it widens a
predicate that matches on words, but *narrows* one that matches on a quote
character. `write-secret-guard-bash.sh` therefore scans the raw and the
normalized spelling as two lines and takes either.

There is no longer a wrapper-path exemption. A legitimate `op-cache.sh` call
does not match the fetch predicates anyway, so all the exemption could ever
clear was text that merely *named* the path — a trailing
`# see scripts/op-cache.sh` used to turn a real fetch into a pass. For the same
reason `op read` is no longer conditioned on the absence of `op item get`: one
command can carry both, and the raw read still needs blocking.

## Fetches inside an invoked script

Every predicate above reads the command line. A command that runs a script —
`bash deploy.sh`, `source env.sh`, `./provision.sh` — puts the fetch one file
away, where none of them can see it, and the value still reaches the transcript
the moment the script runs.

So a command in that shape is followed into the file, and the guard re-enters
itself on the contents. Re-entering rather than re-implementing is the point:
the file is held to exactly the predicates above, not to a second copy of them
that a later widening would reach only one of.

What counts as an invoked script:

- The operand of `sh`/`bash`/`zsh`/`ksh`/`dash`, `source` or `.`, and a path
  executed directly (`./x.sh`, `/opt/x.sh`, `~/x.sh`).
- **Command position only.** A path that is merely an argument — `cat x.sh`,
  `grep -n foo x.sh` — is data, and scanning arguments is the false-positive
  class these predicates already refuse. A leading assignment, `sudo`, `env`,
  `exec`, `time` or `nohup` does not change which word is the command.
- Not under `-n`, which parses the file without running any of it.
- Two levels: the invoked script, and what that script sources.

Reading the file drops full-line comments — prose about a command is not a
command, the same distinction drawn for a command that only *describes* a
guarded fetch — and then keeps the lines that name `op` or `secretsmanager` at
all, plus the lines that invoke a further script, over one normalization of the
whole file. Without that narrowing, re-entry costs a subprocess per line of the
script. A command that starts no script at all is cleared in the shell, with no
subprocess spawned, because this runs on every Bash call.

A path the guard cannot resolve without running something is skipped rather
than guessed at. `~`, `$HOME`, and a path built from the script's own directory
(`$(dirname "$0")`, `${BASH_SOURCE[0]%/*}`) resolve; anything assembled from
another expansion does not. A relative path resolves against the payload's
`cwd`.

### Why this plugin's own tree is exempt

A candidate resolving inside this plugin's own directory is skipped. The masked
wrappers perform the fetch on purpose and mask what they print, so scanning
them would block the exact call the guard's own message tells you to make; the
tests carry guarded command text as data for the same reason the fixtures do.

The exemption is a comparison of resolved paths, never a match on the text, so
it cannot be claimed by naming one of these files — the wrapper-path exemption
that was removed from the command predicates was removed precisely because a
trailing `# see scripts/op-cache.sh` could claim it. Copy a wrapper out of the
tree and it blocks, which is what keeps this an exemption for these files
rather than for their contents.

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

The trade-off is one-directional: because `-m` survives into the scan, a
prose `-m` value whose last word ends in `.pem`/`.key` can raise a prompt
on a command that also begins with a reader. That costs a confirmation,
never a missed read.

That gate also tokenizes with shell quoting rules rather than bare word
splitting. Splitting on whitespace left quote characters attached, so
`cat "secrets.pem"` never matched the basename patterns that
`cat secrets.pem` did. Input it cannot parse — an unbalanced quote —
falls back to a bare split with quotes removed, so the gate still asks
rather than going silent.

Globs are not expanded for the *verdict*, since the hook's working
directory is not necessarily the one the command will run in, and a
verdict that depends on it is not reproducible. An unresolved pattern is
judged by what it could match instead: `cat *`, `cat .env*` and
`cat .ssh/*` all ask, while `cat *.log` does not.

### What an unresolved glob prompt says

Naming only the pattern asks the approver to judge whether it "could
match a secret", which the prompt gives them no way to answer — and a
gate whose only stable replies are always-yes and always-no is one whose
reader has stopped reading it.

So the prompt names the files where it honestly can. An **absolute**
pattern has no working-directory dependence, so it is expanded when the
prompt is written and up to six matching filenames go into the message:
`cat /etc/ssl/private/*` asks with *it matches 3 file(s): server.key
ca.key dhparam.pem*. A **relative** one is still not expanded, and says
so rather than implying the guard knows more than it does.

Expansion happens only on the ask path, so an ordinary command pays
nothing for it, and it carries **filenames only** — putting contents in
the prompt would hand over exactly what the prompt exists to withhold.

### Why a negated find predicate is exempt

`find . -name x.md -not -path '*/.git/*' | head -2` used to ask about
`*/.git/*`, whose basename is a bare wildcard. That token is an
*exclusion*: a negated predicate can only shrink the set of files the
command touches, so it is never something the command reads, and the
reader that armed the gate (`head`) is reading `find`'s stdout rather
than a path. Every `find … -not -path` pipeline containing a reader
prompted, which is most of them.

The exemption is the narrowest shape that covers it — `-not` or `!`,
then a `-path`/`-name`/`-wholename`/`-regex` predicate, then the token —
and it is live only inside a window where find's own grammar governs. A
`find` **token** arms that window and the next reader token closes it,
so `cat -not -path .env` asks, and so does
`find . -type d | head -2; cat -not -path .env`, where the `find`
belongs to a different command on the same line. Arming on a text match
over the whole command instead was tried first and was a fail-open in
both of those, and in `echo "use find for this"; cat -not -path .env`,
where the word never named a command at all. A reader *before* find does
not close the window, since `head -2 <(find . -not -path '*/.git/*')`
still has find governing its own arguments.

Nothing positive is exempted, because a positive predicate can *widen*
what a later `-exec` reads: `find . -name '*.pem'` still asks, and so
does `grep --include='*.pem'`.

Two conditions past the shape itself close the ways the shape alone
lies. A **second negation** makes the predicate positive again, so it
selects the files it names rather than excluding them —
`find . ! ! -name '*.pem' -exec cat {} +` reads every key it matches,
and is not exempt; a third negation fails closed with the rest rather
than being counted. And the operand must carry a **wildcard**, because a
negated predicate naming a literal path is indistinguishable here from a
filename: that is what let a `find`-shaped *argument* to a reader —
`less bin/find -not -path .env` — lend find's grammar to a secret. The
exemption can therefore only ever skip a token containing `*` or `?`,
which is what the reported false positive always was.

### Why grep is gated unconditionally

`grep` is treated as a reader whether or not `-r` is present. The recursive
flag decides *how many* files are read, never whether the one named is a key:
`grep AKIA .env` reads `.env` exactly as `grep -r AKIA .` reaches it. Gating on
`-r` would have exempted the single-file spelling, which is the common one.

The same reasoning admits a reader named by path — `/bin/cat`, `./cat` — since
the basename is what decides, not how the binary was spelled.

### Why the pattern operand is scanned

`grep AKIA... secrets.pem` names two things: a pattern and a file. Only the
second is read, so an earlier version tried to model `grep`'s flag grammar
well enough to skip the pattern operand and judge the file alone.

That modelling is where the fail-opens were. `grep` takes its pattern from a
flag (`-e`, `-f`), from an `--include`/`--exclude` glob, or positionally, and
which one applies depends on flags that may be bundled (`-rne`), separated
from their value, or spelled long with `=`. Every simplification of that
grammar left a spelling where the *file* operand was classified as the pattern
and went unscanned.

So every token is scanned, the pattern operand included. The cost is a prompt
on `grep secrets.pem README.md`, where the key-shaped word is what is being
searched *for* rather than read — rare, and it fails safe. The alternative
failed the other way, silently, on four spellings.

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

`aws-batch-secrets.sh` reports what it fetched, not what it listed: its
trailer reads `Fetched N of M secrets`, and any shortfall — a batch the
CLI refused, an unparseable response, or per-secret `Errors[]` inside an
otherwise successful call — marks the run `INCOMPLETE` and exits non-zero
(the AWS CLI's own status where there was one, `1` otherwise). Partial
results are still printed, so a caller that branches on the exit code
never mistakes a truncated audit for a complete one — but branch on `$?`
(or `${PIPESTATUS[0]}`), never on the length of the output: a run that
fetched 5 of 25 still emits a well-formed 5-element result, and piping it
into `jq` replaces the script's status with `jq`'s.

`sm-cache.sh` selects `SecretString` out of the full JSON response rather
than asking for it with `--query SecretString --output text`. That form
renders an absent field as the literal string `None` — the AWS CLI's text
formatter printing Python's `None` — which is four non-empty bytes, so a
secret holding only `SecretBinary` used to be cached and reported as a
4-byte value. A binary-only secret now fails closed and says so; a secret
whose value genuinely is the text `None` still caches correctly. This
makes `jq` a hard dependency of that wrapper.

`scripts/op-cache-cleanup.sh` is a `Stop` hook that purges both cache
directories when the session ends, so values don't sit in `/tmp`
indefinitely.

### Cache namespacing

Caches and the duplicate-read tracker key on the Claude Code session id
when there is one. Outside a session — a wrapper run straight from a
shell — the fallback used to be the bare parent PID, and PIDs recycle: two
unrelated shells could land on one cache path, where a stale hit serves a
value that has since rotated. The fallback is now
`uid<uid>-pid<pid>-<hash of the parent's start time>`, so a reissued PID
resolves to a different namespace and two users on a shared `/tmp` never
share a path at all. Without `ps` it degrades to uid plus PID rather than
refusing to run.

The tracker's session-less name was previously the fixed string `shared`,
identical for every user on the machine. Combined with the ownership check
that refuses a tracker this user does not own, the first account to create
it locked every other one out of the guard — on a sticky `/tmp` with no way
to remove it. There is no shared name any more. Because a `Stop` hook can
only scope a purge when the payload carried a session id, a tracker created
outside one also prunes itself after 12 hours instead of refusing reads
forever against a record nothing will clear.

AWS profile: all three wrapper scripts read `AWS_PROFILE` if set, or fall
back to whatever your `aws` CLI's own default credential resolution does —
pass `--profile` explicitly to override either.

## Sanctioned fixtures

A known-positive control for a secret scanner **is** a secret-shaped literal.
Without a sanctioned route the only way past the guards is to hide the value
from them — splitting it across variables and rejoining at runtime — which
trains a bypass habit and leaves no record that an exemption was taken. Two
mechanisms replace that habit. Neither reads a destination path, so both work
on the `Bash` surface where most blocks arrive.

### The exact-value allowlist

`fixtures.allow`, shipped with the plugin and read from beside the guard that
uses it.

- One exact value per line. Blank lines and `#` lines are ignored; every other
  line is compared byte-for-byte, so a trailing space silently makes an entry
  dead.
- A call is exempt **only when every matched literal in it is listed**. One
  unlisted match blocks the whole call — otherwise a command carrying an
  approved fixture alongside a real credential would pass.
- A missing or unreadable file blocks everything.
- A private-key header can never be listed, PEM or PuTTY. It is byte-identical
  in a real key, so honouring one would blind the guards to every private key;
  such an entry is ignored and announced on stderr. Generate PEM fixtures
  instead.
- An entry must be a **complete** value of a guarded shape, not a fragment or a
  prefix. A prefix would subtract the part every rotation of the same
  credential shares, so listing one fixture would silently exempt its
  replacements; such an entry is ignored.
- Exemption works by subtracting the listed values from the payload and
  re-testing the remainder, not by enumerating matches. `grep -oE` and
  `grep -qE` disagree on GNU grep when a match's leading boundary was consumed
  by the one before it, so enumeration misses the second of two adjacent
  secrets on Linux while passing on macOS.

When an exemption is taken the guard names the values it cleared on stderr —
but Claude Code sends a hook's stderr to the debug log on **exit 0** and shows
it only on **exit 2**. So the notice is an audit trail you can go and read, not
something surfaced at the moment it happens.

The patterns themselves are untouched by any of this. The allowlist subtracts
named values; it never reshapes a shape.

### The generator

`scripts/fixture-value.sh <shape>` prints one conforming value on stdout for
`aws-access-key`, `slack-bot-token`, `slack-user-token`, `slack-app-token`,
`gitlab-pat`, `gitlab-runner-token`, or `pem-private-key`. It
takes a shape name and nothing else — there is no argument that accepts a
value, which is what makes it incapable of emitting a real secret. It also
checks its own output against the guard pattern before printing, because a
value the guards would not flag is useless as a known-positive.

Generating is not the workaround it resembles. Hiding a value splits a literal
you already have; generating produces one that did not exist until the command
ran, so there is nothing being kept from anyone.

### What this does not make safe

A session can add a value to `fixtures.allow` and then write it. The exemption
is visible in the diff and gated at review, but it is not gated in-session —
strictly better than the alternative, where the same manoeuvre leaves no
artifact at all.

One shape cannot currently be allowlisted: a Slack bot token is matched by its
`xoxb-<digits>-<digits>` prefix as well as its full form, and an entry has to
be a complete value, so listing the full token works while a truncated one is
refused. Nothing else about Slack detection changed.

## Why there is no allowlist-config exemption

Earlier versions let `write-secret-guard.sh` exit 0 without scanning when the
write targeted a secret-scanner allowlist — `.gitleaks.toml`, `gitleaks.toml`,
`.gitleaksignore`, `.secretsignore` — on the reasoning that enumerating ignored
values is what those files are for. That exemption is gone as of 0.5.0.

It was a fail-open, and the shape of it is the reason: the guard exists to stop
a secret being written to disk, and the exemption handed any caller a set of
four basenames that switched the guard off entirely. Writing a real credential
to `.gitleaksignore` was never checked, and "the scanner would ignore it
anyway" only holds while that file stays an allowlist — it is an ordinary file
that can be renamed, copied, or committed to a repo whose scanner reads a
different config. A guard that can be disarmed by choosing a filename is not a
guard on the write; it is a guard on the writer's cooperation.

Both surfaces now behave the same way, which also removes the asymmetry that
made the old behaviour hard to reason about: `write-secret-guard-bash.sh` never
carried the exemption, because a command string only lets the real target be
inferred, and inferred wrongly — `tee .gitleaks.toml other.env` writes both.

If a scanner allowlist genuinely needs a secret-shaped literal, it is a fixture
and belongs in `fixtures.allow`, where its diff is reviewable; see
§ Sanctioned fixtures. Generate the value with `scripts/fixture-value.sh`
rather than typing one.

## What this plugin does not do

- No log sweeping — see [redacto](https://github.com/asaphe/redacto) for
  that; the two are designed to be used together.
- No generic-keyword-context detection (`generic-api-key`-style heuristics)
  — too high a false-positive rate for a hard-blocking path.
- No coverage for exotic exfiltration paths (e.g. a secret smuggled through
  a base64-encoded blob) — this guards the direct, common cases, not an
  adversarial one.
- The 1Password predicates key on the flags the CLI itself documents as
  revealing — `--reveal` and `--otp` on `item get`, no stdout-avoiding
  destination on `document get` and `inject`, `--no-masking` on `run`. A
  subcommand or output format that prints a concealed value without one of
  those is not matched, and nothing here verifies that `op run` really does
  mask its subprocess's output. Each flag is looked for in the fetch's own
  `;`/`&`-delimited segment, so `op item get X && op-cache.sh --reveal <uri>`
  is two commands and not a revealing item-get.
- `op document get` and `op inject` are allowed when their output has somewhere
  to go that is not the transcript: `--out-file`/`-o`, a stdout redirect, or a
  pipe. A pipe whose *consumer* prints the value — `op inject -i x | cat` — is
  therefore not blocked. Only a destination the shell would actually run counts:
  text after an unquoted `#` is dropped as a comment, a redirect operator or
  output flag inside quotes is read as the argument it is, and the pipe has to be
  the fetch's own — one *feeding* `op` is not a destination for what `op` prints.
  The check still reads flags rather than resolving a path, so it does not verify
  that the named file is anywhere sensible.
- Normalization covers every respelling that still spells the verb as adjacent
  words. A verb assembled at runtime from an expansion is not matched.
- A `MultiEdit` value split so that no two fragments are adjacent in array order
  is not detected: the guard concatenates the edits in order, so an intervening
  edit keeps the halves apart, and a sequential rewrite (edit 1 replacing text
  edit 0 inserted) can assemble a value from two fragments that are each at the
  head of their own edit. A cross-edit adjacency probe was tried and withdrawn:
  which text ends up adjacent depends on the file being edited, which the hook
  payload does not contain, so every model of it is a guess that is both too
  narrow and too broad.
- On the AWS side only Secrets Manager carries a predicate.
  `aws ssm get-parameter --with-decryption`, `aws kms decrypt` and
  `aws sts get-session-token` all print a plaintext value and none is matched.
- A script is followed two levels deep — the one invoked and what it sources.
  A fetch a third file away is not reached, and only shell interpreters are
  followed: `python3 fetch.py` is not opened, so a fetch shelled out from
  another language is not seen.
- Inside an invoked script the scan is textual. A fetch behind a condition that
  would never be taken still blocks, because nothing here runs the file to find
  out, and a fetch in a file this plugin's own tree contains is not scanned at
  all.
- The reader list in the ask gate is closed — `cat`, `head`, `tail`, `less`,
  `more`, `grep`. A file read by any other program does not reach the basename
  patterns.

## License

Apache-2.0.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — sign off your commits
(`git commit -s`), no CLA required.
