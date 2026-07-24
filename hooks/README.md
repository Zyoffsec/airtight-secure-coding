# Hooks

The skill is a constraint the model *chooses* to apply. A hook is one it cannot skip.

`airtight-surface-guard.py` runs before every file write. It reads what is about to be
written, works out which security surfaces the code touches, and injects only that
surface's gate lines from `skills/airtight/gates.md`. For a small set of failures it can see
deterministically, it does not advise — it **denies the write**.

## Why this exists

Two things the skill alone cannot do:

**Context decay.** A skill loads once and then competes with everything else in a long
session. Fifty tool calls later the gates are still nominally in context and still
nominally in force, but attention is finite. The hook does not care how long the session
is — it fires on the write itself.

**Advice is ignorable.** Measured on the same prompt, injecting gate lines as context
produced a hardened endpoint on one run and was silently ignored on the next. A denial
is not ignorable: the file does not get written.

## What it denies

| Finding | Condition | Gates |
| --- | --- | --- |
| `OPEN ROUTE` | The file defines HTTP routes and nothing in it derives a server-side identity | 10, 11, 12 |
| `UNVERIFIED WEBHOOK` | An inbound webhook handler that never checks the sender's signature | 96 |
| `QUERY BUILT BY INTERPOLATION` | A value spliced into a query string instead of bound as a parameter | 21, 22, 24 |
| `COMMAND BUILT BY INTERPOLATION` | A value reaching a shell as text, or `shell=True` | 26 |
| `RAW HTML SINK` | A non-literal value assigned to `innerHTML` / `dangerouslySetInnerHTML`, with no sanitiser in the file | 50, 51 |
| `IDOR` | An authenticated lookup by caller-supplied id with no ownership term in the query | 12 |
| `CSRF` | A cookie-authenticated mutation with no CSRF token verified | 130 |
| `MUTATION BEHIND GET` | A route registered for GET that changes state | 131 |
| `CORS ANY-ORIGIN WITH CREDENTIALS` | Wildcard or reflected origin combined with credentials | 80 |
| `SESSION COOKIE FLAGS` | An auth cookie set without httpOnly, secure or sameSite | 7 |
| `PASSWORD UNDER A FAST HASH` | A password put through a general-purpose digest | 3 |
| `CREDENTIAL ENDPOINT WITHOUT A BOUND` | A login-shaped route with no throttle or attempt counter | 120, 121 |
| `HARDCODED SECRET` | A credential literal is assigned in source | 30 |
| `SECRET FALLBACK DEFAULT` | An environment read supplies a literal default | 31 |
| `SECRET REACHES THE CLIENT` | A credential in a browser-served file, or a `NEXT_PUBLIC_*` / `VITE_*` variable carrying one | 35 |

Everything else costs nothing. Advisory gate context is **off by default**: the same
injected advice produced a hardened endpoint on one run and was silently ignored on the
next, so paying tokens for it on every write was not buying enforcement. A write that
touches no deniable failure now injects zero characters. Turn the advisory back on with
`AIRTIGHT_GUARD=verbose` if you want the gate lines in context anyway.

Measured over 26 files of real generated code: **0 tokens** where the old behaviour spent
about 12,000, and ~51 ms per write.

## Where the guard is deliberately looser than the gate

Gate 3 asks for argon2id, or bcrypt where argon2 is unavailable. The guard denies only the
catastrophic shape — a password reaching a general-purpose digest like SHA-256 or MD5,
which a GPU walks at billions of candidates a second. It lets PBKDF2 and scrypt through:
they are real key-derivation functions, salted and iterated, and denying them would be the
guard overruling a defensible choice rather than catching an omission.

So a PBKDF2 login passes the hook and still fails Gate 3. That is the division of labour:
the hook stops the disasters it can prove, the gates carry the full standard. Run
`airtight audit` when you want the gate rather than the guard.

## What it does not cover

- **Code the assistant prints in chat without writing a file.** The hook is a file-write
  guard; a code block in a reply never reaches it.
- **Auth enforced in a file the write does not touch.** A route file whose middleware
  lives elsewhere reads as an open route. Denials are per-write, not per-project.
- **Ownership enforced elsewhere.** The IDOR finding reads one file. A handler whose scoping
  lives in a repository or service layer it calls will be denied; the message says to add the
  role check or the ownership column, and stopping to ask is the correct outcome there.
- **SSRF.** Whether a fetched URL is caller-supplied is not visible in one file, so gates
  70–79 stay advisory rather than risk denying every outbound call.
- **Clickjacking.** Gate 132 asks for `frame-ancestors`; whether a given response serves an
  authenticated page is not decidable from one file, so it stays advisory.
- **Memory safety.** Buffer overflows, use-after-free and format strings are outside the
  67 gates entirely. In C or C++ the guard sees a request handler and nothing beneath it.
- **Anything else outside the findings above.** The remaining gates are advisory here.
- **Prose that teaches.** Markdown and text files are exempt from the route, webhook and
  client-bundle findings, and held to a higher bar on secrets: a documented
  `SECRET_KEY = "changeme"` passes, while a literal carrying a vendor prefix (`sk_live_`,
  `AKIA…`, `ghp_`) or a private-key header is denied and treated as compromised. This
  project's own `skills/airtight/vectors/secrets.md` teaches by quoting the mistakes; a guard
  that cannot tell teaching from leaking blocks the very files that explain it.

## Install

```bash
./hooks/install.sh
```

It self-tests the guard first and refuses to install a failing one, backs up your settings,
adds nothing it cannot remove again, and leaves every other hook untouched. Running it
twice changes nothing the second time. `--uninstall` reverses it; `--with-update-check`
also wires the weekly version check.

Or do it by hand — point a `PreToolUse` hook at the script. In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$HOME/.claude/skills/airtight/hooks/airtight-surface-guard.py\""
          }
        ]
      }
    ]
  }
}
```

Adjust the path to wherever the skill is installed. The script locates `gates.md`
relative to itself, so no other configuration is needed; set `AIRTIGHT_GATES` to an
explicit path if your layout is unusual.

Requires Python 3.8+. No dependencies.

## Turning it off

```bash
AIRTIGHT_GUARD=off claude
```

This is the developer's override and only the developer's. The guard rejects markers
written into the source — a comment claiming a route is intentionally public does not
lift a denial, because an assistant that can write its own exemption has no gate at all.
When a denial is genuinely wrong, the assistant is told to stop and ask you rather than
work around it.

## It cannot break your session

A hook that throws interrupts the developer mid-task, and a security tool that breaks the
session it was meant to protect has spent its credibility. So the entry point holds no
logic at all: `airtight-surface-guard.py` reads stdin, hands it to
`airtight_guard_impl.py`, and swallows everything — including a `SyntaxError` in the
implementation, which an import raises at runtime and the launcher's `except` therefore
catches.

Verified by fault injection. In each case the guard exits 0 and writes nothing to stderr:

| Injected fault | Result |
| --- | --- |
| Syntax error in the implementation | silent, exit 0 |
| Implementation deleted entirely | silent, exit 0 |
| `gates.md` unreadable | silent, exit 0 |
| Malformed JSON on stdin | silent, exit 0 |
| 5 MB file written | silent, exit 0, 0.08 s |

The worst outcome available to a broken guard is a write that passes unchecked.

## Self-test

```bash
python3 hooks/airtight-surface-guard.py --selftest
```

97 cases: 48 that must be denied, 49 that must pass untouched. Every false positive and
every miss ever found against real generated code is pinned here as a case, so a fix that
resurrects one fails the suite rather than shipping. Run it after any edit to the
implementation.

---

# Update check

`airtight-update-check.py` compares the installed version against the published one and
prints a single line when a newer release exists. It is **off unless you turn it on**,
runs at most once a week, times out in three seconds, and fails silently offline.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "AIRTIGHT_UPDATE_CHECK=on python3 \"$HOME/.claude/skills/airtight/hooks/airtight-update-check.py\""
          }
        ]
      }
    ]
  }
}
```

## Why it notifies instead of updating

Because an auto-updater is the thing this skill tells you not to build.

Pulling remote code and putting it on the execution path is **Gate 93** — code fetched
then executed. Doing it without verifying a signature on the artifact is **Gate 95**.
Every agent running Airtight would be one compromised repository away from executing
whatever landed in `main`, and the blast radius would be every machine that installed a
security tool precisely because it wanted fewer holes like that.

A tool that exempts itself from its own gates is not a tool anyone should trust. So the
check tells you an update exists and stops there — applying it stays a command you type,
after reading a changelog you chose to read.
