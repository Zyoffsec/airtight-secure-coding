# Contributing to Airtight

**A topic is one file in `references/vectors/`. You never touch the core to add one.**

That is the rule the whole project is built around. A new topic means a new file and a new gate
range. `SKILL.md` gains one row in its load-trigger table and `references/gates.md` gains one row in
its range table — nothing else moves. Two people writing two topics never touch the same lines, so
they never conflict, so neither of them needs to wait for the other or for a maintainer to arbitrate.

Comparable projects have died because everything lived in one file: every contribution collided, one
maintainer ended up carrying every topic alone, and the repo went quiet within weeks. The file layout
here is not a style preference. It is the thing that lets strangers land work.

You should be able to ship a topic in one PR without asking anyone anything. If something below is
unclear enough that you have to ask, that is a bug in this file — open an issue about it.

## What you can contribute

| Contribution | Where it goes | Touches core? |
| --- | --- | --- |
| A new gate in an existing topic | that topic's file in `references/vectors/` | no |
| A new topic (with its gates) | a new file in `references/vectors/` + one row in two tables | one row each |
| A better `Fails` example | that topic's file | no |
| A `prove` probe shape for a range | `references/proof.md` probe table | no |
| Retiring a gate | that topic's file | no |

## Numbering

Three rules, and they are absolute:

- **Never renumber.** Gate numbers appear in audit reports, commit messages, code comments and issue
  trackers that this repo cannot see. A renumber silently invalidates every existing citation.
- **Never reuse.** A retired gate keeps its number forever. The number is spent.
- **Never renegotiate meaning.** Tightening a threshold (an algorithm falls out of favour) is an edit
  to the gate. Changing what the gate is *about* is a new gate plus a retirement of the old one.

**Leave gaps deliberately.** Numbering 1, 2, 3, 5 with 4 held for the obvious near-future gate is
correct. There is no cost to a gap and no way back from a renumber.

### Which numbers are free

Current allocation, as of the 67 published gates:

| Range | Topic | File | Taken | Free |
| --- | --- | --- | --- | --- |
| 1-9 | Credentials and authentication | `vectors/credentials.md` | 1, 2, 3, 5, 6, 7, 8 | 4, 9 |
| 10-19 | Authorization and access control | `vectors/authorization.md` | 10, 11, 12, 13, 15 | 14, 16-19 |
| 20-29 | Injection | `vectors/injection.md` | 21, 22, 24, 26, 28 | 20, 23, 25, 27, 29 |
| 30-39 | Configuration and secrets | `vectors/secrets.md` | 30, 31, 32, 33, 35, 37 | 34, 36, 38, 39 |
| 40-49 | Input validation | `vectors/input.md` | 40, 41, 43, 44, 45, 46 | 42, 47, 48, 49 |
| 50-59 | Cross-site scripting | `vectors/xss.md` | 50, 51, 53, 55 | 52, 54, 56-59 |
| 60-69 | Cryptographic failures | `vectors/crypto.md` | 60, 61, 63, 65 | 62, 64, 66-69 |
| 70-79 | Server-side request forgery | `vectors/ssrf.md` | 70, 71, 74, 76 | 72, 73, 75, 77-79 |
| 80-89 | Security misconfiguration | `vectors/misconfig.md` | 80, 81, 83, 85, 87 | 82, 84, 86, 88, 89 |
| 90-99 | Software and data integrity | `vectors/integrity.md` | 90, 91, 93, 95, 96 | 92, 94, 97-99 |
| 100-109 | Logging and monitoring | `vectors/logging.md` | 100, 101, 103, 107 | 102, 104-106, 108, 109 |
| 110-119 | Vulnerable components | `vectors/dependencies.md` | 110, 112, 114, 115, 117, 118 | 111, 113, 116, 119 |
| 120-129 | Insecure design | `vectors/design.md` | 120, 121, 123, 125, 127, 128 | 122, 124, 126, 129 |
| 130+ | — | — | — | **entire range unclaimed** |

Re-check the table in `references/gates.md` before you claim — this one can lag.

## Claiming a range without colliding

Ranges are ten numbers wide. If a topic needs more than nine gates, it is two topics: split it and
claim two ranges rather than borrowing a neighbour's numbers.

1. **Open an issue titled `claim: <topic> (range NN-NN)`** before you write the file. One line on
   what the topic covers is enough. This is the whole reservation mechanism — the issue is the lock,
   and it exists so two people don't independently write gates 50-59.
2. **Take the lowest free range from 130.** Don't reserve a nicer number for later.
3. **If someone claimed it an hour before you**, take the next range. Renumbering your draft costs
   you ten minutes; renumbering a published gate costs everyone.
4. **A claim goes stale after 30 days** with no PR. Say so on the issue and take it.

Adding a gate to an existing range needs no claim — just take a free number and open the PR. If two
PRs pick the same number, the second one to merge renumbers. That is the only case where renumbering
is allowed, and it is only allowed because nothing has been published yet.

## Template — copy this literally

Every gate uses exactly this format. Not approximately.

```markdown
### Gate N — {short name, 2-5 words}

> {One-sentence MUST NOT / unless rule. Self-contained. Quotable.}

**Applies when:** {the trigger a model can recognise in the code or request}

**Passes:**
```python
{minimal code that satisfies the gate}
```

**Fails:**
```python
{minimal code that violates it — the default output a model actually produces}
```

**Why:** {1-3 sentences. The consequence, concretely. What an attacker does with the failing
version. No lecture, no history of the vulnerability class.}

**Fix:** {The single concrete remedy. One, not a menu.}
```

Gate 3 in `vectors/credentials.md` and Gate 22 in `vectors/injection.md` are the reference
implementations — both are reproduced in `references/gates.md`. Read one before you write yours.

### Rules for the fields

- **The `Fails` example must be the plausible default**, not a strawman. If it is obviously wrong at
  a glance, the gate is not catching a real default mistake and it will be rejected on rule 5 below.
  The failing example should be code you would not flag while skimming a PR.
- **`Passes` and `Fails` differ in the one thing the gate is about.** Everything else stays
  identical. The diff is the point.
- **`Why` states consequence, not category.** "An attacker who dumps the users table recovers every
  password with a consumer GPU in hours" beats "this is a cryptographic weakness".
- **`Fix` is one remedy.** A developer who wanted to weigh three options would not need a gate.
- **No emoji, no severity labels, no CVSS, no marketing.** The gate number and the consequence carry
  the weight.

### The MUST NOT / unless shape

Write a prohibition with an escape, not a recommendation with a caveat:

> Code that **{does the risky thing}** MUST NOT be emitted unless it **{satisfies the concrete
> condition}**.

The prohibition is the default. The `unless` clause is a finite, named list of ways out — not "unless
appropriate", not "unless the context requires otherwise". If you cannot enumerate the escape clause,
the gate is not binary yet.

## What makes a gate acceptable

All five. Fail one and it is advice wearing a number — it will be ignored exactly like the advice it
came from.

1. **Binary.** Pass or fail, decidable by reading the code.
2. **Checkable without running anything.** The pre-emit self-check happens before the code exists
   anywhere but the response. A gate needing a debugger or a live database cannot gate emission — it
   may make a good `prove` probe instead.
3. **Quotable.** One sentence, self-contained, meaningful pasted into a code review with no context.
4. **Tied to an emission decision.** A line of code either passes or fails it.
5. **A default AI mistake.** Would a competent model get this wrong unprompted, in a normal app, most
   of the time? If no, it does not belong here. **Being narrow is the product.**

### Accepted vs rejected

| Rejected | Why | Accepted instead |
| --- | --- | --- |
| "Passwords should be stored securely." | Not binary. "Securely" is an argument, and a model always wins an argument with itself. | "Code that stores a password MUST NOT be emitted unless the password is hashed with bcrypt, argon2 or scrypt." |
| "Validate all user input." | Not tied to an emission decision. No specific line passes or fails. | "Code that reads a field out of a request MUST NOT be emitted unless the request has first been parsed server-side by a runtime schema that names every accepted field and its type." |
| "Rotate your keys quarterly." | Sound operational advice. No line of code passes or fails it. | "The repository MUST NOT contain a hardcoded credential literal." |
| "Prefer defence in depth." | Not binary, not quotable, not checkable. | Nothing. This is a philosophy, not a gate. |
| "Guard against CRLF injection in SMTP headers via a mail library that doesn't sanitise." | Real, but not a default AI mistake in a normal app. Fails rule 5. | Nothing. Out of scope, and saying so is the feature. |
| "Use HTTPS in production." | Not a property of emitted application code. | "Code that sets a cookie carrying a session identifier MUST NOT be emitted unless the cookie sets `httpOnly`, `secure` and `sameSite`." |

If your gate is real but fails rule 5, the honest outcome is that Airtight does not cover it. That is
not a gap to be papered over — the scope boundary is what makes the tool trustworthy. Overpromising
loses trust the first time it misses.

## Verification sections are read-only

If your topic contributes a probe shape to `references/proof.md`, the rails are conditions, not
defaults:

- **The developer's own local or development code only.** `localhost`, `127.0.0.1`, `::1`, a local
  container, or a dev host the developer names and confirms. Nothing else.
- **Never a third-party host.** No production URL, no public site, no vendor API, no hostname that
  arrived from the code under test rather than from the developer.
- **Read-only probes only.** A probe may read. It must not delete, modify, escalate or persist. No
  `DROP`, no `DELETE`, no `UPDATE`, no writes through the endpoint under test, no state left behind.
  `' OR '1'='1` demonstrates the property; `'; DROP TABLE users; --` demonstrates it once.
- **A probe that would change data is not a probe.** Reason about that gate from the code and mark it
  `UNKNOWN` in the report, with the reason.
- **A failed probe means UNKNOWN, never HELD.** A connection error, a 404, a timeout or a probe you
  declined to send did not settle anything.
- **Trivial volume.** A handful of requests demonstrating a property. Never a load test, never a
  brute-force, never a wordlist.

A probe that breaks any of these is not a self-test of the developer's own code. The only difference
between a self-test and an attack is the target and the intent, and a PR that blurs either will be
closed. If a gate can only be demonstrated destructively, it is not provable — say so and move on.

## Retiring a gate

Keep the number and the heading. Replace the body:

```markdown
### Gate N — {short name} (RETIRED)

Retired {YYYY-MM}: {one line — why}. {Superseded by Gate M. | No replacement.}
```

Retire when the mistake stops being a default (the ecosystem fixed it), when the gate turns out not
to be binary in practice, or when it folds into a broader gate. Never because it is inconvenient to
satisfy.

## Submitting

1. One topic or one gate per PR. A PR that adds a topic *and* rewrites the core is two PRs.
2. Title: `gate: N — short name` or `topic: <name> (range NN-NN)`.
3. In the body, state which of the five acceptance rules the gate clears, especially rule 5. One line
   each. If you cannot make the case for rule 5, make the case in an issue first.
4. If you added a topic, confirm the two table rows — `SKILL.md` load-trigger, `references/gates.md`
   range table — are the only core lines you touched.

Style: sober, technical, short. English. No emoji in headings, no badge rows, no marketing language.
**Never invent a statistic.** If you don't have a real figure, don't use one — an unsourced number in
a security tool is the fastest way to lose a reader who checks.

## License

By contributing you agree your work is licensed under the MIT License — see [LICENSE](LICENSE).
