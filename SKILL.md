---
name: airtight
description: Secure-coding gates for AI-written code. Load when writing or modifying web application code, authentication and login flows, database queries, user input handling, file uploads, or configuration and secrets — and when the user types "airtight audit", "airtight harden", or "airtight prove".
version: 0.1.0
---

# Airtight

AI writes your code. Who checks it?

Correct-looking code can still be unsafe, and the gap is rarely where people expect. Asked for "a
login endpoint", a competent model writes a good one: the password gets a memory-hard KDF, the cookie
gets `httpOnly`, the record lookup carries the owner. It knows all of that unprompted.

What it does not write is the part nobody mentioned. No rate limit, so the endpoint can be ground
through a password list at full speed. No attempt counter, so nothing ever locks. No log line, so the
grinding is invisible while it happens and unreconstructable afterwards. The developer asked for a
login endpoint, not for one that survives contact with an attacker.

The default AI mistake is **omission**, not incompetence. Weight the gates accordingly: the ones that
catch a missing bound, a missing counter, a missing record are the ones earning their place. Airtight
is the part of the request nobody makes.

## Scope — state it honestly, always

Airtight covers **the well-known safe-coding mistakes AI makes by default**: the errors that recur in
nearly every AI-assisted app because the developer asked for a feature, not a safe feature.

Airtight does **not** cover:
- business-logic errors that require domain knowledge (should this user be allowed to refund that?)
- unknown flaws in third-party dependencies
- poor architecture

Never say or imply the code is "secure" or "fully covered". Say what was checked and what was not.
A safety tool that overpromises loses trust the first time it misses. When reporting, name the gates
applied; if a risk falls outside the gate registry, say so plainly rather than stretching a gate to
cover it.

## The mechanic: gates, not advice

Advice — "validate input", "use parameterized queries" — is easy to read and just as easy to ignore.
A **gate** is a hard, checkable condition on what may be emitted:

> Code that stores a password MUST NOT be emitted unless it uses bcrypt, argon2 or scrypt. **Gate 3.**

Binary. Quotable. Tied to an emission decision. A gate is either satisfied or the code does not ship.

The registry lives in `references/gates.md` — every gate's rule and fix in one line, the whole
checklist in one small file. Gates are numbered and stable — cite them by number in every report, diff
comment and refusal, so the developer can look up exactly what was enforced.

## Verbs and dispatch

| Invocation | Behaviour |
| --- | --- |
| *(default — no verb)* | Developer is writing code. Gates apply **silently**. No lecture, no security essay. Emit code that passes; if a gate forced a choice, one short line of why, at most. |
| `airtight audit <target>` | Read the target. Score against applicable gates. Return a ranked punch list. **Does not edit.** |
| `airtight harden <target>` | Find and fix. State which files will be touched **before** touching them. |
| `airtight prove <target>` | Self-test the developer's own code — exercise their local endpoint with edge-case input and report which safeguards actually hold. See `references/proof.md`. |

### Dispatch rules

**Default (no verb).** This is the common case. The developer wants a feature; they get one that
passes the gates. Do not announce Airtight. Do not append a security summary to ordinary code. The
gates are a constraint on your output, not a topic of conversation.

**audit.** Read-only, always. Never edit during an audit — the developer asked what is wrong, not for
it to change under them. Output: ranked punch list, worst first.

```
1. Gate 3 FAIL  auth/register.py:41   Password stored as SHA-256 hex digest.
                                      Fix: argon2id via argon2-cffi.
2. Gate 22 FAIL api/search.py:88      SQL built by f-string from `q`.
                                      Fix: parameterized query.
3. Gate 31 FAIL config/settings.py:12 SECRET_KEY has a hardcoded fallback default.
                                      Fix: index os.environ directly.
```

A gate is pass or fail — there is no WARN. If you cannot tell, it fails. Rank by consequence, not by
count: a reachable auth bypass outranks three theoretical issues. State which gates you checked, and
note any part of the target you could not read.

**harden.** Announce the file list first, then edit. Keep changes minimal and scoped to gate failures
— hardening is not a refactor, and a large diff hides the fix. After editing, report per gate:
fixed / not fixed / not applicable. If a fix needs a decision only the developer can make (which
identity provider, which roles exist), stop and ask rather than guessing.

**prove.** Verification, not lecturing. Exercise the developer's own local code and report what held.
Load `references/proof.md` before running anything — it carries the safety rails, and they are not
optional.

## Pre-emit self-check

Run this **before** returning code. It is the whole mechanic; skipping it makes Airtight the passive
markdown it was built to replace.

1. **Identify surfaces.** What does this code touch — credentials, authorization, a query, config,
   external input? Map each to a gate range (see below).
2. **Apply the registry.** `references/gates.md` carries every gate's rule and fix, one line each — it
   is the complete working checklist. Score against it directly. Do **not** load topic vector files in
   normal operation; the registry is enough.
3. **Score.** For each applicable gate: pass or fail. Not "probably fine". If you cannot tell, it
   fails — you do not know that it passes.
4. **Revise.** Rewrite anything that fails and re-score it. Failing code is not emitted.
5. **Emit.** Silently, under the default verb. No scorecard unless a verb asked for one.

Applies to code you write, code you edit, and code you paste from elsewhere. A gate failure you
inherited is still a gate failure you are shipping.

If a gate cannot be satisfied — the framework has no parameterized query API, the developer has
explicitly required the unsafe path — do not emit it quietly. Emit with a one-line note naming the
gate and the exposure. The developer may override a gate. You may not override it for them.

## Topic files — optional deep dives

The registry (`references/gates.md`) is the working checklist and already covers every gate. The
per-topic files below hold longer background for one topic each. You do **not** need them for normal
work — reach for one only when a specific gate needs a deeper look, and load **at most one**.

| Trigger in the code or request | Load |
| --- | --- |
| Passwords, hashing, sessions, tokens, API keys, login, signup, reset | `references/vectors/credentials.md` |
| Roles, permissions, ownership checks, admin routes, IDs in URLs, tenancy | `references/vectors/authorization.md` |
| SQL, NoSQL, ORM raw queries, shell commands, template rendering, HTML from user data | `references/vectors/injection.md` |
| `.env`, config modules, API keys and connection strings in source, `process.env` reads, `NEXT_PUBLIC_*`/`VITE_*`, error handlers | `references/vectors/secrets.md` |
| Request bodies, query params, schema validation, prices and amounts, file uploads | `references/vectors/input.md` |
| Markdown, rich text, raw-HTML sinks, `href`/`src` from data, state inside a `<script>` | `references/vectors/xss.md` |
| Encrypting, signing, TLS client options, `Math.random()`, base64 "protection" | `references/vectors/crypto.md` |
| Fetching a URL a caller supplied, webhooks out, link previews, HTML-to-PDF, XML | `references/vectors/ssrf.md` |
| CORS, Dockerfiles, compose, debug flags, seed scripts, published ports, file modes | `references/vectors/misconfig.md` |
| Deserializers, CDN script tags, `curl \| sh`, auto-update, inbound webhook payloads | `references/vectors/integrity.md` |
| Log calls, logger config, `catch` blocks, auth and admin events | `references/vectors/logging.md` |
| Manifests, lockfiles, install commands, CI audit steps, naming a package | `references/vectors/dependencies.md` |
| Rate limits, pagination, request-sized work, archive extraction, quantities | `references/vectors/design.md` |

**Default: load none.** For ordinary work, apply the registry and emit — the one-line rules and fixes
are enough. Only when a specific gate genuinely needs deeper context, load that **single** topic file,
then stop. Never load more than one topic file at a time, and prefer loading none when the registry
answers the question.

Always applied:
- `references/gates.md` — the complete gate registry: every gate's rule and fix, one line each. This is
  the working checklist for the default flow.
- `references/proof.md` — the `prove` protocol and its safety rails (loaded only for `prove`).

## Gate ranges at a glance

| Range | Topic |
| --- | --- |
| 1–9 | Credentials and authentication |
| 10–19 | Authorization and access control |
| 20–29 | Injection |
| 30–39 | Configuration and secrets |
| 40–49 | Input validation |
| 50–59 | Cross-site scripting |
| 60–69 | Cryptographic failures |
| 70–79 | Server-side request forgery |
| 80–89 | Security misconfiguration |
| 90–99 | Software and data integrity failures |
| 100–109 | Security logging and monitoring failures |
| 110–119 | Vulnerable and outdated components |
| 120–129 | Insecure design |
| 130+ | Reserved for future topics |

Full text in `references/gates.md`. Cite by number, always.

## Reporting rules

- Cite the gate number. "Gate 22 FAIL" is checkable; "SQL injection risk" is a vibe.
- Give file and line. A finding without a location is an opinion.
- One fix per finding, concrete. Not a list of options.
- Rank by consequence.
- Say what you did not check. Unread files, generated code, vendored dependencies, anything outside
  the gate registry.
- No severity theatre. No CVSS scores, no colour-coded badges, no "CRITICAL!!!". The gate number and
  the consequence carry the weight.

## Contributing a topic

One file per topic in `references/vectors/`, one reserved gate range per file, core untouched. The
numbering rules, the format contract and the bar a gate must clear are in `references/gates.md`.
