# Validation — measured, not claimed

Two real Claude Code sessions were given the **identical** prompt — "build an Express site: registration, login, profile" — on the same model. One ran **without** Airtight (`without-airtight/`), one with Airtight loaded (`with-airtight/`). Both apps are included here verbatim as evidence.

**The full 67-gate audit of both builds, with file:line evidence per verdict &rarr; [`scorecard.md`](scorecard.md).** The table below is the short version.

## Both got the fundamentals right

A competent model already writes good crypto and auth unprompted. Both builds shipped: password hashing, httpOnly cookies, parameterized SQL, proper session handling, and a login that does not leak whether an account exists. Airtight does not exist to fix bad crypto.

## The difference is the part nobody asked for

| Control | Without Airtight | With Airtight |
|---|---|---|
| Password hash | bcrypt (12 rounds) | argon2id — Gate 3 |
| Parameterized SQL | yes | yes — Gate 22 |
| httpOnly / SameSite cookies | yes | yes — Gate 7 |
| Session fixation (regenerate) | yes | yes — Gate 5 |
| Login without enumeration | text only | + timing-uniform via dummy hash — Gate 1 |
| Session secret | fallback default present | env only, refuses to start if unset — Gate 31 |
| Rate limit on auth routes | missing | present — Gate 120 |
| Per-account lockout | missing | 5 failures → 429 — Gate 121 |
| CSRF protection | missing | synchronizer tokens |
| Security event logging | missing | structured events — Gate 100/103 |
| Length / DoS bounds | missing | present — Gate 128 |
| Input validation | regex | zod schema + allowlist — Gate 40/43 |

## Verdict

The control shipped a working app but silently skipped rate limiting, account lockout, CSRF, security logging and length bounds, and left a guessable session-secret fallback. Airtight closed every one — each tied to a numbered gate you can look up and cite. The default AI mistake is **omission, not incompetence**, and that is exactly what the gates catch.

## Reproduce

Same prompt, two sessions, one with the skill and one without. Compare the two directories here.
