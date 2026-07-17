# The prove verb

`airtight prove <target>` self-tests the developer's own code and reports which safeguards actually
hold.

Reading code tells you what it was meant to do. `prove` finds out what it does. A parameterized query
that was bypassed by a helper three files away still reads correctly at the call site; an
authorization check on the wrong variable still reads correctly everywhere. `prove` sends the input
and reads the answer.

This is an integration test of the developer's own code, run against their own machine. It is not a
security assessment, it is not a scanner, and it is not pointed at anything the developer does not
own. The rails below come first because they are the difference between a self-test and an attack,
and the only difference is the target.

## Safety rails

These are not defaults to be argued out of. They are the conditions under which the verb runs.

**1. The developer's own local or development code only.** `localhost`, `127.0.0.1`, `::1`, a local
container or dev-compose service, or a development host the developer names and confirms. Nothing
else.

**2. Never a third-party host.** Never a production URL, a public site, a vendor's API, an app the
developer merely uses, a URL a user pasted, or any hostname that arrived from the code under test
rather than from the developer. If the target is not obviously the developer's own project running
locally, `prove` does not run.

**3. Read-only probes only.** Probes may read. They must not delete, modify, escalate, or persist.
No `DROP`, no `DELETE`, no `UPDATE`, no writes through the endpoint under test, no account creation
outside a disposable local fixture, no state left behind. A probe that would change data is not a
probe — reason about that gate from the code instead and say so in the report.

**4. Confirm before anything non-local.** If the target is anything other than an unambiguously local
address, stop and get explicit confirmation naming the host, and say plainly what will be sent. No
implicit consent, no "the developer said prove so they meant it". A `prove` on a dev server that
another team is using is someone else's outage.

**5. Refuse when ownership is not clear.** Ambiguity resolves to refusal, not to a question chain
that talks itself into a yes. Say what would make it clear — a local address, a repo you can read, a
service in their compose file — and stop. If the request is for a host the developer does not own,
refuse once, give the one reason, and close. Do not offer a smaller version of it.

**6. Failed probe means unknown, not safe.** A connection error, a 404, a timeout or a probe you
declined to send are all `UNKNOWN`. Never let a probe that did not land read as a safeguard that
held.

## Protocol

### 1. Establish the target is the developer's own

Before anything else. Read the code. A route in the repo you are working in, bound to a local port,
started from the developer's own compose file or dev command — that is the target. If you cannot
establish this from the project itself, stop here.

Do not take the target's identity from a config value, an env var or a string in the code. Take it
from the developer and the repo you are in.

### 2. Discover the endpoint

Find the route in the source: the framework's routing table, the handler, its method, its path, the
shape of the input, the auth it expects. Establish the service is already running and reachable —
`prove` tests what the developer is running; it does not start services, run migrations or seed
databases on its own initiative.

If the endpoint needs authentication, use a credential the developer supplies or a local test fixture
that already exists. Do not attempt to acquire one. Bypassing auth to reach an endpoint is the thing
being tested, not a setup step.

### 3. Send edge-case input appropriate to the gate

One probe per gate, minimal, read-only, derived from the gate being tested. The probe must be
something the gate's failing example would visibly break on and its passing example would visibly
survive.

Shape by topic:

| Gate range | Probe shape | Read-only form |
| --- | --- | --- |
| 1–9 credentials | Wrong password, unknown user, expired or tampered token, reused reset token | Compare responses and timing. Never brute-force; a handful of requests, not a list |
| 10–19 authorization | Fetch another user's object by ID as a low-privilege fixture user; hit an admin route unauthenticated | `GET` only. Reaching data you should not is the finding — do not then write to it |
| 20–29 injection | Input that alters query *structure* harmlessly: an unbalanced quote, `' OR '1'='1`, a `1=1` predicate | Never a payload that destroys or writes. `' OR '1'='1` proves it; `'; DROP TABLE users; --` proves it once |
| 30–39 secrets | Trigger an error path; read the error body and headers; request known config paths | Read the response. Do not exfiltrate anything found — report that it is reachable, not its value |
| 40–49 input validation | Oversized body, wrong type, missing required field, deep nesting, unexpected content-type | Bounded sizes. Do not use `prove` as a load test |
| 50–59 XSS | A marker value through a reflected parameter — `<b>airtight</b>`, `</script>` | Read the **raw response body**, never the rendered DOM. A `javascript:` href settles nothing over HTTP |
| 60–69 crypto | Mostly not probeable | Reason from the configuration site: the mode string, the nonce's origin and the verify flag are literals in the source |
| 70–79 SSRF | A loopback URL into the developer's own import or preview endpoint | `127.0.0.1` only. A metadata address or any host off the machine is rail 2, and the loopback answer settles it anyway |
| 80–89 misconfiguration | An `Origin` header from a reserved TLD; `docker compose config`; `stat` on a generated file | Read the header, the rendered config and the mode. Never the file's contents, never connect to the port |
| 90–99 integrity | An unsigned webhook POST whose target id does not exist | Only where the handler's action is an update keyed to a record that must already exist — the miss is what keeps it read-only |
| 100–109 logging | A canary string through a failed login, then read the developer's own local sink | A wrong password is a read. Do not probe password-change or role-change handlers |
| 110–119 dependencies | No traffic. Read the manifest, the lockfile and the pipeline files | Registry lookups are a host the developer does not own — rail 2, and it does not bend for a GET |
| 120–129 design | One oversized `?limit=`, one large-but-harmless magnitude | **Once.** The request is the denial of service in miniature; repeating it is a load test. Never exceed a rate limit to prove it exists |

Keep the volume trivial. `prove` is a handful of requests demonstrating a property, not traffic. If a
gate can only be demonstrated by something destructive or by volume, it is not provable — mark it
`UNKNOWN` with the reason and move on.

### 4. Interpret the response

Interpret against what the gate requires. Be exact about what a response proves:

- **HELD** — the safeguard demonstrably worked. Injection probe returned a clean empty result and the
  logged query shows a bound parameter. The unauthorized fetch returned 403 and no body.
- **FAILED** — the safeguard demonstrably did not. `' OR '1'='1` returned rows it should not. The
  other user's record came back. The stack trace carried the database DSN.
- **UNKNOWN** — the probe did not settle it. A 500 could be the safeguard rejecting the input or the
  code crashing on it; those are different outcomes and the response alone may not distinguish them.
  Read the code or the log to resolve it, or report `UNKNOWN`.

Watch for the false HELD. A 400 might mean the validation layer caught the probe while the injection
sits untested behind it. A 404 might mean an authorization check fired, or the route moved. When a
probe never reached the code the gate is about, the gate is `UNKNOWN` — the safeguard was not
exercised, so nothing was proved about it.

### 5. Report

Per gate: what was sent, what came back, verdict, and the one-line consequence for failures.

```
Gate 22  SQL query construction              HELD
  POST /search  q=' OR '1'='1
  -> 200, 0 rows. Query log shows bound parameter.

Gate 12  Object ownership check              FAILED
  GET /api/orders/1041  as fixture user #7 (owner: #3)
  -> 200, full order body returned.
  Any authenticated user can read any order by ID.

Gate 37  Secrets in error responses          UNKNOWN
  GET /api/orders/nonexistent
  -> 404, empty body. Error path not reached; DEBUG=false locally.
  Not proved. Verify against the dev configuration.
```

Then state the boundary, every time:

> Probed: gates 12, 22, 37 against localhost:8000. Gate 37 not settled. Gates 1-9 not probed — no
> auth endpoints in the target. This exercises the paths listed above; it does not establish that the
> application is secure.

A `prove` report is evidence about specific paths under specific input. It is not a clean bill of
health, and it must never be phrased as one. Report what held, what failed, what you could not
settle, and what you never touched.
