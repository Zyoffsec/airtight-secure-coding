# Changelog

All notable changes to this skill are recorded here.

## [0.3.2] — 2026-07-24

Ten defects found by writing realistic code and watching what the guard did with it.
Two of them were stalls, which matter most: a guard that hangs holds up every write in
the session, and the developer cannot tell it apart from a hung editor.

### Fixed

- **Two inputs made the guard hang for minutes.** A single 150 KB line of ordinary text,
  and a line repeating the word `PASSWORD`. Both came from unbounded quantifiers beside an
  alternation — `[A-Z_]*(SECRET|API_KEY|TOKEN|PASSWORD)[A-Z_]*` under `IGNORECASE` matches
  lowercase too, so it tried every start position with a long greedy match and backed out
  of each. Both are bounded now, and seven hostile inputs are part of `--selftest` with a
  five-second budget, so a stall fails the suite rather than reaching anyone.
- **`f"built from {path}"` was read as SQL.** `SELECT`, `FROM`, `WHERE`, `UPDATE` and
  `DELETE` are ordinary English words; a sentence containing one of them is not a query.
  Interpolation now only counts inside a string carrying a SQL *shape* — `SELECT … FROM`,
  `INSERT INTO`, `UPDATE … SET`, `DELETE FROM` — which prose does not produce by accident.
- **Authentication written in Go or JavaScript casing went unrecognised**, so
  `r.Use(RequireSession)` and `router.use(requireSignedIn)` read as open routes. Both
  casings are recognised, along with middleware chains, `before_request`, and a principal
  arriving on a context object (`info.context["user"]`, `locals`).
- **Cookie flags declared as a dict of quoted keys** — `{"httponly": True, "secure": True}`
  splatted into `set_cookie` — read as flags missing entirely.
- **Multi-line SQL escaped the injection check**, because a triple-quoted f-string is where
  any query longer than one line actually lives.

### Added

- **WebSocket endpoints, GraphQL resolvers and SvelteKit `load` are routes.** None of them
  look like a route decorator, and all three are unauthenticated by default. A resolver is
  recognised by its `info` argument rather than its name, so an ordinary function called
  `resolve_something` is left alone.
- **WebSocket endpoints, GraphQL resolvers and SvelteKit `load`** are treated as routes.
- **PHP's shell family and string concatenation**, so `shell_exec("convert " . $name)` is
  caught — and `escapeshellarg`, `escapeshellcmd` and `shlex.quote` are recognised as the
  remedy rather than flagged as the problem.
- **A CORS origin reflected through a hand-written header**, which is how the wildcard
  usually arrives in Express.
- `--selftest` grows from 97 cases to **145**, and now reports the slowest hostile input.
  Every defect above is pinned as a case, in both directions: the false positive that was
  denied, and the real failure that must still be caught.

### Notes

- **The guard no longer denies its own implementation.** That file necessarily contains an
  example of everything the guard detects — its self-test corpus is made of them — so
  without the exemption nobody can edit the guard at all. Every other file in the project,
  including the vector files full of vulnerable examples, is checked normally.
- Two more false positives were caught by the self-test itself while this release was being
  written: `escapeshellarg` denied as injection, and a static `insertAdjacentHTML` denied
  because `,\s*(?!…)` backtracks to zero spaces and applies the lookahead to whitespace.
  Both are pinned as cases now. The suite catching its author's regressions before they
  ship is the whole point of it.

## [0.3.1] — 2026-07-24

### Fixed

- **The guard denied correctly written SQL.** Found within a day of release, on a
  read-only reporting tool whose queries were properly parameterised: a static
  `SELECT count(*)`, and a `WHERE id BETWEEN ? AND ?` with both values bound. Both were
  refused.

  The interpolation check scanned a 200-character window after the SQL keyword. That
  window ran past the end of the statement and picked up the `f"conv {cid} | {lang}"` of
  an unrelated `print` on the following line, then read it as a substitution inside the
  query above. `strftime('%s', ?)` tripped it too — SQLite's format specifier read as
  Python's.

  Every alternative now stays inside a single string literal, so neighbouring code cannot
  contribute a match. Real injection is unaffected: f-strings, `%`, `+`, `.format()`,
  template literals, a query built into a variable, and `$queryRawUnsafe` all still deny.

  This is the failure mode that matters most. A guard that blocks correct work does not get
  argued with — it gets switched off, and then it protects nothing. Eight cases pinning both
  the false positives and the real injections are now in `--selftest`, which runs 97.

## [0.3.0] — 2026-07-24

### Added

- **Distribution as a Claude Code plugin**, which is the only way the guard reaches you
  without you editing a settings file by hand:

  ```
  /plugin marketplace add Zyoffsec/airtight-secure-coding
  /plugin install airtight
  ```

  Claude Code wires the guard as part of installing the plugin — declared in
  `hooks/hooks.json`, resolved through `${CLAUDE_PLUGIN_ROOT}`. You approved a plugin, so
  nothing is written behind your back, and `/plugin uninstall airtight` removes both halves.
  This matters because the two halves are not equally optional: measured across six runs of
  one prompt, the skill loaded twice on its own.

  Adding `.claude-plugin/` requires the layout the plugin system expects, so **the skill
  moved to `skills/airtight/`**. `npx skills add` still installs the skill alone. No gate
  number changed.

- **`hooks/airtight-surface-guard.py`** — an optional pre-write guard. It reads the code
  about to be written, detects which security surfaces it touches, and injects only that
  surface's gate lines. On fifteen deterministically visible failures it denies the write
  outright rather than advising:
  - `OPEN ROUTE` — HTTP routes with nothing deriving a server-side identity (Gates 10, 11, 12)
  - `UNVERIFIED WEBHOOK` — an inbound webhook handler with no signature check (Gate 96)
  - `QUERY BUILT BY INTERPOLATION` — a value spliced into a query string (Gates 21, 22, 24)
  - `COMMAND BUILT BY INTERPOLATION` — a value reaching a shell as text (Gate 26)
  - `RAW HTML SINK` — a non-literal value at an HTML sink with no sanitiser (Gates 50, 51)
  - `PASSWORD UNDER A FAST HASH` — a password put through SHA-256, MD5 or similar (Gate 3)
  - `CREDENTIAL ENDPOINT WITHOUT A BOUND` — a login route with no throttle or attempt
    counter (Gates 120, 121). The omission the whole registry exists for.
  - `IDOR` — an authenticated lookup by caller-supplied id with no ownership term (Gate 12)
  - `CSRF` — a cookie-authenticated mutation with no token verified (Gate 130)
  - `MUTATION BEHIND GET` — a GET route that changes state (Gate 131)
  - `CORS ANY-ORIGIN WITH CREDENTIALS` — wildcard origin plus credentials (Gate 80)
  - `SESSION COOKIE FLAGS` — an auth cookie missing httpOnly / secure / sameSite (Gate 7)
  - `HARDCODED SECRET` — a credential literal in source (Gate 30)
  - `SECRET FALLBACK DEFAULT` — an environment read with a literal default (Gate 31)
  - `SECRET REACHES THE CLIENT` — a credential in a browser-served file, or a
    `NEXT_PUBLIC_*` / `VITE_*` variable carrying one (Gate 35)
- **`hooks/airtight-update-check.py`** — an opt-in weekly version check. It reports that
  a newer release exists and changes nothing: auto-installing remote code would be
  Gate 93 and Gate 95, and a security tool that exempts itself from its own gates is not
  one. Off unless `AIRTIGHT_UPDATE_CHECK=on`.
- **`hooks/install.sh`** — wires the guard into Claude Code's settings. Idempotent, backs
  the file up, self-tests the guard before installing it, leaves other hooks alone, and
  `--uninstall` reverses it exactly. Upgrading from 0.1.0 brings the gates with `git pull`;
  the hook is opt-in because a hook edits your settings and nothing should do that silently.
- `hooks/README.md` — install, scope, and an explicit statement of what the guard does
  not cover.
- This changelog.

- **Three new gates — 130, 131, 132 — in a new topic, `skills/airtight/vectors/csrf.md`.** Cross-site
  request forgery had no coverage at all: a grep of the registry returned zero. It is the one
  omission that met the bar for a new gate — a recurring AI default (a model asked for a transfer
  endpoint has no reason to invent a token), binary, and checkable without running anything.
  - Gate 130 — Cookie-authenticated state change
  - Gate 131 — Mutation behind a safe method
  - Gate 132 — Framing denial
  The registry is now 70 gates. Range 130-139 is claimed; 140+ stays unallocated. No existing
  number was renamed, renumbered or retired.

- **The guard cannot take a session down.** The hook entry point is now a launcher with no
  logic; the implementation lives in `hooks/airtight_guard_impl.py` and is imported inside
  a `try`, so a syntax error, a missing file or an unreadable registry all end in exit 0
  and silence. Verified by injecting each fault.
- **A self-test, `--selftest`.** 79 cases, half of them regressions found against real
  generated code. A guard that denies clean work gets switched off, so every false positive
  ever seen is pinned as a case.

### Changed

- **Advisory gate context is off by default.** It was measured to be ignorable — the same
  injected advice hardened an endpoint on one run and was skipped on the next — while
  costing tokens on every write that touched a security surface. Over 26 files of real
  generated code the guard now injects **0 tokens** where it previously spent ~12,000.
  `AIRTIGHT_GUARD=verbose` restores it. Denials are unaffected and always fire.
- **Six false positives fixed**, each found by running the guard over real generated code:
  the project's own `skills/airtight/vectors/secrets.md` denied by its own guard, because a file
  that teaches about leaked keys necessarily contains examples of them; a CSS `url(...)`
  read as a Django route; a non-secret environment default (`DATABASE_PATH`)
  read as Gate 31; a fixture password in a test file read as a shipped credential; a cookie
  flag set from a constant rather than a literal read as missing; an authentication
  dependency named `current_session` not recognised as authentication; and the Gate 21
  pattern — a clause built from source literals alongside bound parameters — read as
  injection. The last fix is per call, not per file: one safe `execute` no longer excuses
  a hand-quoted query beside it.

- **Triage now names every surface that has gates.** The pre-emit self-check listed
  surfaces the registry had already outgrown: outbound requests to a caller-supplied URL
  (70–79), deserializers and inbound webhook payloads (90–99), dependency manifests and
  install commands (110–119), and unbounded request-driven work (120–129) all had gates
  but were absent from the list that decides whether to run them.
- **Triage fails closed.** If it cannot tell whether a surface is touched, it is touched
  — matching the rule the gates themselves already used.

### Notes

- The guard's override is the developer's alone (`AIRTIGHT_GUARD=off`). It deliberately
  ignores markers written into the source: an assistant that can write its own exemption
  has no gate at all. This was found by testing, not by design — given a comment-based
  escape hatch, the assistant used it to ship the very route the guard had just blocked.
- The `description` was left unchanged. Widening it to name more surfaces was tried and
  measured against the original; it did not improve loading, and on one case coincided
  with a miss the shorter wording caught. Longer trigger text is not a free win.
- No gate numbers were added, renamed, or retired. The registry stays at 67.

## [0.1.0] — 2026-07-17

- Initial public release: 67 gates across 13 topics, registry-first architecture,
  `audit` / `harden` / `prove` verbs, and a measured A/B against a control build.
