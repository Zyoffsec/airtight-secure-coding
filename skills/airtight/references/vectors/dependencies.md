# Vulnerable and outdated components

Airtight does not detect vulnerable dependencies and must never rule a version safe or unsafe — a
model's package knowledge is frozen at training time; the advisory database is not. That job belongs
to Dependabot, `npm audit`, `pip-audit`, `osv-scanner` and Snyk, which read a current database. Say
so whenever a version comes up. What this file gates is the dependency hygiene those tools stand on:
the graph in the image must match the graph in the repo, every entry must name a version, and every
name must be real — otherwise the audit describes a build nobody shipped.

## Load this file when

- A dependency is added or edited in a manifest — `package.json`, `requirements.txt`,
  `pyproject.toml`, `go.mod`, `Gemfile`, `Cargo.toml`.
- An import or `require` names a third-party package the project does not already depend on.
- A `Dockerfile`, CI workflow, `Procfile`, entrypoint, deploy script or devcontainer installs
  dependencies.
- A README, setup section or chat reply hands the developer an install command.
- Code is installed from a git ref or an archive URL rather than a registry.
- An audit or dependency-bot step is added or edited, or a red audit step needs to go green.
- You are about to name a library from recall rather than from the project or the developer.

## Gates

### Gate 110 — Lockfile-honouring install

> An install command in a Dockerfile, CI workflow or deploy script MUST NOT be emitted unless the
> project's lockfile is committed and the command fails when that lockfile is missing or disagrees
> with the manifest (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`,
> `uv sync --frozen`, `poetry install` against a committed `poetry.lock`).

**Applies when:** any non-interactive install runs — an image build, a pipeline job, a deploy step,
an entrypoint — or a lockfile would be excluded from the repo or build context by `.gitignore` or
`.dockerignore`.

**Fix:** Commit the lockfile, copy it in ahead of the install so the layer cache still works
(`COPY package.json package-lock.json ./`), and call `npm ci`. Python: a `pip install` from
`requirements.txt` is only as frozen as the file is pinned (Gate 112) — prefer `uv sync --frozen`,
or `pip install --no-deps` against a `pip-compile` output that pins the transitive tree too.

**Fails:** `RUN npm install` in a build (re-resolves the tree against the registry, so two builds of
the same commit ship different code and the audited graph is not the shipped graph).

### Gate 112 — Floating version specifier

> A dependency entry MUST NOT be emitted with a specifier of `latest`, `*`, an empty range, or no
> version at all; the entry must name a version or a range with a floor (`"express": "^4.18.2"`,
> `requests==2.32.3`, `requests>=2.32,<3`).

**Applies when:** a package is written into a manifest — by hand, by `npm i <name>@latest`, or by
generating a `requirements.txt` from what the code imports.

**Fix:** Pin every direct dependency to a version, and compile the transitive set with `pip-compile`
(or `uv pip compile`) from a `requirements.in` so those pin too. In JS, write a caret range with a
floor and let the committed lockfile fix the resolution (Gate 110) — never `latest` or `*`, which
re-float the entry the next time anything runs `npm install`.

**Fails:** A bare name in `requirements.txt` (`flask` with no `==`); the version is chosen by the
clock, and `pip-audit` has no version to match against an advisory.

### Gate 114 — Non-registry source pinning

> A dependency installed from a git ref or an archive URL MUST NOT be emitted unless it is pinned to
> an immutable identifier — a full commit SHA, or a downloaded file whose published checksum is
> verified before use.

**Applies when:** an install names something other than a registry package and version:
`git+https://...`, `pip install https://.../x.tar.gz`, `go get ...@master`, a `wget` of a release
archive. A shell installer piped into an interpreter — `curl ... | sh` — is Gate 93 in
`integrity.md`; cite that number, not this one.

**Fix:** Pin the full 40-character commit SHA (content-addressed: you get the tree you reviewed, or
the fetch fails). For an archive URL, fetch to a file and check it against the vendor's published
`sha256` (`sha256sum -c`) before installing — or install the vendor's registry package instead,
which at least carries a version an audit tool can read. Fetching over plain HTTP, or with `curl -k`
/ `--no-check-certificate`, is Gate 60.

**Fails:** `pip install git+https://.../lib.git@main` (a branch is a pointer, not a version; tags
can be moved too, and a branch checkout has no version to match against an advisory).

### Gate 115 — Package name provenance

> An import or install of a third-party package MUST NOT be emitted unless the name comes from one
> of three places: the project's own manifest or lockfile, the developer's own message, or a
> registry lookup performed before emitting it.

**Applies when:** a package is named from recall — "the library for that is X" — including in a
manifest, an install command, a README setup block, or an import line the developer will install to
satisfy.

**Fix:** Emit only names you can point at a source for — the manifest, the lockfile, or the
developer's message. For anything else, confirm before emitting with `npm view <name>` or
`pip index versions <name>`, and read what comes back (the repository link, the publish history)
rather than the exit code. If you cannot confirm it, name it as unverified and let the developer
decide.

**Fails:** A recalled name that was never checked (e.g. `stripe-webhook-middleware`). A name that
does not exist yet can be registered by anyone, and its install script runs with CI credentials
before one line of the app executes; a typo like `reqeusts` lands the same way. This is the one
dependency failure no scanner catches — a squat published this morning is in no advisory database.

### Gate 117 — Audit step in the pipeline

> A CI workflow that installs dependencies MUST NOT be emitted unless it also runs the ecosystem's
> audit command as a step that can fail the job (`npm audit`, `pip-audit`, `osv-scanner`).

**Applies when:** a pipeline definition that installs dependencies is created or edited — GitHub
Actions, GitLab CI, CircleCI, a Jenkinsfile, a `make ci` target.

**Fix:** Add the audit as its own step after the install, in the workflow that already runs the
tests: `npm audit --audit-level=high`, or `pip-audit -r requirements.txt`, or `osv-scanner -r .`
for a polyglot repo. Pick the severity threshold on purpose (a threshold is a decision, unlike Gate
118's suppression), and enable Dependabot or Renovate alongside it.

**Fails:** An `npm ci` + `npm test` workflow with no audit step. No model knows which pinned
transitive version is vulnerable; only a tool reading a current database does, and a tool not wired
into a step that can fail is a tool nobody runs.

### Gate 118 — Suppressed audit result

> A change that makes an audit step stop failing MUST NOT be emitted unless it resolves the finding
> — upgrade, replace or remove the affected package — or records an exception naming the specific
> advisory, with the reason it does not apply and a date to re-check.

**Applies when:** an audit step is red and the request is to get the build green: `|| true`,
`continue-on-error`, `--audit-level` lowered to nothing, a blanket allowlist, `--ignore-vuln` with
no id.

**Fix:** Upgrade to the fixed release. Where upstream has no fix, ignore exactly one advisory by id
with a comment stating why it is not reachable here and a date to revisit — e.g.
`pip-audit -r requirements.txt --ignore-vuln GHSA-0000-0000-0000`. If the finding is real and
unfixable, say that to the developer rather than making it quiet. Not `|| true`, not
`continue-on-error: true` on an audit step, and not `npm audit fix --force`, which installs a
semver-major nothing has been tested against.

**Fails:** `pip-audit -r requirements.txt || true` — it silences this finding and every finding
published after it, converting the pipeline's only current-information defence into decoration. A
scoped exception naming one advisory id still stops the build on the next one.

## Out of scope

- **Which versions are vulnerable.** Airtight does not detect vulnerable dependencies; any version
  judgement recalled from memory is stale. No gate here reads a version and rules on it.
  `misconfig.md` reaches the same conclusion and defers here for the hygiene half.
- **Whether a package is well-maintained.** Download counts, last release, bus factor — arguments,
  not binary conditions. Gate 115 asks whether a name is real and vetted, not whether the project is
  any good.
- **Base image tags and digests.** `FROM node:20-alpine` is a moving target and `@sha256:...` fixes
  it, but a model writes a real tag by default, as does the ecosystem; demanding digests everywhere
  fails rule 5.
- **Install lifecycle scripts.** `--ignore-scripts` breaks packages that legitimately build, so the
  condition is not binary and a model is not wrong by default for omitting the flag.
- **Third-party GitHub Actions on a mutable ref.** `uses: some-org/some-action@v4` is a repointable
  tag — the same failure as Gate 114 — but the whole ecosystem writes tags, so rule 5 is in doubt.
  Gate 116 is held for it.
- **Hash-pinned installs.** `pip install --require-hashes`, npm integrity beyond the lockfile — a
  stronger guarantee than Gate 110 and no ecosystem's default, so omitting it is not a model getting
  it wrong. Gate 113 is held.
- **Dependency confusion.** Whether `@acme/internal-utils` resolves to a private or public registry
  depends on which names your org owns — a fact about the company, not readable in the diff.
- **A lockfile in `.gitignore`, as its own gate.** Gate 110 already fails on it. Gate 32 gates the
  mirror-image secret-file case; Gate 111 is held if the ignore-side proves to be a default.
- **Runtime and language EOL.** Node 16, Python 3.8, an unpatched base OS — a fact about today's
  date, not a property of the diff.
- **Everything else in the Dockerfile and workflow.** Debug flags, ports, seeded credentials and
  file modes are `misconfig.md` (Gates 80-89). Tokens in a workflow are Gates 30-35. A version
  string interpolated into a shell install from a request is Gate 26.

## Prove probes

Nothing here is proved by sending traffic. Every gate is settled by reading files in the developer's
own repository; the registry lookups that would settle the rest are requests to a host the developer
does not own — rail 2, not negotiable.

- Gate 110 — `git ls-files --error-unmatch package-lock.json` and read every install site in the
  `Dockerfile`, workflows and deploy scripts -> HELD if the lockfile is tracked and every
  non-interactive install is `npm ci` or another frozen equivalent; FAILED if it is untracked or any
  site runs a bare `npm install`. Do not run the install — building the image is the re-resolution
  the gate is about.
- Gate 112 — read the manifest. The specifier is in the file or it is not; the pre-emit check
  settles it at the point of writing.
- Gate 114 — `git grep -nE 'git\+|@(main|master|HEAD)|https?://\S+\.(tar\.gz|tgz|zip|whl)'` across
  the tree -> HELD if every hit carries a full commit SHA or verified checksum; FAILED on any branch
  ref, moving tag, or unchecksummed archive URL. Reading a hit is enough; do not fetch the ref.
- Gate 115 — not a prove probe: confirming a name is a registry read done before emit, not a test of
  running code. The local half: compare `package.json` names against `package-lock.json` (or
  `requirements.txt` against the compiled output) -> a direct dependency in the manifest and absent
  from the lockfile has never resolved, and is the first place an invented name shows up. Report it
  as a finding, not proof of the gate.
- Gate 117 — read the pipeline definitions -> HELD if a job that installs dependencies also runs an
  audit command in a step that can fail; FAILED if none does. Running the audit yourself proves
  nothing about the gate — the gate is whether CI runs it.
- Gate 118 — `git grep -nE 'audit.*\|\| *true|continue-on-error|--ignore-vuln'` across the pipeline
  files -> HELD if every hit is a deliberate threshold or an advisory id carrying a comment and a
  date; FAILED on `|| true`, `continue-on-error` on an audit step, or an ignore with no id. It
  cannot settle whether the stated reason is true; read it and say so if it does not hold up.
