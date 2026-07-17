# Software and data integrity failures

Ask a model for "a Stripe webhook that marks the order paid" and it returns exactly that: the route,
the `event.type` switch, the update, a 200 back. Every field name is right, it works against a real
event the first time it is tested, and it is a public POST endpoint that marks any order paid for
anyone who has read the vendor's docs. The verification was not omitted by carelessness — it was
never asked for. The same shape recurs everywhere code trusts something whose origin was never
established: bytes from a caller handed to a deserializer that builds objects, a script tag pointing
at a CDN with nothing pinning what it returns, an installer piped from a URL into a root shell at
build time, an updater that runs whatever answered for the update host. This file gates the emission
decisions in that family: what may deserialize untrusted bytes, what a page may load from a host you
do not run, what may execute after crossing the network, and what a handler must check before it
acts on a payload.

## Load this file when

- A route receives a webhook, callback or event push from another system — payment processor, git
  host, messaging platform, SMS gateway, partner integration.
- Bytes that did not originate in the process reach a deserializer: `pickle`, `yaml.load`,
  `Marshal.load`, `unserialize`, `readObject`, `node-serialize`, `torch.load`, `joblib.load`,
  `dill`.
- A template, component or runtime-built markup string emits `<script src>`, `<link
  rel="stylesheet">` or an injected element pointing at a host other than the app's own origin.
- A Dockerfile, CI step, install script, postinstall hook or provisioning script downloads something
  and runs it.
- Application code imports from a URL, or passes fetched text to `eval`, `new Function`, `exec` or
  `vm.runInNewContext`.
- The code auto-updates, or loads a plugin, extension, theme or remote config bundle that was not in
  the shipped build.
- A "restore", "import", "load session", "resume job" or cache-read path rebuilds an object graph
  from stored bytes.
- The request says the caller is another server, a machine, our own worker, or a trusted partner.

## Gates


### Gate 90 — Untrusted deserialization

> Code that deserializes bytes which crossed a trust boundary MUST NOT be emitted unless the format
> is data-only (JSON, MessagePack, Protobuf) parsed into a declared schema — never `pickle`,
> `yaml.load` without `SafeLoader`, `Marshal.load`, PHP `unserialize`, Java `readObject` or
> `node-serialize`.

**Applies when:** any value that did not originate inside the process — a request body, an uploaded
file, a cookie, a queue message, a cache entry, a row a user wrote — is handed to a deserializer
that reconstructs objects rather than parsing data.


**Fix:** Parse into a declared schema with a data-only format — `Workspace.model_validate_json`
(Pydantic), `yaml.safe_load` where the format must be YAML — and let the parse fail closed on
anything the schema does not name. The escape is not "sign the blob and then unpickle it": that
answers a different question, and an import feature exists precisely so callers can bring files you
never signed. Where a library owns the format, use its data-only mode — `torch.load(...,
weights_only=True)`. A schema parse also gives you Gate 40 for free; the reverse is not true, since
a validator that runs after `pickle.loads` runs after the code did.


### Gate 91 — Third-party script integrity

> Code that loads a script or stylesheet from a host other than the application's own origin MUST
> NOT be emitted unless the tag carries an `integrity` digest and `crossorigin`, or the dependency
> is installed and served from the application's own origin.

**Applies when:** a `<script src>`, `<link rel="stylesheet">`, a framework `<Script>` component or a
runtime-injected element points at a CDN, a vendor's hosted bundle, an analytics tag or a hosted
font or icon stylesheet.


**Fix:** Pin an exact version in the URL, add `integrity` with the SHA-384 digest of that exact
file, and add `crossorigin="anonymous"` — without the attribute the browser makes an opaque
no-CORS request it cannot hash, so the check is skipped while the tag still looks protected. Compute
the digest from the file you already have (`openssl dgst -sha384 -binary <file> | openssl base64
-A`) rather than from whatever the CDN answers with today. Better, take the escape clause: install
the package and serve it from your own origin, and the third party leaves the request path entirely
while the lockfile pins what you built against.


### Gate 93 — Code fetched then executed

> Code that fetches an executable artifact over the network and runs it — a script piped into a
> shell, a module imported from a URL, fetched text passed to an evaluator — MUST NOT be emitted
> unless the artifact is written to disk and verified against a digest recorded literally in the
> source before it executes.

**Applies when:** a Dockerfile, CI step, install script, postinstall hook or provisioning script
downloads and runs something; or application code imports or evaluates something it fetched.


**Fix:** Download to a file, verify with `sha256sum -c` against a digest written in the source, then
execute. Where the tool exists in a package manager, use the package manager and let it do this —
apt, apk, npm and pip already verify artifacts against the index's digests and record them in a
lockfile. The runtime forms — `eval(await (await fetch(url)).text())`, `import(remoteUrl)` — have no
fix that keeps their shape, because there is no digest for content you intend to change without a
deploy: ship the code in the bundle. If the URL comes from a caller it is Gate 70 first; if a
caller's string reaches the evaluator it is Gate 28 first. This gate is the case where nobody
untrusted supplied anything and the code is fetched and run anyway.


### Gate 95 — Update and plugin signature

> Code that installs or loads an artifact obtained after the application was built — an auto-update
> package, a downloaded plugin or extension, a remote bundle that will execute — MUST NOT be emitted
> unless the artifact's signature is verified against a public key shipped with the application,
> before the bytes are written anywhere the loader will look.

**Applies when:** an updater checks a version endpoint and installs a release; a plugin manager
fetches a package and `require`s or imports it; anything executes code that was not in the shipped
build.


**Fix:** Sign the release artifact in the release process with an ed25519 key, ship the public half
in the bundle, and verify the downloaded bytes against it before they are written — an artifact
written first is already sitting in the path the loader reads. A public key in the source is not a
Gate 30 violation: pinning it there is the mechanism, and only the private half must never be in
the repository. Where the platform provides a signed updater — Sparkle, electron-updater with code
signing, the OS package manager — use it instead of writing this.


### Gate 96 — Inbound webhook signature

> Code that acts on a webhook payload MUST NOT be emitted unless the request's signature header is
> verified against the raw request body before the handler reads the payload.

**Applies when:** a route receives an event pushed by another system — Stripe, GitHub, Shopify,
Slack, Twilio, a partner callback — and therefore has no session, because the caller is a machine.


**Fix:** Verify with the vendor's own constructor as the handler's first statement
(`stripe.webhooks.constructEvent`, `@octokit/webhooks` `verify`, Slack's `SignatureVerifier`), and
use the object it returns rather than `req.body`. It must be handed the raw bytes: mount
`express.raw` on this route, because `express.json()` parses and discards them and a re-serialized
object no longer hashes to the signature the sender computed — which is why the check "doesn't work"
and gets deleted rather than fixed. Where no library exists, HMAC the raw body with the shared
secret and compare with a constant-time function, never `===` (Gate 2).


## Out of scope

- **Lockfiles, version specifiers and the install command.** How a dependency is pinned and how it
  arrives is `dependencies.md`, Gates 110-118 — the lockfile-honouring install is Gate 110, the
  floating specifier is Gate 112, the unpinned git ref or archive URL is Gate 114. This file gates
  what executes after crossing the network; that file gates what the dependency is and how it gets
  there. Do not cite a gate from this range for a manifest.
- **Whether a dependency is trustworthy** — dependency confusion, abandoned packages, a postinstall
  hook three levels down. This needs knowledge of the registry and the package's history, not of the
  code in front of you, and SKILL.md already puts unknown flaws in third-party dependencies outside
  the scope. A package name the model recalled rather than checked is the one slice of this that is
  gateable, and it is Gate 115.
- **Mutable tags on base images and CI actions.** `FROM node:20-slim`, `uses: actions/checkout@v4`.
  The tag can move and digest pinning is the durable answer, but this is the ecosystem's own default
  rather than the model getting it wrong, and "is this publisher trusted" is not readable from the
  file. Rejected against rule 5: a gate that fails every Dockerfile ever written is a gate that gets
  switched off. `dependencies.md` reaches the same verdict from the other side and holds Gate 116
  against the actions half; nothing is held for it here.
- **Signed commits, build provenance, SLSA attestation, hardened runners.** The real integrity
  programme, entirely operational. No emission decision, no gate.
- **Replay of a correctly signed webhook.** The signature is valid and the event is genuine; it is
  arriving twice. The vendors' verifiers already reject a stale timestamp, and idempotency by event
  id is a correctness property of the handler — the business logic SKILL.md excludes. Gate 96 stops
  at whether the sender was ever checked.
- **Prototype pollution after a data-only parse.** `JSON.parse` is safe; `lodash.merge(target,
  JSON.parse(body))` is not, and `__proto__` in a request body is a genuine bug. It is the defect
  Gate 13 describes — a caller naming a field the code never meant to accept — and Gate 40's schema
  parse is what stops it. Ungated here; 92 is held.
- **JWTs decoded without verification.** `jwt.decode(token)` standing in for `jwt.verify(token,
  key)` is the same family, but the token is a credential and the range that owns it is 1-9.
- **Where an artifact is fetched from, when the caller picks.** A caller-supplied URL reaching a
  fetch is Gate 70 before it is anything here — integrity does not help when the destination is the
  attack.
- **Key rotation, revocation and expiry for the Gate 95 signing key.** Pinning one key is the gate;
  retiring it is an operational programme with no line of code to fail.
- **Whether a plugin should be allowed to do what it does** — sandboxing, permission models,
  capability limits. A signed plugin is one whose author you know, not one that is safe.
  Architecture, not a default mistake.
- **What the code does with a payload once verified.** That the webhook body is schema-parsed is
  Gate 40; that the parsed value is the one used is Gate 43; that a rejected signature leaves a
  record is Gate 101 and Gate 103.

## Prove probes

- Gate 90 — not provable read-only. A payload that demonstrates the gate is by construction a
  payload that executes; there is no variant of it that only reads. Reason from code — the
  deserializer's name at the call site is the entire finding.
- Gate 91 — GET a page from the developer's own local app and read the HTML it actually returned ->
  HELD if every `<script src>` and `<link rel="stylesheet">` pointing off the app's origin carries
  both `integrity` and `crossorigin`, FAILED if any carries neither or only one. Read the rendered
  response rather than the template: a framework `<Script>` component or a tag injected at runtime
  only appears in the output. Do not fetch the CDN URL to compute the expected digest — the app is
  the developer's, the CDN is not, and rail 2 does not bend for a GET.
- Gate 93 — not provable read-only. Running the build step is running the build step, and the thing
  under test is what it executes. Reason from code — the Dockerfile, install script or CI step is
  the configuration site, and a `curl` piped into an interpreter is readable there without executing
  anything.
- Gate 95 — not provable read-only. Exercising the update path installs the update. Reason from code
  — the verify call either sits between the download and the write or it does not, and its absence
  is the finding.
- Gate 96 — POST the developer's own local webhook route with no signature header and a well-formed
  body whose target id does not exist (`{"type": "checkout.session.completed", "data": {"object":
  {"metadata": {"orderId": "probe-nonexistent"}}}}`) -> HELD if 400 before any lookup runs, FAILED
  if the response or the log shows the handler reached the payload at all — a 404 or a 500 out of
  the lookup can only have come from past the check. This holds only where the handler's action is
  an update keyed to a record that must already exist: the miss on a nonexistent id is what keeps
  the probe read-only. Where the handler inserts, enqueues or calls a third party on receipt, the
  probe writes exactly when the gate fails — reason from code instead.
