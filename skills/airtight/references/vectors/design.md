# Insecure design

Ask a model for "a login endpoint" and it writes a login endpoint. Ask for "a posts list" and it
writes `findMany` with a `take` the caller supplies. Ask for "let users resize their avatar" and the
width comes out of the query string and goes into `sharp`. Every one of those is the feature, exactly
as requested, working on the first try. What is missing in each is the same thing: the bound. Nobody
asked for the endpoint to survive someone who is not using the form. This file gates the emission
decisions where a limit was the thing that did not get written — on the endpoints that verify a
credential, on the queries that return a list, on the work a request is allowed to buy, and on the
quantities the arithmetic trusts.

Most of A04 is not gateable and this file does not pretend otherwise. Threat modelling, trust
boundaries, whether the feature should exist in this shape at all — that is thinking that happens
before there is code to read, and no condition on emitted code can check it. Airtight does not claim
to cover it, and an audit citing this file has not done a design review. Say so when reporting. What
is left is the subset that is a concrete default: the safety limits a model omits because it was
asked for a feature, not a bounded one. The gates below hold a deliberately narrow line — they
require that a bound **exists** and is written literally in the source, never that it is the right
bound. The right bound depends on the product, and Airtight does not know the product.

## Load this file when

- The request asks for a login, signup, password reset, OTP, magic-link, token-refresh or
  API-key-exchange endpoint — anything that verifies a credential or issues one. credentials.md
  gates the credential; this file gates the limit.
- A handler branches on a failed credential check.
- A handler returns a list of records: `findMany`, `.all()`, a `SELECT` with no `LIMIT`, an ORM
  filter serialized straight into the response.
- A request value reaches `take`, `skip`, `limit`, `offset`, `pageSize`, `first`, `per_page` or a
  range parameter — with or without a clamp.
- A request value sizes an operation: image dimensions, a date span, a page count, an iteration
  count, a batch size, a "generate N of these" parameter.
- Code expands caller-supplied bytes: `zipfile`, `tarfile`, `unzipper`, `adm-zip`, `yauzl`,
  `zlib.gunzip`, or an HTTP client decoding a gzip response.
- A `quantity`, `count`, `qty`, `seats`, `days` or `points` field appears in a request body and is
  multiplied by, added to or subtracted from a stored value.
- An export, report, bulk action or "download all" runs inline in a request handler.

## Gates


### Gate 120 — Rate limit on credential endpoints

> Code that defines a route which verifies a caller-supplied credential or issues one MUST NOT be
> emitted unless a rate limiter is applied to that route.

**Applies when:** a route handles login, signup, password-reset, OTP, magic-link, token refresh, or any exchange where the caller presents or requests a secret.

**Passes:**
```js
import rateLimit from "express-rate-limit";

const credentialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/login", credentialLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  const ok = user && (await argon2.verify(user.passwordHash, password));
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });
  return startSession(req, res, user);
});
```

**Fails:**
```js
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  const ok = user && (await argon2.verify(user.passwordHash, password));
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });
  return startSession(req, res, user);
});
```

**Why:** The failing handler passes every other credentials gate yet hands the caller unlimited guesses at line rate — a password list runs in minutes, and on reset/OTP routes each unthrottled request is a real mailer or SMS bill.

**Fix:** Attach a limiter middleware to every route that verifies or issues a credential (`express-rate-limit`, `slowapi`, the framework's throttle class) with a shared counter store, since per-process stores undercount behind multiple workers. This gate is presence, not threshold: the number is in **Out of scope**.

### Gate 121 — Per-account failure backoff

> Code that handles a failed credential verification MUST NOT be emitted unless the failure is
> recorded against the account identifier and further attempts on that account are refused or delayed
> once a threshold written in the source is crossed.

**Applies when:** a login, OTP-check or recovery handler reaches the branch where the presented
credential did not match.

**Passes:**
```js
app.post("/login", credentialLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  const locked = Boolean(user?.lockedUntil && user.lockedUntil > new Date());
  const ok = !locked && user && (await argon2.verify(user.passwordHash, password));
  if (!ok) {
    if (user && !locked) {
      const n = user.failedAttempts + 1;
      const backoffMs = n < 5 ? 0 : Math.min(2 ** (n - 5) * 1000, 15 * 60 * 1000);
      await db.user.update({
        where: { id: user.id },
        data: { failedAttempts: n, lockedUntil: new Date(Date.now() + backoffMs) },
      });
    }
    return res.status(401).json({ error: "Invalid email or password" });
  }
  await db.user.update({ where: { id: user.id }, data: { failedAttempts: 0, lockedUntil: null } });
  return startSession(req, res, user);
});
```

**Fails:**
```js
app.post("/login", credentialLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  const ok = user && (await argon2.verify(user.passwordHash, password));
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });
  return startSession(req, res, user);
});
```

**Why:** Per-IP limiting (Gate 120) does nothing against credential stuffing, where one guess hits each of many accounts from a rotating IP pool — the counter must hang off the account the attacker cannot rotate.

**Fix:** Store `failedAttempts` and `lockedUntil` on the user row, increment on the failure branch,
set `lockedUntil` from a backoff that grows with the count, and clear both on success. Prefer growing
backoff to a hard lockout: a lockout with no expiry lets anyone disable any account by name, which
trades one denial of service for another. Return the same 401 whether the account is locked or the
password was wrong — a distinct "account locked" response is Gate 1 again, and it is also a free
signal that the guessing is working.

### Gate 123 — Result-set ceiling

> Code that returns a list of records from a datastore MUST NOT be emitted unless the number of
> records it may return is bounded by a maximum written literally in the source.

**Applies when:** any handler queries a collection and returns rows — even a small or already-paginated one.

**Passes:**
```ts
const MAX_PAGE = 100;

app.get("/api/posts", async (req, res) => {
  const requested = Number(req.query.limit);
  const limit = Number.isInteger(requested) ? Math.min(Math.max(requested, 1), MAX_PAGE) : 20;
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const posts = await db.post.findMany({
    take: limit,
    skip: offset,
    orderBy: { createdAt: "desc" },
  });
  res.json(posts);
});
```

**Fails:**
```ts
app.get("/api/posts", async (req, res) => {
  const limit = Number(req.query.limit) || 20;
  const offset = Number(req.query.offset) || 0;
  const posts = await db.post.findMany({
    take: limit,
    skip: offset,
    orderBy: { createdAt: "desc" },
  });
  res.json(posts);
});
```

**Why:** `?limit=1000000` is a one-request denial of service — the DB scans, the driver materializes, and the event loop stalls for everyone. The failing version reads as finished because it *is* the pagination idiom, and behaves identically on a small dev table.

**Fix:** Clamp the caller's value to a maximum written literally in the source, and clamp the bottom end too (`|| 20` accepts `-5`, a backwards `take` in Prisma). Always give the query a `take` even when the caller asked for nothing, and keep the maximum a literal so raising it is a reviewed diff.

### Gate 125 — Request-sized work

> Code that lets a request value determine how much work, memory or output an operation produces MUST
> NOT be emitted unless that value is clamped to a maximum written literally in the source, at the
> point it enters the operation.

**Applies when:** a request value reaches an image dimension, page count, iteration count, scale/quality factor, batch size, date span, or "generate N" parameter — resize, PDF/report generation, CSV export, chart rendering, bulk fetch.

**Passes:**
```ts
const MAX_DIM = 2048;

function dim(value: unknown, fallback: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? Math.min(n, MAX_DIM) : fallback;
}

app.get("/api/avatar/:id", async (req, res) => {
  const src = await storage.get(`avatars/${req.params.id}`);
  const out = await sharp(src)
    .resize(dim(req.query.w, 256), dim(req.query.h, 256))
    .jpeg()
    .toBuffer();
  res.type("jpeg").send(out);
});
```

**Fails:**
```ts
app.get("/api/avatar/:id", async (req, res) => {
  const src = await storage.get(`avatars/${req.params.id}`);
  const out = await sharp(src)
    .resize(Number(req.query.w), Number(req.query.h))
    .jpeg()
    .toBuffer();
  res.type("jpeg").send(out);
});
```

**Why:** `?w=30000&h=30000` asks for a 900-megapixel surface (3.6 GB) and never returns. Gate 45's upload cap bounds input bytes, not output size; Gate 40's schema confirms `w` is a number, which `30000` is. The failing version is the feature exactly as requested.

**Fix:** Clamp each request-supplied magnitude to a source-literal maximum where it enters the operation, not where it is parsed (a validated copy nothing reads is Gate 43). Where the cost scales on a range or filter, bound the unit — a maximum span, a maximum row count (Gate 123) — or move the work to a queued job with a ceiling instead of running it inline.

### Gate 127 — Bounded expansion

> Code that expands caller-supplied data — archive extraction, decompression — MUST NOT be emitted
> unless a total expanded-byte limit and an entry-count limit, both written literally in the source,
> are enforced *during* the expansion.

**Applies when:** `zipfile`, `tarfile`, `unzipper`, `yauzl`, `zlib.gunzip`, or any code turning a
small caller-supplied input into a larger caller-chosen output — `extractall` being the default.

**Fails:**
```python
@app.post("/import")
async def import_archive(file: UploadFile = File(...)):
    dest = tempfile.mkdtemp()
    with zipfile.ZipFile(io.BytesIO(await file.read())) as zf:
        zf.extractall(dest)
    return {"files": os.listdir(dest)}
```

**Why:** A zip bomb is a few hundred KB that expands to gigabytes, so it clears the upload cap (Gate 45); `extractall` streams with no running total until the disk fills or OOM. Checking `info.file_size` fails too — that field lives inside the archive and is author-controlled; only bytes you actually wrote are trustworthy.

**Fix:** Open each entry and read it through a fixed-size chunk loop, keeping a running total of
bytes written that aborts the moment it crosses a source-literal ceiling. Cap the entry count in the
same pass — a bomb can be a million empty files. The same shape applies to gzip: decompress in chunks
against a budget, never `zlib.decompress(body)`. Where the filenames go is Gate 46.

### Gate 128 — Bounded quantity

> Code that takes a quantity, count or multiplier from a request and uses it to size a transaction
> MUST NOT be emitted unless the value is constrained to an inclusive integer range whose bounds are
> written literally in the source.

**Applies when:** a non-monetary magnitude (`quantity`, `qty`, `count`, `seats`, `days`, `points`) arrives in a request and is multiplied by, added to or subtracted from a stored value.

**Passes:**
```ts
const CheckoutSchema = z.object({
  items: z
    .array(
      z.object({
        productId: z.string().uuid(),
        quantity: z.number().int().min(1).max(100),
      }),
    )
    .min(1)
    .max(50),
});

app.post("/api/checkout", requireAuth, async (req, res) => {
  const { items } = CheckoutSchema.parse(req.body);
  const products = await db.product.findMany({ where: { id: { in: items.map(i => i.productId) } } });
  const total = items.reduce(
    (sum, i) => sum + products.find(p => p.id === i.productId)!.priceCents * i.quantity, 0);
  const intent = await stripe.paymentIntents.create({ amount: total, currency: "usd" });
  res.json({ clientSecret: intent.client_secret });
});
```

**Fails:**
```ts
const CheckoutSchema = z.object({
  items: z.array(
    z.object({
      productId: z.string().uuid(),
      quantity: z.number().int(),
    }),
  ),
});

app.post("/api/checkout", requireAuth, async (req, res) => {
  const { items } = CheckoutSchema.parse(req.body);
  const products = await db.product.findMany({ where: { id: { in: items.map(i => i.productId) } } });
  const total = items.reduce(
    (sum, i) => sum + products.find(p => p.id === i.productId)!.priceCents * i.quantity, 0);
  const intent = await stripe.paymentIntents.create({ amount: total, currency: "usd" });
  res.json({ clientSecret: intent.client_secret });
});
```

**Why:** `quantity: -1` is a valid integer that subtracts a product's price from the cart; `quantity: 1e9` overflows the total or stock ledger. Server-side pricing and schema parsing don't help — the type was validated but the range wasn't.

**Fix:** Give the field an inclusive range — `.int().min(1).max(N)` — and bound the array length in the same schema. `N` is a product decision Airtight can't know; the gate only requires that some literal `N` exists. Even a generous cap stops the negative and the billion.

## Out of scope

- **Threat modelling, trust boundaries and design review.** The bulk of A04, and unreachable from
  here: it is reasoning about a system that does not exist yet, and a gate is a condition on emitted
  code. There is nothing binary to check, so there is no gate. When reporting against this file, say
  the design was not reviewed rather than letting six gates imply it was.
- **What the limit should be.** The threshold, the window, the counter store, the lockout duration,
  the page maximum, the largest sane quantity. Nothing in the source says whether ten attempts in
  fifteen minutes is right for this product. Gates 120, 121, 123, 125, 127 and 128 gate the
  *presence* of a source-literal bound, never its value — an absent bound is readable, a wrong bound
  is a judgement.
- **credentials.md's "Login rate limiting and lockout" entry.** That file listed it as wholly out of
  scope on the ground that the threshold, the counter store and the lockout behaviour are deployment
  decisions. It is right about the values and was wrong that this leaves nothing to gate: whether a
  limiter is attached to the route, and whether the failure branch counts against the account, are
  both readable in the source and both binary. Gates 120 and 121 take that half; the values stay out
  of scope in both files, and the entry there now says so.
- **Rate limiting at the gateway.** A WAF or API gateway limit is the durable answer to volumetric
  attacks and it is at a layer the repository cannot see. If the developer says the route is behind
  one, that is an **override** of Gate 120 and should be recorded as one — a limiter you cannot read
  is a limiter you cannot check, and Gate 120 does not pass on an assurance.
- **Workflow sequencing.** Whether checkout step three is reachable without step two, whether a draft
  can publish without review, whether a refund can follow a refund. Real flaws, and settling any of
  them means knowing the intended flow. No line of code passes or fails "the states are in the right
  order".
- **Race conditions on a limited resource.** Two concurrent redemptions of a one-use coupon, a
  balance checked and then debited, stock decremented twice. The model never writes the lock, so it
  clears rule 5 — but which pairs of operations must be atomic is domain knowledge, and check-then-act
  is not reliably decidable by reading a handler. Gate 8 pins the single case where the transaction
  boundary is not a judgement call. Note the rest in an audit without a gate number.
- **Spend ceilings on metered third-party calls** — model tokens, SMS, translation, geocoding. The
  ceiling is a budget, and whether the caller or the account owner absorbs the overrun is pricing.
  Gate 120 bounds the request rate into the route; it does not know what a request costs you.
- **CAPTCHA, proof of work, device fingerprinting, bot detection.** Product decisions with a
  conversion cost, usually bought rather than written. Their absence is not a defect in the code that
  was asked for.
- **Security questions and knowledge-based recovery.** Considered as a gate and rejected against rule
  5. A maiden name is a public record and a recovery path that accepts one is a real weakness, but
  the condition only fires when the developer has asked for security questions or "forgot password
  without email" by name — a model does not volunteer KBA when asked for a login, so it is not a
  default it gets wrong unprompted, and knowledge-based recovery is not in a normal app. It sits
  where credentials.md puts MFA: a product feature with a support cost, on the far side of the scope
  boundary. Report an answer-gated reset as an ungated finding, and note that a token returned in the
  response body rather than sent to the registered channel skips the proof entirely. 122 is held in
  case the trigger turns out to be commoner than it looks.
- **Timeouts and retry budgets.** The right values are deployment decisions and no line in the
  handler passes or fails them. ssrf.md declines them on the same ground.
- **Whether this caller may perform the action at all.** Gates 10-19. That the body parses is Gate
  40; that a price is not read from it is Gate 41; that the byte count of an upload is capped is Gate
  45; that a filename out of an archive stays inside its directory is Gate 46. Passwords, tokens,
  sessions and reset-token lifetimes are Gates 1-8.
- 122, 124, 126 and 129 are held. 122 for knowledge-based recovery if it turns out to be a default
  after all, 124 for a bound on request-driven fan-out (one request, N outbound calls or queued
  jobs), 126 and 129 unclaimed.

## Prove probes

- Gate 120 — not provable read-only. Demonstrating a limiter means exceeding it, which is volume
  against an authentication endpoint and exactly what proof.md's 1-9 row rules out, and it persists a
  counter besides. Reason from the configuration site: the limiter's construction (`rateLimit({...})`,
  slowapi's `Limiter`, the framework's throttle class) and the route's middleware chain are both
  literal in the source, and a credential route whose chain contains no limiter is the finding. Read
  the store while you are there — a `rateLimit` call with no `store` is counting per process.
- Gate 121 — not provable read-only, for Gate 120's reason plus the failure counter it writes.
  Reason from code: the branch handling a failed verification either updates a per-account counter
  and consults it before verifying, or it does not. Both are one read of the handler.
- Gate 123 — GET the developer's own list endpoint **once** with `?limit=1000000` and count the
  records that come back -> HELD if the count is at or under the maximum written in the source, or a
  400 rejects the value. FAILED if the body carries more than that maximum. The probe only settles
  the gate when the local dataset is larger than the cap: against a dev table of twelve rows a
  clamped and an unclamped handler both return twelve, and the verdict is UNKNOWN — read the handler
  instead. A 500 is UNKNOWN too: it may be the validator rejecting the value or the query dying on
  it, and those are opposite verdicts. Send it once. The request is the denial of service in
  miniature, and repeating it against the developer's machine is a load test (rail 3).
- Gate 125 — GET the developer's own resize or render endpoint with a magnitude that is large but
  harmless — `?w=8000` against a source cap that should be 2048 — and read the dimension of what
  comes back -> HELD if the output is at or under the source maximum, or a 400 rejects the value.
  FAILED if an 8000-pixel image is returned: the clamp is absent, and the only reason the process
  survived is that you asked politely. Do not send the number that would actually exhaust the
  machine. The returned dimension settles the gate; `?w=100000` settles nothing further and costs the
  developer their dev server.
- Gate 127 — not provable read-only. Settling it needs an archive built to expand, and sending one is
  the destructive act the rails exist to prevent: the failure mode *is* a full disk or an OOM kill on
  the developer's own machine. Reason from code: the extraction site either reads entries through a
  chunk loop against a running total, or it calls `extractall` / `unzipper.Extract` and leaves the
  limit to the caller. Nothing in between.
- Gate 128 — not provable read-only. A negative quantity settles the gate by creating an order, a
  payment intent or a stock movement — a write through the endpoint under test, and one that reaches
  a payment provider even in a dev configuration, which is rail 2 as well as rail 3. Reason from
  code: the schema either carries `.min()` and `.max()` on the quantity field or it does not.
