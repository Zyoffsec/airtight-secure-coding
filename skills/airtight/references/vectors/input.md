# Input validation

Client-side checks (`required`, `type="email"`, submit-handler guards) run in a browser the caller
does not have to use. Every request field is untrusted until the server parses it. This range gates
the shape and provenance of values that arrive in a request. Rule and fix per gate below.

## Load this file when

- A handler reads `req.body`, `req.query`, `req.params`, `request.json()`, form data or a query param.
- A request body is cast or destructured into a typed shape (`as Body`, `payload: dict`) with no
  runtime parse.
- The code accepts a file upload — multer, busboy, formidable, FastAPI `UploadFile`, a signed-URL
  handler.
- A price, total, quantity, discount, credit or currency amount appears in a request body.
- A validator is called: zod, yup, joi, express-validator, Pydantic, marshmallow, a DRF serializer.
- The route receives a webhook, a redirect target (`?next=`, `?returnUrl=`), or a serialized object.
- The developer says the frontend already checks it, or the field is hidden, disabled or read-only in
  the UI.

## Gates

### Gate 40 — Server-side request validation

> Code that reads a field out of a request MUST NOT be emitted unless the request has first been
> parsed server-side by a runtime schema that names every accepted field and its type, and rejects
> the request when the parse fails.

**Applies when:** any handler consumes a request body, query string or path parameter — including one
whose only caller today is the app's own form.

**Fix:** Parse at the top of the handler with a runtime schema (zod, Pydantic) and use only its
output. Use an allowlist of accepted fields and types — never a denylist of bad substrings.

```ts
import { z } from "zod";

const CreatePost = z.object({
  title: z.string().min(1).max(200),
  tags: z.array(z.string()).max(5),
});

app.post("/api/posts", requireAuth, async (req, res) => {
  const parsed = CreatePost.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid body" });
  const post = await db.post.create({ data: { ...parsed.data, authorId: req.session.userId } });
  res.json(post);
});
```

**Fails:** `const { title, tags } = req.body as CreatePost;` — a TypeScript cast is erased at runtime
and checks nothing; the interface is a note to the compiler, which is not in the request path.

### Gate 41 — Server-computed amounts

> Code that charges, credits or records a monetary amount MUST NOT be emitted unless the amount is
> computed server-side from stored values — never read from a price, total, subtotal or discount field
> in the request.

**Applies when:** checkout, order creation, payment-intent creation, subscription change, refund or
credit grant — any handler where money appears in the request body.

**Fix:** Accept only identifiers and quantities from the client, look up every price server-side by
id, and compute the total in the handler. Where the client must show a total first, have it read that
total from a server endpoint rather than send its own back.

```ts
app.post("/api/checkout", requireAuth, async (req, res) => {
  const { items } = CheckoutSchema.parse(req.body); // [{ productId, quantity }]
  const products = await db.product.findMany({ where: { id: { in: items.map(i => i.productId) } } });
  const total = items.reduce(
    (sum, i) => sum + products.find(p => p.id === i.productId)!.priceCents * i.quantity, 0);
  const intent = await stripe.paymentIntents.create({ amount: total, currency: "usd" });
  res.json({ clientSecret: intent.client_secret });
});
```

**Fails:** reading `total` (or `priceCents`) from the request body and passing it to the charge. A
schema confirms `total` is an integer, never that it is the *right* integer.

### Gate 43 — Validated value is the one used

> Code that validates a request MUST NOT be emitted unless the value passed downstream is the
> validator's output and the handler returns before use when validation fails.

**Applies when:** a handler calls a validator that returns a result rather than raising —
`safeParse`, `schema.validate`, `validationResult(req)`, `serializer.is_valid()` — and later reads the
raw request again.

**Fix:** Use only the validator's output for the rest of the handler — `serializer.validated_data`,
`parsed.data` — and never reference the raw request again after the parse. The output has undeclared
fields stripped and declared ones coerced; the raw request has neither.

```python
@api_view(["PATCH"])
def update_profile(request):
    serializer = ProfileSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=400)
    Profile.objects.filter(user=request.user).update(**serializer.validated_data)
    return Response({"ok": True})
```

**Fails:** validating, then writing `**request.data` instead of `**serializer.validated_data` — the
raw request reaches the ORM, reintroducing Gate 13 mass assignment two lines below a passing check.

### Gate 44 — Upload type from content

> Code that accepts an uploaded file MUST NOT be emitted unless the accepted type is decided from the
> file's bytes server-side — a magic-number sniff or a decoder that parses it — never from the
> filename extension or the client's `Content-Type`.

**Applies when:** any upload handler restricts what may be uploaded: avatars, attachments, imports,
document uploads, signed-URL flows that record a type.

**Fix:** Sniff the bytes server-side (`file-type` in Node, `python-magic` or a Pillow
`Image.open(...).verify()` in Python) and take both the accept decision and the stored extension from
the sniff result, never from a client-supplied string.

```ts
import { fileTypeFromBuffer } from "file-type";

const ALLOWED = new Set(["image/jpeg", "image/png"]);

app.post("/api/avatar", requireAuth, upload.single("file"), async (req, res) => {
  const sniffed = await fileTypeFromBuffer(req.file.buffer);
  if (!sniffed || !ALLOWED.has(sniffed.mime)) return res.status(400).json({ error: "Not an image" });
  await store(req.file.buffer, sniffed.ext);
  res.json({ ok: true });
});
```

**Fails:** trusting `req.file.mimetype` (the client's `Content-Type`) or `originalname` (a
client-typed string) for the accept decision.

### Gate 45 — Upload size cap

> Code that accepts an uploaded file MUST NOT be emitted unless the framework enforces a maximum byte
> size before the file is buffered to memory or disk.

**Applies when:** a multipart or streaming upload is configured — multer, busboy, formidable, FastAPI
`UploadFile` — or a route reads a body of caller-controlled length.

**Fix:** Set `limits.fileSize` and `limits.files` on the upload instance to the largest file the
feature actually needs, so the stream aborts at the cap rather than after it.

```ts
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
});

app.post("/api/avatar", requireAuth, upload.single("file"), handler);
```

**Fails:** `multer({ storage: multer.memoryStorage() })` with no `limits` — multer sets no default
size cap and buffers the whole upload into the process heap.

### Gate 46 — Upload destination path

> Code that writes an uploaded file to disk MUST NOT be emitted unless the destination path is built
> from a server-generated filename inside a directory that is not served as static content.

**Applies when:** an upload handler calls `writeFile`, `mv`, `save`, `copyfileobj`, or configures
`multer.diskStorage`.

**Fix:** Generate the filename server-side — a UUID plus the extension from the Gate 44 sniff — write
it to a directory outside every static root, and serve files through a handler that looks up the
stored key.

```ts
import { randomUUID } from "node:crypto";

const UPLOAD_DIR = "/var/app/uploads"; // outside the static root

app.post("/api/avatar", requireAuth, upload.single("file"), async (req, res) => {
  const sniffed = await fileTypeFromBuffer(req.file.buffer); // Gate 44
  if (!sniffed) return res.status(400).json({ error: "Not an image" });
  const key = `${randomUUID()}.${sniffed.ext}`;
  await writeFile(join(UPLOAD_DIR, key), req.file.buffer);
  res.json({ ok: true });
});
```

**Fails:** building the path from `req.file.originalname` (client-chosen, so it can escape the
directory or collide) and writing into a statically-served directory (serves attacker bytes back from
the app's own origin).

## Out of scope

- **Identity and authority fields** — `userId`, `role`, `isAdmin`, `orgId`. Validation confirms `role`
  is a string, never that this caller may set it: authorization range, gates 10-19.
- **Escaping at the sink.** A validated string is still untrusted where it meets SQL, a shell or HTML —
  validation does not replace escaping: injection range, gates 20-29.
- **Whether a value is correct for the business** — discount eligibility, stock on hand, refund
  windows. Domain knowledge, not a default mistake.
- **Webhook signature verification and deserialization of untrusted formats.** `integrity.md` owns
  both: an unverified webhook is Gate 96, `pickle.loads` on caller bytes is Gate 90. Gate 40's schema
  parse runs after Gate 96's signature check, not instead of it.
- **Open redirects.** `?next=`, `?returnUrl=` handed to `res.redirect`. Ungated in this range today;
  42 and 47-49 are held. Say it is ungated rather than stretching a gate to reach it. Where the value
  reaches an `href` rendered into a page rather than a redirect header, that is Gate 53.
- **Antivirus scanning, image re-encoding, CDN placement.** Defence-in-depth on top of the upload
  gates, not defaults a model gets wrong.
- **Request rate limits.** Gate 45 caps one upload; how many a caller may send is an operational
  control no line in the handler passes or fails.

## Prove probes

- Gate 40 — to a read-only list or search endpoint, send an undeclared field and a declared field with
  the wrong type (`?limit=abc&role=admin`) -> HELD if 400 before any lookup runs, FAILED if 200 with
  results or a 500 showing the value reached the query. Handlers that write are not probed; reason
  from code.
- Gate 41 — not provable read-only. The charge path writes an order. Reason from code.
- Gate 43 — not provable read-only. The raw body reaching the ORM only shows up in a write. Reason
  from code.
- Gate 44 — not provable read-only. A failing check stores the probe file. Reason from code.
- Gate 45 — not provable read-only. Which happens — abort at the cap or buffer and store — is the
  gate. Reason from code; `limits.fileSize` is readable at the upload instance's configuration site.
- Gate 46 — not provable read-only. The traversal it would demonstrate is itself a write outside the
  upload directory. Reason from code.
