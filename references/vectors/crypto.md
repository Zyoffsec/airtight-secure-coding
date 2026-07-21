# Cryptographic failures

Gates the emission decisions where a cryptographic choice is load-bearing: whether a connection
identifies its peer, where unpredictable bytes come from, how a cipher is invoked, and whether a
transformation protects anything at all. Each gate below leads with its rule and its fix.

## Load this file when

- The request mentions encrypting, decrypting, signing, obfuscating or "hiding" a value.
- Code calls `node:crypto`, `crypto.subtle`, `hashlib`, `hmac`, `secrets`, `cryptography`,
  `pycryptodome`, libsodium, or any package whose job is encryption.
- Code opens an outbound TLS connection: an HTTP client, an `https.Agent`, an `SSLContext`, a
  database, broker or SMTP connection with TLS options.
- An error naming a certificate is being fixed — `self signed certificate in certificate chain`,
  `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `SSLCertVerificationError`, `x509: certificate signed by unknown
  authority`.
- `Math.random()`, `random.random()`, `random.randint`, `rand()`, `uuid.uuid1()` or `Date.now()`
  contributes to a value that must be unguessable.
- A value is base64-, hex- or URL-encoded before being handed to a client, then decoded and acted on
  when it comes back.
- A field, cookie payload, file or config blob is stored in a form the code calls encrypted,
  protected or obfuscated.
- Anything names an algorithm or a mode: `aes-256-cbc`, `MODE_ECB`, `sha1`, `md5`, `HS256`.

## Gates

### Gate 60 — TLS verification

> Code that opens a TLS connection MUST NOT be emitted with certificate or hostname verification
> disabled, unless it is a test asserting that an invalid certificate is rejected.

**Applies when:** any client is constructed for an `https://`, `wss://`, `postgres://?sslmode=`,
`amqps://` or `smtps://` peer — especially when the change is a response to a certificate error
rather than a feature.

**Fix:** Supply the peer's CA as an explicit trust anchor so the one certificate you meant to accept
is the only one added — `new https.Agent({ ca })`, Python `requests.get(url, verify="/path/ca.pem")`
or `httpx.Client(verify=ctx)`, Go `RootCAs`. The same gate covers `verify=False`,
`ssl._create_unverified_context()`, `InsecureSkipVerify: true` and `curl -k` in a script. The
`NODE_TLS_REJECT_UNAUTHORIZED=0` form in a Dockerfile or start script is the same failure with a
wider blast radius — it disables verification for every connection the process makes.

**Fails:** `new https.Agent({ rejectUnauthorized: false })` — the connection is still encrypted, but
the peer is no longer identified.

### Gate 61 — Unpredictable values from a CSPRNG

> Code that generates a value whose security depends on an attacker being unable to predict it MUST
> NOT be emitted unless every byte derives from a cryptographic random source (`crypto.randomBytes`,
> `crypto.randomInt`, `crypto.getRandomValues`, Python `secrets`, `os.urandom`).

**Applies when:** the generated value is a password, a one-time or invite code, a coupon code, an
unguessable URL slug, a CSRF token, a salt, a nonce, key material, or any shuffle or selection an
attacker profits from predicting. Gate 6 in `credentials.md` is this same rule narrowed to values
that later prove identity — session tokens, reset tokens, API keys, magic links — and governs those;
this gate covers everything else that must be unguessable.

**Fix:** Draw from the CSPRNG: `crypto.randomInt(n)` per character where the value has a format to
satisfy, or `crypto.randomBytes(32).toString("base64url")` where it does not (Python:
`secrets.choice(alphabet)` / `secrets.token_urlsafe(32)`). Do not hand-roll it as
`randomBytes(1)[0] % alphabet.length` — that reintroduces a modulo bias `randomInt`'s rejection
sampling exists to remove.

**Fails:** `Math.floor(Math.random() * ALPHABET.length)`, or Python's `random` module — both are
non-cryptographic generators whose internal state is recoverable from a short run of outputs.

### Gate 63 — Cipher mode and nonce

> Code that encrypts data MUST NOT be emitted unless it uses an AEAD construction — AES-GCM,
> ChaCha20-Poly1305, libsodium `secretbox`, or `cryptography`'s `Fernet`/`AESGCM` — with a nonce
> drawn fresh from a CSPRNG on every encryption and stored alongside the ciphertext.

**Applies when:** `createCipheriv`, the deprecated `createCipher`, `AES.new`, `Cipher(...)`, or any
request to encrypt a database field, a file, a cookie payload or a config blob.

**Fix:** Use `aes-256-gcm` with a 12-byte nonce from `crypto.randomBytes` generated *inside* the
encrypt function on each call, and store `nonce || tag || ciphertext` as one blob — the nonce is not
secret and needs no second column. GCM's tag makes a modified ciphertext fail to decrypt instead of
decrypting to something else, which removes the padding-oracle and bit-flipping paths outright. In
Python reach for `cryptography`'s `Fernet` or `AESGCM` rather than composing it by hand. The key
comes from the environment, never a literal in source (Gate 30 in `secrets.md`); a fallback default
for a missing key is Gate 31.

```js
import crypto from "node:crypto";

const key = Buffer.from(process.env.FIELD_KEY, "hex");

export function encryptField(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64");
}

export function decryptField(stored) {
  const buf = Buffer.from(stored, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8");
}
```

**Fails:** `aes-256-cbc` with a constant/zero IV (`Buffer.alloc(16, 0)`), or `aes-256-ecb` /
`AES.new(key, AES.MODE_ECB)` — a fixed IV makes encryption deterministic (equal plaintexts yield
equal ciphertext, leaking which rows match) and CBC/ECB carry no integrity check.

### Gate 65 — Encoding is not protection

> Code that hands an encoded value to an untrusted party MUST NOT be emitted if the code's safety
> depends on that party being unable to read or alter it, unless the value is encrypted (Gate 63) or
> carries a MAC that the receiving handler verifies.

**Applies when:** base64, hex, `btoa`, `Buffer.toString("base64")` or `encodeURIComponent` is applied
to a value on its way into a URL, a cookie, a hidden field or a QR code, and a handler decodes it on
the way back and acts on what it says. The tell is usually the name: `encrypted`, `obfuscate`,
`token`, or a comment saying the value is now hidden.

**Fix:** Attach an HMAC-SHA256 of the value computed with a server-side key and verify it with
`timingSafeEqual` (Gate 2) before acting, so the handler accepts only links the server issued. Keep
the base64 — it is the right tool for fitting bytes into a URL; it is simply not the thing making the
link trustworthy. Where the value must also be unreadable, that is encryption (Gate 63); where it
need not travel at all, store a random token and look it up (Gate 6).

```js
import { createHmac, timingSafeEqual } from "node:crypto";

const sign = (email) =>
  createHmac("sha256", process.env.UNSUBSCRIBE_KEY).update(email).digest("base64url");

export function unsubscribeUrl(email) {
  const u = Buffer.from(email).toString("base64url");
  return `${process.env.APP_URL}/unsubscribe?u=${u}&s=${sign(email)}`;
}

app.get("/unsubscribe", async (req, res) => {
  const email = Buffer.from(String(req.query.u ?? ""), "base64url").toString("utf8");
  const expected = Buffer.from(sign(email));
  const presented = Buffer.from(String(req.query.s ?? ""));
  if (expected.length !== presented.length || !timingSafeEqual(expected, presented)) {
    return res.status(400).send("Invalid unsubscribe link");
  }
  await db.subscriber.update({ where: { email }, data: { subscribed: false } });
  res.send("You have been unsubscribed.");
});
```

**Fails:** base64-encoding an address into `?u=` with no MAC — base64 takes no key, so anyone can
decode it and, worse, re-encode any other address and act as them.

## Out of scope

- **Password hashing.** Gate 3 in `credentials.md`. A fast hash on a password is the one place an
  algorithm choice decides an outcome in a normal application, and it is gated there. Do not cite a
  gate from this file for it.
- **The encryption key written into the source.** Gate 30 in `secrets.md` — a key literal is a
  credential literal, and feeding `createCipheriv` rather than an HTTP header changes nothing about
  the gate. Gate 63 governs how a key is used; where it comes from is Gate 30, and a fallback default
  for a missing key is Gate 31.
- **Identity tokens from `Math.random()`.** Gate 6. Gate 61 is the general case; where both would
  apply, cite Gate 6.
- **MD5 and SHA-1.** Considered and rejected against rule 5. Where a model reaches for MD5 in a
  normal application it is building a fingerprint — a cache key, an ETag, a dedupe hash, a shard
  selector — and a collision there is a curiosity that nothing decides on. Where collision resistance
  genuinely settles something — code signing, an update manifest, a certificate chain — an
  AI-assisted application is not writing that code. Where a fast hash on a secret is a real default
  mistake, the secret is a password and it is Gate 3. A gate reading "MUST NOT use MD5" would fire
  almost entirely on cases it should not, and a number that mostly cries wolf teaches developers to
  skip every number. Report a weak hash that genuinely guards something as an ungated finding.
- **Rolling your own crypto primitive.** Considered and rejected against rule 5: it is not a default.
  Asked to encrypt something, a model reaches for `node:crypto` or `cryptography`; it does not sit
  down and write a cipher, so the gate would never fire. The model's actual failure is misusing a
  primitive that is already correct, which is Gate 63. A hand-written cipher, when it appears, was
  asked for — "no dependencies" — and that is a conversation, not an emission gate.
- **Server-side TLS** — protocol versions, cipher suites, HSTS, certificate provisioning. It lives in
  a terminator, a load balancer or a CDN, and no line the model emits passes or fails it. Gate 60 is
  about the client the model writes.
- **Certificate pinning.** Defence in depth, and a product decision with an outage attached. Gate 60
  requires verification, not pinning.
- **Key rotation, key custody, HSMs and KMS choice.** Operational: rule 4. No emitted line passes or
  fails "rotate quarterly".
- **JWT algorithm confusion** — `alg: none`, an HS256 token against an RS256 key. Real, but the
  libraries a model reaches for reject it by default, so it does not clear the default-mistake bar.
  Report a hand-rolled verify as an ungated finding.
- **What a decrypted value is then allowed to do.** Ownership and role checks are Gates 10-19; the
  shape of the value coming back in is Gates 40-49.

## Prove probes

- Gate 60 — not provable read-only. Verification is a property of the client, not of a response.
  Reason from the configuration site: search the project for `rejectUnauthorized`, `verify=False`,
  `InsecureSkipVerify`, `ssl._create_unverified_context`, `NODE_TLS_REJECT_UNAUTHORIZED` and
  `curl -k` -> HELD if every hit is inside a test asserting rejection, FAILED for each hit on a path
  that runs outside tests. Check the Dockerfile, the compose environment and package scripts as well
  as the source; the env-var form is not in the code.
- Gate 61 — not provable read-only. A handful of samples does not establish a source: twelve
  characters from `Math.random()` and twelve from `randomBytes` are indistinguishable by eye. Reason
  from code — the generator names its source on one line.
- Gate 63 — not provable through the endpoint read-only; producing a ciphertext to inspect means
  writing one through the app. Reason from the configuration site: the mode string and the nonce's
  origin are both literals in the encrypt function -> HELD if the mode is an AEAD and the nonce comes
  from a CSPRNG call *inside* the per-message function, FAILED if the mode is `ecb`, or if the IV is
  a module-level constant, a zero buffer, a string literal, or derived from the key. Where the
  developer's local database already holds rows they confirm carry the same plaintext, a read-only
  `SELECT` of those two ciphertexts settles the nonce reuse case directly: identical ciphertext is
  FAILED. Do not write rows to create the pair — that is rail 3.
- Gate 65 — where the encoded value is consumed by a **read-only** route (a share link, a preview),
  `GET` it with the parameter re-encoded for a subject the developer confirms the fixture user is not
  entitled to -> HELD if 400 or 403, FAILED if the object comes back. Where the route mutates —
  unsubscribe, confirm, apply — do not send it; rail 3 forbids the write, and the probe would be
  performed on a real record. Reason from code instead: HELD if the handler verifies a MAC or looks
  up a stored random token before acting, FAILED if it decodes and acts.
