"use strict";

const argon2 = require("argon2");

// Gate 3 — passwords are hashed with argon2id. We store argon2's full encoded
// output (it embeds the salt and parameters) and verify with argon2.verify,
// never by re-hashing and string-comparing.
const HASH_OPTIONS = { type: argon2.argon2id };

// Gate 1 — a hash computed once at startup with the same parameters as the real
// ones. When a login lookup misses (no such user), we still verify against this
// throwaway hash so a missing account and a wrong password take the same time
// and return the same response. Never compare the password string itself.
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = argon2.hash(
      "airtight-timing-equalizer-not-a-real-password",
      HASH_OPTIONS
    );
  }
  return dummyHashPromise;
}

async function hashPassword(plain) {
  return argon2.hash(plain, HASH_OPTIONS);
}

// Returns true/false. On a lookup miss, pass encoded=null: we burn the same work
// against the dummy hash and always return false (Gate 1).
async function verifyPassword(encoded, plain) {
  try {
    if (encoded == null) {
      await argon2.verify(await dummyHash(), plain);
      return false;
    }
    return await argon2.verify(encoded, plain);
  } catch {
    // A malformed stored hash must not throw a 500 into the auth path.
    return false;
  }
}

// Warm the dummy hash so the first real login isn't measurably slower.
dummyHash();

module.exports = { hashPassword, verifyPassword };
