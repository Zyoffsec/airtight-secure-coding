"use strict";

const { z } = require("zod");

// Gate 40/43/128 — every request body is parsed by one of these schemas at the
// top of its handler, and only the schema's OUTPUT is used afterwards. Every
// free-text field carries an explicit maximum length so a single request cannot
// pin CPU/memory (Gate 128) — argon2, in particular, will hash whatever it is
// given, so the password length is capped here at the boundary.

const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254) // RFC 5321 upper bound.
  .email();

// Cap the password length: 8..200. The floor is a usability/strength minimum;
// the ceiling bounds hashing work (Gate 125/128).
const password = z.string().min(8).max(200);

const displayName = z.string().trim().max(80);
const bio = z.string().trim().max(500);

const registerSchema = z.object({
  email,
  password,
  displayName: displayName.optional().default(""),
});

const loginSchema = z.object({
  email,
  password,
});

// Gate 13 — mass-assignment allowlist. Only these two fields are editable on a
// profile; email and password_hash are deliberately absent and can never be set
// through this path.
const profileSchema = z.object({
  displayName,
  bio,
});

module.exports = { registerSchema, loginSchema, profileSchema };
