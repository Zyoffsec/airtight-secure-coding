"use strict";

const db = require("../db");

// Gate 22 — every statement uses bound parameters (the `?` placeholders); no
// value is ever concatenated into SQL. better-sqlite3 binds them for us.

const stmts = {
  insert: db.prepare(
    `INSERT INTO users (email, password_hash, display_name, created_at)
     VALUES (?, ?, ?, ?)`
  ),
  byEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  byId: db.prepare(`SELECT * FROM users WHERE id = ?`),
  updateProfile: db.prepare(
    `UPDATE users SET display_name = ?, bio = ? WHERE id = ?`
  ),
  registerFailure: db.prepare(
    `UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`
  ),
  resetFailures: db.prepare(
    `UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?`
  ),
};

function create({ email, passwordHash, displayName }) {
  const info = stmts.insert.run(email, passwordHash, displayName, Date.now());
  return info.lastInsertRowid;
}

function findByEmail(email) {
  return stmts.byEmail.get(email);
}

function findById(id) {
  return stmts.byId.get(id);
}

// Gate 12/13 — the row is located by its owner's id (passed from the session,
// not the request) and only the two allowlisted columns are written.
function updateProfile(id, { displayName, bio }) {
  stmts.updateProfile.run(displayName, bio, id);
}

function recordFailure(id, failedAttempts, lockedUntil) {
  stmts.registerFailure.run(failedAttempts, lockedUntil, id);
}

function resetFailures(id) {
  stmts.resetFailures.run(id);
}

module.exports = {
  create,
  findByEmail,
  findById,
  updateProfile,
  recordFailure,
  resetFailures,
};
