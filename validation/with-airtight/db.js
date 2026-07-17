"use strict";

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "app.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// Schema. failed_attempts / locked_until back the per-account backoff (Gate 121).
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    email          TEXT    NOT NULL UNIQUE,
    password_hash  TEXT    NOT NULL,
    display_name   TEXT    NOT NULL DEFAULT '',
    bio            TEXT    NOT NULL DEFAULT '',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER,
    created_at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid    TEXT PRIMARY KEY,
    sess   TEXT NOT NULL,
    expire INTEGER NOT NULL
  );
`);

module.exports = db;
