'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Храним БД в отдельной папке data/, чтобы не мусорить в корне проекта.
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'app.sqlite'));

// WAL — быстрее и надёжнее при параллельных запросах.
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

module.exports = db;
