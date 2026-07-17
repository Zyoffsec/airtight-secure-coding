'use strict';

const bcrypt = require('bcryptjs');
const db = require('../db');

const SALT_ROUNDS = 12;

// Подготовленные запросы кешируются better-sqlite3 — быстро и без SQL-инъекций.
const insertUser = db.prepare(
  'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
);
const findById = db.prepare('SELECT * FROM users WHERE id = ?');
const findByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const findByEmail = db.prepare('SELECT * FROM users WHERE email = ?');

async function createUser({ username, email, password }) {
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const info = insertUser.run(username, email, passwordHash);
  return getById(info.lastInsertRowid);
}

function getById(id) {
  return findById.get(id);
}

function getByUsername(username) {
  return findByUsername.get(username);
}

function getByEmail(email) {
  return findByEmail.get(email);
}

async function verifyPassword(user, password) {
  return bcrypt.compare(password, user.password_hash);
}

module.exports = {
  createUser,
  getById,
  getByUsername,
  getByEmail,
  verifyPassword,
};
