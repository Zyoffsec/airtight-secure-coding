"use strict";

// Gate 10 — identity is read only from the server-side session, never from a
// request field the client could set. Handlers downstream use req.session.userId
// as the sole source of "who is calling".
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect("/login");
  }
  return next();
}

// If already logged in, keep the user off the login/register pages.
function redirectIfAuthed(req, res, next) {
  if (req.session && req.session.userId) {
    return res.redirect("/profile");
  }
  return next();
}

module.exports = { requireAuth, redirectIfAuthed };
