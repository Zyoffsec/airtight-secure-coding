"use strict";

const crypto = require("crypto");

// Synchronizer-token CSRF protection. SameSite=Lax on the session cookie already
// blocks cross-site POSTs in modern browsers; this is defense in depth for
// state-changing forms (register, login, logout, profile update).

function getToken(req) {
  if (!req.session.csrfToken) {
    // Gate 6/61 — token drawn from the CSPRNG.
    req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
  }
  return req.session.csrfToken;
}

// Expose the token to every template as res.locals.csrfToken.
function provideToken(req, res, next) {
  res.locals.csrfToken = getToken(req);
  next();
}

// Verify on unsafe methods. Gate 2 — constant-time comparison on equal-length
// buffers; a length mismatch is rejected before timingSafeEqual is called.
function verifyToken(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();

  const expected = req.session.csrfToken || "";
  const provided = (req.body && req.body._csrf) || "";
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).render("error", {
      title: "Forbidden",
      message: "Invalid or missing form token. Please reload the page and try again.",
    });
  }
  return next();
}

module.exports = { provideToken, verifyToken };
