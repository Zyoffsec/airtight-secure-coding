"use strict";

const express = require("express");
const rateLimit = require("express-rate-limit");

const User = require("../models/user");
const { hashPassword, verifyPassword } = require("../lib/password");
const { registerSchema, loginSchema } = require("../lib/validate");
const { redirectIfAuthed } = require("../middleware/auth");
const log = require("../lib/logger");

const router = express.Router();

// Gate 120 — a rate limiter on every credential endpoint. This gate is presence,
// not a specific threshold; the numbers below are a reasonable default. NOTE: the
// default store is per-process and will undercount behind multiple workers — put
// a shared store (Redis) here before scaling out.
const credentialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // registration/login attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: undefined,
  handler: (req, res) => {
    log.warn("auth.rate_limited", { ip: req.ip, path: req.path });
    res.status(429).render("error", {
      title: "Too many requests",
      message: "Too many attempts. Please wait a few minutes and try again.",
    });
  },
});

// Gate 121 — per-account lockout thresholds.
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

// ---- Register ------------------------------------------------------------

router.get("/register", redirectIfAuthed, (req, res) => {
  res.render("register", { title: "Create account", values: {}, error: null });
});

router.post("/register", credentialLimiter, redirectIfAuthed, async (req, res) => {
  // Gate 40/43 — parse first, then use ONLY the parsed output.
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).render("register", {
      title: "Create account",
      values: { email: req.body?.email || "" },
      error: "Please enter a valid email and a password of at least 8 characters.",
    });
  }
  const { email, password, displayName } = parsed.data;

  try {
    // Uniqueness is enforced by the UNIQUE constraint; we also check first to
    // give a friendly message. Either way we do not leak which addresses exist
    // via timing differences beyond the DB lookup.
    const existing = User.findByEmail(email);
    if (existing) {
      return res.status(409).render("register", {
        title: "Create account",
        values: { email },
        error: "That email is already registered. Try logging in instead.",
      });
    }

    const passwordHash = await hashPassword(password); // Gate 3
    const userId = User.create({ email, passwordHash, displayName });
    log.info("auth.register", { userId, email }); // Gate 103

    // Gate 5 — regenerate the session on the login that follows signup so the
    // pre-auth session id cannot be fixated into an authenticated one.
    req.session.regenerate((err) => {
      if (err) {
        log.error("session.regenerate_failed", { userId, msg: err.message });
        return res.status(500).render("error", {
          title: "Error",
          message: "Something went wrong. Please try logging in.",
        });
      }
      req.session.userId = userId;
      res.redirect("/profile");
    });
  } catch (err) {
    // Gate 101 — no swallowed exception; log with enough context to place it.
    log.error("auth.register_failed", { email, msg: err.message });
    // Gate 37 — the client gets a literal message, never the exception detail.
    res.status(500).render("error", {
      title: "Error",
      message: "Could not create the account. Please try again.",
    });
  }
});

// ---- Login ---------------------------------------------------------------

router.get("/login", redirectIfAuthed, (req, res) => {
  res.render("login", { title: "Log in", values: {}, error: null });
});

router.post("/login", credentialLimiter, redirectIfAuthed, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    // Same generic message as a credential mismatch — do not reveal which field
    // was wrong (Gate 1).
    return res.status(401).render("login", {
      title: "Log in",
      values: { email: req.body?.email || "" },
      error: "Invalid email or password.",
    });
  }
  const { email, password } = parsed.data;

  try {
    const user = User.findByEmail(email);

    // Gate 121 — account temporarily locked after repeated failures.
    if (user && user.locked_until && user.locked_until > Date.now()) {
      log.warn("auth.login_locked", { userId: user.id, email });
      return res.status(429).render("login", {
        title: "Log in",
        values: { email },
        error: "Account temporarily locked due to too many failed attempts. Try again later.",
      });
    }

    // Gate 1 — verify unconditionally. On a lookup miss we still burn a hash
    // against the dummy (verifyPassword handles the null), so miss and mismatch
    // are indistinguishable in time and in response.
    const ok = await verifyPassword(user ? user.password_hash : null, password);

    if (!ok) {
      if (user) {
        const attempts = user.failed_attempts + 1;
        const lockedUntil = attempts >= MAX_FAILURES ? Date.now() + LOCK_MS : null;
        User.recordFailure(user.id, attempts, lockedUntil);
        log.warn("auth.login_failed", { userId: user.id, email, attempts });
      } else {
        log.warn("auth.login_failed", { email, attempts: null });
      }
      return res.status(401).render("login", {
        title: "Log in",
        values: { email },
        error: "Invalid email or password.",
      });
    }

    // Success: clear the failure counter and rotate the session (Gate 5).
    User.resetFailures(user.id);
    req.session.regenerate((err) => {
      if (err) {
        log.error("session.regenerate_failed", { userId: user.id, msg: err.message });
        return res.status(500).render("error", {
          title: "Error",
          message: "Something went wrong. Please try again.",
        });
      }
      req.session.userId = user.id;
      log.info("auth.login", { userId: user.id, email }); // Gate 103
      res.redirect("/profile");
    });
  } catch (err) {
    log.error("auth.login_error", { email, msg: err.message });
    res.status(500).render("error", {
      title: "Error",
      message: "Could not log you in. Please try again.",
    });
  }
});

// ---- Logout --------------------------------------------------------------

router.post("/logout", (req, res) => {
  const userId = req.session.userId;
  // Gate 5 — destroy the session on logout, don't just clear a field.
  req.session.destroy((err) => {
    if (err) log.error("session.destroy_failed", { userId, msg: err.message });
    res.clearCookie("sid");
    log.info("auth.logout", { userId });
    res.redirect("/login");
  });
});

module.exports = router;
