"use strict";

const express = require("express");

const User = require("../models/user");
const { profileSchema } = require("../lib/validate");
const { requireAuth } = require("../middleware/auth");
const log = require("../lib/logger");

const router = express.Router();

// Every route here requires an authenticated session (Gate 10).
router.use(requireAuth);

router.get("/profile", (req, res) => {
  // Gate 10/12 — the record is loaded by the id held in the session, so a user
  // can only ever see their own profile. There is no user id in the URL to tamper.
  const user = User.findById(req.session.userId);
  if (!user) {
    // Session points at a deleted user — treat as logged out.
    return req.session.destroy(() => res.redirect("/login"));
  }
  res.render("profile", { title: "Your profile", user, saved: false, error: null });
});

router.post("/profile", (req, res) => {
  // Gate 40/43 — parse, then use only the parsed output.
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) {
    const user = User.findById(req.session.userId);
    return res.status(400).render("profile", {
      title: "Your profile",
      user,
      saved: false,
      error: "Display name must be 80 characters or fewer and bio 500 or fewer.",
    });
  }

  try {
    // Gate 12/13 — write is scoped to the session user's own id, and the schema
    // only permits displayName + bio. email/password_hash can't be touched here.
    User.updateProfile(req.session.userId, parsed.data);
    log.info("profile.update", { userId: req.session.userId });

    const user = User.findById(req.session.userId);
    res.render("profile", { title: "Your profile", user, saved: true, error: null });
  } catch (err) {
    log.error("profile.update_failed", { userId: req.session.userId, msg: err.message });
    const user = User.findById(req.session.userId);
    res.status(500).render("profile", {
      title: "Your profile",
      user,
      saved: false,
      error: "Could not save your changes. Please try again.",
    });
  }
});

module.exports = router;
