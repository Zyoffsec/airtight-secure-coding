"use strict";

const path = require("path");
const express = require("express");
const session = require("express-session");
const SqliteStore = require("better-sqlite3-session-store")(session);

const config = require("./config");
const db = require("./db");
const log = require("./lib/logger");
const { provideToken, verifyToken } = require("./middleware/csrf");

const authRoutes = require("./routes/auth");
const profileRoutes = require("./routes/profile");

const app = express();

// We sit behind a proxy in production (so req.ip / secure cookies work).
if (config.isProd) app.set("trust proxy", 1);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false, limit: "16kb" })); // bounded body
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    name: "sid",
    store: new SqliteStore({
      client: db,
      expired: { clear: true, intervalMs: 15 * 60 * 1000 },
    }),
    secret: config.sessionSecret, // Gate 31 — from env, no fallback
    resave: false,
    saveUninitialized: false,
    cookie: {
      // Gate 7 — httpOnly and sameSite always on; `secure` is gated on the
      // environment so local dev over plain HTTP still works.
      httpOnly: true,
      sameSite: "lax",
      secure: config.isProd,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

// CSRF: expose a token to every view, verify it on every unsafe method.
app.use(provideToken);
app.use(verifyToken);

// Routes
app.get("/", (req, res) => {
  res.redirect(req.session.userId ? "/profile" : "/login");
});
app.use("/", authRoutes);
app.use("/", profileRoutes);

// 404
app.use((req, res) => {
  res.status(404).render("error", {
    title: "Not found",
    message: "The page you were looking for does not exist.",
  });
});

// Central error handler. Gate 37 — the client never sees exception internals.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log.error("unhandled_error", { path: req.path, msg: err.message });
  res.status(500).render("error", {
    title: "Error",
    message: "Something went wrong. Please try again.",
  });
});

app.listen(config.port, () => {
  log.info("server.start", { port: config.port, env: config.isProd ? "production" : "development" });
});
