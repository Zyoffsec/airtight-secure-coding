"use strict";

require("dotenv").config();

// Gate 31 — required secrets are indexed directly with no fallback default.
// A missing value stops the process at startup instead of silently running
// with a guessable/insecure key.
function required(name) {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    console.error(
      `[config] Missing required environment variable: ${name}\n` +
        `Copy .env.example to .env and set it. See .env.example for how to generate SESSION_SECRET.`
    );
    process.exit(1);
  }
  return value;
}

const isProd = process.env.NODE_ENV === "production";

module.exports = {
  isProd,
  port: Number(process.env.PORT) || 3000,
  // Never given a hardcoded fallback (Gate 30/31).
  sessionSecret: required("SESSION_SECRET"),
};
