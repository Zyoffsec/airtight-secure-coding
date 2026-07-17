"use strict";

// Gate 100/103/107 — structured records to stdout, built from named fields.
// The platform's collector owns everything downstream; the app just prints JSON.
function write(level, event, fields) {
  const record = {
    ts: new Date().toISOString(),
    level,
    event,
    ...fields,
  };
  // One line per record so log collectors can parse it.
  process.stdout.write(JSON.stringify(record) + "\n");
}

module.exports = {
  info: (event, fields = {}) => write("info", event, fields),
  warn: (event, fields = {}) => write("warn", event, fields),
  error: (event, fields = {}) => write("error", event, fields),
};
