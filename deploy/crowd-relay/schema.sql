-- One row per test result an app reported. No addresses, no device ids:
-- `reporter` and `source` are pseudonyms that change every day (see
-- worker.js).
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  net TEXT NOT NULL,
  reporter TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  item TEXT NOT NULL,
  ok INTEGER NOT NULL,
  ms INTEGER
);
CREATE INDEX IF NOT EXISTS reports_ts ON reports (ts);
CREATE INDEX IF NOT EXISTS reports_source ON reports (source, ts);
