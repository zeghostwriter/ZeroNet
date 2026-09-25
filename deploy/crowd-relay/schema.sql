-- One row per test result an app reported. No addresses, no device ids:
-- `reporter` is a pseudonym that changes every day (see worker.js).
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  net TEXT NOT NULL,
  reporter TEXT NOT NULL,
  kind TEXT NOT NULL,
  item TEXT NOT NULL,
  ok INTEGER NOT NULL,
  ms INTEGER
);
CREATE INDEX IF NOT EXISTS reports_ts ON reports (ts);
CREATE INDEX IF NOT EXISTS reports_reporter ON reports (reporter, ts);
