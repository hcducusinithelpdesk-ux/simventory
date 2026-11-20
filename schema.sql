-- SIM Inventory D1 schema
CREATE TABLE IF NOT EXISTS sims (
  id          TEXT PRIMARY KEY,
  number      TEXT NOT NULL,
  number_norm TEXT NOT NULL,
  account     TEXT NOT NULL DEFAULT '',
  sim_no      TEXT NOT NULL DEFAULT '',
  sim_norm    TEXT NOT NULL DEFAULT '',
  brand       TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'Active',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sims_number ON sims(number_norm);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sims_simno  ON sims(sim_norm) WHERE sim_norm <> '';
CREATE INDEX IF NOT EXISTS ix_sims_brand ON sims(brand);

CREATE TABLE IF NOT EXISTS brands (
  name TEXT PRIMARY KEY,
  pos  INTEGER NOT NULL DEFAULT 0
);

-- data version counter (used by clients to auto-refresh)
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta (k, v) VALUES ('ver', 1);

-- login audit log
CREATE TABLE IF NOT EXISTS auth_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT NOT NULL,
  success    INTEGER NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- brute-force lockout per IP
CREATE TABLE IF NOT EXISTS login_attempts (
  ip           TEXT PRIMARY KEY,
  fails        INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO brands (name, pos) VALUES ('Globe', 1), ('Smart', 2);
