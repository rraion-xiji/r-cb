CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  dom TEXT NOT NULL,
  sub TEXT NOT NULL,
  auto_delete_days INTEGER NOT NULL DEFAULT 30,
  delete_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS lock_state_v2 (
  user_id INTEGER PRIMARY KEY,
  locked INTEGER NOT NULL,
  unlock_time TEXT,
  scheduled_at TEXT,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS lock_events_v2 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  locked INTEGER,
  unlock_time TEXT,
  remaining_time TEXT,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT OR IGNORE INTO lock_state_v2 (user_id, locked, unlock_time, scheduled_at, updated_by, updated_at)
SELECT user_id, locked, unlock_time, scheduled_at, updated_by, updated_at
FROM lock_state_v2;

DROP TABLE IF EXISTS lock_state;
ALTER TABLE lock_state_v2 RENAME TO lock_state;

DROP TABLE IF EXISTS lock_events;
ALTER TABLE lock_events_v2 RENAME TO lock_events;

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_delete_at ON users(delete_at);
CREATE INDEX IF NOT EXISTS idx_lock_events_user_id ON lock_events(user_id);
