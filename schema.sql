CREATE TABLE IF NOT EXISTS lock_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  locked INTEGER NOT NULL,
  unlock_time TEXT,
  scheduled_at TEXT,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lock_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  locked INTEGER,
  unlock_time TEXT,
  remaining_time TEXT,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);

INSERT OR IGNORE INTO lock_state (id, locked, unlock_time, scheduled_at, updated_by, updated_at)
VALUES (1, 1, NULL, NULL, 'system', datetime('now'));
