-- Server configuration (key-value store)
CREATE TABLE IF NOT EXISTS server_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
