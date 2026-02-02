-- Server configuration key-value store
-- Timestamps generated in application code
CREATE TABLE server_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
