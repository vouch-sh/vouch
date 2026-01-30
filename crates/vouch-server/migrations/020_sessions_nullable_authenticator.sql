-- Make authenticator_id nullable in sessions table
-- This is needed for OIDC-authenticated users who haven't registered a security key yet
-- (e.g., during direct enrollment flow)

-- SQLite doesn't support ALTER COLUMN, so we need to recreate the table
-- Step 1: Create new table with nullable authenticator_id
CREATE TABLE sessions_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    authenticator_id TEXT REFERENCES authenticators(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Step 2: Copy data from old table
INSERT INTO sessions_new (id, user_id, token_hash, authenticator_id, expires_at, created_at)
SELECT id, user_id, token_hash, authenticator_id, expires_at, created_at
FROM sessions;

-- Step 3: Drop old table
DROP TABLE sessions;

-- Step 4: Rename new table
ALTER TABLE sessions_new RENAME TO sessions;

-- Step 5: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
