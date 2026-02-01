-- Enrollment sessions table for device enrollment flow
-- DSQL compatible: no REFERENCES constraints (user_id references users.id)
CREATE TABLE enrollment_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,  -- references users(id)
    user_email TEXT NOT NULL,
    session_token_hash TEXT UNIQUE NOT NULL,
    device_auth_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW()
);
