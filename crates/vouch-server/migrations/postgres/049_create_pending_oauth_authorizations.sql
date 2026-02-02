-- Pending OAuth authorizations table for authorization code flow
-- Timestamps generated in application code
CREATE TABLE pending_oauth_authorizations (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    response_type TEXT NOT NULL DEFAULT 'code',
    state TEXT,
    scope TEXT,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
