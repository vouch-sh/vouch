-- RFC 9126: OAuth 2.0 Pushed Authorization Requests (PAR)
-- Stores authorization request parameters pushed by authenticated clients
-- before the browser-based authorization flow begins.

CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
    id TEXT PRIMARY KEY,
    request_uri TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    response_type TEXT NOT NULL DEFAULT 'code',
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    state TEXT,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    resource TEXT,
    acr_values TEXT,
    max_age INTEGER,
    prompt TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
