-- Pending OAuth authorizations (RFC 6749, RFC 9700)
-- Stores OAuth authorization request parameters during browser login flow.
-- This prevents parameter tampering during the authentication redirect.

CREATE TABLE pending_oauth_authorizations (
    id TEXT PRIMARY KEY,
    -- OAuth 2.0 required parameters
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    response_type TEXT NOT NULL DEFAULT 'code',
    -- OAuth 2.0 optional parameters
    state TEXT,
    scope TEXT,
    -- OIDC parameters
    nonce TEXT,
    -- PKCE parameters (RFC 7636)
    code_challenge TEXT,
    code_challenge_method TEXT,
    -- Lifecycle management
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    -- Track if this was consumed (single-use)
    consumed_at TEXT
);

-- Index for cleanup of expired entries
CREATE INDEX idx_pending_oauth_expires ON pending_oauth_authorizations(expires_at);
