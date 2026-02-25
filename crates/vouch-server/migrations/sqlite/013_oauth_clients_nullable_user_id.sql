-- Make oauth_clients.user_id nullable to support RFC 7591 open registration.
-- Open registration creates clients without user association; the client_id
-- alone grants zero access (FIDO2 authentication still required for tokens).

-- SQLite doesn't support ALTER COLUMN, so we create a new table and copy data.
-- Column order must match the old table exactly for INSERT ... SELECT * to work.
CREATE TABLE oauth_clients_new (
    id TEXT PRIMARY KEY,
    user_id TEXT,  -- nullable for open registration (was NOT NULL)
    client_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    application_type TEXT NOT NULL DEFAULT 'web'
        CHECK (application_type IN ('web', 'native', 'spa', 'service')),
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_used_at TEXT,
    access_scope TEXT NOT NULL DEFAULT 'personal'
        CHECK (access_scope IN ('organization', 'personal', 'public')),
    org_id TEXT,
    resource_uris TEXT NOT NULL DEFAULT '[]',
    jwks TEXT,
    jwks_uri TEXT,
    jwks_uri_cached_at TEXT,
    jwks_uri_cache TEXT,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
    request_object_signing_alg TEXT,
    require_signed_request_object BOOLEAN DEFAULT FALSE,
    fapi_profile TEXT NOT NULL DEFAULT 'none',
    dpop_bound_access_tokens BOOLEAN NOT NULL DEFAULT FALSE,
    grant_types TEXT,
    response_types TEXT,
    software_id TEXT,
    software_version TEXT,
    registration_source TEXT NOT NULL DEFAULT 'portal',
    registration_access_token_hash TEXT,
    registration_metadata TEXT
);

INSERT INTO oauth_clients_new SELECT * FROM oauth_clients;
DROP TABLE oauth_clients;
ALTER TABLE oauth_clients_new RENAME TO oauth_clients;

-- Recreate indexes lost during table recreation
CREATE INDEX idx_oauth_clients_user ON oauth_clients(user_id);
CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX idx_oauth_clients_active ON oauth_clients(active);
CREATE INDEX idx_oauth_clients_org ON oauth_clients(org_id);
CREATE INDEX idx_oauth_clients_access_scope ON oauth_clients(access_scope);
