-- RFC 7523: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants.

-- Phase 1: JWT Client Authentication (private_key_jwt)
ALTER TABLE oauth_clients ADD COLUMN jwks TEXT;
ALTER TABLE oauth_clients ADD COLUMN jwks_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN jwks_uri_cached_at TEXT;
ALTER TABLE oauth_clients ADD COLUMN jwks_uri_cache TEXT;
ALTER TABLE oauth_clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic';

-- JTI replay prevention for JWT assertions.
CREATE TABLE IF NOT EXISTS jwt_assertion_jtis (
    id TEXT PRIMARY KEY,
    jti TEXT NOT NULL,
    client_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (jti, client_id)
);
CREATE INDEX idx_jwt_assertion_jtis_expires ON jwt_assertion_jtis(expires_at);

-- Phase 2: Trusted JWT issuers for authorization grants.
CREATE TABLE IF NOT EXISTS trusted_jwt_issuers (
    id TEXT PRIMARY KEY,
    issuer TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    jwks_uri TEXT NOT NULL,
    jwks_cache TEXT,
    jwks_cached_at TEXT,
    subject_claim_mapping TEXT NOT NULL DEFAULT 'email',
    allowed_scopes TEXT,
    max_token_lifetime_seconds INTEGER NOT NULL DEFAULT 3600,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_trusted_jwt_issuers_enabled ON trusted_jwt_issuers(enabled);
