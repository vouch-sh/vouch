-- RFC 7523 Section 2.1: Trusted JWT issuers for authorization grants.
-- DSQL compatible: no REFERENCES constraints. DEFAULT allowed in CREATE TABLE.
CREATE TABLE IF NOT EXISTS trusted_jwt_issuers (
    id TEXT PRIMARY KEY,
    issuer TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    jwks_uri TEXT NOT NULL,
    jwks_cache TEXT,
    jwks_cached_at TIMESTAMPTZ,
    subject_claim_mapping TEXT NOT NULL DEFAULT 'email',
    allowed_scopes TEXT,
    max_token_lifetime_seconds INTEGER NOT NULL DEFAULT 3600,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
