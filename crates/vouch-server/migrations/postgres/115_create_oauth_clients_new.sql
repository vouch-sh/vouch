-- DSQL table recreation: make user_id nullable for RFC 7591 open registration,
-- apply NOT NULL on fapi_profile and dpop_bound_access_tokens.
-- DSQL does not support ALTER COLUMN SET/DROP NOT NULL (one DDL per migration).
CREATE TABLE oauth_clients_new (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    client_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    application_type TEXT NOT NULL
        CHECK (application_type IN ('web', 'native', 'spa', 'service')),
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    access_scope TEXT NOT NULL DEFAULT 'personal'
        CHECK (access_scope IN ('organization', 'personal', 'public')),
    org_id TEXT,
    resource_uris TEXT,
    jwks TEXT,
    jwks_uri TEXT,
    jwks_uri_cached_at TIMESTAMPTZ,
    jwks_uri_cache TEXT,
    token_endpoint_auth_method TEXT,
    request_object_signing_alg TEXT,
    require_signed_request_object BOOLEAN,
    fapi_profile TEXT NOT NULL,
    dpop_bound_access_tokens BOOLEAN NOT NULL,
    grant_types TEXT,
    response_types TEXT,
    software_id TEXT,
    software_version TEXT,
    registration_source TEXT,
    registration_access_token_hash TEXT,
    registration_metadata TEXT
);
