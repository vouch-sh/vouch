-- DPoP JTI cache table (prevents replay attacks)
CREATE TABLE dpop_jti_cache (
    jti TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
