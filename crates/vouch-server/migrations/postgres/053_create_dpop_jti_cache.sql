-- DPoP JTI cache table (prevents replay attacks)
-- Timestamps generated in application code
CREATE TABLE dpop_jti_cache (
    jti TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
