-- DPoP nonces table (Demonstrating Proof of Possession - RFC 9449)
-- Timestamps generated in application code
CREATE TABLE dpop_nonces (
    id TEXT PRIMARY KEY,
    nonce TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
