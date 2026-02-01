-- DPoP nonces table (Demonstrating Proof of Possession - RFC 9449)
CREATE TABLE dpop_nonces (
    id TEXT PRIMARY KEY,
    nonce TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
