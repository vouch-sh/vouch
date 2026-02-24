-- RFC 7523 Section 3: JTI replay prevention for JWT assertions.
-- DSQL compatible: no REFERENCES constraints.
CREATE TABLE IF NOT EXISTS jwt_assertion_jtis (
    id TEXT PRIMARY KEY,
    jti TEXT NOT NULL,
    client_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (jti, client_id)
);
