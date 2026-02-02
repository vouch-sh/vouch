-- OIDC states for device authorization
-- DSQL compatible: no REFERENCES constraints (device_auth_id references device_auth_requests.id)
-- Timestamps generated in application code
CREATE TABLE oidc_states (
    id TEXT PRIMARY KEY,
    state TEXT UNIQUE NOT NULL,
    device_auth_id TEXT NOT NULL,  -- references device_auth_requests(id)
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
