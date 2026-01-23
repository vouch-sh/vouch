-- vouch database schema
-- Initial migration

-- Users (from OIDC identity provider)
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- FIDO2 authenticators (YubiKeys, Touch ID, etc.)
CREATE TABLE authenticators (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    -- WebAuthn credential data (stored as JSON)
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    -- Metadata
    aaguid TEXT, -- Authenticator type identifier
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

CREATE INDEX idx_authenticators_user ON authenticators(user_id);
CREATE INDEX idx_authenticators_credential ON authenticators(credential_id);

-- Sessions (active login sessions)
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    authenticator_id TEXT NOT NULL REFERENCES authenticators(id),
    token_hash TEXT NOT NULL UNIQUE, -- SHA256 of JWT
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
    ip_address TEXT,
    user_agent TEXT
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);

-- Pending authentication flows (registration/login)
CREATE TABLE auth_flows (
    code TEXT PRIMARY KEY,
    flow_type TEXT NOT NULL, -- 'register' or 'login'
    user_id TEXT REFERENCES users(id), -- NULL for registration
    challenge BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'complete', 'expired'
    result_data TEXT, -- JSON with result (credential ID, session token, etc.)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX idx_auth_flows_state ON auth_flows(state, expires_at);

-- Delegations (agent authorizations)
CREATE TABLE delegations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE, -- SHA256 of delegation JWT
    scope TEXT NOT NULL, -- JSON of DelegationScope
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    use_count INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER -- NULL = unlimited
);

CREATE INDEX idx_delegations_user ON delegations(user_id);
CREATE INDEX idx_delegations_token ON delegations(token_hash);

-- Credential issuance audit log
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    user_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL, -- 'credential_issued', 'delegation_created', etc.
    target_type TEXT NOT NULL, -- 'github', 'aws', 'ssh'
    target_details TEXT, -- JSON with details
    presence_type TEXT NOT NULL, -- 'human_present', 'human_delegated'
    delegation_id TEXT REFERENCES delegations(id),
    ip_address TEXT,
    user_agent TEXT
);

CREATE INDEX idx_audit_log_user ON audit_log(user_id, timestamp);
CREATE INDEX idx_audit_log_delegation ON audit_log(delegation_id);
