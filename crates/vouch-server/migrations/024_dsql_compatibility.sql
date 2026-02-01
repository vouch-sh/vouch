-- DSQL Compatibility Migration
-- Removes ON DELETE CASCADE, ON DELETE SET NULL, and CHECK constraints.
-- These are now handled in application code for Aurora DSQL compatibility.
--
-- Note: SQLite requires table recreation to remove constraints.
-- This migration preserves basic FK constraints for data integrity during
-- the transition period. When migrating to DSQL, all FKs should be removed.

-- ============================================================================
-- 1. Recreate authenticators table without CASCADE
-- ============================================================================
CREATE TABLE authenticators_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    credential_id BLOB UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    aaguid TEXT,
    user_handle BLOB
);

INSERT INTO authenticators_new SELECT * FROM authenticators;
DROP TABLE authenticators;
ALTER TABLE authenticators_new RENAME TO authenticators;

CREATE INDEX IF NOT EXISTS idx_authenticators_user ON authenticators(user_id);
CREATE INDEX IF NOT EXISTS idx_authenticators_credential ON authenticators(credential_id);

-- ============================================================================
-- 2. Recreate sessions table without CASCADE
-- ============================================================================
CREATE TABLE sessions_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT UNIQUE NOT NULL,
    authenticator_id TEXT REFERENCES authenticators(id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    dpop_jkt TEXT
);

INSERT INTO sessions_new SELECT * FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- ============================================================================
-- 3. Recreate oidc_states table without CASCADE
-- ============================================================================
CREATE TABLE oidc_states_new (
    id TEXT PRIMARY KEY,
    state TEXT UNIQUE NOT NULL,
    device_auth_id TEXT NOT NULL REFERENCES device_auth_requests(id),
    nonce TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO oidc_states_new SELECT * FROM oidc_states;
DROP TABLE oidc_states;
ALTER TABLE oidc_states_new RENAME TO oidc_states;

CREATE INDEX IF NOT EXISTS idx_oidc_states_state ON oidc_states(state);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expires ON oidc_states(expires_at);

-- ============================================================================
-- 4. Recreate oauth_clients table without CASCADE and CHECK
-- ============================================================================
CREATE TABLE oauth_clients_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    application_type TEXT NOT NULL,  -- CHECK removed, validated in app
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    access_scope TEXT NOT NULL DEFAULT 'personal',
    org_id TEXT REFERENCES organizations(id)
);

INSERT INTO oauth_clients_new SELECT * FROM oauth_clients;
DROP TABLE oauth_clients;
ALTER TABLE oauth_clients_new RENAME TO oauth_clients;

CREATE INDEX IF NOT EXISTS idx_oauth_clients_user ON oauth_clients(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(active);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_org ON oauth_clients(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_access_scope ON oauth_clients(access_scope);

-- ============================================================================
-- 5. Recreate oauth_client_secrets table without CASCADE
-- ============================================================================
CREATE TABLE oauth_client_secrets_new (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    secret_hash TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT
);

INSERT INTO oauth_client_secrets_new SELECT * FROM oauth_client_secrets;
DROP TABLE oauth_client_secrets;
ALTER TABLE oauth_client_secrets_new RENAME TO oauth_client_secrets;

CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_client ON oauth_client_secrets(oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_client_secrets_hash ON oauth_client_secrets(secret_hash);

-- ============================================================================
-- 6. Recreate oauth_usage_events table without CASCADE and CHECK
-- ============================================================================
CREATE TABLE oauth_usage_events_new (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    event_type TEXT NOT NULL,  -- CHECK removed, validated in app
    user_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO oauth_usage_events_new SELECT * FROM oauth_usage_events;
DROP TABLE oauth_usage_events;
ALTER TABLE oauth_usage_events_new RENAME TO oauth_usage_events;

CREATE INDEX IF NOT EXISTS idx_oauth_usage_client ON oauth_usage_events(oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_usage_created ON oauth_usage_events(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_usage_type ON oauth_usage_events(event_type);

-- ============================================================================
-- 7. Recreate scim_audit_log table without SET NULL FK
-- ============================================================================
CREATE TABLE scim_audit_log_new (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    actor_token_id TEXT,  -- FK removed, app handles SET NULL
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO scim_audit_log_new SELECT * FROM scim_audit_log;
DROP TABLE scim_audit_log;
ALTER TABLE scim_audit_log_new RENAME TO scim_audit_log;

CREATE INDEX IF NOT EXISTS idx_scim_audit_created ON scim_audit_log(created_at);

-- ============================================================================
-- 8. Recreate scim_group_members table without CASCADE
-- ============================================================================
CREATE TABLE scim_group_members_new (
    group_id TEXT NOT NULL REFERENCES scim_groups(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (group_id, user_id)
);

INSERT INTO scim_group_members_new SELECT * FROM scim_group_members;
DROP TABLE scim_group_members;
ALTER TABLE scim_group_members_new RENAME TO scim_group_members;

CREATE INDEX IF NOT EXISTS idx_scim_group_members_group_id ON scim_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user_id ON scim_group_members(user_id);

-- ============================================================================
-- 9. Recreate enrollment_sessions table without CASCADE
-- ============================================================================
CREATE TABLE enrollment_sessions_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    user_email TEXT NOT NULL,
    session_token_hash TEXT UNIQUE NOT NULL,
    device_auth_id TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    last_used_at TEXT DEFAULT (datetime('now'))
);

INSERT INTO enrollment_sessions_new SELECT * FROM enrollment_sessions;
DROP TABLE enrollment_sessions;
ALTER TABLE enrollment_sessions_new RENAME TO enrollment_sessions;

CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_token_hash ON enrollment_sessions(session_token_hash);
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_user_id ON enrollment_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_expires_at ON enrollment_sessions(expires_at);

-- ============================================================================
-- 10. Recreate auth_events table without CASCADE
-- ============================================================================
CREATE TABLE auth_events_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    event_type TEXT NOT NULL,
    authenticator_id TEXT,
    client_ip TEXT,
    user_agent TEXT,
    client_hostname TEXT,
    client_os TEXT,
    client_arch TEXT,
    client_version TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    failure_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO auth_events_new SELECT * FROM auth_events;
DROP TABLE auth_events;
ALTER TABLE auth_events_new RENAME TO auth_events;

CREATE INDEX IF NOT EXISTS idx_auth_events_user_id ON auth_events(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_client_ip ON auth_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_auth_events_event_type ON auth_events(event_type);

-- ============================================================================
-- 11. Recreate ssh_revoked_certificates table without CASCADE
-- ============================================================================
CREATE TABLE ssh_revoked_certificates_new (
    id TEXT PRIMARY KEY,
    serial TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    reason TEXT,
    revoked_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_by TEXT
);

INSERT INTO ssh_revoked_certificates_new SELECT * FROM ssh_revoked_certificates;
DROP TABLE ssh_revoked_certificates;
ALTER TABLE ssh_revoked_certificates_new RENAME TO ssh_revoked_certificates;

CREATE INDEX IF NOT EXISTS idx_ssh_revoked_serial ON ssh_revoked_certificates(serial);
CREATE INDEX IF NOT EXISTS idx_ssh_revoked_user_id ON ssh_revoked_certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_ssh_revoked_expires_at ON ssh_revoked_certificates(expires_at);

-- ============================================================================
-- 12. Recreate github_installations table without CASCADE
-- ============================================================================
CREATE TABLE github_installations_new (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    installation_id INTEGER NOT NULL UNIQUE,
    github_account_login TEXT NOT NULL,
    github_account_type TEXT NOT NULL,
    permissions TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    installed_at TEXT NOT NULL DEFAULT (datetime('now')),
    installed_by_user_id TEXT REFERENCES users(id),
    suspended_at TEXT,
    repositories TEXT
);

INSERT INTO github_installations_new SELECT * FROM github_installations;
DROP TABLE github_installations;
ALTER TABLE github_installations_new RENAME TO github_installations;

CREATE INDEX IF NOT EXISTS idx_github_installations_org ON github_installations(org_id);
CREATE INDEX IF NOT EXISTS idx_github_installations_account ON github_installations(github_account_login);
