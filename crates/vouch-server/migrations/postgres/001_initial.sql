-- PostgreSQL/Aurora DSQL compatible schema
-- This migration is for PostgreSQL and Aurora DSQL deployments
--
-- Key differences from SQLite:
-- - Uses BOOLEAN instead of INTEGER for boolean fields
-- - Uses TIMESTAMPTZ instead of TEXT for timestamps
-- - Uses BYTEA instead of BLOB for binary data
-- - Uses NOW() instead of datetime('now')
-- - Uses ON CONFLICT DO NOTHING instead of INSERT OR IGNORE
-- - Removes ON DELETE CASCADE (not enforced by DSQL, handled in application)
-- - Uses CREATE INDEX (ASYNC keyword removed for standard PostgreSQL compatibility)
-- - No index on BYTEA columns (not supported in DSQL)

-- Organizations (must be created before users due to foreign key)
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_user_id TEXT
);

CREATE INDEX idx_organizations_domain ON organizations(domain);

-- Users
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    external_id TEXT,
    org_id TEXT REFERENCES organizations(id),
    is_org_admin BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_external_id ON users(external_id);
CREATE INDEX idx_users_active ON users(active);
CREATE INDEX idx_users_org ON users(org_id);

-- Authenticators
CREATE TABLE authenticators (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    aaguid TEXT,
    user_handle BYTEA
);

CREATE INDEX idx_authenticators_user ON authenticators(user_id);
-- Note: No index on credential_id (BYTEA cannot be indexed in DSQL)

-- Sessions
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT UNIQUE NOT NULL,
    authenticator_id TEXT REFERENCES authenticators(id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- Device authorization requests (OAuth 2.0 Device Authorization Grant)
CREATE TABLE device_auth_requests (
    id TEXT PRIMARY KEY,
    device_code_hash TEXT UNIQUE NOT NULL,
    user_code TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, authorized, denied
    user_id TEXT REFERENCES users(id),
    user_email TEXT,
    authenticator_id TEXT REFERENCES authenticators(id),
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_auth_user_code ON device_auth_requests(user_code);
CREATE INDEX idx_device_auth_expires ON device_auth_requests(expires_at);

-- OIDC states for device authorization
CREATE TABLE oidc_states (
    id TEXT PRIMARY KEY,
    state TEXT UNIQUE NOT NULL,
    device_auth_id TEXT NOT NULL REFERENCES device_auth_requests(id),
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_states_state ON oidc_states(state);
CREATE INDEX idx_oidc_states_expires ON oidc_states(expires_at);

-- Server configuration
CREATE TABLE server_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authentication events for audit logging
CREATE TABLE auth_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    event_type TEXT NOT NULL,  -- login_success, login_failed, enrollment, logout
    authenticator_id TEXT,
    client_ip TEXT,
    user_agent TEXT,
    client_hostname TEXT,
    client_os TEXT,
    client_arch TEXT,
    client_version TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_events_user_id ON auth_events(user_id);
CREATE INDEX idx_auth_events_created_at ON auth_events(created_at);
CREATE INDEX idx_auth_events_client_ip ON auth_events(client_ip);
CREATE INDEX idx_auth_events_event_type ON auth_events(event_type);

-- SCIM tokens for provisioning
CREATE TABLE scim_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    org_id TEXT REFERENCES organizations(id),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_scim_tokens_hash ON scim_tokens(token_hash);
CREATE INDEX idx_scim_tokens_org ON scim_tokens(org_id);

-- SCIM audit log
CREATE TABLE scim_audit_log (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,  -- create, update, delete
    resource_type TEXT NOT NULL,  -- User
    resource_id TEXT NOT NULL,
    actor_token_id TEXT REFERENCES scim_tokens(id),
    details TEXT,  -- JSON with operation details
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scim_audit_created ON scim_audit_log(created_at);

-- SCIM groups
CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY,
    display_name TEXT UNIQUE NOT NULL,
    external_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scim_groups_external_id ON scim_groups(external_id);

-- SCIM group membership
CREATE TABLE scim_group_members (
    group_id TEXT NOT NULL REFERENCES scim_groups(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_scim_group_members_group_id ON scim_group_members(group_id);
CREATE INDEX idx_scim_group_members_user_id ON scim_group_members(user_id);

-- OAuth clients
CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    application_type TEXT NOT NULL CHECK (application_type IN ('web', 'native', 'spa', 'service')),
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    access_scope TEXT NOT NULL DEFAULT 'personal'
        CHECK (access_scope IN ('organization', 'personal', 'public')),
    org_id TEXT REFERENCES organizations(id)
);

CREATE INDEX idx_oauth_clients_user ON oauth_clients(user_id);
CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX idx_oauth_clients_active ON oauth_clients(active);
CREATE INDEX idx_oauth_clients_org ON oauth_clients(org_id);
CREATE INDEX idx_oauth_clients_access_scope ON oauth_clients(access_scope);

-- OAuth client secrets
CREATE TABLE oauth_client_secrets (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    secret_hash TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_oauth_client_secrets_client ON oauth_client_secrets(oauth_client_id);
CREATE INDEX idx_oauth_client_secrets_hash ON oauth_client_secrets(secret_hash);

-- OAuth usage events
CREATE TABLE oauth_usage_events (
    id TEXT PRIMARY KEY,
    oauth_client_id TEXT NOT NULL REFERENCES oauth_clients(id),
    event_type TEXT NOT NULL CHECK (event_type IN ('token_issued', 'token_refreshed', 'token_revoked', 'auth_success', 'auth_failure')),
    user_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_usage_client ON oauth_usage_events(oauth_client_id);
CREATE INDEX idx_oauth_usage_created ON oauth_usage_events(created_at);
CREATE INDEX idx_oauth_usage_type ON oauth_usage_events(event_type);

-- Pending OAuth authorizations
CREATE TABLE pending_oauth_authorizations (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    response_type TEXT NOT NULL DEFAULT 'code',
    state TEXT,
    scope TEXT,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_pending_oauth_expires ON pending_oauth_authorizations(expires_at);

-- DPoP nonces (Demonstrating Proof of Possession)
CREATE TABLE dpop_nonces (
    id TEXT PRIMARY KEY,
    nonce TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_dpop_nonces_expires ON dpop_nonces(expires_at);

-- DPoP JTI cache (prevents replay attacks)
CREATE TABLE dpop_jti_cache (
    jti TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_dpop_jti_expires ON dpop_jti_cache(expires_at);

-- Token exchanges (RFC 8693)
CREATE TABLE token_exchanges (
    id TEXT PRIMARY KEY,
    subject_user_id TEXT NOT NULL REFERENCES users(id),
    subject_token_hash TEXT NOT NULL,
    actor_user_id TEXT REFERENCES users(id),
    issued_token_hash TEXT UNIQUE NOT NULL,
    requested_audience TEXT,
    granted_scope TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_token_exchanges_subject ON token_exchanges(subject_user_id);
CREATE INDEX idx_token_exchanges_issued ON token_exchanges(issued_token_hash);

-- Delegation policies
CREATE TABLE delegation_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    grantor_pattern TEXT NOT NULL,
    grantee_pattern TEXT NOT NULL,
    allowed_scopes TEXT,
    max_ttl_seconds INTEGER DEFAULT 28800,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_delegation_policies_enabled ON delegation_policies(enabled);

-- SSH revoked certificates
CREATE TABLE ssh_revoked_certificates (
    id TEXT PRIMARY KEY,
    serial TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    reason TEXT,
    revoked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_by TEXT
);

CREATE INDEX idx_ssh_revoked_serial ON ssh_revoked_certificates(serial);
CREATE INDEX idx_ssh_revoked_user_id ON ssh_revoked_certificates(user_id);
CREATE INDEX idx_ssh_revoked_expires_at ON ssh_revoked_certificates(expires_at);

-- Enrollment sessions
CREATE TABLE enrollment_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    user_email TEXT NOT NULL,
    session_token_hash TEXT UNIQUE NOT NULL,
    device_auth_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_enrollment_sessions_token_hash ON enrollment_sessions(session_token_hash);
CREATE INDEX idx_enrollment_sessions_user_id ON enrollment_sessions(user_id);
CREATE INDEX idx_enrollment_sessions_expires_at ON enrollment_sessions(expires_at);

-- GitHub installations
CREATE TABLE github_installations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    installation_id BIGINT NOT NULL UNIQUE,
    github_account_login TEXT NOT NULL,
    github_account_type TEXT NOT NULL,  -- "Organization" or "User"
    permissions TEXT NOT NULL,           -- JSON
    repository_selection TEXT NOT NULL,  -- "all" or "selected"
    installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    installed_by_user_id TEXT REFERENCES users(id),
    suspended_at TIMESTAMPTZ,
    repositories TEXT
);

CREATE INDEX idx_github_installations_org ON github_installations(org_id);
CREATE INDEX idx_github_installations_account ON github_installations(github_account_login);

-- GitHub credential events
CREATE TABLE github_credential_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    user_email TEXT NOT NULL,
    org_id TEXT REFERENCES organizations(id),
    installation_id BIGINT,
    session_id TEXT,
    authenticator_id TEXT,
    repositories TEXT,
    permissions TEXT,
    token_expires_at TIMESTAMPTZ,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_code TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_github_events_user ON github_credential_events(user_id);
CREATE INDEX idx_github_events_org ON github_credential_events(org_id);
CREATE INDEX idx_github_events_created ON github_credential_events(created_at);

-- Cloud integrations (GCP, AWS)
CREATE TABLE cloud_integrations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    provider TEXT NOT NULL,  -- 'gcp', 'aws'
    config TEXT NOT NULL,    -- JSON configuration
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_user_id TEXT,
    UNIQUE(org_id, provider)
);

CREATE INDEX idx_cloud_integrations_org ON cloud_integrations(org_id);
