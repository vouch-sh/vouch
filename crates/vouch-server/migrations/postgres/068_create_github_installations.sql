-- GitHub installations table for GitHub App integration
-- DSQL compatible: no REFERENCES constraints
-- (org_id references organizations.id, installed_by_user_id references users.id)
-- Timestamps generated in application code
CREATE TABLE github_installations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,  -- references organizations(id)
    installation_id BIGINT NOT NULL UNIQUE,
    github_account_login TEXT NOT NULL,
    github_account_type TEXT NOT NULL,  -- "Organization" or "User"
    permissions TEXT NOT NULL,           -- JSON
    repository_selection TEXT NOT NULL,  -- "all" or "selected"
    installed_at TIMESTAMPTZ NOT NULL,
    installed_by_user_id TEXT,  -- references users(id)
    suspended_at TIMESTAMPTZ,
    repositories TEXT
);
