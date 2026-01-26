-- Organizations table for domain-based multi-tenancy
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by_user_id TEXT
);

-- Add org_id to users (NULL = personal account, e.g., gmail.com)
ALTER TABLE users ADD COLUMN org_id TEXT REFERENCES organizations(id);

-- Add is_org_admin flag to track organization administrators
ALTER TABLE users ADD COLUMN is_org_admin INTEGER NOT NULL DEFAULT 0;

-- Index for efficient org lookups
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
