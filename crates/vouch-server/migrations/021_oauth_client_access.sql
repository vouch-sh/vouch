-- OAuth Client Access Scoping
-- Add access control to OAuth applications with three scope options:
-- - organization: Only users in the same org can authenticate
-- - personal: Only the app creator can authenticate
-- - public: Any authenticated Vouch user can authenticate

-- Add access_scope to oauth_clients
-- Values: 'organization', 'personal', 'public'
-- Default to 'personal' for backwards compatibility (only creator can access)
ALTER TABLE oauth_clients ADD COLUMN access_scope TEXT NOT NULL DEFAULT 'personal'
    CHECK (access_scope IN ('organization', 'personal', 'public'));

-- Add org_id for org-scoped apps (references the organization the app belongs to)
ALTER TABLE oauth_clients ADD COLUMN org_id TEXT REFERENCES organizations(id);

-- Backfill org_id from creator's org for existing apps
UPDATE oauth_clients
SET org_id = (SELECT org_id FROM users WHERE users.id = oauth_clients.user_id);

-- Index for org-based queries
CREATE INDEX IF NOT EXISTS idx_oauth_clients_org ON oauth_clients(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_access_scope ON oauth_clients(access_scope);
