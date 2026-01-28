-- Allow multiple GitHub installations per Vouch organization
-- SQLite doesn't support DROP CONSTRAINT, so we recreate the table

-- Create new table without UNIQUE(org_id) constraint
CREATE TABLE github_installations_new (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    installation_id INTEGER NOT NULL UNIQUE,
    github_account_login TEXT NOT NULL,
    github_account_type TEXT NOT NULL,  -- "Organization" or "User"
    permissions TEXT NOT NULL,           -- JSON
    repository_selection TEXT NOT NULL,  -- "all" or "selected"
    installed_at TEXT NOT NULL DEFAULT (datetime('now')),
    installed_by_user_id TEXT REFERENCES users(id),
    suspended_at TEXT
    -- Removed: UNIQUE(org_id) to allow multiple GitHub orgs per Vouch org
);

-- Copy existing data
INSERT INTO github_installations_new
SELECT * FROM github_installations;

-- Drop old table
DROP TABLE github_installations;

-- Rename new table
ALTER TABLE github_installations_new RENAME TO github_installations;

-- Recreate index
CREATE INDEX IF NOT EXISTS idx_github_installations_org ON github_installations(org_id);

-- Add index for looking up by github account
CREATE INDEX IF NOT EXISTS idx_github_installations_account ON github_installations(github_account_login);
