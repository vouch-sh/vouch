-- SCIM 2.0 Groups (RFC 7643)
CREATE TABLE IF NOT EXISTS scim_groups (
    id TEXT PRIMARY KEY,
    display_name TEXT UNIQUE NOT NULL,
    external_id TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Group membership
CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES scim_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for listing members by group
CREATE INDEX IF NOT EXISTS idx_scim_group_members_group_id ON scim_group_members(group_id);

-- Index for finding groups by user
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user_id ON scim_group_members(user_id);

-- Index for external ID lookup
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id ON scim_groups(external_id);
