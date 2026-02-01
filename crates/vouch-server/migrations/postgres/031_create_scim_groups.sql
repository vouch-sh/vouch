-- SCIM groups table
CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY,
    display_name TEXT UNIQUE NOT NULL,
    external_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
