-- SCIM groups table
-- Timestamps generated in application code
CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY,
    display_name TEXT UNIQUE NOT NULL,
    external_id TEXT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
