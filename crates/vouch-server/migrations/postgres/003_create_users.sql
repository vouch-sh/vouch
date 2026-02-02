-- Users table
-- DSQL compatible: no REFERENCES constraints (org_id references organizations.id)
-- Timestamps generated in application code
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    external_id TEXT,
    org_id TEXT,  -- references organizations(id)
    is_org_admin BOOLEAN NOT NULL DEFAULT FALSE
);
