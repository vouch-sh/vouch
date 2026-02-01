-- Organizations table for domain-based multi-tenancy
-- DSQL compatible: no REFERENCES constraints
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_user_id TEXT
);
