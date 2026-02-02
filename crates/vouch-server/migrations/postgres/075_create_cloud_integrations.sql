-- Cloud integrations table (GCP, AWS)
-- DSQL compatible: no REFERENCES constraints (org_id references organizations.id)
-- Timestamps generated in application code
CREATE TABLE cloud_integrations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,  -- references organizations(id)
    provider TEXT NOT NULL,  -- 'gcp', 'aws'
    config TEXT NOT NULL,    -- JSON configuration
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by_user_id TEXT,
    UNIQUE(org_id, provider)
);
