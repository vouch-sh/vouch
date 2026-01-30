-- Cloud provider integration configurations per organization.
-- Similar to github_installations but for AWS/GCP.
-- GCP config JSON: {"project_number": "...", "pool_id": "...", "provider_id": "...", "service_account": "..."}
-- AWS config JSON: {"default_role_arn": "..."}

CREATE TABLE IF NOT EXISTS cloud_integrations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    provider TEXT NOT NULL,  -- 'gcp', 'aws'
    config TEXT NOT NULL,    -- JSON configuration
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by_user_id TEXT,
    UNIQUE(org_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_cloud_integrations_org ON cloud_integrations(org_id);
