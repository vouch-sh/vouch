-- Index for cloud integration lookups by organization
CREATE INDEX ASYNC idx_cloud_integrations_org ON cloud_integrations(org_id);
