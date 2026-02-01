-- Index for GitHub installation lookups by organization
CREATE INDEX ASYNC idx_github_installations_org ON github_installations(org_id);
