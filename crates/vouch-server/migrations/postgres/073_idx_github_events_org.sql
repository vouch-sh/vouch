-- Index for GitHub credential event lookups by organization
CREATE INDEX ASYNC idx_github_events_org ON github_credential_events(org_id);
