-- Index for organization user lookups
CREATE INDEX ASYNC idx_users_org ON users(org_id);
