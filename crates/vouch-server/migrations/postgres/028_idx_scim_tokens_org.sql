-- Index for organization SCIM token lookups
CREATE INDEX ASYNC idx_scim_tokens_org ON scim_tokens(org_id);
