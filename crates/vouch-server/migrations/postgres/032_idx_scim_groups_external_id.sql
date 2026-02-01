-- Index for SCIM group external_id lookups
CREATE INDEX ASYNC idx_scim_groups_external_id ON scim_groups(external_id);
