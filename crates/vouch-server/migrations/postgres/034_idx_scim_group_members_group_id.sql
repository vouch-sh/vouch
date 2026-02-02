-- Index for group member lookups by group
CREATE INDEX ASYNC idx_scim_group_members_group_id ON scim_group_members(group_id);
