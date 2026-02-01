-- Index for group member lookups by user
CREATE INDEX ASYNC idx_scim_group_members_user_id ON scim_group_members(user_id);
