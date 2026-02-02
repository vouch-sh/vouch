-- SCIM group membership table
-- DSQL compatible: no REFERENCES constraints
-- (group_id references scim_groups.id, user_id references users.id)
-- Timestamps generated in application code
CREATE TABLE scim_group_members (
    group_id TEXT NOT NULL,  -- references scim_groups(id)
    user_id TEXT NOT NULL,  -- references users(id)
    created_at TIMESTAMPTZ,
    PRIMARY KEY (group_id, user_id)
);
