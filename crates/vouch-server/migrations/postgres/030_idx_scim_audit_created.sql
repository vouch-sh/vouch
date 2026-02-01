-- Index for SCIM audit log time-based queries
CREATE INDEX ASYNC idx_scim_audit_created ON scim_audit_log(created_at);
