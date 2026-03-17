CREATE INDEX IF NOT EXISTS idx_audit_events_user_created ON audit_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_domain_created ON audit_events(email_domain, created_at);
